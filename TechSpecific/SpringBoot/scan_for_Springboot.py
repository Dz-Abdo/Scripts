#!/usr/bin/env python3
"""
SPresearch_v1.py

Standard-library-only reconnaissance tool that detects whether a target is
running Spring Boot, given a single URL or a list of domains/hosts.

This is a fingerprinting tool, not an exploit tool: every signal it looks
for is either default, publicly-documented Spring Boot behavior (the
"Whitelabel Error Page", the default Actuator HAL index, the default
error-JSON shape) or an unauthenticated, side-effect-free GET request to a
handful of well-known paths. It doesn't try to read, modify, or exfiltrate
anything from a target - it only classifies "is this Spring Boot" and, at
most, "does this look like Actuator is exposed", which is itself useful
defensive information (exposed Actuator endpoints are a common
misconfiguration).

DETECTION SIGNALS (each contributes weighted points to a per-host score;
the score is not a single boolean because any one signal alone can have a
plausible non-Spring-Boot explanation - e.g. a JSESSIONID cookie is just
"this is a Java web app" - so the verdict is evidence-based and the report
shows exactly which signals fired):

  * Whitelabel Error Page          - Spring Boot's literal default error
                                      page text; the single most distinctive
                                      signal in the whole set.
  * Whitelabel companion sentence  - "There was an unexpected error
                                      (type=...)" - the sentence that always
                                      accompanies the Whitelabel page; used
                                      as a confirmation bonus, not stand-alone.
  * Actuator media type            - Content-Type
                                      application/vnd.spring-boot.actuator.v{2,3}+json
                                      is a Spring-Boot-specific MIME type; if
                                      present, this is close to conclusive on
                                      its own.
  * Actuator HAL index             - the default JSON shape returned by GET
                                      /actuator, a HATEOAS "_links" object
                                      with entries like "self"/"health".
  * Actuator health shape          - {"status": "UP"|"DOWN"|...} returned by
                                      /actuator/health.
  * Default Spring error-JSON shape - GET with Accept: application/json to a
                                      404/error path returns Spring's default
                                      error body shape:
                                      {"timestamp","status","error","path"[,"trace"]}.
  * Embedded stack trace           - "org.springframework" appearing in a
                                      "trace" field or rendered HTML stack
                                      trace (only present if the app runs
                                      with debug/trace error attributes on).
  * X-Application-Context header   - legacy (Spring Boot 1.x) response
                                      header exposing "<app-name>:<profile>:<port>".
  * Server: Apache-Coyote header   - weak/supportive only; Apache Coyote is
                                      embedded Tomcat's connector, the
                                      default Spring Boot servlet container,
                                      but this alone is common to any
                                      Tomcat-based Java app.
  * JSESSIONID cookie              - weakest, purely supportive signal;
                                      generic to Java servlet containers.

Usage:
    # single URL
    TARGET=https://example.com python3 SPresearch_v1.py

    # multiple hosts (comma-separated, scheme optional - both http/https
    # are tried for bare hosts)
    TARGET=example.com,https://api.example.com python3 SPresearch_v1.py

    # list of domains from a file, one per line ('#' comments / blanks ignored)
    THREADS=10 TARGETS_FILE=hosts.txt python3 SPresearch_v1.py

    # route through a proxy (e.g. Burp), TLS verification disabled so an
    # intercepting proxy's self-signed CA doesn't need to be trusted
    TARGET=https://example.com PROXY=http://127.0.0.1:8080 python3 SPresearch_v1.py

Env vars:
    THREADS               default 10  - max concurrent hosts/probes
    TIMEOUT               default 12  - per-request timeout, seconds
    RETRIES               default 1  - retries for transient errors / 429
    RETRY_BACKOFF_BASE     default 0.5 - seconds, exponential backoff base
    MAX_BODY_SIZE         default 262144 (256 KB) - cap on bytes read per probe
    PROXY                 optional upstream HTTP(S) proxy URL
    JSON_OUT              optional path to also write machine-readable JSON results

Only the Python standard library is used.
"""

import sys
import os
import re
import ssl
import json
import time
import random
import string
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from collections import OrderedDict

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

try:
    THREADS = max(1, int(os.environ.get("THREADS", "10")))
except ValueError:
    THREADS = 10

try:
    TIMEOUT = max(1, int(os.environ.get("TIMEOUT", "12")))
except ValueError:
    TIMEOUT = 12

try:
    RETRIES = max(0, int(os.environ.get("RETRIES", "1")))
except ValueError:
    RETRIES = 1

try:
    RETRY_BACKOFF_BASE = max(0.0, float(os.environ.get("RETRY_BACKOFF_BASE", "0.5")))
except ValueError:
    RETRY_BACKOFF_BASE = 0.5

try:
    MAX_BODY_SIZE = max(4096, int(os.environ.get("MAX_BODY_SIZE", str(256 * 1024))))
except ValueError:
    MAX_BODY_SIZE = 256 * 1024

PROXY = os.environ.get("PROXY")
JSON_OUT = os.environ.get("JSON_OUT")

# Probe paths. "__RANDOM_404__" is replaced per-host with a random,
# guaranteed-not-to-exist path so we reliably trigger the app's real
# not-found handling (safer/more reliable than assuming "/" 404s).
PROBE_PATHS = [
    "/",
    "__RANDOM_404__",
    "/error",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/loggers",
]


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

class HTTPResponseData:
    __slots__ = ("status", "headers", "body", "error")

    def __init__(self, status=None, headers=None, body=b"", error=None):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.error = error

    def header(self, name):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


def _build_insecure_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class HTTPClient:
    """Follows redirects (we want the final rendered page/JSON for
    fingerprinting, not the raw redirect), optionally routes through a
    proxy with TLS verification disabled, and retries transient errors /
    429s with exponential backoff."""

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; SPresearch/1.0; +fingerprinting)",
    }

    def __init__(self, timeout=TIMEOUT, proxy=PROXY, retries=RETRIES, backoff_base=RETRY_BACKOFF_BASE):
        self.timeout = timeout
        self.retries = retries
        self.backoff_base = backoff_base

        handlers = [urllib.request.HTTPSHandler(context=_build_insecure_ssl_context())]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, url, method="GET", headers=None, max_bytes=MAX_BODY_SIZE):
        merged = dict(self.DEFAULT_HEADERS)
        merged.update(headers or {})
        req = urllib.request.Request(url, method=method, headers=merged)

        attempt = 0
        while True:
            result = self._do(req, max_bytes)
            transient = (result.error is not None) or (result.status == 429)
            if not transient or attempt >= self.retries:
                return result
            time.sleep(self.backoff_base * (2 ** attempt))
            attempt += 1

    def _do(self, req, max_bytes):
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                hdrs = dict(resp.headers.items())
                body = resp.read(max_bytes) if max_bytes else resp.read()
                return HTTPResponseData(status=status, headers=hdrs, body=body)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(max_bytes) if max_bytes else e.read()
            except Exception:
                body = b""
            hdrs = dict(e.headers.items()) if e.headers else {}
            return HTTPResponseData(status=e.code, headers=hdrs, body=body)
        except urllib.error.URLError as e:
            return HTTPResponseData(error=str(e.reason))
        except Exception as e:
            return HTTPResponseData(error=str(e))


# --------------------------------------------------------------------------
# Signal detection
# --------------------------------------------------------------------------

WHITELABEL_TEXT_RE = re.compile(r'Whitelabel\s+Error\s+Page', re.IGNORECASE)
WHITELABEL_COMPANION_RE = re.compile(
    r'This\s+application\s+has\s+no\s+explicit\s+mapping\s+for\s*/error'
    r'|There\s+was\s+an\s+unexpected\s+error\s*\(type=',
    re.IGNORECASE,
)

ACTUATOR_MEDIA_TYPE_RE = re.compile(r'application/vnd\.spring-boot\.actuator\.v\d\+json', re.IGNORECASE)

SPRING_TRACE_RE = re.compile(r'org\.springframework[\w\.]*', re.IGNORECASE)

X_APP_CONTEXT_RE = re.compile(r'^[\w\-\.]+:[\w\-]+:\d+$')  # "app:profile:port" (legacy header value)

SPRING_ERROR_JSON_KEYS = {"timestamp", "status", "error", "path"}

# Weighted point values per signal. Tuned so that the single most
# distinctive signals (Whitelabel text, actuator media type) are close to
# conclusive on their own, while generic/weak signals (JSESSIONID, bare
# Apache-Coyote) only ever nudge the score and can't cause a false
# CONFIRMED by themselves.
WEIGHTS = {
    "whitelabel_text": 45,
    "whitelabel_companion_bonus": 10,
    "actuator_media_type": 45,
    "actuator_hal_index": 30,
    "actuator_health_shape": 25,
    "spring_error_json_shape": 15,
    "spring_stacktrace": 30,
    "x_application_context_header": 30,
    "server_apache_coyote": 8,
    "jsessionid_cookie": 5,
}

THRESHOLDS = OrderedDict([
    ("CONFIRMED", 50),
    ("LIKELY", 25),
    ("POSSIBLE", 10),
])


def _random_404_path():
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return "/__sb_probe_%s__" % token


def _try_parse_json(body):
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _has_actuator_hal_shape(data):
    """Default Spring Boot Actuator index response is a HATEOAS document:
    {"_links": {"self": {"href": ...}, "health": {"href": ...}, ...}}"""
    if not isinstance(data, dict):
        return False
    links = data.get("_links")
    if not isinstance(links, dict):
        return False
    # "self" is present on essentially every HAL document Spring produces;
    # health/info are the most common actuator-specific neighbors.
    return "self" in links


def _has_actuator_health_shape(data):
    if not isinstance(data, dict):
        return False
    status = data.get("status")
    return isinstance(status, str) and status.upper() in ("UP", "DOWN", "OUT_OF_SERVICE", "UNKNOWN")


def _has_spring_error_json_shape(data):
    if not isinstance(data, dict):
        return False
    present = SPRING_ERROR_JSON_KEYS & set(data.keys())
    # Require at least 3 of the 4 canonical keys - avoids matching
    # unrelated JSON error bodies that happen to share one key name.
    return len(present) >= 3


class Evidence:
    __slots__ = ("signal", "weight", "path", "detail")

    def __init__(self, signal, weight, path, detail):
        self.signal = signal
        self.weight = weight
        self.path = path
        self.detail = detail


def analyze_response(path, resp, evidence_out):
    """Run every signal check against a single probe response, appending
    any that fire to evidence_out. Never raises."""
    if resp.error:
        return

    body = resp.body or b""
    text = None
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    content_type = resp.header("Content-Type") or ""

    # -- Whitelabel Error Page (+ companion sentence bonus) --
    if WHITELABEL_TEXT_RE.search(text):
        evidence_out.append(Evidence("whitelabel_text", WEIGHTS["whitelabel_text"], path,
                                      "response body contains the literal 'Whitelabel Error Page' text"))
        if WHITELABEL_COMPANION_RE.search(text):
            evidence_out.append(Evidence("whitelabel_companion_bonus", WEIGHTS["whitelabel_companion_bonus"], path,
                                          "companion sentence ('no explicit mapping for /error' / "
                                          "'unexpected error (type=...)') also present"))

    # -- Actuator-specific media type --
    if ACTUATOR_MEDIA_TYPE_RE.search(content_type):
        evidence_out.append(Evidence("actuator_media_type", WEIGHTS["actuator_media_type"], path,
                                      "Content-Type is a Spring Boot Actuator-specific media type: %s" % content_type))

    # -- JSON-shaped signals --
    data = _try_parse_json(body)
    if data is not None:
        if _has_actuator_hal_shape(data):
            evidence_out.append(Evidence("actuator_hal_index", WEIGHTS["actuator_hal_index"], path,
                                          "response is a HAL '_links' document typical of the Actuator index"))
        if _has_actuator_health_shape(data):
            evidence_out.append(Evidence("actuator_health_shape", WEIGHTS["actuator_health_shape"], path,
                                          "response has Actuator health shape: status=%r" % data.get("status")))
        if _has_spring_error_json_shape(data):
            evidence_out.append(Evidence("spring_error_json_shape", WEIGHTS["spring_error_json_shape"], path,
                                          "response is Spring's default error-JSON shape "
                                          "(timestamp/status/error/path)"))
        trace_val = data.get("trace") if isinstance(data, dict) else None
        if isinstance(trace_val, str) and SPRING_TRACE_RE.search(trace_val):
            evidence_out.append(Evidence("spring_stacktrace", WEIGHTS["spring_stacktrace"], path,
                                          "'trace' field contains an org.springframework stack frame"))

    # -- Stack trace leaking into rendered HTML (debug mode) --
    if data is None and SPRING_TRACE_RE.search(text):
        evidence_out.append(Evidence("spring_stacktrace", WEIGHTS["spring_stacktrace"], path,
                                      "response body contains an org.springframework stack frame"))

    # -- Legacy X-Application-Context header --
    xac = resp.header("X-Application-Context")
    if xac and X_APP_CONTEXT_RE.match(xac.strip()):
        evidence_out.append(Evidence("x_application_context_header", WEIGHTS["x_application_context_header"], path,
                                      "X-Application-Context header present: %s" % xac))

    # -- Weak supportive signals --
    server = resp.header("Server") or ""
    if "apache-coyote" in server.lower():
        evidence_out.append(Evidence("server_apache_coyote", WEIGHTS["server_apache_coyote"], path,
                                      "Server header indicates embedded Tomcat/Coyote: %s" % server))

    set_cookie = resp.header("Set-Cookie") or ""
    if "jsessionid" in set_cookie.lower():
        evidence_out.append(Evidence("jsessionid_cookie", WEIGHTS["jsessionid_cookie"], path,
                                      "JSESSIONID cookie set"))


# --------------------------------------------------------------------------
# Host-level orchestration
# --------------------------------------------------------------------------

class HostResult:
    def __init__(self, target):
        self.target = target
        self.evidence = []
        self.score = 0
        self.verdict = "NOT_DETECTED"
        self.probes_attempted = 0
        self.probes_errored = 0

    def to_dict(self):
        return {
            "target": self.target,
            "verdict": self.verdict,
            "score": self.score,
            "probes_attempted": self.probes_attempted,
            "probes_errored": self.probes_errored,
            "evidence": [
                {"signal": e.signal, "weight": e.weight, "path": e.path, "detail": e.detail}
                for e in self.evidence
            ],
        }


def classify_score(score):
    for verdict, threshold in THRESHOLDS.items():
        if score >= threshold:
            return verdict
    return "NOT_DETECTED"


def _probe_one(client, random_paths, target, path):
    """Run a single (target, probe-path) request. Standalone (not a
    closure) so it can be submitted straight into a shared pool alongside
    every other host's probe tasks."""
    actual_path = random_paths[target] if path == "__RANDOM_404__" else path
    url = target.rstrip("/") + actual_path
    # For error/actuator paths, ask for JSON explicitly - Spring will
    # honor Accept and return its default error-JSON shape instead of
    # the HTML Whitelabel page, which is a signal in its own right and
    # also lets us parse structured fields.
    headers = {"Accept": "application/json, text/html;q=0.8, */*;q=0.5"}
    resp = client.request(url, method="GET", headers=headers)
    local_evidence = []
    if not resp.error:
        analyze_response(actual_path, resp, local_evidence)
    return target, resp, local_evidence


def probe_all_hosts(resolved_targets, client, pool):
    """Probe every host's PROBE_PATHS through ONE shared pool, so THREADS
    bounds total concurrent in-flight requests across the whole run
    instead of being applied independently per-host and per-probe (which
    could previously multiply out to THREADS^2-ish concurrent requests).
    Prints and finalizes each host's result as soon as its own probes are
    all in, so streaming output behavior is unchanged."""
    random_paths = {t: _random_404_path() for t in resolved_targets}
    results_by_target = OrderedDict((t, HostResult(t)) for t in resolved_targets)
    evidence_by_target = {t: [] for t in resolved_targets}
    pending = {t: len(PROBE_PATHS) for t in resolved_targets}

    futures = [
        pool.submit(_probe_one, client, random_paths, t, p)
        for t in resolved_targets
        for p in PROBE_PATHS
    ]

    for fut in concurrent.futures.as_completed(futures):
        target, resp, local_evidence = fut.result()
        result = results_by_target[target]
        result.probes_attempted += 1
        if resp.error:
            result.probes_errored += 1
        else:
            evidence_by_target[target].extend(local_evidence)

        pending[target] -= 1
        if pending[target] == 0:
            # De-duplicate identical (signal, path) pairs defensively
            # (shouldn't normally happen, but keeps the score honest if a
            # check ever fires twice for the same response).
            seen = set()
            deduped = []
            for e in evidence_by_target[target]:
                key = (e.signal, e.path)
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(e)

            result.evidence = deduped
            result.score = sum(e.weight for e in deduped)
            result.verdict = classify_score(result.score)
            print_host_result(result)

    return list(results_by_target.values())


def _resolve_schemes(t, client):
    if t.startswith(("http://", "https://")):
        return [t]
    working = []
    for scheme in ("https://", "http://"):
        candidate = scheme + t
        resp = client.request(candidate + "/", method="GET", max_bytes=1024)
        if not resp.error or resp.status is not None:
            working.append(candidate)
    if not working:
        print("WARNING: could not connect to %s via http or https; defaulting to https://" % t)
        return ["https://" + t]
    return working


def resolve_all_schemes(targets, client, pool):
    """Scheme resolution for every target, run through the shared pool
    instead of a sequential for-loop. Previously this phase ran fully
    sequentially in the main thread regardless of THREADS, which made it
    the dominant cost for large TARGETS_FILE runs."""
    future_to_target = {pool.submit(_resolve_schemes, t, client): t for t in targets}
    resolved_by_target = {}
    for fut in concurrent.futures.as_completed(future_to_target):
        t = future_to_target[fut]
        try:
            resolved_by_target[t] = fut.result()
        except Exception as e:
            print("WARNING: scheme resolution failed for %s: %s" % (t, e))
            resolved_by_target[t] = []

    resolved_targets = []
    seen = set()
    for t in targets:  # preserve original input order in the report
        for resolved in resolved_by_target.get(t, []):
            if resolved not in seen:
                seen.add(resolved)
                resolved_targets.append(resolved)
                if resolved != t:
                    print("Resolved %s -> %s" % (t, resolved))
    return resolved_targets


def _parse_target_list():
    targets = []
    raw_target = os.environ.get("TARGET")
    if raw_target:
        for part in raw_target.split(","):
            part = part.strip()
            if part:
                targets.append(part)

    targets_file = os.environ.get("TARGETS_FILE")
    if targets_file:
        try:
            with open(targets_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.append(line)
        except OSError as e:
            print("ERROR: could not read TARGETS_FILE (%s): %s" % (targets_file, e))
            sys.exit(1)

    deduped = []
    seen = set()
    for t in targets:
        t = t.rstrip("/")
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_host_result(result):
    print()
    print("========================================")
    print("Target: %s" % result.target)
    print("========================================")
    print("Verdict: %s  (score: %d)" % (result.verdict, result.score))
    print("Probes: %d attempted, %d errored" % (result.probes_attempted, result.probes_errored))
    if result.evidence:
        print("Evidence:")
        for e in sorted(result.evidence, key=lambda x: x.weight, reverse=True):
            print("  [+%d] %-30s %-28s %s" % (e.weight, e.signal, e.path, e.detail))
    else:
        print("Evidence: none")


def print_grand_summary(all_results):
    print()
    print("========================================")
    print("Summary (all targets)")
    print("========================================")
    by_verdict = OrderedDict((v, []) for v in list(THRESHOLDS.keys()) + ["NOT_DETECTED"])
    for r in all_results:
        by_verdict[r.verdict].append(r.target)

    for verdict, targets in by_verdict.items():
        print("%-12s %d" % (verdict + ":", len(targets)))
    print()
    for verdict in ("CONFIRMED", "LIKELY", "POSSIBLE"):
        targets = by_verdict.get(verdict, [])
        if targets:
            print("%s:" % verdict)
            for t in targets:
                print("  - %s" % t)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    targets = _parse_target_list()
    if not targets:
        print("ERROR: no targets specified.")
        print("Set TARGET (comma-separated URLs/hosts) and/or TARGETS_FILE.")
        print("Usage: TARGET=https://example.com python3 SPresearch_v1.py")
        print("       TARGET=example.com,https://api.example.com python3 SPresearch_v1.py")
        print("       TARGETS_FILE=hosts.txt python3 SPresearch_v1.py")
        sys.exit(1)

    client = HTTPClient()

    if PROXY:
        print("Proxy: %s (TLS verification disabled)" % PROXY)
    print("Threads: %d | Timeout: %ds | Retries: %d" % (THREADS, TIMEOUT, RETRIES))

    # One shared pool for the whole run (scheme resolution AND probing).
    # THREADS now means "total concurrent requests in flight" throughout,
    # rather than being applied independently at multiple nested levels.
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        resolved_targets = resolve_all_schemes(targets, client, pool)

        print("Hosts to test: %d" % len(resolved_targets))
        for t in resolved_targets:
            print("  - %s" % t)

        if not resolved_targets:
            print("ERROR: no reachable hosts.")
            sys.exit(1)

        all_results = probe_all_hosts(resolved_targets, client, pool)

    # probe_all_hosts already returns results in resolved_targets order.
    print_grand_summary(all_results)

    if JSON_OUT:
        try:
            with open(JSON_OUT, "w") as f:
                json.dump([r.to_dict() for r in all_results], f, indent=2)
            print()
            print("JSON results written to %s" % JSON_OUT)
        except OSError as e:
            print("WARNING: could not write JSON_OUT (%s): %s" % (JSON_OUT, e))

    any_detected = any(r.verdict in ("CONFIRMED", "LIKELY") for r in all_results)
    sys.exit(0 if any_detected else 1)


if __name__ == "__main__":
    main()
