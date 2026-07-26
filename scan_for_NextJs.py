#!/usr/bin/env python3
"""
scan_nextjs.py

Bulk-scan a list of domains to detect whether they are built with Next.js.

Usage:
    python scan_nextjs.py domains.txt [--concurrency 500] [--output nextjs_domains.txt] [--verbose]

Detection signals (see README section below for rationale):
  Strong:
    - x-powered-by: Next.js header
    - x-vercel-* / x-nextjs-cache headers (Vercel-hosted Next.js)
    - __NEXT_DATA__ script tag with valid JSON (props/page/buildId keys)
    - self.__next_f (App Router streaming/RSC marker)
    - id="__next" / id='__next' root div
  Corroborating:
    - /_next/static/ resolving with 200/301/302/307/308 (403 dropped: WAF false-positive prone)
    - /_next/image optimizer returning a Next-specific error body on 400
"""

import argparse
import asyncio
import json
import re
import sys

import aiohttp
import aiofiles

DEFAULT_CONCURRENCY = 500
TIMEOUT = aiohttp.ClientTimeout(total=8)
LIMIT_PER_HOST = 10

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/xhtml+xml",
}

# Body markers checked via simple substring match (cheap, first pass)
NEXT_DATA_RE = re.compile(
    rb'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.DOTALL
)
NEXT_F_MARKER = b"self.__next_f"
NEXT_ROOT_MARKERS = (b'id="__next"', b"id='__next'")
NEXT_STATIC_REF = b"/_next/static/"

# Next.js image optimizer emits this specific complaint on malformed requests
NEXT_IMAGE_ERROR_HINT = b'"url" parameter is not allowed'

STATIC_OK_STATUSES = (200, 301, 302, 307, 308)  # 403 intentionally excluded


def _has_vercel_headers(headers) -> bool:
    for key in headers:
        lk = key.lower()
        if lk.startswith("x-vercel-") or lk == "x-nextjs-cache":
            return True
    return False


def _has_next_data(body: bytes) -> bool:
    match = NEXT_DATA_RE.search(body)
    if not match:
        return False
    try:
        data = json.loads(match.group(1))
    except (json.JSONDecodeError, ValueError):
        # tag present but didn't parse cleanly; still a reasonably strong signal
        return True
    return any(k in data for k in ("props", "page", "buildId"))


async def check_homepage(session, base: str) -> bool:
    async with session.get(
        base, headers=HEADERS, allow_redirects=True, ssl=False
    ) as resp:
        powered = resp.headers.get("x-powered-by", "").lower()
        if "next.js" in powered:
            return True

        if _has_vercel_headers(resp.headers):
            return True

        if resp.status >= 400:
            return False

        body = await resp.read()

        if _has_next_data(body):
            return True

        if NEXT_F_MARKER in body:
            return True

        if any(marker in body for marker in NEXT_ROOT_MARKERS):
            return True

        if NEXT_STATIC_REF in body:
            return True

    return False


async def check_static(session, base: str) -> bool:
    async with session.get(
        base + "/_next/static/", headers=HEADERS, allow_redirects=False, ssl=False
    ) as resp:
        return resp.status in STATIC_OK_STATUSES


async def check_image(session, base: str) -> bool:
    async with session.get(
        base + "/_next/image",
        params={"url": "/", "w": "64", "q": "75"},
        headers=HEADERS,
        allow_redirects=False,
        ssl=False,
    ) as resp:
        if resp.status == 200:
            return True

        server = resp.headers.get("server", "").lower()
        if "next" in server:
            return True

        if resp.status == 400:
            body = await resp.read()
            if NEXT_IMAGE_ERROR_HINT in body:
                return True

    return False


async def check_scheme(session, base: str) -> bool:
    """Run all three checks for one scheme concurrently."""
    try:
        results = await asyncio.gather(
            check_homepage(session, base),
            check_static(session, base),
            check_image(session, base),
            return_exceptions=True,
        )
    except Exception:
        return False
    return any(r is True for r in results)


async def is_nextjs(session, domain: str) -> bool:
    # Try https first; only fall back to http if https never even connected.
    try:
        https_result = await check_scheme(session, "https://" + domain)
        if https_result:
            return True
        # https reachable but not a match -> don't bother with http fallback
        return False
    except Exception:
        pass

    try:
        return await check_scheme(session, "http://" + domain)
    except Exception:
        return False


def normalize_domains(lines):
    seen = set()
    out = []
    for line in lines:
        d = line.strip()
        if not d:
            continue
        d = d.removeprefix("https://").removeprefix("http://")
        d = d.split("/")[0].strip().lower()
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


async def worker(name, queue, session, outfile, write_lock, stats, verbose):
    while True:
        domain = await queue.get()
        try:
            matched = await is_nextjs(session, domain)
            stats["checked"] += 1
            if matched:
                stats["matched"] += 1
                print(domain)
                async with write_lock:
                    await outfile.write(domain + "\n")
                    if stats["matched"] % 25 == 0:
                        await outfile.flush()
            elif verbose:
                print(f"  .. {domain} (no match)", file=sys.stderr)
        except Exception as exc:
            if verbose:
                print(f"  !! {domain} error: {exc}", file=sys.stderr)
        finally:
            queue.task_done()


async def progress_reporter(stats, total, interval=5):
    while stats["checked"] < total:
        await asyncio.sleep(interval)
        print(
            f"[progress] {stats['checked']}/{total} checked, "
            f"{stats['matched']} matched",
            file=sys.stderr,
        )


async def main(domains, concurrency, output_path, verbose):
    domains = normalize_domains(domains)
    total = len(domains)
    if total == 0:
        print("No valid domains to scan.", file=sys.stderr)
        return

    try:
        resolver = aiohttp.AsyncResolver()
    except Exception:
        # aiodns not installed; fall back to default threaded resolver
        resolver = None
        if verbose:
            print(
                "aiodns not available, falling back to default resolver "
                "(pip install aiodns for better DNS performance)",
                file=sys.stderr,
            )

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=LIMIT_PER_HOST,
        resolver=resolver,
        ssl=False,
        ttl_dns_cache=3600,
    )

    queue = asyncio.Queue()
    for domain in domains:
        queue.put_nowait(domain)

    stats = {"checked": 0, "matched": 0}
    write_lock = asyncio.Lock()

    async with aiofiles.open(output_path, "w") as outfile:
        async with aiohttp.ClientSession(
            connector=connector, timeout=TIMEOUT
        ) as session:
            workers = [
                asyncio.create_task(
                    worker(i, queue, session, outfile, write_lock, stats, verbose)
                )
                for i in range(concurrency)
            ]
            reporter = asyncio.create_task(progress_reporter(stats, total))

            await queue.join()

            for task in workers:
                task.cancel()
            reporter.cancel()

            await outfile.flush()

    print(
        f"Done. {stats['matched']}/{total} domains matched. "
        f"Results written to {output_path}",
        file=sys.stderr,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan a list of domains for Next.js fingerprints."
    )
    parser.add_argument("domains_file", help="Path to a file with one domain per line")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Max concurrent workers (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--output",
        default="nextjs_domains.txt",
        help="Output file for matched domains (default: nextjs_domains.txt)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print non-matches and errors to stderr as they happen",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    with open(args.domains_file, "r") as f:
        raw_domains = f.readlines()

    asyncio.run(main(raw_domains, args.concurrency, args.output, args.verbose))
