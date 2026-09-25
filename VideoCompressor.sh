#!/usr/bin/env bash
set -euo pipefail

# =========================
#./VideoCompressor.sh video.mp4 compressed.mp4 
#Configuration
# =========================
INPUT="${1:-myrecording.mp4}"
OUTPUT="${2:-output.mp4}"

TARGET_MIB=5          # Target total file size
AUDIO_KBIT=128        # Audio bitrate when audio exists

MIN_VIDEO_KBIT=100    # Minimum video bitrate
MAX_VIDEO_KBIT=10000  # Maximum video bitrate

PRESET="medium"

# =========================
# Check dependencies
# =========================
command -v ffmpeg >/dev/null 2>&1 || {
    echo "Error: ffmpeg is not installed."
    exit 1
}

command -v ffprobe >/dev/null 2>&1 || {
    echo "Error: ffprobe is not installed."
    exit 1
}

[[ -f "$INPUT" ]] || {
    echo "Error: input file not found: $INPUT"
    exit 1
}

# =========================
# Get duration
# =========================
duration=$(ffprobe -v error \
    -show_entries format=duration \
    -of default=noprint_wrappers=1:nokey=1 \
    "$INPUT")

[[ -n "$duration" ]] || {
    echo "Error: could not determine video duration."
    exit 1
}

# =========================
# Detect audio
# =========================
if ffprobe -v error \
    -select_streams a:0 \
    -show_entries stream=index \
    -of csv=p=0 "$INPUT" | grep -q .; then
    HAS_AUDIO=1
else
    HAS_AUDIO=0
    AUDIO_KBIT=0
fi

# =========================
# Calculate video bitrate
# =========================
video_bitrate=$(awk \
    -v size="$TARGET_MIB" \
    -v d="$duration" \
    -v audio="$AUDIO_KBIT" \
    'BEGIN {
        printf "%.0f", ((size * 8192 / d) - audio)
    }')

# =========================
# Validate bitrate
# =========================
if (( video_bitrate <= 0 )); then
    echo "Error: target size is too small for this video duration."
    echo "Target: ${TARGET_MIB} MiB"
    echo "Duration: ${duration} seconds"
    echo "Audio bitrate: ${AUDIO_KBIT} kbps"
    exit 1
fi

# Apply minimum / maximum limits
if (( video_bitrate < MIN_VIDEO_KBIT )); then
    echo "Warning: calculated bitrate (${video_bitrate}k) is below minimum."
    echo "Using minimum bitrate: ${MIN_VIDEO_KBIT}k"
    video_bitrate=$MIN_VIDEO_KBIT
fi

if (( video_bitrate > MAX_VIDEO_KBIT )); then
    echo "Warning: calculated bitrate (${video_bitrate}k) exceeds maximum."
    echo "Using maximum bitrate: ${MAX_VIDEO_KBIT}k"
    video_bitrate=$MAX_VIDEO_KBIT
fi

# =========================
# Show settings
# =========================
echo
echo "Input:          $INPUT"
echo "Output:         $OUTPUT"
echo "Duration:       ${duration}s"
echo "Target size:    ${TARGET_MIB} MiB"
echo "Audio:          $([[ $HAS_AUDIO -eq 1 ]] && echo yes || echo no)"
echo "Audio bitrate:  ${AUDIO_KBIT}k"
echo "Video bitrate:  ${video_bitrate}k"
echo "Preset:         $PRESET"
echo

# =========================
# Two-pass encode
# =========================
ffmpeg -y -i "$INPUT" \
    -c:v libx264 \
    -preset "$PRESET" \
    -pix_fmt yuv420p \
    -b:v "${video_bitrate}k" \
    -pass 1 \
    -an \
    -f mp4 \
    /dev/null

if (( HAS_AUDIO )); then
    ffmpeg -y -i "$INPUT" \
        -c:v libx264 \
        -preset "$PRESET" \
        -pix_fmt yuv420p \
        -b:v "${video_bitrate}k" \
        -pass 2 \
        -c:a aac \
        -b:a "${AUDIO_KBIT}k" \
        "$OUTPUT"
else
    ffmpeg -y -i "$INPUT" \
        -c:v libx264 \
        -preset "$PRESET" \
        -pix_fmt yuv420p \
        -b:v "${video_bitrate}k" \
        -pass 2 \
        -an \
        "$OUTPUT"
fi

# =========================
# Clean two-pass files
# =========================
rm -f ffmpeg2pass-0.log ffmpeg2pass-0.log.mbtree

# =========================
# Report actual size
# =========================
actual_bytes=$(stat -c%s "$OUTPUT")
actual_mib=$(awk -v b="$actual_bytes" 'BEGIN {
    printf "%.2f", b / 1048576
}')

echo
echo "Encoding complete."
echo "Output: $OUTPUT"
echo "Actual size: ${actual_mib} MiB"
