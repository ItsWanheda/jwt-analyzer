#!/bin/bash
# Process every .txt file in /app/tokens/batch/, write a report for each.
# Designed to run inside the jwt-analyzer-batch container.

set -euo pipefail

INPUT_DIR="/app/tokens"
OUTPUT_DIR="/app/reports"
WORDLIST="/app/wordlists/common_secrets.txt"

mkdir -p "$OUTPUT_DIR"

total=0
cracked=0
failed=0

for token_file in "$INPUT_DIR"/*.txt; do
    [ -e "$token_file" ] || continue  # handle empty dir
    total=$((total + 1))

    filename=$(basename "$token_file" .txt)
    timestamp=$(date +%Y%m%d-%H%M%S)
    report_path="$OUTPUT_DIR/${filename}-${timestamp}"

    echo "[$(date +%H:%M:%S)] Processing: $filename"

    # Run audit. Continue on error so one bad token doesn't kill the batch.
    if python /app/main.py audit \
        --token-file "$token_file" \
        --wordlist "$WORDLIST" \
        --output "$report_path" \
        --format json 2>> "$OUTPUT_DIR/errors.log"; then
        cracked=$((cracked + 1))
    else
        failed=$((failed + 1))
        echo "  FAILED - see $OUTPUT_DIR/errors.log"
    fi
done

echo ""
echo "==================================="
echo "Batch complete"
echo "  Total:   $total"
echo "  Cracked: $cracked"
echo "  Failed:  $failed"
echo "==================================="