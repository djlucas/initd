#!/bin/bash
# meson-flawfinder.sh - Security-focused static analysis wrapper for meson

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
LOG_FILE="$OUTPUT_DIR/flawfinder.log"

mkdir -p "$OUTPUT_DIR"

echo "=== Running flawfinder security analysis ===" | tee "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check if flawfinder is installed
if ! command -v flawfinder &> /dev/null; then
    echo "Error: flawfinder is not installed" | tee -a "$LOG_FILE"
    echo "Install with: sudo apt install flawfinder" | tee -a "$LOG_FILE"
    exit 1
fi

cd "$PROJECT_ROOT"

echo "Analyzing source code in src/..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

flawfinder --minlevel=1 \
           --context \
           --dataonly \
           src/ 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "=== flawfinder analysis complete ===" | tee -a "$LOG_FILE"
echo "Output saved to: $LOG_FILE" | tee -a "$LOG_FILE"
