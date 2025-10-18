#!/bin/bash
# meson-cppcheck.sh - Static code analysis wrapper for meson

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
LOG_FILE="$OUTPUT_DIR/cppcheck.log"

mkdir -p "$OUTPUT_DIR"

echo "=== Running cppcheck static analysis ===" | tee "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check if cppcheck is installed
if ! command -v cppcheck &> /dev/null; then
    echo "Error: cppcheck is not installed" | tee -a "$LOG_FILE"
    echo "Install with: sudo apt install cppcheck" | tee -a "$LOG_FILE"
    exit 1
fi

cd "$PROJECT_ROOT"

echo "Analyzing source code in src/..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

cppcheck --enable=all \
         --suppress=missingIncludeSystem \
         --std=c11 \
         --platform=unix64 \
         --verbose \
         src/ 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "=== cppcheck analysis complete ===" | tee -a "$LOG_FILE"
echo "Output saved to: $LOG_FILE" | tee -a "$LOG_FILE"
