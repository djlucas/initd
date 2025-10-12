#!/bin/bash
# meson-scan-build.sh - Clang static analyzer wrapper for meson

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
BUILD_DIR="$OUTPUT_DIR/build-scan"
LOG_FILE="$OUTPUT_DIR/scan-build.log"

mkdir -p "$OUTPUT_DIR"

echo "=== Running Clang static analyzer ===" | tee "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check if scan-build is installed
if ! command -v scan-build &> /dev/null; then
    echo "Error: scan-build is not installed" | tee -a "$LOG_FILE"
    echo "Install with: sudo apt install clang-tools" | tee -a "$LOG_FILE"
    exit 1
fi

# Clean build directory
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning existing scan-build directory..." | tee -a "$LOG_FILE"
    rm -rf "$BUILD_DIR"
fi

# Run scan-build with meson
cd "$PROJECT_ROOT"

echo "Setting up build with scan-build..." | tee -a "$LOG_FILE"
scan-build meson setup "$BUILD_DIR" 2>&1 | tee -a "$LOG_FILE"

echo "Running analysis..." | tee -a "$LOG_FILE"
scan-build --status-bugs meson compile -C "$BUILD_DIR" 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "=== scan-build analysis complete ===" | tee -a "$LOG_FILE"
echo "Output saved to: $LOG_FILE" | tee -a "$LOG_FILE"
