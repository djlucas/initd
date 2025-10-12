#!/bin/bash
# meson-sanitizers.sh - Build and test with sanitizers wrapper for meson

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
BUILD_DIR="$OUTPUT_DIR/build-sanitizers"
LOG_FILE="$OUTPUT_DIR/sanitizers.log"

mkdir -p "$OUTPUT_DIR"

echo "=== Building and testing with sanitizers ===" | tee "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Clean any existing sanitizer build
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning existing sanitizer build..." | tee -a "$LOG_FILE"
    rm -rf "$BUILD_DIR"
fi

cd "$PROJECT_ROOT"

# Build with AddressSanitizer, UndefinedBehaviorSanitizer, and LeakSanitizer
# Use dynamic linking for sanitizers
echo "Setting up build with sanitizers..." | tee -a "$LOG_FILE"
meson setup "$BUILD_DIR" \
    -Ddynamic-init=true \
    -Db_sanitize=address,undefined \
    -Db_lundef=false 2>&1 | tee -a "$LOG_FILE"

echo "Compiling with sanitizers..." | tee -a "$LOG_FILE"
meson compile -C "$BUILD_DIR" 2>&1 | tee -a "$LOG_FILE"

echo "Running test suite with sanitizers..." | tee -a "$LOG_FILE"
meson test -C "$BUILD_DIR" 2>&1 | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "=== Sanitizer tests complete ===" | tee -a "$LOG_FILE"
echo "Output saved to: $LOG_FILE" | tee -a "$LOG_FILE"
