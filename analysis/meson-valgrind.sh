#!/bin/bash
# meson-valgrind.sh - Memory leak and error detection wrapper for meson

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
BUILD_DIR="$OUTPUT_DIR/build-valgrind"
LOG_FILE="$OUTPUT_DIR/valgrind.log"

mkdir -p "$OUTPUT_DIR"

echo "=== Running valgrind on test suite ===" | tee "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Check if valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo "Error: valgrind is not installed" | tee -a "$LOG_FILE"
    echo "Install with: sudo apt install valgrind" | tee -a "$LOG_FILE"
    exit 1
fi

# Valgrind needs a clean build without sanitizers
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning existing valgrind build..." | tee -a "$LOG_FILE"
    rm -rf "$BUILD_DIR"
fi

cd "$PROJECT_ROOT"

echo "Setting up build for valgrind (with debug symbols)..." | tee -a "$LOG_FILE"
meson setup "$BUILD_DIR" -Dbuildtype=debug 2>&1 | tee -a "$LOG_FILE"

echo "Compiling..." | tee -a "$LOG_FILE"
meson compile -C "$BUILD_DIR" 2>&1 | tee -a "$LOG_FILE"

# Run each test under valgrind
TESTS=(
    "test-calendar"
    "test-parser"
    "test-control"
    "test-socket"
    "test-ipc"
    "test-scanner"
    "test-dependency"
    "test-state"
    "test-log"
    "test-integration"
)

echo "" | tee -a "$LOG_FILE"
for test in "${TESTS[@]}"; do
    echo "Running valgrind on $test..." | tee -a "$LOG_FILE"
    valgrind --leak-check=full \
             --show-leak-kinds=all \
             --track-origins=yes \
             --error-exitcode=1 \
             "$BUILD_DIR/tests/$test" 2>&1 | tee -a "$LOG_FILE"
    echo "✓ $test passed" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
done

echo "=== All tests passed valgrind checks ===" | tee -a "$LOG_FILE"
echo "Output saved to: $LOG_FILE" | tee -a "$LOG_FILE"
