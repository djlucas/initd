#!/bin/bash
# meson-analyze-all.sh - Run all analysis tools in sequence

set -e

PROJECT_ROOT="$1"
OUTPUT_DIR="$PROJECT_ROOT/analysis-output"
SUMMARY_FILE="$OUTPUT_DIR/analysis-summary.log"

mkdir -p "$OUTPUT_DIR"
cd "$PROJECT_ROOT"

echo "========================================" | tee "$SUMMARY_FILE"
echo "  Running Complete Analysis Suite" | tee -a "$SUMMARY_FILE"
echo "========================================" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"
echo "Individual logs will be saved to: $OUTPUT_DIR" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

# Track failures
FAILED_TESTS=()
SKIPPED_TESTS=()

# 1. cppcheck
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "1/7 Running cppcheck..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
# Run cppcheck but don't fail on style warnings - they're documented in the log
meson compile -C build analyze-cppcheck 2>&1 | tee "$OUTPUT_DIR/cppcheck.log" || true
# Check if there are any error or warning level issues (not just style)
if grep -E "^.*(error|warning):" "$OUTPUT_DIR/cppcheck.log" | grep -v "style:" > /dev/null; then
    echo "✗ cppcheck found errors or warnings" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("cppcheck")
else
    echo "✓ cppcheck passed (style suggestions logged)" | tee -a "$SUMMARY_FILE"
fi
echo "" | tee -a "$SUMMARY_FILE"

# 2. flawfinder
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "2/7 Running flawfinder..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
if meson compile -C build analyze-flawfinder 2>&1 | tee "$OUTPUT_DIR/flawfinder.log"; then
    echo "✓ flawfinder passed" | tee -a "$SUMMARY_FILE"
else
    echo "✗ flawfinder failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("flawfinder")
fi
echo "" | tee -a "$SUMMARY_FILE"

# 3. scan-build
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "3/7 Running scan-build..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
if meson compile -C build analyze-scan 2>&1; then
    echo "✓ scan-build passed" | tee -a "$SUMMARY_FILE"
else
    echo "✗ scan-build failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("scan-build")
fi
echo "" | tee -a "$SUMMARY_FILE"

# 4. sanitizers
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "4/7 Running sanitizers..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
if meson compile -C build analyze-sanitizers 2>&1; then
    echo "✓ sanitizers passed" | tee -a "$SUMMARY_FILE"
else
    echo "✗ sanitizers failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("sanitizers")
fi
echo "" | tee -a "$SUMMARY_FILE"

# 5. valgrind
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "5/7 Running calendar fuzz harness..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
set +e
meson compile -C build analyze-fuzz-calendar 2>&1 | tee "$OUTPUT_DIR/fuzz-calendar.log"
FUZZ_STATUS=${PIPESTATUS[0]}
set -e
if [ "$FUZZ_STATUS" -eq 0 ]; then
    echo "✓ calendar fuzz completed (5,000 runs)" | tee -a "$SUMMARY_FILE"
elif grep -qi "unknown target" "$OUTPUT_DIR/fuzz-calendar.log" || grep -qi "Unknown target" "$OUTPUT_DIR/fuzz-calendar.log"; then
    echo "∙ calendar fuzz skipped (clang/libFuzzer unavailable)" | tee -a "$SUMMARY_FILE"
    SKIPPED_TESTS+=("fuzz-calendar")
else
    echo "✗ calendar fuzz failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("fuzz-calendar")
fi
echo "" | tee -a "$SUMMARY_FILE"

echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "6/7 Running valgrind..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
if meson compile -C build analyze-valgrind 2>&1; then
    echo "✓ valgrind passed" | tee -a "$SUMMARY_FILE"
else
    echo "✗ valgrind failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("valgrind")
fi
echo "" | tee -a "$SUMMARY_FILE"

# 6. shellcheck
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
echo "7/7 Running shellcheck..." | tee -a "$SUMMARY_FILE"
echo "----------------------------------------" | tee -a "$SUMMARY_FILE"
if meson compile -C build analyze-shellcheck 2>&1; then
    echo "✓ shellcheck passed" | tee -a "$SUMMARY_FILE"
else
    echo "✗ shellcheck failed" | tee -a "$SUMMARY_FILE"
    FAILED_TESTS+=("shellcheck")
fi
echo "" | tee -a "$SUMMARY_FILE"

# Summary
echo "========================================" | tee -a "$SUMMARY_FILE"
echo "  Analysis Summary" | tee -a "$SUMMARY_FILE"
echo "========================================" | tee -a "$SUMMARY_FILE"
if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo "✓ All analysis tools passed!" | tee -a "$SUMMARY_FILE"
    echo "" | tee -a "$SUMMARY_FILE"
    echo "Log files:" | tee -a "$SUMMARY_FILE"
    echo "  - cppcheck:    $OUTPUT_DIR/cppcheck.log" | tee -a "$SUMMARY_FILE"
    echo "  - flawfinder:  $OUTPUT_DIR/flawfinder.log" | tee -a "$SUMMARY_FILE"
    echo "  - scan-build:  $OUTPUT_DIR/scan-build.log" | tee -a "$SUMMARY_FILE"
    echo "  - sanitizers:  $OUTPUT_DIR/sanitizers.log" | tee -a "$SUMMARY_FILE"
    echo "  - fuzz:        $OUTPUT_DIR/fuzz-calendar.log" | tee -a "$SUMMARY_FILE"
    echo "  - valgrind:    $OUTPUT_DIR/valgrind.log" | tee -a "$SUMMARY_FILE"
    echo "  - shellcheck:  $OUTPUT_DIR/shellcheck.log" | tee -a "$SUMMARY_FILE"
    if [ ${#SKIPPED_TESTS[@]} -ne 0 ]; then
        echo "" | tee -a "$SUMMARY_FILE"
        echo "Skipped analyses: ${SKIPPED_TESTS[*]}" | tee -a "$SUMMARY_FILE"
    fi
    exit 0
else
    echo "✗ Failed tests: ${FAILED_TESTS[*]}" | tee -a "$SUMMARY_FILE"
    echo "" | tee -a "$SUMMARY_FILE"
    echo "Check individual log files in $OUTPUT_DIR for details" | tee -a "$SUMMARY_FILE"
    exit 1
fi
