#!/bin/bash
# Run all fuzzers with a bounded iteration count.
# Usage: run-all-fuzzers.sh [builddir] [runs]

set -euo pipefail

BUILD_DIR="${1:-$(pwd)}"
RUNS="${2:-5000}"

FUZZ_DIR="${BUILD_DIR%/}/analysis"

calendar_bin="${FUZZ_DIR}/fuzz-calendar"
parser_bin="${FUZZ_DIR}/fuzz-parser"
control_bin="${FUZZ_DIR}/fuzz-control"
ipc_bin="${FUZZ_DIR}/fuzz-ipc"

for bin in "$calendar_bin" "$parser_bin" "$control_bin" "$ipc_bin"; do
    if [ ! -x "$bin" ]; then
        echo "error: expected fuzz binary '$bin' (build the fuzz targets first)" >&2
        exit 1
    fi
done

EXIT_CODE=0

echo "Running fuzzing suite ($RUNS iterations per fuzzer)..."
echo ""

echo "1/4 Fuzzing calendar parser..."
"$calendar_bin" -runs="$RUNS" || EXIT_CODE=1

echo ""
echo "2/4 Fuzzing unit file parser..."
"$parser_bin" -runs="$RUNS" || EXIT_CODE=1

echo ""
echo "3/4 Fuzzing control protocol..."
"$control_bin" -runs="$RUNS" || EXIT_CODE=1

echo ""
echo "4/4 Fuzzing IPC protocol..."
"$ipc_bin" -runs="$RUNS" || EXIT_CODE=1

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ All fuzzers completed successfully"
else
    echo "✗ One or more fuzzers found issues"
fi

exit $EXIT_CODE
