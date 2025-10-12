#!/bin/bash
# Wrapper script for running shellcheck on all shell scripts

set -e

PROJECT_ROOT="${1}"
OUTPUT_DIR="${PROJECT_ROOT}/analysis-output"
LOG_FILE="${OUTPUT_DIR}/shellcheck.log"

echo "=== Running shellcheck on shell scripts ==="
echo

# Create output directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Find all shell scripts by examining file contents
# 1. All files in scripts/ (regardless of executable bit)
# 2. All .sh files in analysis/
SCRIPT_FILES=$(find "${PROJECT_ROOT}/scripts" -type f 2>/dev/null)
ANALYSIS_SCRIPTS=$(find "${PROJECT_ROOT}/analysis" -name "*.sh" -type f 2>/dev/null)

# Combine the lists
ALL_SCRIPTS="${SCRIPT_FILES} ${ANALYSIS_SCRIPTS}"

# Filter to only actual shell scripts (have #!/bin/bash or #!/bin/sh shebang)
SHELL_SCRIPTS=""
for file in ${ALL_SCRIPTS}; do
    if head -n 1 "${file}" 2>/dev/null | grep -q '^#!/bin/\(ba\)\?sh'; then
        SHELL_SCRIPTS="${SHELL_SCRIPTS} ${file}"
    fi
done

# Use filtered list
ALL_SCRIPTS="${SHELL_SCRIPTS}"

if [ -z "${ALL_SCRIPTS}" ]; then
    echo "No shell scripts found to analyze"
    exit 0
fi

# Run shellcheck
echo "Analyzing shell scripts..."
echo "${ALL_SCRIPTS}" | xargs shellcheck --format=gcc > "${LOG_FILE}" 2>&1 || true

# Check results
ERROR_COUNT=$(grep -c "error:" "${LOG_FILE}" 2>/dev/null || true)
WARNING_COUNT=$(grep -c "warning:" "${LOG_FILE}" 2>/dev/null || true)
NOTE_COUNT=$(grep -c "note:" "${LOG_FILE}" 2>/dev/null || true)

# Default to 0 if grep returns empty
ERROR_COUNT=${ERROR_COUNT:-0}
WARNING_COUNT=${WARNING_COUNT:-0}
NOTE_COUNT=${NOTE_COUNT:-0}

echo
echo "=== ShellCheck Results ==="
echo "Errors:   ${ERROR_COUNT}"
echo "Warnings: ${WARNING_COUNT}"
echo "Notes:    ${NOTE_COUNT}"
echo
echo "Full results saved to: ${LOG_FILE}"
echo

if [ "${ERROR_COUNT}" -gt 0 ]; then
    echo "ShellCheck found ${ERROR_COUNT} error(s)"
    exit 1
elif [ "${WARNING_COUNT}" -gt 0 ]; then
    echo "ShellCheck found ${WARNING_COUNT} warning(s)"
    exit 0
else
    echo "✓ ShellCheck passed (only style notes)"
    exit 0
fi
