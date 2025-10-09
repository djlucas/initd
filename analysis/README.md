# Security and Static Analysis Scripts

This directory contains scripts for running various security and code quality checks on the initd codebase.

## Prerequisites

Install required tools:

```bash
sudo apt install cppcheck flawfinder clang-tools valgrind
```

## Available Scripts

### Static Analysis

**run-cppcheck.sh** - General static analysis
- Checks for bugs, code quality issues, and common mistakes
- Fast execution
- Run: `./run-cppcheck.sh`

**run-flawfinder.sh** - Security-focused analysis
- Scans for security vulnerabilities (buffer overflows, format strings, race conditions)
- Identifies dangerous function usage
- Run: `./run-flawfinder.sh`

**run-scan-build.sh** - Clang static analyzer
- Deep static analysis using LLVM/Clang
- Rebuilds project with analysis enabled
- Run: `./run-scan-build.sh`

### Dynamic Analysis

**run-valgrind.sh** - Memory leak and error detection
- Runs entire test suite under valgrind
- Detects memory leaks, buffer overflows, use-after-free
- Run: `./run-valgrind.sh`

**run-sanitizers.sh** - AddressSanitizer + UndefinedBehaviorSanitizer
- Builds and tests with runtime sanitizers
- Catches memory errors and undefined behavior
- Run: `./run-sanitizers.sh`

## Workflow

Recommended order for comprehensive testing:

```bash
# 1. Quick static checks
./run-cppcheck.sh
./run-flawfinder.sh

# 2. Deep static analysis (slower)
./run-scan-build.sh

# 3. Dynamic analysis
./run-valgrind.sh
./run-sanitizers.sh
```

## Output

All scripts write to stdout/stderr. You can redirect output to files:

```bash
./run-cppcheck.sh 2>&1 | tee cppcheck-results.txt
./run-flawfinder.sh 2>&1 | tee flawfinder-results.txt
```

## Notes

- This directory is git-ignored (output files won't be committed)
- Scripts expect to be run from within the `analysis/` directory
- Some scripts (scan-build, sanitizers) will create temporary build directories
- All scripts set `set -e` to exit on first error
