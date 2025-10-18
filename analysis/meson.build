# Analysis targets for static and dynamic analysis

# 1. cppcheck - Static analysis
cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
  bash = find_program('bash')
  run_target('analyze-cppcheck',
    command: [bash, meson.project_source_root() / 'analysis' / 'meson-cppcheck.sh', meson.project_source_root()]
  )
endif

# 2. flawfinder - Security-focused static analysis
flawfinder = find_program('flawfinder', required: false)
if flawfinder.found()
  bash = find_program('bash')
  run_target('analyze-flawfinder',
    command: [bash, meson.project_source_root() / 'analysis' / 'meson-flawfinder.sh', meson.project_source_root()]
  )
endif

# 3. scan-build requires a separate build directory
# Create a wrapper script for scan-build
scan_build = find_program('scan-build', required: false)
if scan_build.found()
  bash = find_program('bash')
  run_target('analyze-scan',
    command: [bash, meson.project_source_root() / 'analysis' / 'meson-scan-build.sh', meson.project_source_root()]
  )
endif

# 4. sanitizers require a separate build with special flags
# Create a wrapper script for sanitizer builds
bash = find_program('bash')
run_target('analyze-sanitizers',
  command: [bash, meson.project_source_root() / 'analysis' / 'meson-sanitizers.sh', meson.project_source_root()]
)

# 5. fuzzing harness for calendar parser (requires clang + libFuzzer)
fuzz_cc = meson.get_compiler('c')
if fuzz_cc.get_id() == 'clang' and fuzz_cc.has_argument('-fsanitize=fuzzer-no-link') and fuzz_cc.has_link_argument('-fsanitize=fuzzer')
  fuzz_c_args = ['-fsanitize=fuzzer-no-link']
  fuzz_link_args = ['-fsanitize=fuzzer']
  fuzz_calendar = executable(
    'fuzz-calendar',
    [
      'fuzz/calendar_fuzz.c',
      '../src/timer-daemon/calendar.c',
    ],
    include_directories: [
      include_directories('../src'),
      include_directories('../src/timer-daemon')
    ],
    c_args: fuzz_c_args,
    link_args: fuzz_link_args
  )

  run_target(
    'analyze-fuzz-calendar',
    command: [fuzz_calendar, '-runs=5000'],
    depends: fuzz_calendar
  )
endif

# 5. valgrind - Memory analysis on regular build
valgrind = find_program('valgrind', required: false)
if valgrind.found()
  bash = find_program('bash')
  run_target('analyze-valgrind',
    command: [bash, meson.project_source_root() / 'analysis' / 'meson-valgrind.sh', meson.project_source_root()]
  )
endif

# 6. shellcheck - Shell script static analysis
shellcheck = find_program('shellcheck', required: false)
if shellcheck.found()
  bash = find_program('bash')
  run_target('analyze-shellcheck',
    command: [bash, meson.project_source_root() / 'analysis' / 'meson-shellcheck.sh', meson.project_source_root()]
  )
endif

# Combined target to run all analysis tools
bash = find_program('bash')
run_target('analyze-all',
  command: [
    bash,
    meson.project_source_root() / 'analysis' / 'meson-analyze-all.sh',
    meson.project_source_root()
  ]
)
