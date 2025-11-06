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

# 5. fuzzing harnesses (requires clang + libFuzzer)
# Find clang explicitly for fuzzing, even if main build uses gcc
clang = find_program('clang', required: false)

# Check if clang supports fuzzer instrumentation
# Simple check: clang with -fsanitize=fuzzer support indicates libFuzzer availability
clang_supports_fuzzing = clang.found()

if clang_supports_fuzzing
  fuzz_includes = ['-I' + meson.project_source_root() / 'src']
  fuzz_timer_includes = ['-I' + meson.project_source_root() / 'src' / 'timer-daemon']
  fuzz_flags = ['-fsanitize=fuzzer', '-g', '-O1']

  # Calendar parser fuzzer
  fuzz_calendar = custom_target(
    'fuzz-calendar',
    output: 'fuzz-calendar',
    input: [
      'fuzz/calendar_fuzz.c',
      '../src/timer-daemon/calendar.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      fuzz_timer_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Unit file parser fuzzer
  fuzz_parser = custom_target(
    'fuzz-parser',
    output: 'fuzz-parser',
    input: [
      'fuzz/parser_fuzz.c',
      '../src/common/parser.c',
      '../src/common/scanner.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Control protocol fuzzer
  fuzz_control = custom_target(
    'fuzz-control',
    output: 'fuzz-control',
    input: [
      'fuzz/control_fuzz.c',
      '../src/common/control.c',
      '../src/common/log.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # IPC protocol fuzzer
  fuzz_ipc = custom_target(
    'fuzz-ipc',
    output: 'fuzz-ipc',
    input: [
      'fuzz/ipc_fuzz.c',
      '../src/common/ipc.c',
      '../src/common/log.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Socket IPC protocol fuzzer
  fuzz_socket_ipc = custom_target(
    'fuzz-socket-ipc',
    output: 'fuzz-socket-ipc',
    input: [
      'fuzz/socket_ipc_fuzz.c',
      '../src/common/socket-ipc.c',
      '../src/common/log.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Path security validation fuzzer
  fuzz_path_security = custom_target(
    'fuzz-path-security',
    output: 'fuzz-path-security',
    input: [
      'fuzz/path_security_fuzz.c',
      '../src/common/path-security.c',
      '../src/common/log.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Exec argv parsing fuzzer
  fuzz_exec_argv = custom_target(
    'fuzz-exec-argv',
    output: 'fuzz-exec-argv',
    input: [
      'fuzz/exec_argv_fuzz.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # IPC list receivers fuzzer
  fuzz_list_recv = custom_target(
    'fuzz-list-recv',
    output: 'fuzz-list-recv',
    input: [
      'fuzz/list_recv_fuzz.c',
      '../src/common/control.c',
      '../src/common/log.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Environment parsing fuzzer
  fuzz_environment = custom_target(
    'fuzz-environment',
    output: 'fuzz-environment',
    input: [
      'fuzz/environment_fuzz.c',
      '../src/common/parser.c',
      '../src/common/scanner.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Timer IPC protocol fuzzer
  fuzz_timer_ipc = custom_target(
    'fuzz-timer-ipc',
    output: 'fuzz-timer-ipc',
    input: [
      'fuzz/timer_ipc_fuzz.c',
      '../src/common/timer-ipc.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Privileged master/worker IPC fuzzer
  fuzz_priv_ipc = custom_target(
    'fuzz-priv-ipc',
    output: 'fuzz-priv-ipc',
    input: [
      'fuzz/priv_ipc_fuzz.c',
      '../src/common/ipc.c',
    ],
    command: [
      clang,
      fuzz_flags,
      fuzz_includes,
      '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true
  )

  # Unified fuzzing target
  run_target(
    'analyze-fuzz',
    command: [
      bash,
      meson.project_source_root() / 'analysis' / 'fuzz' / 'run-all-fuzzers.sh',
      meson.project_build_root()
    ],
    depends: [fuzz_calendar, fuzz_parser, fuzz_control, fuzz_ipc,
              fuzz_socket_ipc, fuzz_path_security, fuzz_exec_argv,
              fuzz_list_recv, fuzz_environment, fuzz_timer_ipc,
              fuzz_priv_ipc]
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
