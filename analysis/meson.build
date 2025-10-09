# Analysis targets for static and dynamic analysis

# 1. cppcheck - Static analysis
cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
  run_target('analyze-cppcheck',
    command: [
      cppcheck,
      '--enable=all',
      '--suppress=missingIncludeSystem',
      '--std=c11',
      '--platform=unix64',
      '--verbose',
      meson.project_source_root() / 'src'
    ]
  )
endif

# 2. flawfinder - Security-focused static analysis
flawfinder = find_program('flawfinder', required: false)
if flawfinder.found()
  run_target('analyze-flawfinder',
    command: [
      flawfinder,
      '--minlevel=1',
      '--context',
      '--dataonly',
      meson.project_source_root() / 'src'
    ]
  )
endif

# 3. scan-build requires a separate build directory
# Create a wrapper script for scan-build
scan_build = find_program('scan-build', required: false)
if scan_build.found()
  scan_build_script = find_program(meson.project_source_root() / 'analysis' / 'meson-scan-build.sh')
  run_target('analyze-scan',
    command: [scan_build_script, meson.project_source_root()]
  )
endif

# 4. sanitizers require a separate build with special flags
# Create a wrapper script for sanitizer builds
sanitizer_script = find_program(meson.project_source_root() / 'analysis' / 'meson-sanitizers.sh')
run_target('analyze-sanitizers',
  command: [sanitizer_script, meson.project_source_root()]
)

# 5. valgrind - Memory analysis on regular build
valgrind = find_program('valgrind', required: false)
if valgrind.found()
  valgrind_script = find_program(meson.project_source_root() / 'analysis' / 'meson-valgrind.sh')
  run_target('analyze-valgrind',
    command: [valgrind_script, meson.project_source_root()]
  )
endif

# Combined target to run all analysis tools
run_target('analyze-all',
  command: [
    find_program(meson.project_source_root() / 'analysis' / 'meson-analyze-all.sh'),
    meson.project_source_root()
  ]
)
