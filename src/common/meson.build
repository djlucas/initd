common_sources = files(
  'parser.c',
  'scanner.c',
  'ipc.c',
  'control.c',
  'log.c',
)

common_lib = static_library(
  'common',
  common_sources,
  include_directories: include_directories('.'),
)

common_dep = declare_dependency(
  link_with: common_lib,
  include_directories: include_directories('.'),
)
