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

# Privileged operations library (only for daemons, not workers)
privileged_ops_sources = files(
  'privileged-ops.c',
)

privileged_ops_lib = static_library(
  'privileged-ops',
  privileged_ops_sources,
  include_directories: include_directories('.'),
)

privileged_ops_dep = declare_dependency(
  link_with: privileged_ops_lib,
  include_directories: include_directories('.'),
)

# Timer IPC library
timer_ipc_sources = files(
  'timer-ipc.c',
)

timer_ipc_lib = static_library(
  'timer-ipc',
  timer_ipc_sources,
  include_directories: include_directories('.'),
)

timer_ipc_dep = declare_dependency(
  link_with: timer_ipc_lib,
  include_directories: include_directories('.'),
)

# Socket IPC library
socket_ipc_sources = files(
  'socket-ipc.c',
)

socket_ipc_lib = static_library(
  'socket-ipc',
  socket_ipc_sources,
  include_directories: include_directories('.'),
)

socket_ipc_dep = declare_dependency(
  link_with: socket_ipc_lib,
  include_directories: include_directories('.'),
)
