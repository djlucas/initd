os_name = host_machine.system().to_lower()
is_linux = os_name == 'linux'
is_darwin = os_name == 'darwin'
is_hurd = os_name == 'gnu'
is_bsd = os_name in ['freebsd', 'netbsd', 'openbsd', 'dragonfly']

platform_conf = configuration_data()
platform_conf.set_quoted('PLATFORM_NAME', os_name)
platform_conf.set('INITD_PLATFORM_LINUX', is_linux)
platform_conf.set('INITD_PLATFORM_DARWIN', is_darwin)
platform_conf.set('INITD_PLATFORM_HURD', is_hurd)
platform_conf.set('INITD_PLATFORM_BSD', is_bsd)

platform_conf.set('INITD_HAVE_EPOLL', is_linux)
platform_conf.set('INITD_HAVE_KQUEUE', is_bsd or is_darwin)
# pidfile(3) style APIs exist on most Unix platforms we target
platform_conf.set('INITD_HAVE_PIDFILE', true)

configure_file(
  input: 'platform-config.h.in',
  output: 'platform-config.h',
  configuration: platform_conf,
)

common_includes = [
  include_directories('.'),
]

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
  include_directories: common_includes,
)

common_dep = declare_dependency(
  link_with: common_lib,
  include_directories: common_includes,
)

# Privileged operations library (only for daemons, not workers)
privileged_ops_sources = files(
  'privileged-ops.c',
  'path-security.c',
)

privileged_ops_lib = static_library(
  'privileged-ops',
  privileged_ops_sources,
  include_directories: common_includes,
)

privileged_ops_dep = declare_dependency(
  link_with: privileged_ops_lib,
  include_directories: common_includes,
)

# Timer IPC library
timer_ipc_sources = files(
  'timer-ipc.c',
)

timer_ipc_lib = static_library(
  'timer-ipc',
  timer_ipc_sources,
  include_directories: common_includes,
)

timer_ipc_dep = declare_dependency(
  link_with: timer_ipc_lib,
  include_directories: common_includes,
)

# Socket IPC library
socket_ipc_sources = files(
  'socket-ipc.c',
)

socket_ipc_lib = static_library(
  'socket-ipc',
  socket_ipc_sources,
  include_directories: common_includes,
)

socket_ipc_dep = declare_dependency(
  link_with: socket_ipc_lib,
  include_directories: common_includes,
)
