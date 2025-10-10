socket_daemon_sources = files('initd-socket.c')
socket_worker_sources = files('initd-socket-worker.c')

socket_c_args = [
  '-DWORKER_PATH="@0@"'.format(get_option('libexecdir') / 'initd' / 'initd-socket-worker'),
  '-DSOCKET_USER="@0@"'.format(get_option('socket-user')),
]

# Build initd-socket (privileged daemon)
socket_daemon = executable(
  'initd-socket',
  socket_daemon_sources,
  c_args: socket_c_args,
  dependencies: [common_dep, privileged_ops_dep, socket_ipc_dep],
  install: true,
  install_dir: get_option('sbindir'),
)

# Build initd-socket-worker (unprivileged worker)
socket_worker = executable(
  'initd-socket-worker',
  socket_worker_sources,
  c_args: socket_c_args,
  dependencies: [common_dep, socket_ipc_dep],
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)
