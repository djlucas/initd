timer_daemon_sources = files('initd-timer.c')
timer_worker_sources = files('initd-timer-worker.c', 'calendar.c')

timer_c_args = [
  '-DWORKER_PATH="@0@"'.format(get_option('libexecdir') / 'initd' / 'initd-timer-worker'),
  '-DTIMER_USER="@0@"'.format(get_option('timer-user')),
]

# Build initd-timer (privileged daemon)
timer_daemon = executable(
  'initd-timer',
  timer_daemon_sources,
  c_args: timer_c_args,
  dependencies: [common_dep, privileged_ops_dep, timer_ipc_dep],
  install: true,
  install_dir: get_option('sbindir'),
)

# Build initd-timer-worker (unprivileged worker)
timer_worker = executable(
  'initd-timer-worker',
  timer_worker_sources,
  c_args: timer_c_args,
  dependencies: [common_dep, privileged_ops_dep, timer_ipc_dep],
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)
