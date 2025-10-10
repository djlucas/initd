timer_daemon = executable(
  'initd-timer',
  ['initd-timer.c', 'calendar.c'],
  dependencies: common_dep,
  install: true,
  install_dir: get_option('sbindir')
)
