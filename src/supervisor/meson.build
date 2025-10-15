supervisor_sources = files('initd-supervisor.c', 'service-registry.c')
supervisor_worker_sources = files('initd-supervisor-worker.c')

supervisor_c_args = [
  '-DWORKER_PATH="@0@"'.format(get_option('libexecdir') / 'initd' / 'initd-supervisor-worker'),
  '-DSUPERVISOR_USER="@0@"'.format(get_option('supervisor-user')),
]

# Build initd-supervisor (privileged daemon)
supervisor = executable(
  'initd-supervisor',
  supervisor_sources,
  c_args: supervisor_c_args,
  dependencies: [common_dep, privileged_ops_dep],
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)

# Build initd-supervisor-worker (unprivileged worker)
supervisor_worker = executable(
  'initd-supervisor-worker',
  supervisor_worker_sources,
  c_args: supervisor_c_args,
  dependencies: common_dep,
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)
