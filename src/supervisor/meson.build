supervisor_sources = files('initd-supervisor.c', 'service-registry.c', 'process-tracking.c')
supervisor_worker_sources = files('initd-supervisor-worker.c')

supervisor_c_args = [
  '-DWORKER_PATH="@0@"'.format(get_option('prefix') / get_option('libexecdir') / 'initd' / 'initd-supervisor-worker'),
  '-DSUPERVISOR_USER="@0@"'.format(get_option('supervisor-user')),
]

# Build initd-supervisor (privileged daemon)
supervisor_deps = [common_dep, privileged_ops_dep]
if libcap_dep.found()
  supervisor_deps += libcap_dep
endif

supervisor = executable(
  'initd-supervisor',
  supervisor_sources,
  c_args: supervisor_c_args,
  dependencies: supervisor_deps,
  install: true,
  install_dir: get_option('sbindir'),
)

# Build initd-supervisor-worker (unprivileged worker)
supervisor_worker_deps = [common_dep]
if dbus_dep.found()
  supervisor_worker_deps += dbus_dep
endif

supervisor_worker = executable(
  'initd-supervisor-worker',
  supervisor_worker_sources,
  c_args: supervisor_c_args,
  dependencies: supervisor_worker_deps,
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)
