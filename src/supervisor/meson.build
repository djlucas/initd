supervisor_master_sources = files('supervisor-master.c')
supervisor_slave_sources = files('supervisor-slave.c')

supervisor_c_args = [
  '-DSLAVE_PATH="@0@"'.format(get_option('libexecdir') / 'initd' / 'supervisor-slave'),
  '-DSUPERVISOR_USER="@0@"'.format(get_option('supervisor-user')),
]

# Build supervisor-master
supervisor_master = executable(
  'supervisor-master',
  supervisor_master_sources,
  c_args: supervisor_c_args,
  dependencies: common_dep,
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)

# Build supervisor-slave
supervisor_slave = executable(
  'supervisor-slave',
  supervisor_slave_sources,
  c_args: supervisor_c_args,
  dependencies: common_dep,
  install: true,
  install_dir: get_option('libexecdir') / 'initd',
)
