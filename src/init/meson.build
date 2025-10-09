init_sources = files('init.c')

init_c_args = [
  '-DSUPERVISOR_PATH="@0@"'.format(get_option('libexecdir') / 'initd' / 'supervisor-master'),
]

# Build init statically by default, optionally dynamic
init_link_args = []
if not get_option('dynamic-init')
  init_link_args += ['-static']
endif

init = executable(
  'init',
  init_sources,
  c_args: init_c_args,
  link_args: init_link_args,
  install: true,
  install_dir: get_option('sbindir'),
)
