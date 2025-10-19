init_sources = files('init.c')

init_c_args = [
  '-DSUPERVISOR_PATH="@0@"'.format(get_option('sbindir') / 'initd-supervisor'),
  '-DINITD_VERSION="@0@"'.format(meson.project_version()),
  '-DINITD_SHUTDOWN="@0@"'.format('poweroff'),
  '-DINITD_HALT="@0@"'.format('halt'),
  '-DINITD_REBOOT="@0@"'.format('reboot'),
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
  dependencies: [common_dep],
  install: true,
  install_dir: get_option('sbindir'),
)
