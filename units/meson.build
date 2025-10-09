# Install unit files
unit_files = files(
  'default.target',
  'multi-user.target',
  'basic.target',
  'sysinit.target',
  'test.service',
)

install_data(
  unit_files,
  install_dir: get_option('libdir') / 'initd' / 'system',
)
