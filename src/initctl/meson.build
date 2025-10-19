initctl = executable(
  'initctl',
  'initctl.c',
  dependencies: [common_dep, privileged_ops_dep],
  install: true,
  install_dir: get_option('bindir')
)

# Create systemctl symlink for compatibility
install_symlink(
  'systemctl',
  pointing_to: 'initctl',
  install_dir: get_option('bindir')
)
