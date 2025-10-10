# Reference installation scripts
# Install with: meson install --tags reference

# Install helper scripts
install_data(
  'ifup',
  'ifdown',
  'journalctl',
  install_dir: get_option('sbindir'),
  install_mode: 'rwxr-xr-x',
  install_tag: 'reference',
)

# Install service scripts
install_data(
  'service-scripts/checkfs',
  'service-scripts/console',
  'service-scripts/createfiles',
  'service-scripts/localnet',
  'service-scripts/modules-load',
  'service-scripts/mountvirtfs',
  'service-scripts/network-configure',
  'service-scripts/udev-retry',
  'service-scripts/udev-trigger',
  install_dir: get_option('libexecdir') / 'initd' / 'service-scripts',
  install_mode: 'rwxr-xr-x',
  install_tag: 'reference',
)

# Install network service scripts (excluding dhclient - replaced by KEA DHCP)
install_data(
  'network-services/dhcpcd',
  'network-services/iwd',
  'network-services/pppoe',
  'network-services/static',
  'network-services/wpa_supplicant',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'reference',
)
