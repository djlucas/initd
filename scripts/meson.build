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
  'service-scripts/netfs',
  'service-scripts/network-configure',
  'service-scripts/udev-retry',
  'service-scripts/udev-trigger',
  install_dir: get_option('libexecdir') / 'initd' / 'service-scripts',
  install_mode: 'rwxr-xr-x',
  install_tag: 'reference',
)

# Install static network service (installed by default with reference)
install_data(
  'network-services/static',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'reference',
)

# Optional network services - individual install targets
install_data(
  'network-services/bridge',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-bridge',
)

install_data(
  'network-services/dhclient',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-dhclient',
)

install_data(
  'network-services/dhcpcd',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-dhcpcd',
)

install_data(
  'network-services/iwd',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-iwd',
)

install_data(
  'network-services/pppoe',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-pppoe',
)

install_data(
  'network-services/wpa_supplicant',
  install_dir: get_option('libexecdir') / 'initd' / 'network-services',
  install_mode: 'rwxr-xr-x',
  install_tag: 'install-network-wpa_supplicant',
)
