# Install journalctl script (default install)
# Other scripts (ifup, ifdown, etc.) are installed via install-reference target

journalctl_script = configure_file(
  input: 'journalctl',
  output: 'journalctl',
  configuration: configuration_data({
    'PREFIX': get_option('prefix'),
    'SYSCONFDIR': get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir'),
    'SYSCONFIG_DIR': (get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir')) / 'sysconfig',
    'INITD_SYSCONFIG_DIR': (get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir')) / 'sysconfig' / 'initd',
    'UDEV_RULES_DIR': (get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir')) / 'udev' / 'rules.d',
    'PPP_DIR': (get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir')) / 'ppp',
    'HOSTNAME_FILE': (get_option('sysconfdir').startswith('/') ? get_option('sysconfdir') : get_option('prefix') / get_option('sysconfdir')) / 'hostname',
    'LIBDIR': get_option('libdir').startswith('/') ? get_option('libdir') : get_option('prefix') / get_option('libdir'),
    'SBINDIR': get_option('sbindir').startswith('/') ? get_option('sbindir') : get_option('prefix') / get_option('sbindir'),
    'BINDIR': get_option('bindir').startswith('/') ? get_option('bindir') : get_option('prefix') / get_option('bindir'),
    'LIBEXECDIR': (get_option('libexecdir').startswith('/') ? get_option('libexecdir') : get_option('prefix') / get_option('libexecdir')) / 'initd',
  }),
)

install_data(
  journalctl_script,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)
