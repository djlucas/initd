# Default installation: minimal set for testing
unit_files = files(
  'default.target',
  'multi-user.target',
  'basic.target',
  'sysinit.target',
  '../tests/units/test.service',
)

install_data(
  unit_files,
  install_dir: get_option('libdir') / 'initd' / 'system',
)

# Reference installation: LFS-derived complete system
# This is a custom target, not installed by default
# Install with: meson install --tags reference

# Target files for reference installation
reference_targets = files(
  'default.target',
  'multi-user.target',
  'basic.target',
  'sysinit.target',
)

# Service files for reference installation
# Excludes: backup.*, docker.socket, echo.*, test
# No .socket or .timer files installed
# rsyslog and syslog-ng are installed but not enabled (alternatives to syslogd)
reference_services = files(
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'klogd.service',
  'localnet.service',
  'modules-load.service',
  'mountfs.service',
  'mountvirtfs.service',
  'network@.service',
  'remount-root.service',
  'rsyslog.service',
  'swap.service',
  'sysctl.service',
  'syslog-ng.service',
  'syslogd.service',
  'udev-retry.service',
  'udev-settle.service',
  'udev-trigger.service',
  'udevd.service',
)

# Configuration files
reference_configs = files(
  'sysconfig/console.conf',
  'sysconfig/createfiles.conf',
  'sysconfig/modules.conf',
  'sysconfig/network-eth0.conf.example',
  'sysconfig/udev_retry.conf',
)

# Install reference targets and services
install_data(
  reference_targets,
  install_dir: get_option('libdir') / 'initd' / 'system',
  install_tag: 'reference',
)

install_data(
  reference_services,
  install_dir: get_option('libdir') / 'initd' / 'system',
  install_tag: 'reference',
)

install_data(
  reference_configs,
  install_dir: get_option('sysconfdir') / 'sysconfig',
  install_tag: 'reference',
)

# Enable reference services (create symlinks)
# All services enabled except network@.service
# Services to enable in multi-user.target.wants
multi_user_wants = [
  'klogd.service',
  'syslogd.service',
]

# Services to enable in sysinit.target.wants
sysinit_wants = [
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'localnet.service',
  'modules-load.service',
  'mountfs.service',
  'mountvirtfs.service',
  'remount-root.service',
  'swap.service',
  'sysctl.service',
  'udev-retry.service',
  'udev-settle.service',
  'udev-trigger.service',
  'udevd.service',
]

# Create symlinks for enabled services
meson.add_install_script('sh', '-c', '''
  SYSCONFDIR="$DESTDIR@0@"
  LIBDIR="$DESTDIR@1@"

  # Create wants directories
  mkdir -p "$SYSCONFDIR/initd/system/multi-user.target.wants"
  mkdir -p "$SYSCONFDIR/initd/system/sysinit.target.wants"

  # Enable multi-user.target services
  for service in @2@; do
    ln -sf "$LIBDIR/initd/system/$service" \
           "$SYSCONFDIR/initd/system/multi-user.target.wants/$service"
  done

  # Enable sysinit.target services
  for service in @3@; do
    ln -sf "$LIBDIR/initd/system/$service" \
           "$SYSCONFDIR/initd/system/sysinit.target.wants/$service"
  done
'''.format(
  get_option('sysconfdir'),
  '/' + get_option('prefix') / get_option('libdir'),
  ' '.join(multi_user_wants),
  ' '.join(sysinit_wants)
), install_tag: 'reference')
