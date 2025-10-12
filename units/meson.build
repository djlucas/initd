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
# Core system services that are installed and enabled by default
reference_services = files(
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'getty@.service',
  'klogd.service',
  'localnet.service',
  'modules-load.service',
  'mountfs.service',
  'mountvirtfs.service',
  'netfs.service',
  'network@.service',
  'remount-root.service',
  'swap.service',
  'sysctl.service',
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
  'getty@tty1.service',
  'getty@tty2.service',
  'getty@tty3.service',
  'getty@tty4.service',
  'getty@tty5.service',
  'getty@tty6.service',
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
  'random-seed.service',
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

# Create ninja target for reference installation
bash = find_program('bash')
install_cmd = find_program('install')

run_target('install-reference',
  command: [bash, '-c', '''
set -e
DESTDIR="${DESTDIR:-}"
SRCDIR="@0@"
LIBDIR="$DESTDIR@1@"
SYSCONFDIR="$DESTDIR@2@"

# Install targets
install -D -m 644 "$SRCDIR/default.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/multi-user.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/basic.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/sysinit.target" -t "$LIBDIR/initd/system"

# Install services
install -D -m 644 "$SRCDIR/checkfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/console.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/createfiles.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/getty@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/klogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/localnet.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/modules-load.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/mountfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/mountvirtfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/netfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/network@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/remount-root.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/swap.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/sysctl.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/syslogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/udev-retry.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/udev-settle.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/udev-trigger.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/udevd.service" -t "$LIBDIR/initd/system"

# Install configs
install -D -m 644 "$SRCDIR/sysconfig/console.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SRCDIR/sysconfig/createfiles.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SRCDIR/sysconfig/modules.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SRCDIR/sysconfig/network-eth0.conf.example" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SRCDIR/sysconfig/udev_retry.conf" -t "$SYSCONFDIR/sysconfig"

# Create wants directories
mkdir -p "$SYSCONFDIR/initd/system/multi-user.target.wants"
mkdir -p "$SYSCONFDIR/initd/system/sysinit.target.wants"

# Enable multi-user.target services
for service in getty@tty1.service getty@tty2.service getty@tty3.service getty@tty4.service getty@tty5.service getty@tty6.service klogd.service syslogd.service; do
  ln -sf "$LIBDIR/initd/system/$service" "$SYSCONFDIR/initd/system/multi-user.target.wants/$service"
done

# Enable sysinit.target services
for service in checkfs.service console.service createfiles.service localnet.service modules-load.service mountfs.service mountvirtfs.service random-seed.service remount-root.service swap.service sysctl.service udev-retry.service udev-settle.service udev-trigger.service udevd.service; do
  ln -sf "$LIBDIR/initd/system/$service" "$SYSCONFDIR/initd/system/sysinit.target.wants/$service"
done
'''.format(meson.current_source_dir(), '/' + get_option('prefix') / get_option('libdir'), get_option('sysconfdir'))]
)
