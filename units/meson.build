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
  'reference/checkfs.service',
  'reference/console.service',
  'reference/createfiles.service',
  'reference/getty@.service',
  'reference/klogd.service',
  'reference/localnet.service',
  'reference/modules-load.service',
  'reference/mountfs.service',
  'reference/mountvirtfs.service',
  'reference/netfs.service',
  'reference/network@.service',
  'reference/remount-root.service',
  'reference/swap.service',
  'reference/sysctl.service',
  'reference/syslogd.service',
  'reference/udev-retry.service',
  'reference/udev-settle.service',
  'reference/udev-trigger.service',
  'reference/udevd.service',
)

# Configuration files
reference_configs = files(
  '../sysconfig/reference/console.conf',
  '../sysconfig/reference/createfiles.conf',
  '../sysconfig/reference/modules.conf',
  '../sysconfig/reference/network-eth0.conf.example',
  '../sysconfig/reference/udev_retry.conf',
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
install -D -m 644 "$SRCDIR/reference/checkfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/console.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/createfiles.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/getty@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/klogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/localnet.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/modules-load.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/mountfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/mountvirtfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/netfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/network@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/remount-root.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/swap.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/sysctl.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/syslogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-retry.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-settle.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-trigger.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udevd.service" -t "$LIBDIR/initd/system"

# Install configs
SYSCONFIGSRCDIR="@3@"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/console.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/createfiles.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/modules.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/network-eth0.conf.example" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/udev_retry.conf" -t "$SYSCONFDIR/sysconfig"

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
'''.format(meson.current_source_dir(), '/' + get_option('prefix') / get_option('libdir'), get_option('sysconfdir'), meson.project_source_root() / 'sysconfig')]
)
