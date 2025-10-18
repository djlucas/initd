# Default installation: completely minimal - no targets, no services
# All targets and services are installed via install-reference or optional install targets

# Reference installation: LFS-derived complete system
# This is a custom target, not installed by default
# Install with: meson install --tags reference

# Target files for reference installation
reference_targets = files(
  'default.target',
  'multi-user.target',
  'basic.target',
  'sysinit.target',
  'graphical.target',
  'local-fs.target',
  'network.target',
  'network-online.target',
  'network-pre.target',
  'nfs-server.target',
  'nss-lookup.target',
  'remote-fs.target',
  'rpcbind.target',
  'shutdown.target',
  'sockets.target',
  'time-sync.target',
  'umount.target',
)

# Service files for reference installation
# Core system services that are installed and enabled by default
reference_services = files(
  'reference/checkfs.service',
  'reference/console.service',
  'reference/createfiles.service',
  'reference/getty@.service',
  'reference/initd-socket.service',
  'reference/initd-timer.service',
  'reference/klogd.service',
  'reference/localnet.service',
  'reference/modules-load.service',
  'reference/mountfs.service',
  'reference/mountvirtfs.service',
  'reference/netfs.service',
  'reference/network@.service',
  'reference/network-wait-online.service',
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

# Reference installation is done via run_target below, not install_data
# This ensures reference files are ONLY installed when explicitly requested

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

# Services to enable in basic.target.wants
basic_wants = [
  'initd-socket.service',
  'initd-timer.service',
]

# Helper scripts installed as part of the reference profile
reference_script_helpers = [
  'ifup',
  'ifdown',
  'journalctl',
]

reference_service_scripts = [
  'checkfs',
  'console',
  'createfiles',
  'localnet',
  'modules-load',
  'mountvirtfs',
  'netfs',
  'network-configure',
  'network-wait-online',
  'udev-retry',
  'udev-trigger',
]

reference_network_scripts = [
  'static',
]

# Symlink creation handled inside the install-reference run target below

# Create ninja target for reference installation
bash = find_program('bash')
install_cmd = find_program('install')

run_target('install-reference',
  command: [bash, '-c', '''
set -e
DESTDIR="${DESTDIR:-}"
SRCDIR="$1"
SCRIPTDIR="$2"
PREFIX="$3"
SYSCONFDIR="$DESTDIR$4"
LIBDIR="$DESTDIR$PREFIX/$5"
SBINDIR="$DESTDIR$PREFIX/$6"
LIBEXECDIR="$DESTDIR$PREFIX/$7/initd"
SCRIPT_HELPERS="$8"
SERVICE_SCRIPTS="$9"
NETWORK_SCRIPTS="${10}"
MULTI_WANTS="${11}"
SYSINIT_WANTS="${12}"
BASIC_WANTS="${13}"
SYSCONFIG="${14}"

# Install targets
install -D -m 644 "$SRCDIR/default.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/multi-user.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/basic.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/sysinit.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/graphical.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/local-fs.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/network.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/network-online.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/network-pre.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/nfs-server.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/nss-lookup.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/remote-fs.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/rpcbind.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/shutdown.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/sockets.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/time-sync.target" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/umount.target" -t "$LIBDIR/initd/system"

# Install services
install -D -m 644 "$SRCDIR/reference/checkfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/console.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/createfiles.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/getty@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/initd-socket.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/initd-timer.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/klogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/localnet.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/modules-load.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/mountfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/mountvirtfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/netfs.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/network@.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/network-wait-online.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/remount-root.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/swap.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/sysctl.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/syslogd.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-retry.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-settle.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udev-trigger.service" -t "$LIBDIR/initd/system"
install -D -m 644 "$SRCDIR/reference/udevd.service" -t "$LIBDIR/initd/system"

# Install helper scripts
for script in $SCRIPT_HELPERS; do
  install -D -m 755 "$SCRIPTDIR/$script" "$SBINDIR/$script"
done

install -D -m 755 "$SCRIPTDIR/initd-user-manager" "$LIBEXECDIR/initd-user-manager"

for script in $SERVICE_SCRIPTS; do
  install -D -m 755 "$SCRIPTDIR/service-scripts/$script" "$LIBEXECDIR/service-scripts/$script"
done

for script in $NETWORK_SCRIPTS; do
  install -D -m 755 "$SCRIPTDIR/network-services/$script" "$LIBEXECDIR/network-services/$script"
done

# Install configs
SYSCONFIGSRCDIR="$SYSCONFIG"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/console.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/createfiles.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/modules.conf" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/network-eth0.conf.example" -t "$SYSCONFDIR/sysconfig"
install -D -m 644 "$SYSCONFIGSRCDIR/reference/udev_retry.conf" -t "$SYSCONFDIR/sysconfig"

# Create wants directories
mkdir -p "$SYSCONFDIR/initd/system/multi-user.target.wants"
mkdir -p "$SYSCONFDIR/initd/system/sysinit.target.wants"
mkdir -p "$SYSCONFDIR/initd/system/basic.target.wants"

# Enable multi-user.target services
for service in $MULTI_WANTS; do
  ln -sf "$LIBDIR/initd/system/$service" "$SYSCONFDIR/initd/system/multi-user.target.wants/$service"
done

# Enable sysinit.target services
for service in $SYSINIT_WANTS; do
  ln -sf "$LIBDIR/initd/system/$service" "$SYSCONFDIR/initd/system/sysinit.target.wants/$service"
done

# Enable basic.target services
for service in $BASIC_WANTS; do
  ln -sf "$LIBDIR/initd/system/$service" "$SYSCONFDIR/initd/system/basic.target.wants/$service"
done
''',
    'install-reference',
    meson.current_source_dir(),
    meson.project_source_root() / 'scripts',
    get_option('prefix'),
    get_option('sysconfdir'),
    get_option('libdir'),
    get_option('sbindir'),
    get_option('libexecdir'),
    ' '.join(reference_script_helpers),
    ' '.join(reference_service_scripts),
    ' '.join(reference_network_scripts),
    ' '.join(multi_user_wants),
    ' '.join(sysinit_wants),
    ' '.join(basic_wants),
    meson.project_source_root() / 'sysconfig',
  ]
)
