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

# Create basename lists for passing to bash script
reference_targets_basenames = [
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
]

reference_services_basenames = [
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'getty@.service',
  'initd-socket.service',
  'initd-timer.service',
  'klogd.service',
  'localnet.service',
  'modules-load.service',
  'mountfs.service',
  'mountvirtfs.service',
  'netfs.service',
  'network@.service',
  'network-wait-online.service',
  'remount-root.service',
  'swap.service',
  'sysctl.service',
  'syslogd.service',
  'udev-retry.service',
  'udev-settle.service',
  'udev-trigger.service',
  'udevd.service',
]

reference_configs_relative = [
  'reference/console.conf',
  'reference/createfiles.conf',
  'reference/modules.conf',
  'reference/network-eth0.conf.example',
  'reference/udev_retry.conf',
]

# Create ninja target for reference installation
bash = find_program('bash')
install_cmd = find_program('install')

run_target('install-reference',
  command: [bash, '-c', '''
set -e

resolve_path() {
  base="$1"
  rel="$2"
  case "$rel" in
    /*) echo "$rel" ;;
    *) echo "$base/$rel" ;;
  esac
}

DESTDIR="${DESTDIR:-}"
SRCDIR="$1"
SCRIPTDIR="$2"
PREFIX="$3"
SYSCONFDIR_REAL=$(resolve_path "$PREFIX" "$4")
LIBDIR_REAL=$(resolve_path "$PREFIX" "$5")
SBINDIR_REAL=$(resolve_path "$PREFIX" "$6")
BINDIR_REAL=$(resolve_path "$PREFIX" "$7")
LIBEXECDIR_BASE_REAL=$(resolve_path "$PREFIX" "$8")
LIBEXECDIR_REAL="$LIBEXECDIR_BASE_REAL/initd"

SYSCONFDIR="$DESTDIR$SYSCONFDIR_REAL"
LIBDIR="$DESTDIR$LIBDIR_REAL"
SBINDIR="$DESTDIR$SBINDIR_REAL"
BINDIR="$DESTDIR$BINDIR_REAL"
LIBEXECDIR="$DESTDIR$LIBEXECDIR_REAL"

TARGETS="$9"
SERVICES="${10}"
CONFIGS="${11}"
SCRIPT_HELPERS="${12}"
SERVICE_SCRIPTS="${13}"
NETWORK_SCRIPTS="${14}"
MULTI_WANTS="${15}"
SYSINIT_WANTS="${16}"
BASIC_WANTS="${17}"
SYSCONFIG_ROOT="${18}"

SYSCONFIG_DIR_REAL="$SYSCONFDIR_REAL/sysconfig"
INITD_SYSCONFIG_DIR_REAL="$SYSCONFIG_DIR_REAL/initd"
UDEV_RULES_DIR_REAL="$SYSCONFDIR_REAL/udev/rules.d"
PPP_DIR_REAL="$SYSCONFDIR_REAL/ppp"
HOSTNAME_FILE_REAL="$SYSCONFDIR_REAL/hostname"

render_template() {
  src="$1"
  dest="$2"
  mode="$3"
  mkdir -p "$(dirname "$dest")"
  sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@SYSCONFDIR@|$SYSCONFDIR_REAL|g" -e "s|@SYSCONFIG_DIR@|$SYSCONFIG_DIR_REAL|g" -e "s|@INITD_SYSCONFIG_DIR@|$INITD_SYSCONFIG_DIR_REAL|g" -e "s|@UDEV_RULES_DIR@|$UDEV_RULES_DIR_REAL|g" -e "s|@PPP_DIR@|$PPP_DIR_REAL|g" -e "s|@HOSTNAME_FILE@|$HOSTNAME_FILE_REAL|g" -e "s|@LIBDIR@|$LIBDIR_REAL|g" -e "s|@SBINDIR@|$SBINDIR_REAL|g" -e "s|@BINDIR@|$BINDIR_REAL|g" -e "s|@LIBEXECDIR@|$LIBEXECDIR_REAL|g" "$src" > "$dest"
  chmod "$mode" "$dest"
}

# Install targets
for target in $TARGETS; do
  render_template "$SRCDIR/$target" "$LIBDIR/initd/system/$target" 644
done

# Install services
for service in $SERVICES; do
  render_template "$SRCDIR/reference/$service" "$LIBDIR/initd/system/$service" 644
done

# Install helper scripts
for script in $SCRIPT_HELPERS; do
  render_template "$SCRIPTDIR/$script" "$SBINDIR/$script" 755
done

render_template "$SCRIPTDIR/initd-user-manager" "$LIBEXECDIR/initd-user-manager" 755

for script in $SERVICE_SCRIPTS; do
  render_template "$SCRIPTDIR/service-scripts/$script" "$LIBEXECDIR/service-scripts/$script" 755
done

for script in $NETWORK_SCRIPTS; do
  render_template "$SCRIPTDIR/network-services/$script" "$LIBEXECDIR/network-services/$script" 755
done

# Install configs
for config in $CONFIGS; do
  install -D -m 644 "$SYSCONFIG_ROOT/$config" -t "$SYSCONFDIR/sysconfig"
done
''',
    'install-reference',
    meson.current_source_dir(),
    meson.project_source_root() / 'scripts',
    get_option('prefix'),
    get_option('sysconfdir'),
    get_option('libdir'),
    get_option('sbindir'),
    get_option('bindir'),
    get_option('libexecdir'),
    ' '.join(reference_targets_basenames),
    ' '.join(reference_services_basenames),
    ' '.join(reference_configs_relative),
    ' '.join(reference_script_helpers),
    ' '.join(reference_service_scripts),
    ' '.join(reference_network_scripts),
    ' '.join(multi_user_wants),
    ' '.join(sysinit_wants),
    ' '.join(basic_wants),
    meson.project_source_root() / 'sysconfig',
  ]
)
