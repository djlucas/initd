# Default installation: completely minimal - no targets, no services
# All targets and services are installed via meson install --tags=reference

# Configuration data for template substitution
conf_data = configuration_data()
prefix = get_option('prefix')
conf_data.set('PREFIX', prefix)

# Handle absolute vs relative paths
sysconfdir = get_option('sysconfdir')
if not sysconfdir.startswith('/')
  sysconfdir = prefix / sysconfdir
endif

libdir = get_option('libdir')
if not libdir.startswith('/')
  libdir = prefix / libdir
endif

sbindir = get_option('sbindir')
if not sbindir.startswith('/')
  sbindir = prefix / sbindir
endif

bindir = get_option('bindir')
if not bindir.startswith('/')
  bindir = prefix / bindir
endif

libexecdir = get_option('libexecdir')
if not libexecdir.startswith('/')
  libexecdir = prefix / libexecdir
endif

conf_data.set('SYSCONFDIR', sysconfdir)
conf_data.set('SYSCONFIG_DIR', sysconfdir / 'sysconfig')
conf_data.set('INITD_SYSCONFIG_DIR', sysconfdir / 'sysconfig' / 'initd')
conf_data.set('UDEV_RULES_DIR', sysconfdir / 'udev' / 'rules.d')
conf_data.set('PPP_DIR', sysconfdir / 'ppp')
conf_data.set('HOSTNAME_FILE', sysconfdir / 'hostname')
conf_data.set('LIBDIR', libdir)
conf_data.set('SBINDIR', sbindir)
conf_data.set('BINDIR', bindir)
conf_data.set('LIBEXECDIR', libexecdir / 'initd')

bash = find_program('bash')

# Target files (no templating needed)
reference_targets = [
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

# Service files (need templating)
reference_services = [
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'getty@.service',
  'initd-socket.service',
  'initd-timer.service',
  'initd-user-manager.service',
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

reference_enable_services = []
foreach service : reference_services
  if service != 'network@.service' and service != 'getty@.service'
    reference_enable_services += service
  endif
endforeach
reference_enable_services = ' '.join(reference_enable_services)

# Helper scripts (need templating)
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
  'bridge',
  'dhclient',
  'dhcpcd',
  'iwd',
  'pppoe',
  'static',
  'wpa_supplicant',
]

# Configuration files (no templating)
reference_configs = [
  'console.conf',
  'createfiles.conf',
  'modules.conf',
  'network-eth0.conf.example',
  'udev_retry.conf',
]

# Optional service files (need templating)
optional_services = [
  'accounts-daemon.service',
  'acpid.service',
  'alsa.service',
  'atd.service',
  'autofs.service',
  'avahi-daemon.service',
  'avahi-dnsconfd.service',
  'bluetooth.service',
  'cups.service',
  'dbus.service',
  'dhcpcdat.service',
  'dovecot.service',
  'exim.service',
  'fcron.service',
  'firewalld.service',
  'git-daemon.service',
  'gpm.service',
  'haveged.service',
  'httpd.service',
  'iptables.service',
  'kea-ctrl-agent.service',
  'kea-ddns-server.service',
  'kea-dhcp4-server.service',
  'kea-dhcp6-server.service',
  'krb5-kadmind.service',
  'krb5-kdc.service',
  'krb5-kpropd.service',
  'lightdm.service',
  'mariadb.service',
  'named.service',
  'networkmanager.service',
  'nfs-client.service',
  'nfs-server.service',
  'nfsd.service',
  'nftables.service',
  'nmbd.service',
  'ntpd.service',
  'php-fpm.service',
  'postfix.service',
  'postgresql.service',
  'power-profiles-daemon.service',
  'proftpd.service',
  'random-seed.service',
  'rpc-idmapd.service',
  'rpc-mountd.service',
  'rpc-statd-notify.service',
  'rpc-statd.service',
  'rpcbind.service',
  'rsyncd.service',
  'rsyncdat.service',
  'rsyslog.service',
  'samba.service',
  'saslauthd.service',
  'sendmail.service',
  'slapd.service',
  'sm-client.service',
  'smartd.service',
  'smbd.service',
  'smbdat.service',
  'sshd.service',
  'sshdat.service',
  'stunnel.service',
  'svnserve.service',
  'syslog-ng.service',
  'sysmond.service',
  'sysstat.service',
  'unbound.service',
  'vsftpd.service',
  'winbindd.service',
  'xdm.service',
]

# Collect reference targets and generate service files
reference_target_sources = []
foreach target : reference_targets
  reference_target_sources += [meson.current_source_dir() / target]
endforeach

reference_service_outputs = []
foreach service : reference_services
  reference_service_outputs += [configure_file(
    input: 'reference' / service,
    output: service,
    configuration: conf_data,
    install: false
  )]
endforeach

# Process helper scripts
scriptdir = meson.project_source_root() / 'scripts'
reference_sbin_scripts = []
foreach script : reference_script_helpers
  reference_sbin_scripts += [configure_file(
    input: scriptdir / script,
    output: script,
    configuration: conf_data,
    install: false
  )]
endforeach

# Install initd-user-manager
reference_libexec_scripts = [configure_file(
  input: scriptdir / 'initd-user-manager',
  output: 'initd-user-manager',
  configuration: conf_data,
  install: false
)]

# Process service scripts
reference_service_script_outputs = []
foreach script : reference_service_scripts
  reference_service_script_outputs += [configure_file(
    input: scriptdir / 'service-scripts' / script,
    output: script,
    configuration: conf_data,
    install: false
  )]
endforeach

# Process network scripts
reference_network_script_outputs = []
foreach script : reference_network_scripts
  reference_network_script_outputs += [configure_file(
    input: scriptdir / 'network-services' / script,
    output: script,
    configuration: conf_data,
    install: false
  )]
endforeach

# Collect configuration sources
reference_config_sources = []
foreach config : reference_configs
  reference_config_sources += [meson.project_source_root() / 'sysconfig' / 'reference' / config]
endforeach

install_cmd = find_program('install')

unit_dest = get_option('libdir') / 'initd' / 'system'
sbin_dest = get_option('sbindir')
libexec_dest = get_option('libexecdir') / 'initd'
service_script_dest = libexec_dest / 'service-scripts'
network_script_dest = libexec_dest / 'network-services'
config_dest = get_option('sysconfdir') / 'sysconfig'

reference_install_args = []
foreach src : reference_target_sources
  reference_install_args += ['--unit', unit_dest, src]
endforeach
foreach src : reference_service_outputs
  reference_install_args += ['--unit', unit_dest, src]
endforeach
foreach src : reference_sbin_scripts
  reference_install_args += ['--exec', sbin_dest, src]
endforeach
foreach src : reference_libexec_scripts
  reference_install_args += ['--exec', libexec_dest, src]
endforeach
foreach src : reference_service_script_outputs
  reference_install_args += ['--exec', service_script_dest, src]
endforeach
foreach src : reference_network_script_outputs
  reference_install_args += ['--exec', network_script_dest, src]
endforeach
foreach src : reference_config_sources
  reference_install_args += ['--config', config_dest, src]
endforeach

# Convenience run target for reference installation
# Use: ninja -C build install-reference (or DESTDIR=... ninja -C build install-reference)
# This will show each file being installed
run_target('install-reference',
  command: [bash, '-c', '''
set -eu
if [ "$#" -lt 1 ] || [ "$1" != "--" ]; then
    echo "internal error: missing argument sentinel" >&2
    exit 1
fi
shift
if ! command -v install >/dev/null 2>&1; then
    echo "install command not found" >&2
    exit 1
fi
while [ $# -gt 0 ]; do
    key="$1"
    dest="$2"
    src="$3"
    case "$key" in
        --unit)
            mode=0644
            ;;
        --exec)
            mode=0755
            ;;
        --config)
            mode=0644
            ;;
        *)
            echo "unknown install key $key" >&2
            exit 1
            ;;
    esac
    base=$(basename "$src")
    install -D -m "$mode" "$src" "$dest/$base"
    shift 3
done

if [ "${DESTDIR:-}" = "" ]; then
    INITCTL=''' + (bindir / 'initctl') + '''
    if [ ! -x "$INITCTL" ]; then
        INITCTL="$(command -v initctl || true)"
    fi
    if [ -z "$INITCTL" ] || [ ! -x "$INITCTL" ]; then
        echo "initctl not found; skipping enablement" >&2
        exit 1
    fi
    for svc in ''' + reference_enable_services + '''; do
        "$INITCTL" enable "$svc"
    done
    for tty in 1 2 3 4 5 6; do
        "$INITCTL" enable "getty@tty${tty}"
    done
fi
''', 'initd-install-helper', '--'] + reference_install_args
)

# Optional service install targets are defined in units/optional/meson.build (included from main meson.build)
# Use: ninja -C build install-sshd (or install-networkmanager, etc.)
# These targets use 'install -D -v' to show what's being installed
