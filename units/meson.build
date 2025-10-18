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

# Process and install targets
foreach target : reference_targets
  install_data(target,
    install_dir: get_option('libdir') / 'initd' / 'system',
    install_tag: 'reference'
  )
endforeach

# Process and install services
foreach service : reference_services
  configure_file(
    input: 'reference' / service,
    output: service,
    configuration: conf_data,
    install: true,
    install_dir: get_option('libdir') / 'initd' / 'system',
    install_tag: 'reference'
  )
endforeach

# Process and install helper scripts
scriptdir = meson.project_source_root() / 'scripts'
foreach script : reference_script_helpers
  configure_file(
    input: scriptdir / script,
    output: script,
    configuration: conf_data,
    install: true,
    install_mode: 'rwxr-xr-x',
    install_dir: get_option('sbindir'),
    install_tag: 'reference'
  )
endforeach

# Install initd-user-manager
configure_file(
  input: scriptdir / 'initd-user-manager',
  output: 'initd-user-manager',
  configuration: conf_data,
  install: true,
  install_mode: 'rwxr-xr-x',
  install_dir: get_option('libexecdir') / 'initd',
  install_tag: 'reference'
)

# Process and install service scripts
foreach script : reference_service_scripts
  configure_file(
    input: scriptdir / 'service-scripts' / script,
    output: script,
    configuration: conf_data,
    install: true,
    install_mode: 'rwxr-xr-x',
    install_dir: get_option('libexecdir') / 'initd' / 'service-scripts',
    install_tag: 'reference'
  )
endforeach

# Process and install network scripts
foreach script : reference_network_scripts
  configure_file(
    input: scriptdir / 'network-services' / script,
    output: script,
    configuration: conf_data,
    install: true,
    install_mode: 'rwxr-xr-x',
    install_dir: get_option('libexecdir') / 'initd' / 'network-services',
    install_tag: 'reference'
  )
endforeach

# Install configuration files
foreach config : reference_configs
  install_data(
    meson.project_source_root() / 'sysconfig' / 'reference' / config,
    install_dir: get_option('sysconfdir') / 'sysconfig',
    install_tag: 'reference'
  )
endforeach

# Optional services - install individually with tags
foreach service : optional_services
  service_name = service.replace('.service', '')
  configure_file(
    input: 'optional' / service,
    output: service,
    configuration: conf_data,
    install: true,
    install_dir: get_option('libdir') / 'initd' / 'system',
    install_tag: service_name
  )
endforeach

# Convenience run target for reference installation
# Use: ninja -C build install-reference (or DESTDIR=... ninja -C build install-reference)
# This will show each file being installed
run_target('install-reference',
  command: ['meson', 'install', '-C', meson.project_build_root(), '--tags', 'reference', '--no-rebuild']
)

# For optional services, use: meson install --tags=sshd (or --tags=networkmanager, etc.)
