# Optional BLFS services - not installed by default
# Each service has its own ninja target: ninja -C build install-<service>

# Define all optional units
optional_units = {
  'accounts-daemon': ['accounts-daemon.service'],
  'acpid': ['acpid.service', 'acpid.socket'],
  'alsa': ['alsa.service'],
  'atd': ['atd.service'],
  'autofs': ['autofs.service'],
  'avahi-daemon': ['avahi-daemon.service'],
  'avahi-dnsconfd': ['avahi-dnsconfd.service'],
  'bluetooth': ['bluetooth.service'],
  'cups': ['cups.service'],
  'dbus': ['dbus.service', 'dbus.socket'],
  'dhcpcd-at': ['dhcpcdat.service'],
  'dovecot': ['dovecot.service'],
  'exim': ['exim.service'],
  'fcron': ['fcron.service'],
  'firewalld': ['firewalld.service'],
  'git-daemon': ['git-daemon.service'],
  'gpm': ['gpm.service'],
  'haveged': ['haveged.service'],
  'httpd': ['httpd.service'],
  'iptables': ['iptables.service'],
  'kea-ctrl-agent': ['kea-ctrl-agent.service'],
  'kea-ddns-server': ['kea-ddns-server.service'],
  'kea-dhcp4-server': ['kea-dhcp4-server.service'],
  'kea-dhcp6-server': ['kea-dhcp6-server.service'],
  'krb5-kadmind': ['krb5-kadmind.service'],
  'krb5-kdc': ['krb5-kdc.service'],
  'krb5-kpropd': ['krb5-kpropd.service'],
  'lightdm': ['lightdm.service'],
  'mariadb': ['mariadb.service'],
  'named': ['named.service'],
  'networkmanager': ['networkmanager.service'],
  'nfs-client': ['nfs-client.service'],
  'nfs-server': ['nfs-server.service'],
  'nfsd': ['nfsd.service'],
  'nftables': ['nftables.service'],
  'nmbd': ['nmbd.service'],
  'ntpd': ['ntpd.service'],
  'php-fpm': ['php-fpm.service'],
  'postfix': ['postfix.service'],
  'postgresql': ['postgresql.service'],
  'power-profiles-daemon': ['power-profiles-daemon.service'],
  'proftpd': ['proftpd.service'],
  'rpc-idmapd': ['rpc-idmapd.service'],
  'rpc-mountd': ['rpc-mountd.service'],
  'rpc-statd-notify': ['rpc-statd-notify.service'],
  'rpc-statd': ['rpc-statd.service'],
  'rpcbind': ['rpcbind.service', 'rpcbind.socket'],
  'rsyncd': ['rsyncd.service', 'rsyncd.socket'],
  'rsync-at': ['rsyncdat.service'],
  'rsyslog': ['rsyslog.service'],
  'samba': ['samba.service'],
  'saslauthd': ['saslauthd.service'],
  'sendmail': ['sendmail.service'],
  'slapd': ['slapd.service'],
  'smartd': ['smartd.service'],
  'sm-client': ['sm-client.service'],
  'smbd': ['smbd.service', 'smbd.socket'],
  'smbd-at': ['smbdat.service'],
  'sshd': ['sshd.service', 'sshd.socket'],
  'ssh-at': ['sshdat.service'],
  'stunnel': ['stunnel.service'],
  'svnserve': ['svnserve.service'],
  'syslog-ng': ['syslog-ng.service'],
  'sysmond': ['sysmond.service'],
  'sysstat': ['sysstat.service'],
  'unbound': ['unbound.service'],
  'vsftpd': ['vsftpd.service'],
  'winbindd': ['winbindd.service'],
  'xdm': ['xdm.service'],
}

bash = find_program('bash')
install_cmd = find_program('install')

# Sysconfig file mapping
sysconfig_map = {
  'autofs': 'autofs',
  'bluetooth': 'bluetooth',
  'firewalld': 'firewalld',
  'git-daemon': 'git-daemon',
  'nfs-server': 'nfs-utils',
  'nfsd': 'nfs-utils',
  'rpc-idmapd': 'nfs-utils',
  'rpc-mountd': 'nfs-utils',
  'rpc-statd': 'nfs-utils',
  'rpc-statd-notify': 'nfs-utils',
  'samba': 'samba',
  'nmbd': 'samba',
  'smbd': 'samba',
  'smbd-at': 'samba',
  'winbindd': 'samba',
  'saslauthd': 'saslauthd',
  'sendmail': 'sendmail',
  'smartd': 'smartmontools',
  'sm-client': 'sendmail',
  'slapd': 'slapd',
  'svnserve': 'svnserve',
  'xdm': 'xdm',
}

# Create ninja install target for each optional service
foreach service_name, unit_files : optional_units
  # Build list of source files
  unit_sources = []
  foreach unit_file : unit_files
    unit_sources += meson.current_source_dir() / unit_file
  endforeach

  # Build install script
  install_script = '#!/bin/bash\nset -e\necho "Installing ' + service_name + ' unit files..."\n'

  # Install unit files
  foreach src : unit_sources
    install_script += 'install -D -v -m 0644 "' + src + '" "${DESTDIR:-}' + get_option('prefix') / get_option('libdir') / 'initd' / 'system' + '/$(basename ' + src + ')"\n'
  endforeach

  # Check if this service has a sysconfig file
  config_file = sysconfig_map.get(service_name, '')

  if config_file != ''
    config_src = meson.project_source_root() / 'sysconfig' / 'optional' / config_file
    config_dest = get_option('sysconfdir') / 'sysconfig' / config_file
    install_script += '''
echo "Installing sysconfig file for ''' + service_name + '''..."
SYSCONFIG_DEST="${DESTDIR:-}''' + config_dest + '''"
if [ -f "$SYSCONFIG_DEST" ]; then
  # Find next available .new-N suffix
  if [ ! -f "${SYSCONFIG_DEST}.new" ]; then
    install -D -v -m 0644 "''' + config_src + '''" "${SYSCONFIG_DEST}.new"
  else
    COUNTER=1
    while [ -f "${SYSCONFIG_DEST}.new-${COUNTER}" ]; do
      COUNTER=$((COUNTER + 1))
    done
    install -D -v -m 0644 "''' + config_src + '''" "${SYSCONFIG_DEST}.new-${COUNTER}"
  fi
else
  install -D -v -m 0644 "''' + config_src + '''" "$SYSCONFIG_DEST"
fi
'''
  endif

  install_script += 'echo "Installation of ' + service_name + ' complete"\n'

  # Create custom target
  install_target = custom_target('install-' + service_name + '-stamp',
    output: 'install-' + service_name + '.stamp',
    command: [bash, '-c', install_script + 'touch @OUTPUT@\n'],
    build_by_default: false,
    console: true,
  )

  # Create phony alias for convenience
  alias_target('install-' + service_name, install_target)
endforeach

# Create install-everything target to install all optional services
all_install_script = '#!/bin/bash\nset -e\n\n'

foreach service_name, unit_files : optional_units
  all_install_script += '# Install ' + service_name + '\n'
  all_install_script += 'echo "Installing ' + service_name + '..."\n'

  # Install unit files
  foreach unit_file : unit_files
    src = meson.current_source_dir() / unit_file
    all_install_script += 'install -D -v -m 0644 "' + src + '" "${DESTDIR:-}' + get_option('prefix') / get_option('libdir') / 'initd' / 'system' + '/' + unit_file + '"\n'
  endforeach

  # Install sysconfig if applicable
  config_file = sysconfig_map.get(service_name, '')
  if config_file != ''
    config_src = meson.project_source_root() / 'sysconfig' / 'optional' / config_file
    config_dest = get_option('sysconfdir') / 'sysconfig' / config_file
    all_install_script += '''SYSCONFIG_DEST="${DESTDIR:-}''' + config_dest + '''"
if [ -f "$SYSCONFIG_DEST" ]; then
  if [ ! -f "${SYSCONFIG_DEST}.new" ]; then
    install -D -v -m 0644 "''' + config_src + '''" "${SYSCONFIG_DEST}.new"
  else
    COUNTER=1
    while [ -f "${SYSCONFIG_DEST}.new-${COUNTER}" ]; do
      COUNTER=$((COUNTER + 1))
    done
    install -D -v -m 0644 "''' + config_src + '''" "${SYSCONFIG_DEST}.new-${COUNTER}"
  fi
else
  install -D -v -m 0644 "''' + config_src + '''" "$SYSCONFIG_DEST"
fi
'''
  endif

  all_install_script += '\n'
endforeach

all_install_script += 'echo "All optional services installed"\n'

# Create custom target
install_everything_target = custom_target('install-everything-stamp',
  output: 'install-everything.stamp',
  command: [bash, '-c', all_install_script + 'touch @OUTPUT@\n'],
  build_by_default: false,
  console: true,
)

# Create phony alias for convenience
alias_target('install-everything', install_everything_target)
