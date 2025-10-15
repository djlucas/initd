# Optional BLFS services - not installed by default
# Each service has its own install target: meson install --tags install-<service>

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
  'random-seed': ['random-seed.service'],
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

# Create ninja install targets for each optional service
install_cmd = find_program('install')
bash = find_program('bash')

# Sysconfig file mapping (from sysconfig/meson.build)
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

foreach service_name, unit_files : optional_units
  install_args = []
  foreach unit_file : unit_files
    install_args += [
      meson.current_source_dir() / unit_file,
    ]
  endforeach

  # Check if this service has a sysconfig file
  config_file = sysconfig_map.get(service_name, '')

  if config_file != ''
    run_target('install-' + service_name,
      command: [
        bash, '-c', '''
set -e
# Install unit files
install -D -m 644 ''' + ' '.join(install_args) + ''' -t "${DESTDIR:-}''' + get_option('prefix') / get_option('libdir') / 'initd' / 'system"' + '''
# Install sysconfig file, preserving existing files
SYSCONFIG_DEST="${DESTDIR:-}''' + get_option('sysconfdir') / 'sysconfig' / config_file + '''"
if [ -f "$SYSCONFIG_DEST" ]; then
  # Find next available .new-N suffix
  if [ ! -f "${SYSCONFIG_DEST}.new" ]; then
    install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "${SYSCONFIG_DEST}.new"
  else
    COUNTER=1
    while [ -f "${SYSCONFIG_DEST}.new-${COUNTER}" ]; do
      COUNTER=$((COUNTER + 1))
    done
    install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "${SYSCONFIG_DEST}.new-${COUNTER}"
  fi
else
  install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "$SYSCONFIG_DEST"
fi
'''
      ],
    )
  else
    run_target('install-' + service_name,
      command: [
        bash, '-c',
        'install -D -m 644 ' + ' '.join(install_args) + ' -t "${DESTDIR:-}' + get_option('prefix') / get_option('libdir') / 'initd' / 'system"'
      ],
    )
  endif
endforeach

# Create install-everything target to install all optional services
all_install_commands = []
foreach service_name, unit_files : optional_units
  install_args = []
  foreach unit_file : unit_files
    install_args += [
      meson.current_source_dir() / unit_file,
    ]
  endforeach

  config_file = sysconfig_map.get(service_name, '')

  if config_file != ''
    all_install_commands += ['''
# Install ''' + service_name + '''
install -D -m 644 ''' + ' '.join(install_args) + ''' -t "${DESTDIR:-}''' + get_option('prefix') / get_option('libdir') / 'initd' / 'system"' + '''
SYSCONFIG_DEST="${DESTDIR:-}''' + get_option('sysconfdir') / 'sysconfig' / config_file + '''"
if [ -f "$SYSCONFIG_DEST" ]; then
  if [ ! -f "${SYSCONFIG_DEST}.new" ]; then
    install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "${SYSCONFIG_DEST}.new"
  else
    COUNTER=1
    while [ -f "${SYSCONFIG_DEST}.new-${COUNTER}" ]; do
      COUNTER=$((COUNTER + 1))
    done
    install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "${SYSCONFIG_DEST}.new-${COUNTER}"
  fi
else
  install -D -m 644 ''' + meson.project_source_root() / 'sysconfig' / 'optional' / config_file + ''' "$SYSCONFIG_DEST"
fi
''']
  else
    all_install_commands += ['''
# Install ''' + service_name + '''
install -D -m 644 ''' + ' '.join(install_args) + ''' -t "${DESTDIR:-}''' + get_option('prefix') / get_option('libdir') / 'initd' / 'system"' + '''
''']
  endif
endforeach

run_target('install-everything',
  command: [
    bash, '-c',
    'set -e\n' + '\n'.join(all_install_commands)
  ],
)
