# Sysconfig files for BLFS services
# Some config files are shared by multiple services

# Config file to services mapping
# Note: winbindd shares the samba config file
config_to_services = {
  'optional/git-daemon': ['git-daemon'],
  'optional/nfs-utils': ['nfs-server', 'nfsd', 'rpc-idmapd', 'rpc-mountd', 'rpc-statd', 'rpc-statd-notify'],
  'optional/samba': ['samba', 'nmbd', 'smbd', 'smbdat', 'winbindd'],
  'optional/saslauthd': ['saslauthd'],
  'optional/sendmail': ['sendmail', 'sm-client'],
  'optional/slapd': ['slapd'],
  'optional/svnserve': ['svnserve'],
}

bash = find_program('bash')

# Install each config file via a helper run target (not part of default install)
foreach config_file, service_list : config_to_services
  src_path = meson.current_source_dir() / config_file
  dest_file = config_file.split('/')[-1]
  dest_path = get_option('prefix') / get_option('sysconfdir') / 'sysconfig' / dest_file
  install_command = 'set -e; DESTDIR="${DESTDIR:-}"; install -D -m 644 "{0}" "$DESTDIR{1}"'.format(src_path, dest_path)
  foreach service_name : service_list
    run_target('install-' + service_name + '-config',
      command: [bash, '-c', install_command]
    )
  endforeach
endforeach
