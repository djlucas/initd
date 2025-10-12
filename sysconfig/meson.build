# Sysconfig files for BLFS services
# Some config files are shared by multiple services

# Config file to services mapping
# Note: winbindd shares the samba config file
config_to_services = {
  'git-daemon': ['git-daemon'],
  'nfs-utils': ['nfs-server', 'nfsd', 'rpc-idmapd', 'rpc-mountd', 'rpc-statd', 'rpc-statd-notify'],
  'samba': ['samba', 'nmbd', 'smbd', 'smbdat', 'winbindd'],
  'saslauthd': ['saslauthd'],
  'sendmail': ['sendmail', 'sm-client'],
  'slapd': ['slapd'],
  'svnserve': ['svnserve'],
}

# Install each config file with all services that need it
foreach config_file, service_list : config_to_services
  foreach service_name : service_list
    install_data(
      config_file,
      install_dir: get_option('sysconfdir') / 'sysconfig',
      install_tag: 'install-' + service_name,
    )
  endforeach
endforeach
