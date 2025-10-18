optional_network_scripts = [
  'bridge',
  'dhclient',
  'dhcpcd',
  'iwd',
  'pppoe',
  'wpa_supplicant',
]

bash = find_program('bash')

foreach script : optional_network_scripts
  src_path = meson.current_source_dir() / ('network-services/' + script)
  dst_path = get_option('prefix') / get_option('libexecdir') / ('initd/network-services/' + script)
  install_cmd = 'set -e; DESTDIR="${DESTDIR:-}"; install -D -m 755 "{0}" "$DESTDIR{1}"'.format(
    src_path,
    dst_path,
  )
  run_target('install-network-' + script,
    command: [bash, '-c', install_cmd]
  )
endforeach
