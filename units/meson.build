# Default installation: completely minimal - no targets, no services
# Reference installation: ninja -C build install-reference

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
  'emergency.target',
  'rescue.target',
]

# Service files (need templating)
reference_services = [
  'checkfs.service',
  'console.service',
  'createfiles.service',
  'emergency.service',
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
  'random-seed.service',
  'remount-root.service',
  'rescue.service',
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

# Process template files at meson setup time
scriptdir = meson.project_source_root() / 'scripts'
sysconfigdir = meson.project_source_root() / 'sysconfig'

# Process service templates
reference_service_files = []
foreach service : reference_services
  reference_service_files += configure_file(
    input: 'reference' / service,
    output: service,
    configuration: conf_data,
  )
endforeach

# Process script helper templates
reference_sbin_script_files = []
foreach script : reference_script_helpers
  reference_sbin_script_files += configure_file(
    input: scriptdir / script,
    output: 'sbin-' + script,
    configuration: conf_data,
  )
endforeach

# Process libexec script templates
reference_libexec_script_files = [configure_file(
  input: scriptdir / 'initd-user-manager',
  output: 'libexec-initd-user-manager',
  configuration: conf_data,
)]

# Process service script templates
reference_service_script_files = []
foreach script : reference_service_scripts
  reference_service_script_files += configure_file(
    input: scriptdir / 'service-scripts' / script,
    output: 'servicescript-' + script,
    configuration: conf_data,
  )
endforeach

# Process network script templates
reference_network_script_files = []
foreach script : reference_network_scripts
  reference_network_script_files += configure_file(
    input: scriptdir / 'network-services' / script,
    output: 'networkscript-' + script,
    configuration: conf_data,
  )
endforeach

# Create individual install targets for each reference service
install_sh = find_program('install')
bash = find_program('bash')

# Mapping of services to their helper scripts (if any)
service_helpers = {
  'checkfs.service': 'checkfs',
  'console.service': 'console',
  'createfiles.service': 'createfiles',
  'localnet.service': 'localnet',
  'modules-load.service': 'modules-load',
  'mountvirtfs.service': 'mountvirtfs',
  'netfs.service': 'netfs',
  'network@.service': 'network-configure',
  'network-wait-online.service': 'network-wait-online',
  'udev-retry.service': 'udev-retry',
  'udev-trigger.service': 'udev-trigger',
}

# Create install target for each reference service
builddir = meson.current_build_dir()
reference_service_targets = []

foreach service : reference_services
  service_base = service.replace('.service', '')

  # Build install script for this service
  install_script = '''#!/bin/bash
set -e

DESTDIR="${DESTDIR:-}"
UNIT_DIR="@0@"
SERVICE_SCRIPT_DIR="@1@"

# Install service file
install -D -v -m 0644 "@2@" "${DESTDIR}@0@/@3@"
'''.format(
    libdir / 'initd' / 'system',
    libexecdir / 'initd' / 'service-scripts',
    builddir / service,
    service
  )

  # Add helper script if this service has one
  if service in service_helpers
    helper_script = service_helpers[service]
    install_script += '''
# Install service helper script
install -D -v -m 0755 "@0@" "${DESTDIR}@1@/@2@"
'''.format(
      builddir / ('servicescript-' + helper_script),
      libexecdir / 'initd' / 'service-scripts',
      helper_script
    )
  endif

  install_script += '''
echo "@0@ installation complete"
'''.format(service_base)

  # Create custom target
  target_name = 'install-' + service_base + '-stamp'
  install_target = custom_target(target_name,
    output: target_name.replace('-stamp', '.stamp'),
    command: [bash, '-c', install_script + '\ntouch @OUTPUT@'],
    build_by_default: false,
    console: true,
  )

  # Create phony alias
  alias_target('install-' + service_base, install_target)
  reference_service_targets += install_target
endforeach

# Build install script for reference installation

install_reference_script = '''#!/bin/bash
set -e

DESTDIR="${DESTDIR:-}"
UNIT_DIR="@0@"
SBIN_DIR="@1@"
LIBEXEC_DIR="@2@"
SERVICE_SCRIPT_DIR="@3@"
NETWORK_SCRIPT_DIR="@4@"
CONFIG_DIR="@5@"
MAN8_DIR="@6@"
BINDIR="@7@"
ETC_UNIT_DIR="@8@"
INITCTL="${DESTDIR}@7@/initctl"

# Create unit directories
install -d -v "${DESTDIR}${UNIT_DIR}"
install -d -v "${DESTDIR}${ETC_UNIT_DIR}"

# Install target files
'''.format(
  libdir / 'initd' / 'system',
  sbindir,
  libexecdir / 'initd',
  libexecdir / 'initd' / 'service-scripts',
  libexecdir / 'initd' / 'network-services',
  sysconfdir / 'sysconfig',
  get_option('mandir') / 'man8',
  bindir,
  sysconfdir / 'initd' / 'system',
)

foreach target : reference_targets
  install_reference_script += 'install -D -v -m 0644 "@0@" "${DESTDIR}@1@/@2@"\n'.format(
    meson.current_source_dir() / target,
    libdir / 'initd' / 'system',
    target
  )
endforeach

install_reference_script += '\n# Install service files\n'
builddir = meson.current_build_dir()
foreach i : range(reference_services.length())
  src_path = builddir / reference_services[i]
  install_reference_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + libdir / 'initd' / 'system' / reference_services[i] + '"\n'
endforeach

install_reference_script += '\n# Install sbin scripts\n'
foreach i : range(reference_script_helpers.length())
  src_path = builddir / ('sbin-' + reference_script_helpers[i])
  install_reference_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + sbindir / reference_script_helpers[i] + '"\n'
endforeach

install_reference_script += '\n# Install libexec scripts\n'
src_path = builddir / 'libexec-initd-user-manager'
install_reference_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'initd-user-manager' + '"\n'

install_reference_script += '\n# Install service scripts\n'
foreach i : range(reference_service_scripts.length())
  src_path = builddir / ('servicescript-' + reference_service_scripts[i])
  install_reference_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'service-scripts' / reference_service_scripts[i] + '"\n'
endforeach

install_reference_script += '\n# Install network scripts\n'
foreach i : range(reference_network_scripts.length())
  src_path = builddir / ('networkscript-' + reference_network_scripts[i])
  install_reference_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'network-services' / reference_network_scripts[i] + '"\n'
endforeach

install_reference_script += '\n# Install config files\n'
foreach config : reference_configs
  src_path = sysconfigdir / 'reference' / config
  dest_path = sysconfdir / 'sysconfig' / config
  install_reference_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'
endforeach

install_reference_script += '\n# Install man pages\n'
src_path = meson.project_source_root() / 'docs' / 'man' / 'man8' / 'ifup.8'
dest_path = get_option('mandir') / 'man8' / 'ifup.8'
install_reference_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'

src_path = meson.project_source_root() / 'docs' / 'man' / 'man8' / 'ifdown.8'
dest_path = get_option('mandir') / 'man8' / 'ifdown.8'
install_reference_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'

# Enable services if not using DESTDIR
reference_enable_services = []
foreach service : reference_services
  if service != 'network@.service' and service != 'getty@.service'
    reference_enable_services += service
  endif
endforeach

install_reference_script += '''
# Enable services if not using DESTDIR
if [ -z "${DESTDIR}" ]; then
  if [ ! -x "$INITCTL" ]; then
    INITCTL="$(command -v initctl 2>/dev/null || true)"
  fi
  if [ -n "$INITCTL" ] && [ -x "$INITCTL" ]; then
'''

foreach service : reference_enable_services
  install_reference_script += '    "$INITCTL" enable @0@ || true\n'.format(service)
endforeach

install_reference_script += '''    for tty in 1 2 3 4 5 6; do
      "$INITCTL" enable "getty@tty${tty}" || true
    done
  else
    echo "Warning: initctl not found, skipping service enablement" >&2
  fi
fi

echo "Reference installation complete"
'''

# Create separate script for units only (targets + services + service scripts + sbin + libexec)
install_units_script = '''#!/bin/bash
set -e

DESTDIR="${DESTDIR:-}"
LIBDIR="@0@"
SBINDIR="@1@"
LIBEXECDIR="@2@"
SERVICESCRIPTDIR="@3@"
SYSCONFIGDIR="@4@"
MANDIR="@5@"
BINDIR="@6@"
ETC_UNIT_DIR="@7@"
INITCTL="${DESTDIR}@6@/initctl"

# Create unit directories
install -d -v "${DESTDIR}${LIBDIR}"
install -d -v "${DESTDIR}${ETC_UNIT_DIR}"

# Install target files
'''.format(
  libdir / 'initd' / 'system',
  sbindir,
  libexecdir / 'initd',
  libexecdir / 'initd' / 'service-scripts',
  sysconfdir / 'sysconfig',
  get_option('mandir') / 'man8',
  bindir,
  sysconfdir / 'initd' / 'system',
)

foreach target : reference_targets
  install_units_script += 'install -D -v -m 0644 "@0@" "${DESTDIR}@1@/@2@"\n'.format(
    meson.current_source_dir() / target,
    libdir / 'initd' / 'system',
    target
  )
endforeach

install_units_script += '\n# Install service files\n'
builddir = meson.current_build_dir()
foreach i : range(reference_services.length())
  src_path = builddir / reference_services[i]
  install_units_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + libdir / 'initd' / 'system' / reference_services[i] + '"\n'
endforeach

install_units_script += '\n# Install sbin scripts\n'
foreach i : range(reference_script_helpers.length())
  src_path = builddir / ('sbin-' + reference_script_helpers[i])
  install_units_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + sbindir / reference_script_helpers[i] + '"\n'
endforeach

install_units_script += '\n# Install libexec scripts\n'
src_path = builddir / 'libexec-initd-user-manager'
install_units_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'initd-user-manager' + '"\n'

install_units_script += '\n# Install service scripts\n'
foreach i : range(reference_service_scripts.length())
  src_path = builddir / ('servicescript-' + reference_service_scripts[i])
  install_units_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'service-scripts' / reference_service_scripts[i] + '"\n'
endforeach

install_units_script += '\n# Install config files\n'
foreach config : reference_configs
  src_path = sysconfigdir / 'reference' / config
  dest_path = sysconfdir / 'sysconfig' / config
  install_units_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'
endforeach

install_units_script += '\n# Install man pages\n'
src_path = meson.project_source_root() / 'docs' / 'man' / 'man8' / 'ifup.8'
dest_path = get_option('mandir') / 'man8' / 'ifup.8'
install_units_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'

src_path = meson.project_source_root() / 'docs' / 'man' / 'man8' / 'ifdown.8'
dest_path = get_option('mandir') / 'man8' / 'ifdown.8'
install_units_script += 'install -D -v -m 0644 "' + src_path + '" "${DESTDIR}' + dest_path + '"\n'

# Enable services if not using DESTDIR
install_units_script += '''
# Enable services if not using DESTDIR
if [ -z "${DESTDIR}" ]; then
  if [ ! -x "$INITCTL" ]; then
    INITCTL="$(command -v initctl 2>/dev/null || true)"
  fi
  if [ -n "$INITCTL" ] && [ -x "$INITCTL" ]; then
'''

foreach service : reference_enable_services
  install_units_script += '    "$INITCTL" enable @0@ || true\n'.format(service)
endforeach

install_units_script += '''    for tty in 1 2 3 4 5 6; do
      "$INITCTL" enable "getty@tty${tty}" || true
    done
  else
    echo "Warning: initctl not found, skipping service enablement" >&2
  fi
fi

echo "Reference units installation complete"
'''

# Create separate script for network scripts only
install_network_script = '''#!/bin/bash
set -e

DESTDIR="${DESTDIR:-}"
NETWORKSERVICEDIR="@0@"

# Install network scripts
'''.format(
  libexecdir / 'initd' / 'network-services'
)

builddir = meson.current_build_dir()
foreach i : range(reference_network_scripts.length())
  src_path = builddir / ('networkscript-' + reference_network_scripts[i])
  install_network_script += 'install -D -v -m 0755 "' + src_path + '" "${DESTDIR}' + libexecdir / 'initd' / 'network-services' / reference_network_scripts[i] + '"\n'
endforeach

install_network_script += '''
echo "Reference network scripts installation complete"
'''

# Create ninja targets
install_units_target = custom_target('install-reference-units-stamp',
  output: 'install-reference-units.stamp',
  command: [bash, '-c', install_units_script + '\ntouch @OUTPUT@'],
  build_by_default: false,
  console: true,
  depends: reference_service_targets,
)

install_network_target = custom_target('install-reference-network-stamp',
  output: 'install-reference-network.stamp',
  command: [bash, '-c', install_network_script + '\ntouch @OUTPUT@'],
  build_by_default: false,
  console: true,
)

# Create ninja target for install-reference (runs both)
install_reference_target = custom_target('install-reference-stamp',
  output: 'install-reference.stamp',
  command: [bash, '-c', install_reference_script + '\ntouch @OUTPUT@'],
  build_by_default: false,
  console: true,
  depends: [install_units_target, install_network_target],
)

# Create phony aliases for convenience
alias_target('install-reference-units', install_units_target)
alias_target('install-reference-network', install_network_target)
alias_target('install-reference', install_reference_target)
