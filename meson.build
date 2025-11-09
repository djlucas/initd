project('initd', 'c',
  version: '0.1',
  license: 'MIT',
  default_options: [
    'c_std=c23',
    'warning_level=3',
    'prefix=/usr',
    'sysconfdir=/etc',
    'localstatedir=/var',
    'libdir=lib',
  ]
)

# Optional dependencies
libcap_dep = dependency('libcap', required: false)
if libcap_dep.found()
  add_project_arguments('-D__HAVE_LIBCAP__', language: 'c')
endif

dbus_dep = dependency('dbus-1', required: false)
if dbus_dep.found()
  add_project_arguments('-DHAVE_DBUS', language: 'c')
endif

# Subdirectories
subdir('src/common')
subdir('src/init')
subdir('src/supervisor')
subdir('src/initctl')

subdir('src/timer-daemon')
subdir('src/socket-activator')
subdir('scripts')
subdir('units')
subdir('units/optional')
subdir('sysconfig')
subdir('docs')
subdir('tests')
subdir('analysis')

# Create unit directories on install
install_sh = find_program('install')

# Handle absolute vs relative paths
sysconfdir = get_option('sysconfdir')
if not sysconfdir.startswith('/')
  sysconfdir = get_option('prefix') / sysconfdir
endif

libdir = get_option('libdir')
if not libdir.startswith('/')
  libdir = get_option('prefix') / libdir
endif

meson.add_install_script(install_sh, '-d', '-v',
  libdir / 'initd' / 'system')
meson.add_install_script(install_sh, '-d', '-v',
  sysconfdir / 'initd' / 'system')
