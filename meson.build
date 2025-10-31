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
