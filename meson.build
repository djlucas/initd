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

# Tarball creation target - creates both .tar.xz and .tar.gz
run_target('tarball',
  command: [
    'bash', '-c',
    '''
    VER=''' + meson.project_version() + '''
    SRCDIR="''' + meson.project_source_root() + '''"
    BUILDDIR="''' + meson.project_build_root() + '''"

    cd "${SRCDIR}/.."
    rm -rf initd-${VER}
    cp -ra "${SRCDIR}" initd-${VER}
    rm -rf initd-${VER}/{build,.git,analysis-output,profile.md}

    tar -cJf "${BUILDDIR}/initd-${VER}.tar.xz" initd-${VER}
    tar -czf "${BUILDDIR}/initd-${VER}.tar.gz" initd-${VER}

    rm -rf initd-${VER}

    echo "Created ${BUILDDIR}/initd-${VER}.tar.xz"
    echo "Created ${BUILDDIR}/initd-${VER}.tar.gz"
    '''
  ]
)
