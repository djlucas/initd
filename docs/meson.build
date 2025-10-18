# Install man pages

# Section 1 - User commands
install_man('man/man1/journalctl.1')
install_man('man/man1/initctl.1')

# Section 5 - File formats
install_man('man/man5/initd.unit.5')

# Section 8 - System administration
install_man('man/man8/init.8')
install_man('man/man8/initd-supervisor.8')
install_man('man/man8/initd-supervisor-worker.8')
install_man('man/man8/timer-daemon.8')
install_man('man/man8/socket-activator.8')
install_man('man/man8/ifup.8')
install_man('man/man8/ifdown.8')

# Create systemctl symlink for initctl man page
install_symlink(
  'systemctl.1',
  pointing_to: 'initctl.1',
  install_dir: get_option('mandir') / 'man1'
)
