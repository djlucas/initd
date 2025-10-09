# initd

A lightweight, portable init system with systemd unit file compatibility.

---

## ⚠️ **WARNING: PRE-ALPHA SOFTWARE** ⚠️

**DO NOT USE THIS SOFTWARE IN PRODUCTION OR ON ANY SYSTEM YOU CARE ABOUT.**

This is actively developed, incomplete, and untested code. It is not ready for any use beyond experimentation and development. Expect bugs, missing features, and breaking changes.

**You have been warned.**

---

## Overview

**initd** provides modern service management for unix-like systems without the
complexity and ecosystem lock-in of systemd. It implements the good ideas from
systemd (declarative unit files, dependency resolution, socket activation) while
maintaining a clean, auditable codebase and true portability.

### Design Philosophy

- **Minimal and Auditable** - Small, readable C23 codebase
- **Privilege Separated** - Security by design, minimal root code
- **Systemd Compatible** - Use existing unit files where beneficial
- **Truly Portable** - Multi-platform Unix-like support
- **Unix Philosophy** - Each component does one thing well

## Key Features

### Core Functionality

- **Modern Service Management**
  - systemd-compatible unit file format
  - Dependency resolution with parallel startup
  - Service supervision and automatic restart
  - Timer-based scheduling (cron replacement)
  - Socket activation with idle timeout

- **Security First**
  - Privilege-separated architecture (master/slave supervisor)
  - Minimal code running as root
  - Optional cgroup isolation (Linux only)
  - Service sandboxing via User/Group directives

- **Platform Support**
  - Linux: Full feature set with cgroups v2
  - Other Unix-like systems: Process group-based supervision
  - Two deployment modes:
    - **PID 1 mode**: Full init replacement (primary use case)
    - **Standalone mode**: Run under existing init (testing, containers, BSD rc, sysvinit)
  - Portable architecture for broad compatibility

### User-Facing Tools

- **initctl** - Service control interface compatible with systemd
- **journalctl** - Log query wrapper for traditional syslog
- Standard targets (rescue, multi-user, graphical)
- Drop-in compatibility with existing systemd unit files

## Architecture

### Daemon Independence

**Core Principle:** Each component is a separate, independent daemon - fundamentally different from systemd's monolithic design.

- Each daemon can be installed and run standalone
- No interdependencies - cross-daemon communication is optional
- Each manages its own control socket
- Can be packaged separately or as a suite

### Components

```
init (PID 1) - optional, not needed in standalone mode
  └─ supervisor-master (root, minimal)
      ├─ supervisor-slave (unprivileged, main logic)
      │   ├─ Parses unit files
      │   ├─ Resolves dependencies
      │   ├─ Monitors services
      │   └─ Control socket: /run/initd/supervisor.sock
      └─ Spawns services with privilege dropping

timer-daemon (independent)
  ├─ Manages .timer units
  ├─ Cron replacement functionality
  └─ Control socket: /run/initd/timer.sock

socket-activator (independent)
  ├─ Manages .socket units
  ├─ On-demand service activation
  └─ Control socket: /run/initd/socket-activator.sock

initctl/systemctl
  └─ Routes commands to appropriate daemon based on unit type
```

**Key Components:**

1. **init** - PID 1, zombie reaping, supervisor lifecycle (optional)
2. **supervisor** (master + slave) - Service management daemon
3. **timer-daemon** - Timer/cron functionality (independent, optional)
4. **socket-activator** - On-demand service activation (independent, optional)
5. **initctl/systemctl** - Control interface (routes to correct daemon)
6. **journalctl** - Log query tool (syslog wrapper)

## Differentiating Features

### What Makes initd Different

- **Privilege Separation from Day One**
  - Bulk of code runs unprivileged
  - Minimal attack surface
  - Easier security audits

- **Socket Activator with Idle Timeout**
  - Kill idle services after configurable timeout
  - Feature systemd doesn't have
  - Saves resources on low-traffic services

- **True Portability**
  - Not just "works on Linux"
  - Multi-platform Unix-like support
  - Platform abstraction from the start

- **No Ecosystem Lock-in**
  - Use existing syslog (rsyslog, syslog-ng)
  - Use existing elogind for session management
  - Plain text logs, standard tools

- **Reuses Existing Infrastructure**
  - Doesn't replace working solutions
  - Integrates with traditional Unix tools
  - Leverages proven components

## What initd Is NOT

- **Not a systemd fork** - Written from scratch
- **Not a complete systemd replacement** - Doesn't include journald, resolved, networkd, etc.
- **Not trying to replace everything** - Works with existing tools (elogind, syslog)
- **Not Linux-only** - Portable by design

## Quick Start

### Building

```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

### Configuration

Unit files go in:
- `/etc/initd/system/` - Local administrator configs
- `/lib/initd/system/` - Distribution-provided units

Or use existing systemd unit directories for compatibility.

### Usage

```bash
# Start a service
systemctl start nginx

# Enable at boot
systemctl enable nginx

# Check status
systemctl status nginx

# View logs
journalctl -u nginx -f
```

## Development Status

**Current Phase:** Phase 2 Complete - Ready for Phase 3

**Overall Progress:** ~50% complete

Core init system functionality is implemented with comprehensive test coverage.

### Implementation Phases

#### ✅ Phase 1: Minimal Boot - **COMPLETE (100%)**
- [x] Init binary (PID 1, zombie reaping)
- [x] Supervisor master/slave split with privilege separation
- [x] Basic unit file parser (systemd-compatible format)
- [x] Start/stop simple services
- [x] Shutdown handling with proper service ordering
- [x] Service PID monitoring and restart policies

#### ✅ Phase 2: Core Features & Independent Daemons - **COMPLETE (100%)**
- [x] Dependency resolution (Requires, Wants, After, Before)
- [x] Target support
- [x] Service restart/recovery (RESTART_ALWAYS, RESTART_ON_FAILURE)
- [x] Basic systemctl commands (start, stop, status, is-active)
- [x] Syslog integration for logging
- [x] Enable/disable commands
- [x] List-units command (with --all flag for systemd directories)
- [x] Timer daemon (independent, cron replacement)
- [x] Socket activator daemon (independent, with idle timeout)
- [x] Daemon independence (separate control sockets, optional communication)
- [x] Full systemctl compatibility (command routing to daemons)
- [x] list-timers command
- [x] journalctl wrapper (complete)

#### ⏳ Phase 3: Platform Support & Polishing - **PLANNED (0%)**
- [ ] Cgroup integration (Linux)

#### ⏳ Phase 4: Multi-Platform Support - **PLANNED (0%)**
- [ ] Platform abstraction layer
- [ ] Standalone supervisor mode (run without replacing init)
- [ ] Multi-platform support beyond Linux
- [ ] Testing on multiple platforms
- [ ] Portable process supervision

#### ⏳ Phase 5: Production Hardening - **PLANNED (0%)**
- [ ] Service script testing
- [ ] Comprehensive documentation
- [ ] Performance optimization
- [ ] Security audit

### What Works Now
- PID 1 init with signal handling
- Privilege-separated supervisor architecture
- Unit file parsing and dependency resolution
- Starting and stopping services
- Automatic service restart on failure
- Control interface (`initctl`/`systemctl` commands)
- Proper system shutdown
- Independent timer daemon with cron replacement
- Socket activator with idle timeout
- Comprehensive test suite (10 suites, 83 tests)

### Test Coverage
The project includes extensive automated testing:
- **10 test suites** with **83 individual tests** (100% passing)
- Calendar expression parser tests
- Unit file parser and validation tests
- Control protocol serialization tests
- Socket activation tests
- IPC communication tests
- Unit scanner tests
- Dependency resolution tests
- State machine tests
- Logging system tests
- Integration tests

Build and run tests:
```bash
meson compile -C build
meson test -C build -v
```

### What's Next
- Cgroup integration (Linux)
- Platform abstraction layer
- Multi-platform testing
- Production hardening

## Requirements

### Runtime
- libc
- syslog daemon (rsyslog, syslog-ng, etc.)
- elogind (for session management)

### Build
- C23-capable compiler (GCC 14+, Clang 18+)
- Meson build system
- Ninja
- pkg-config

### Optional
- Linux kernel with cgroup v2 (for full feature set)
- p11-kit (if using trust anchors)

## Contributing

Contributions welcome! This project aims to be:
- Clean and readable
- Well-documented
- Thoroughly tested
- Portable across platforms

## License

MIT

## Why "initd"?

Simple, memorable, and to the point. It's an init daemon - **initd**.

---

**Status:** Early Development | **Version:** 0.1.0-dev | **Language:** C23
