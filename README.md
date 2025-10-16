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
maintaining a clean, auditable codebase and true portability. Note: this is not
an "e" package extracted from systemd, but a completely separate codebase. No
systemd files or code are reused here.

### Design Philosophy

- **Minimal and Auditable** - Small, readable C23 codebase
- **Privilege Separated** - Security by design, minimal root code
- **Systemd Compatible** - Use existing unit files where beneficial
- **Truly Portable** - Multi-platform Unix-like support
- **Unix Philosophy** - Each component does one thing well
- **No Lock-in** - Zero defaults, complete freedom to design your own target system

## Key Features

### Core Functionality

- **Modern Service Management**
  - systemd-compatible unit file format
  - Dependency resolution with parallel startup
  - Service supervision and automatic restart
  - Timer-based scheduling (cron replacement)
  - Socket activation with idle timeout

- **Security First**
  - Privilege-separated architecture (master/worker supervisor)
  - Minimal code running as root
  - Service registry prevents arbitrary kill() attacks
  - DoS prevention via restart rate limiting
  - Path security with TOCTOU and symlink attack prevention
  - Secure IPC with proper serialization (no raw pointers)
  - File descriptor leak prevention (SOCK_CLOEXEC)
  - Signal race condition hardening
  - Service sandboxing via User/Group directives
  - Optional cgroup isolation (Linux only - not implemented yet)

- **Platform Support**
  - Linux: Full feature set with cgroups v2
  - Other Unix-like systems: Process group-based supervision
  - Two deployment modes:
    - **PID 1 mode**: Full init replacement (primary use case)
    - **Standalone mode**: Run under existing init (testing, containers, BSD rc, sysvinit)
  - Portable architecture for broad compatibility

### User-Facing Tools

- **initctl** - Service control interface compatible with systemd's systemctl (a symlink provided)
- **journalctl** - Log query wrapper for traditional syslog that mimics some of systemd's journalctl
- Standard targets (rescue, multi-user, graphical)
- Drop-in compatibility with existing systemd unit files (will convert on the fly if a systemd service is enabled)

## Credits

Many of the service scripts for sysinit.target (checkfs, console, createfiles, localnet, modules-load, mountvirtfs, udev-retry, udev-trigger) were adapted from the [Linux From Scratch bootscripts](https://github.com/lfs-book/lfs/tree/trunk/bootscripts) project.

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
  └─ initd-supervisor (root, minimal master)
      ├─ initd-supervisor-worker (unprivileged, main logic)
      │   ├─ Parses unit files
      │   ├─ Resolves dependencies
      │   ├─ Monitors services
      │   └─ Control socket: /run/initd/supervisor.sock
      └─ Spawns services with privilege dropping

initd-timer (independent master)
  └─ initd-timer-worker (unprivileged worker)
      ├─ Manages .timer units
      ├─ Cron replacement functionality
      └─ Control socket: /run/initd/timer.sock

initd-socket (independent master)
  └─ initd-socket-worker (unprivileged worker)
      ├─ Manages .socket units
      ├─ On-demand service activation
      └─ Control socket: /run/initd/socket-activator.sock

initctl/systemctl
  └─ Routes commands to appropriate daemon based on unit type
```

**Key Components:**

1. **init** - PID 1, zombie reaping, supervisor lifecycle (optional)
2. **initd-supervisor** (master + worker) - Service management daemon with privilege separation
3. **initd-timer** (master + worker) - Timer/cron functionality (independent, optional)
4. **initd-socket** (master + worker) - On-demand service activation (independent, optional)
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

- **Zero Defaults, Complete Freedom**
  - Default install contains **nothing** - no targets, no services
  - Provides mechanism, not policy
  - Design your own target hierarchy or use the reference implementation
  - No forced boot sequence or system organization

## What initd Is NOT

- **Not a systemd fork** - Written from scratch
- **Not a complete systemd replacement** - Doesn't include journald, resolved, networkd, etc.
- **Not trying to replace everything** - Works with existing tools (elogind, syslog)
- **Not Linux-only** - Portable by design

### Supported Unit Types

initd supports the essential systemd unit types:
- ✅ `.service` - Service management
- ✅ `.timer` - Scheduled task activation (cron replacement)
- ✅ `.socket` - Socket-based activation
- ✅ `.target` - Unit grouping and ordering

Unit types **not supported** (use traditional alternatives):
- ❌ `.mount` - Use `/etc/fstab` for filesystem mounts
- ❌ `.automount` - Use `/etc/fstab` with auto mount options
- ❌ `.swap` - Use `/etc/fstab` for swap configuration
- ❌ `.path` - Path-based activation not implemented
- ❌ `.device` - Hardware management not implemented
- ❌ `.scope` - Runtime-created units (systemd internal)
- ❌ `.slice` - cgroup hierarchy management (not implemented)

### Supported Service Directives

**[Service] Section:**
- `Type=` - simple, forking, oneshot
- `ExecStart=`, `ExecStop=`, `ExecReload=` - Service commands
- `ExecStartPre=`, `ExecStartPost=` - Pre/post start commands
- `User=`, `Group=` - Run as specific user/group
- `WorkingDirectory=` - Set working directory
- `Environment=` - Set environment variables
- `EnvironmentFile=` - Load environment from file
- `Restart=` - no, always, on-failure
- `RestartSec=` - Delay before restart
- `TimeoutStartSec=`, `TimeoutStopSec=` - Startup/shutdown timeouts
- `PrivateTmp=` - Private /tmp namespace (Linux only)
- `LimitNOFILE=` - File descriptor limit (portable)
- `KillMode=` - process, control-group, mixed, none (portable)

**Security & Resource Control:**
- ✅ **PrivateTmp** - Isolated /tmp per service (Linux only, uses mount namespaces)
- ✅ **LimitNOFILE** - Control max open files (portable, uses setrlimit)
- ✅ **KillMode** - Fine-grained process termination control (portable, uses killpg)
- ❌ **Other resource limits** - Not yet implemented
- ❌ **Capabilities** - Not yet implemented
- ❌ **SecureBits** - Not yet implemented

## Quick Start

### Building

```bash
# Generate build files with Meson
meson setup build

# Build with Ninja
ninja -C build

# Install (requires root)
sudo ninja -C build install
```

### Configuration

Unit files go in:
- `/etc/initd/system/` - Local administrator configs
- `/lib/initd/system/` - Distribution-provided units

Or use existing systemd unit directories for compatibility.

### Directory Structure

The project follows a consistent organization:

**Unit Files:**
- `units/reference/` - Core system units
- `units/optional/` - Optional service units (installed on demand)

**Configuration Files:**
- `sysconfig/reference/` - Configuration files for reference units
- `sysconfig/optional/` - Configuration files for optional services

### Installation

**Important: Zero Default Policy**

The default installation (`ninja install`) installs **only the core binaries** - no targets, no services, no configuration. This is intentional:

✅ **Provides complete freedom** - Design your own system organization
✅ **No forced policy** - Choose your own boot sequence and dependencies
✅ **No lock-in** - Not tied to any particular init philosophy

**Main Installation:**
```bash
# Install ONLY core binaries (init, supervisor, timer, socket, initctl)
# NO targets or services are installed by default
DESTDIR=/path/to/staging ninja -C build install

# Install reference implementation (17 targets + 19 core services)
# This gives you a working system as a starting point
DESTDIR=/path/to/staging ninja -C build install-reference
```

**Reference Implementation Includes:**
- All system targets (basic, multi-user, graphical, network, etc.)
- Core system services (getty, udev, syslog, network, etc.)
- Enabled symlinks for automatic boot

You can use the reference implementation as-is, modify it, or ignore it completely and build your own.

**Optional Services:**
```bash
# Install individual optional services (51 available)
DESTDIR=/path/to/staging ninja -C build install-acpid
DESTDIR=/path/to/staging ninja -C build install-samba
DESTDIR=/path/to/staging ninja -C build install-httpd
# ... etc for any of 51 optional services

# Or install all optional services at once
DESTDIR=/path/to/staging ninja -C build install-everything
```

**Configuration File Protection:**

When reinstalling services, existing configuration files in `/etc/sysconfig/` are preserved:
- First reinstall: `config.new`
- Second reinstall: `config.new-1`
- Third reinstall: `config.new-2`
- And so on...

This allows administrators to compare new defaults with their customizations without losing changes.

### Usage

```bash
# Start a service
initctl start nginx

# Enable at boot
initctl enable nginx

# Check status
initctl status nginx

# View logs with grep (traditional)
grep nginx /var/log/messages | tail -20

# View logs with journalctl wrapper
journalctl -u nginx -f

# systemctl compatibility (symlink to initctl)
systemctl start nginx
systemctl status nginx
```

## Development Status

**Current Phase:** Phase 2 Complete - Starting Phase 3

**Overall Progress:** ~60% complete

Core init system functionality is implemented with comprehensive test coverage and security hardening.

### Implementation Phases

#### ✅ Phase 1: Minimal Boot - **COMPLETE (100%)**
- [x] Init binary (PID 1, zombie reaping)
- [x] Supervisor master/worker split with privilege separation
- [x] Basic unit file parser (systemd-compatible format)
- [x] Start/stop simple services
- [x] Shutdown handling with proper service ordering
- [x] Service PID monitoring and restart policies
- [x] **Process groups** (setsid, killpg) - POSIX portable foundation

#### ✅ Phase 2: Core Features & Security - **COMPLETE (100%)**
- [x] Dependency resolution (Requires, Wants, After, Before)
- [x] **Circular dependency detection** with STATE_ACTIVATING/DEACTIVATING guards
- [x] **Recursion depth limits** to prevent stack overflow
- [x] Target support
- [x] Service restart/recovery (RESTART_ALWAYS, RESTART_ON_FAILURE)
- [x] Basic systemctl commands (start, stop, status, is-active, enable, disable)
- [x] Syslog integration with early boot buffering
- [x] List-units command (with --all flag for systemd directories)
- [x] list-timers command
- [x] journalctl wrapper (complete)
- [x] **Service registry** - prevents arbitrary kill() attacks with 256-service limit
- [x] **DoS prevention** - restart rate limiting (5 restarts/60s window, 1s min interval)
- [x] **IPC security** - proper serialization, no raw struct pointers, malformed input validation
- [x] **Privilege escalation prevention** - master validates User/Group from unit files
- [x] **TOCTOU and path traversal prevention** - realpath(), O_NOFOLLOW, symlink protection
- [x] **File descriptor leak prevention** - SOCK_CLOEXEC on all sockets
- [x] **Signal race hardening** - sigprocmask() during critical operations
- [x] **Orphaned process cleanup** - kill_remaining_processes() during shutdown
- [x] **KillMode support** using process groups (control-group, process, mixed, none)

#### ⏳ Phase 3: Independent Daemons - **IN PROGRESS (30%)**
- [x] Timer daemon architecture (master/worker split)
- [x] Socket activator architecture (master/worker split)
- [x] Daemon independence concept (separate control sockets)
- [ ] Timer daemon implementation (cron replacement)
- [ ] Socket activator implementation (with idle timeout)
- [ ] Full systemctl routing to independent daemons
- [ ] Integration testing with all daemons

#### ⏳ Phase 4: Linux-Specific Enhancements - **FUTURE (0%)**
- [ ] **Cgroup v2 integration** (Linux-only, parallel to process groups)
  - Process tracking (replaces kill(pid, 0) checks)
  - Memory/CPU limits
  - OOM handling
- [ ] Additional Linux namespaces beyond PrivateTmp
- [ ] Seccomp filters (optional security hardening)

#### ⏳ Phase 5: Multi-Platform & Standalone Mode - **FUTURE (0%)**
- [ ] Platform detection and feature flags
- [ ] Standalone supervisor mode (run without replacing init)
- [ ] Multi-platform testing (BSD, Hurd)
- [ ] Platform-specific optimizations

#### ⏳ Phase 6: Production Hardening - **FUTURE (0%)**
- [ ] Service script testing
- [ ] Comprehensive documentation
- [ ] Performance optimization
- [ ] External security audit

### What Works Now
- **PID 1 init** with signal handling and zombie reaping
- **Privilege-separated supervisor** (master/worker architecture)
- **Unit file parsing** with systemd compatibility
- **Dependency resolution** with circular dependency detection and recursion limits
- **Service lifecycle** - start, stop, restart with proper state transitions
- **Service registry** - prevents arbitrary process termination attacks
- **Secure IPC** - no raw pointers, proper serialization
- **Path security** - TOCTOU prevention, symlink attack protection
- **Process groups** - POSIX-portable service isolation (setsid, killpg)
- **KillMode support** - control-group, process, mixed, none
- **Control interface** (`initctl`/`systemctl` commands)
- **System shutdown** with reverse dependency ordering and orphaned process cleanup
- **DoS prevention** - restart rate limiting with sliding time windows
- **Comprehensive test suite** (15 suites, 102 tests + privileged tests)
- **Security hardening** - SOCK_CLOEXEC, signal race fixes, path security

### Test Coverage & Analysis
The project includes extensive automated testing and static/dynamic analysis:

**Test Suites:**
- **15 test suites** with **102 individual tests** (100% passing)
- Calendar expression parser tests
- Unit file parser and validation tests
- Control protocol serialization tests
- Socket activation tests
- IPC communication tests (supervisor, timer, socket daemons)
  - Includes malformed input tests (invalid types, oversized fields, many/large args)
- Unit scanner tests
- Dependency resolution tests
- State machine tests
- Logging system tests
- Service features tests (PrivateTmp, LimitNOFILE, KillMode)
- Service registry tests (DoS prevention, rate limiting - includes 62-second timing test)
- Integration tests
- **Privileged operations tests** (requires root)

**Running Tests:**
```bash
# Build all tests
ninja -C build

# Run all tests (15 test suites total - includes non-privileged tests)
ninja -C build test

# Run privileged tests (requires root - 1 test with 6 sub-tests)
sudo ninja -C build test-privileged
```

**Privileged Test Suite:**
The privileged operations test suite validates critical root-only functionality:
- Converting systemd unit files to initd format
- Enabling units (WantedBy and RequiredBy)
- Disabling units
- Checking if units are enabled
- Handling units without Install sections

These tests require root privileges because they:
- Create files in system directories (`/lib/initd/system/`, `/etc/initd/system/`)
- Create symlinks for unit dependencies
- Validate real-world privilege separation scenarios

When run without root, the test properly skips with exit code 77 (meson skip).

**Static & Dynamic Analysis:**
- **cppcheck** - Static code analysis
- **flawfinder** - Security-focused static analysis
- **Clang scan-build** - Static analyzer with deeper checks
- **AddressSanitizer/UndefinedBehaviorSanitizer** - Runtime memory error detection
- **Valgrind** - Memory leak and error detection
- **shellcheck** - Shell script static analysis

Run complete analysis suite:
```bash
ninja -C build analyze-all
```

Individual analysis tools:
```bash
ninja -C build analyze-cppcheck
ninja -C build analyze-flawfinder
ninja -C build analyze-scan
ninja -C build analyze-sanitizers
ninja -C build analyze-valgrind
ninja -C build analyze-shellcheck
```

Analysis results are saved to `analysis-output/` with individual log files for review.

**Code Quality:**
- Zero compiler warnings (clean build with `-Wall -Wextra`)
- All format truncation warnings resolved
- Comprehensive test coverage for privilege-separated architecture

### What's Next (Phase 3)
- Complete timer daemon implementation
- Complete socket activator implementation
- Full daemon integration and testing
- Enhanced systemctl command routing

### Future Work
- **Phase 4:** Linux-specific cgroup v2 integration (parallel to existing process groups)
- **Phase 5:** Multi-platform support (BSD, Hurd) and standalone mode
- **Phase 6:** Production hardening and external security audit

## Requirements

### Runtime
- libc
- syslog daemon (rsyslog, syslog-ng, etc.)
- elogind (for session management)

### Build
- C23-capable compiler (GCC 14+, Clang 18+)
- Meson (build system generator)
- Ninja (build tool)
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
