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

## Key Components

1. **init** – Optional PID 1 wrapper that reaps zombies and, when acting as system init, starts the supervisor master.
2. **initd-supervisor** – Privilege-separated master (root) and worker (unprivileged) that parse units, resolve dependencies, and manage services.
3. **initd-timer** – Independent timer daemon (master/worker) providing cron-style scheduling, including `OnUnitInactiveSec` with persistence.
4. **initd-socket** – Independent socket activator (master/worker) that binds listeners, enforces IdleTimeout/RuntimeMaxSec, and reports adopted services back to the supervisor.
5. **initctl / systemctl** – CLI front-end that routes requests to the appropriate daemon over their control sockets.
6. **journalctl wrapper** – Convenience shim over syslog for journalctl-like log viewing.

### Architecture

**Core Principle:** Each component is a separate, independent daemon - fundamentally different from systemd's monolithic design.

- Each daemon can be installed and run standalone
- Cross-daemon communication is optional
- Each manages its own control socket
- Components can be packaged separately or as a suite

```
init (PID 1, optional)
  └─ Launches initd-supervisor master and reaps zombies when running as the system init

initd-supervisor (root master)
  └─ initd-supervisor-worker (unprivileged logic)
      ├─ Parses unit files
      ├─ Resolves dependencies
      ├─ Monitors services
      └─ Control socket: /run/initd/supervisor.sock

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

- **Platform Support**
  - Linux: Full feature set with cgroups v2
  - Other Unix-like systems: Process group-based supervision (active work to ensure parity before layering cgroup-specific features)
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

## Differentiating Features

### What Makes initd Different

- **Privilege Separation from Day One**
  - Bulk of code runs unprivileged
  - Minimal attack surface
  - Easier security audits

- **Socket Activator with Idle Timeout**
  - Kill idle services after configurable timeout

- **True Portability**
  - Not just "works on Linux"
  - Multi-platform Unix-like support
  - Platform abstraction from the start

- **No Ecosystem Lock-in**
  - Use existing syslog (syslogd, rsyslog, syslog-ng)
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
- ❌ `.mount`     - Use `/etc/fstab`
- ❌ `.automount` - Use `/etc/fstab`
- ❌ `.swap`      - Use `/etc/fstab`
- ❌ `.device`    - Use eudev or udev directly
- ❌ `.path`      - Path-based activation not implemented
- ❌ `.scope`     - Runtime-created units (systemd internal)
- ❌ `.slice`     - cgroup hierarchy management (not implemented)

### Supported Service Directives

- `Type=` - simple, forking, oneshot
- `ExecStart=` - service start (master-validated, privilege-separated launch)
- `ExecStartPre=`, `ExecStartPost=` - pre/post start commands (privileged master with shared validation)
- `ExecStop=`, `ExecReload=` - service lifecycle commands (privileged master execution with worker mediation)
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
sudo ninja -C build install

# Install reference implementation (17 targets + 19 core services)
# This gives you a working system as a starting point
sudo ninja -C build install-reference
```

**Reference Implementation Includes:**
- All system targets (basic, multi-user, graphical, network, etc.)
- Core system services (getty, udev, syslog, network, etc.)
- Enabled symlinks for automatic boot

You can use the reference implementation as-is, modify it, or ignore it completely and build your own.

**Optional Services:**
```bash
# Install individual optional services (51 available)
sudo ninja -C build install-acpid
sudo ninja -C build install-samba
sudo ninja -C build install-httpd
# ... etc for any of 51 optional services

# Or install all optional services at once
sudo ninja -C build install-everything
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

- PID 1 + supervisor master/worker manage services with restart policies and safe shutdown ordering  
- Systemctl-compatible CLI drives services, timers, sockets, and journal logs  
- Security guardrails (service registry, rate limiting, path/IPC checks) are all active  
- Socket/timer daemons deliver on-demand activation and cron-style scheduling  
- Automated coverage: 20 suites / 106 tests (see `tests/README.md` for suite details)

## Running Tests
```bash
# Build all tests
ninja -C build

# Run all tests (18 non-privileged suites)
ninja -C build test

# Run privileged tests (requires root for privileged-ops suite)
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


## Development Status

### Phase 1 – Minimal Boot (100%)
- Init (PID 1) binary handles zombie reaping and starts the supervisor
- Supervisor split into root master and unprivileged worker
- Basic systemd-compatible unit parsing and simple service lifecycle
- Ordered shutdown with process-group isolation (setsid/killpg)

### Phase 2 – Core Features & Security (100%)
- Dependency graph with cycle detection and recursion limits
- Systemctl-compatible CLI, logging, journalctl wrapper
- Service registry + restart limiter prevent privilege/DoS abuse
- Hardened IPC/path handling, KillMode, PrivateTmp, signal safety

### Phase 3 – Independent Daemons (60%)
- Timer daemon: cron-style scheduling, OnUnitInactiveSec persistence
- Socket activator: listeners, IdleTimeout/RuntimeMaxSec, supervisor adopt
- Remaining: unify initctl routing across daemons; add full integration tests
- Maintain daemon independence (optional control sockets, standalone modes)

### Phase 4 – Linux Enhancements (0%)
- Cgroup v2 integration: tracking, resource limits, OOM handling
- Additional namespace hardening and optional seccomp filters
- Platform detection/feature flags for shared code paths

### Phase 5 – Multi-Platform & Standalone (0%)
- Standalone supervisor workflows (non-PID 1) and packaging
- Cross-platform testing (BSD, Hurd) with process-group parity
- Documentation and installer guidance for diverse environments

### Phase 6 – Production Hardening (0%)
- Service script QA, performance tuning, external security review
- Comprehensive documentation polish and release readiness


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
