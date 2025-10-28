# initd

A lightweight, portable init system with systemd unit file compatibility.

---

## ⚠️ **WARNING: PRE-ALPHA SOFTWARE** ⚠️

**DO NOT USE THIS SOFTWARE IN PRODUCTION OR ON ANY SYSTEM YOU CARE ABOUT.**

This is actively developed, incomplete, and untested code. It is not ready for
any use beyond experimentation and development. Expect bugs, missing features,
and breaking changes.

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

1. **init** – Optional PID 1 wrapper that reaps zombies and, when acting as system init, starts initd-supervisor by default (optionally any binary via the kernel command line `supervisor=PATH` parameter).
2. **initd-supervisor** – Privilege-separated master (root) and worker (unprivileged) that parse units, resolve dependencies, and manage services.
3. **initd-timer** – Independent timer daemon (master/worker) providing cron-style scheduling, including `OnUnitInactiveSec` with persistence.
4. **initd-socket** – Independent socket activator (master/worker) that binds listeners, enforces IdleTimeout/RuntimeMaxSec, and reports adopted services back to the supervisor.
5. **initctl / systemctl** – CLI front-end that routes requests to the appropriate daemon over their control sockets; includes `--user` routing and root-only `initctl user` helpers to seed per-user configs.
6. **journalctl convenience script** – Convenience shim over syslog for journalctl-like log viewing.
7. **initd-user-manager** – Boot-time helper script and unit that start the user-mode daemons according to `/etc/initd/users-enabled/` and `~/.config/initd/user-daemons.conf`.

### Architecture

**Core Principle:** Each component is a separate, independent daemon - fundamentally different from systemd's monolithic design.

- Each daemon can be installed and run standalone
- Cross-daemon communication is optional
- Each manages its own control socket
- Components can be packaged separately or as a suite

```
init (PID 1, optional)
  └─ Launches initd-supervisor and reaps zombies when running as the system init

initd-supervisor (supervisor master)
  └─ initd-supervisor-worker (unprivileged logic)
      ├─ Parses unit files
      ├─ Resolves dependencies
      ├─ Monitors services
      └─ Control socket: /run/initd/supervisor.sock

initd-timer (timer master)
  └─ initd-timer-worker (unprivileged worker)
      ├─ Manages .timer units
      ├─ Cron replacement functionality
      └─ Control socket: /run/initd/timer.sock

initd-socket (socket master)
  └─ initd-socket-worker (unprivileged worker)
      ├─ Manages .socket units
      ├─ On-demand service activation
      └─ Control socket: /run/initd/socket-activator.sock

initctl (user/administrator control utility)
  └─ Routes commands to appropriate daemon based on unit type
```

### Design Philosophy

- **Minimal and Auditable** - Small, readable C23 codebase
- **Privilege Separated** - Security by design, minimal root code
- **Systemd Compatible** - Use existing unit files where beneficial
- **Truly Portable** - Multi-platform Unix-like support
- **Unix Philosophy** - Each component does one thing well
- **No Lock-in** - Zero defaults, design your own targets 

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
  - Process group-based supervision (cgroups to be added for Linux in phase 4)
  - Two deployment modes:
    - **PID 1 mode**: Full init replacement (primary use case)
    - **Standalone mode**: Run under existing init (testing, containers, BSD rc, sysvinit)
  - Portable architecture for broad compatibility

### User-Facing Tools

- **initctl** - Service control interface compatible with systemd's systemctl (a symlink provided)
- **journalctl** - Log query wrapper for traditional syslog that mimics some of systemd's journalctl
- Standard targets (rescue, multi-user, graphical)
- Drop-in compatibility with existing systemd unit files (converts on the fly if a systemd service is enabled)

### Per-User Daemons

- Root seeds per-user settings: `initctl user enable alice supervisor timer`
- Enable the boot helper: `systemctl enable --now initd-user-manager.service`
- Users manage their units under `~/.config/initd/user/`; `initctl --user …` targets the user instance
- `loginctl enable-linger` is not necessary (but can be used if elogind is present) - independent for portability

## Credits

All of the reference units were adapted from the [Linux From Scratch bootscripts](https://github.com/lfs-book/lfs/tree/trunk/bootscripts) project.

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
  - Each utility is a standalone daemon and works independent of the others:
    - init - reaps processes, handles shutdown signals, and manages your service manager or runlevel control
    - supervisor - provides use of .service units to start managed services
    - timer - provides use of .timer files for cron replacement (or supplement)
    - socket - provides use of .socket files for super-daemon features

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
- ❌ `.slice`     - cgroup hierarchy management - elogind has user slices

### Supported Unit Directives

- `AllowIsolate=` - permit isolation to this target (only meaningful for .target units)
- `DefaultDependencies=` - add implicit After=basic.target Conflicts=shutdown.target Before=shutdown.target for services/timers/sockets (default: yes)
- `BindsTo=` / `PartOf=` lifecycle linkage for dependent units
- `StopWhenUnneeded=` automatic teardown when no dependents remain
- `RefuseManualStart=` / `RefuseManualStop=` guards for manual control
- `ConditionPath*` checks with optional `!` negation to skip units
- `StartLimitIntervalSec=` / `StartLimitBurst=` (with StartLimitAction= logging)
- `Also=` / `Alias=` / `DefaultInstance=` install metadata helpers

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
- `ExecStopPost=`, `ExecCondition=` - additional lifecycle hooks
- `PIDFile=` - adopt forked services using PID files
- `RestartPreventExitStatus=` / `RestartForceExitStatus=` - restart filters
- `RemainAfterExit=` - keep oneshot services active after exit
- `StandardInput=`/`StandardOutput=`/`StandardError=` - null, inherit, tty, tty-force, syslog, journal, file:path, socket, data
- `StandardInputText=` / `StandardInputData=` - embed literal input data (text or base64)
- `TTYPath=` - device to use with tty stdio modes
- `SyslogIdentifier=` / `SyslogFacility=` / `SyslogLevel=` / `SyslogLevelPrefix=` - syslog configuration
- `UMask=` - file creation mask (octal)
- `NoNewPrivileges=` - prevent privilege escalation via setuid/setgid (Linux/FreeBSD only)

## Quick Start

### Building

```bash
# Create required system users and groups (before building)
# Each daemon runs as a dedicated unprivileged user for security
sudo groupadd -r initd-supervisor
sudo useradd -r -g initd-supervisor -d /var/empty -s /bin/false -c "initd supervisor" initd-supervisor

sudo groupadd -r initd-timer
sudo useradd -r -g initd-timer -d /var/empty -s /bin/false -c "initd timer daemon" initd-timer

sudo groupadd -r initd-socket
sudo useradd -r -g initd-socket -d /var/empty -s /bin/false -c "initd socket activator" initd-socket

# Generate build files with Meson
meson setup build

# Build with Ninja
ninja -C build

# Install (requires root)
sudo ninja -C build install
```

### Init Flexibility

The init binary is service-manager agnostic. It launches initd-supervisor by
default, but you can use any service manager or runlevel control utility of your
choice via the kernel command line:

```bash
# Default: use initd supervisor
linux /vmlinuz root=/dev/sda1

# Use traditional BSD or Linux sysvinit style rc
linux /vmlinuz root=/dev/sda1 supervisor=/etc/init.d/rc

# Use s6
linux /vmlinuz root=/dev/sda1 supervisor=/bin/s6-svscan /service
```

The init process simply:
- Reaps zombies (universal PID 1 responsibility)
- Starts and monitors the specified service manager
- Handles shutdown signals (SIGTERM=poweroff, SIGINT=reboot, SIGUSR1=halt)

This design provides complete freedom to choose your service management approach
while still benefiting from a clean, minimal PID 1 implementation.


### Configuration

Unit files go in:
- `/etc/initd/system/` - Local administrator configs
- `/lib/initd/system/` - Distribution-provided units

Or use existing systemd unit directories for compatibility.

**Important: Zero Default Policy**

The default installation (`ninja install`) installs **only the core binaries**—no targets, services, or configuration. This is intentional:

- ✅ **Provides complete freedom** – Design your own system organization
- ✅ **No forced policy** – Choose your own boot sequence and dependencies
- ✅ **No lock-in** – Not tied to any particular init philosophy

That said, a sample reference implementation is provided:

**Reference installation:**
```bash
# Install reference implementation (17 targets + 19 core services)
# This gives you a working system as a starting point
sudo ninja -C build install-reference
```

**⚠️ WARNING: install-reference OVERWRITES EXISTING CONFIGURATIONS ⚠️**

The `install-reference` target will **overwrite all files** in `/lib/initd/system/` including:
- All `.target` files
- All `.service` files
- Network configuration scripts in `/usr/libexec/initd/network-services/`
- Service helper scripts in `/usr/libexec/initd/service-scripts/`

**Any local modifications to these files will be lost.**

If you have customized reference units, use the individual install targets instead:
```bash
# Install only reference units (targets + services)
sudo ninja -C build install-reference-units

# Install only network scripts
sudo ninja -C build install-reference-network
```

**Reference Implementation Includes:**
- All system targets (basic, multi-user, graphical, network, rescue, emergency, etc.)
- Core system services (getty, udev, syslog, network, etc.)
- Required targets (default.target, emergency.target, basic.target, shutdown.target)
- Enabled symlinks for automatic boot

You can use the reference implementation as-is, modify it, or ignore it
completely and build your own. If you use the reference implementation, it will
enable critical services for boot - while network scripts are installed, they
are not activated by default.

Also included are optional services (taken almost entirely from BLFS):

**Optional services:**
```bash
# Install individual optional services (51 available)
sudo ninja -C build install-acpid
sudo ninja -C build install-samba
sudo ninja -C build install-httpd
# ... etc for any of 51 optional services

# Or install all optional services at once
sudo ninja -C build install-everything

# Installing any service file does not activate it:
sudo initctl enable acpid && sudo initctl start acpid
```

Note: When reinstalling services, existing configuration files in
`/etc/sysconfig/` are preserved:
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

# View logs with the journalctl convenience script
journalctl -u nginx -f

# System shutdown commands
initctl poweroff    # Shut down and power off
initctl reboot      # Shut down and reboot
initctl halt        # Halt the system

# systemctl compatibility (symlink to initctl)
systemctl start nginx
systemctl status nginx
systemctl reboot
```

## Running Tests
```bash
# Run all tests (23 test suites, 182 individual tests: 20 non-privileged, 3 privileged)
ninja -C build test

# Run privileged tests (requires root)
sudo ninja -C build test-privileged
```

**Privileged Test Suites (3 total):**
The privileged test suites validate critical functionality:

1. **offline enable/disable** - Unit enable/disable without running daemons
2. **Exec lifecycle** - ExecStartPre/Post/Stop/Reload execution paths
3. **privileged operations** - Converting systemd units, creating symlinks in system directories

These tests require root privileges because they:
- Create files in system directories (`/lib/initd/system/`, `/etc/initd/system/`)
- Create symlinks for unit dependencies (`*.wants`, `*.requires`)
- Validate real-world privilege separation scenarios

When run without root, privileged tests properly skip with exit code 77 (meson skip).

**Static & Dynamic Analysis:**
- **cppcheck** - Static code analysis
- **flawfinder** - Security-focused static analysis
- **Clang scan-build** - Static analyzer with deeper checks
- **AddressSanitizer/UndefinedBehaviorSanitizer** - Runtime memory error detection
- **Valgrind** - Memory leak and error detection
- **Fuzzing suite** - libFuzzer run (requires clang) for calendar, parser, control, and IPC protocols
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
ninja -C build analyze-fuzz
ninja -C build analyze-shellcheck
```

Analysis results are saved to `analysis-output/` with individual log files for review.

**Code Quality:**
- Zero compiler warnings (clean build with `-Wall -Wextra`)
- Comprehensive test coverage for privilege-separated architecture
- Ships with reasonably comprehensive analyzer suite

## Development Status

### Phase 1 – Minimal Boot (100%)
- Init (PID 1) binary handles zombie reaping and starts the supervisor
- Supervisor split into root master and unprivileged worker
- Basic systemd-compatible unit parsing and simple service lifecycle
- Ordered shutdown with process-group isolation (setsid/killpg)

### Phase 2 – Core Features & Security (100%)
- Dependency graph with cycle detection and recursion limits
- Systemctl-compatible CLI, logging, journalctl convenience script
- Service registry + restart limiter prevent privilege/DoS abuse
- Hardened IPC/path handling, KillMode, PrivateTmp, signal safety

### Phase 3 – Independent Daemons (100%)
- Timer daemon: cron-style scheduling, OnUnitInactiveSec persistence
- Socket activator: listeners, IdleTimeout/RuntimeMaxSec, supervisor adopt
- Per-User daemons and reboot persistence, independent of elogind's linger
- Target-based shutdown with proper ordering (shutdown.target + implicit dependencies)
- Full systemd directive parity (in progress)

### Phase 4 – Linux Enhancements (0%)
- Cgroup v2 integration: tracking, resource limits, OOM handling
- Additional namespace hardening and optional seccomp filters

## Requirements

### Runtime
- libc
- syslog daemon (rsyslog, syslog-ng, etc.)

### Build
- C23-capable compiler (GCC 14+, Clang 18+)
- Meson (build system generator)
- Ninja (build tool)
- pkg-config

### Testing
- cppcheck
- flawfinder
- clang (with libFuzzer)
- valgrind
- shellcheck

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
