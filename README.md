# initd

A lightweight, portable init system with systemd unit file compatibility.

## Overview

**initd** provides modern service management for unix-like systems without the
complexity and ecosystem lock-in of systemd. It implements the good ideas from
systemd (declarative unit files, dependency resolution, socket activation) while
maintaining a clean, auditable codebase and true portability.

### Design Philosophy

- **Minimal and Auditable** - Small, readable C23 codebase
- **Privilege Separated** - Security by design, minimal root code
- **Systemd Compatible** - Use existing unit files where beneficial
- **Truly Portable** - Works on Linux, BSD, and GNU Hurd
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
  - FreeBSD/OpenBSD/NetBSD: Process group-based supervision
  - GNU Hurd: Core functionality with platform-specific adaptations

### User-Facing Tools

- **systemctl** - Service control interface compatible with systemd
- **journalctl** - Log query wrapper for traditional syslog
- Standard targets (rescue, multi-user, graphical)
- Drop-in compatibility with existing systemd unit files

## Architecture

```
init (PID 1)
  └─ supervisor-master (root, minimal)
      ├─ supervisor-slave (unprivileged, main logic)
      │   ├─ Parses unit files
      │   ├─ Resolves dependencies
      │   ├─ Monitors services
      │   └─ Handles systemctl requests
      └─ Spawns services with privilege dropping
```

**Key Components:**

1. **init** - PID 1, zombie reaping, supervisor lifecycle
2. **supervisor-master** - Privileged operations only (fork/exec, cgroups)
3. **supervisor-slave** - Unprivileged service management
4. **socket-activator** - On-demand service activation
5. **systemctl** - Control interface (binary protocol over Unix socket)
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
  - First-class BSD and Hurd support
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

**Current Phase:** Initial Development

This project is under active development. The architecture is complete and implementation is underway.

### Roadmap

- [x] Architecture design
- [x] Complete specification
- [ ] Phase 1: Minimal boot capability
- [ ] Phase 2: Core features (dependencies, targets)
- [ ] Phase 3: Advanced features (timers, sockets)
- [ ] Phase 4: Multi-platform support
- [ ] Phase 5: Production hardening

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
