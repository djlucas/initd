# Init System Project Specification

## Project Overview

A lightweight, portable init system providing systemd unit file compatibility without the systemd ecosystem bloat. Designed for Linux, BSD, and GNU Hurd.

**Version:** 0.1.0  
**Language:** C (C23 standard)  
**Build System:** Meson + Ninja  
**License:** TBD

## Core Philosophy

- **Minimal and auditable** - small, readable codebase
- **Privilege separation** - minimize root code exposure
- **Systemd compatibility** - use existing unit files where beneficial
- **Portability** - works on Linux, BSD, Hurd
- **Unix philosophy** - each component does one thing well

## Architecture

### Core Principle: Daemon Independence

Each component is a **separate, independent daemon** that can be installed and run standalone. This is fundamentally different from systemd's monolithic design.

**Independence Requirements:**
- Each daemon has a clearly defined purpose
- Each can function without others being present
- Each manages its own control socket
- Each can be packaged/installed separately
- Cross-daemon communication is optional, not required

**Allowed Coupling:**
- Shared IPC protocol definitions (headers)
- Common libraries (parser, etc.)
- Build together with Meson
- Install as a suite when desired

### Components

1. **init** - PID 1, minimal responsibilities (optional - not needed in standalone mode)
2. **supervisor** (master + slave) - service management daemon
3. **timer-daemon** - timer/cron functionality (independent, optional)
4. **socket-activator** - on-demand service activation (independent, optional)
5. **initctl** - control interface (routes to appropriate daemon)
6. **journalctl** - log query wrapper (independent script)

### Component Details

#### 1. Init (PID 1)

**Responsibilities:**
- Reap zombie processes (waitpid loop)
- Start supervisor-master
- Monitor supervisor health
- Handle shutdown signals (SIGTERM, SIGINT)
- Coordinate system shutdown

**Does NOT handle:**
- Service management
- Configuration parsing
- Complex logic

**Signals:**
- SIGCHLD → reap zombies
- SIGTERM → shutdown (poweroff)
- SIGINT → Ctrl+Alt+Del (reboot)
- SIGUSR1 → halt

**Config:**
- Command line arguments: `supervisor=/path/to/supervisor timeout=N`
- Defaults: supervisor path from compile-time define, timeout=30
- No config file (keeps init minimal)

**Code size target:** ~200-300 lines

#### 2. Supervisor Master (root)

**Responsibilities:**
- Fork supervisor-slave
- Handle privileged requests from slave
- Set up cgroups (Linux only)
- Set up namespaces
- Drop privileges before exec
- Fork service processes

**Privilege operations:**
- `fork()` + `exec()` services
- Create cgroups
- `unshare()` for namespaces
- `setuid()`/`setgid()`

**IPC with slave:**
- Pipe/socket for requests
- Binary protocol for efficiency

**Request types:**
```c
enum priv_request_type {
    REQ_START_SERVICE,
    REQ_STOP_SERVICE,
    REQ_SHUTDOWN_COMPLETE
};
```

#### 3. Supervisor Slave (unprivileged)

**Responsibilities:**
- Parse unit files
- Build dependency graph
- Manage service state
- Monitor service PIDs
- Handle timer scheduling
- Accept systemctl connections
- Log to syslog

**Runs as:** Dedicated unprivileged user (`initd-supervisor`)

**Main loop:**
- Poll control socket for systemctl requests
- Monitor service PIDs
- Check timer expirations
- Receive responses from master

**State tracking:**
- Service PIDs
- Service states (running, stopped, failed)
- Restart counts
- Timer schedules

#### 4. Socket Activator

**Independent daemon for socket activation**

**Independence:**
- Runs standalone without supervisor
- Own control socket: `/run/initd/socket-activator.sock`
- Manages its own .socket unit files
- Can activate services via supervisor OR exec directly

**Features:**
- Listen on socket (TCP/Unix/etc.)
- Launch service on connection
- Pass socket as fd 3 to service
- **Idle timeout** - kill service after N seconds idle
- `RuntimeMaxSec=` - hard time limit

**Unique feature:** Idle timeout (systemd doesn't have this!)

**Service Activation:**
1. Check if supervisor socket exists (`/run/initd/supervisor.sock`)
2. If yes: send activation request to supervisor
3. If no: exec service directly or use native init commands

**Implementation:**
- One process per .socket unit OR single daemon managing multiple sockets
- Poll socket for connections
- Monitor service for activity
- SIGTERM service on timeout

#### 4a. Timer Daemon

**Independent daemon for timer/cron functionality**

**Independence:**
- Runs standalone without supervisor
- Own control socket: `/run/initd/timer.sock`
- Manages its own .timer unit files
- Can activate services via supervisor OR exec directly

**Features:**
- OnCalendar - systemd calendar expressions
- OnBootSec - delay after boot
- OnStartupSec - delay after timer activation
- OnUnitActiveSec - periodic after service starts
- OnUnitInactiveSec - periodic after service stops
- Persistent - catch up on missed runs
- RandomizedDelaySec - jitter

**Service Activation:**
1. Timer expires
2. Check if supervisor socket exists (`/run/initd/supervisor.sock`)
3. If yes: send activation request to supervisor
4. If no: exec service directly or use `systemctl start foo`

**Implementation:**
- Single daemon managing all timer units
- Poll/sleep for next timer expiration
- Track persistent timer state
- Read timer units from standard directories

#### 5. initctl (systemctl)

**Binary name:** `initctl`, symlinked as `systemctl` for compatibility

**Routes commands to appropriate daemon based on unit type**

**Control Sockets:**
- `/run/initd/supervisor.sock` - for .service units
- `/run/initd/timer.sock` - for .timer units
- `/run/initd/socket-activator.sock` - for .socket units

**Protocol:**
```c
struct msg_header {
    uint32_t length;    // Total message length
    uint16_t command;   // Command code
    uint16_t flags;     // Reserved
};

// Followed by null-terminated strings
```

**Command Routing:**
```c
// initctl determines unit type and routes to correct daemon
if (unit ends with ".service" || no extension) {
    socket = "/run/initd/supervisor.sock";
} else if (unit ends with ".timer") {
    socket = "/run/initd/timer.sock";
} else if (unit ends with ".socket") {
    socket = "/run/initd/socket-activator.sock";
}

// If daemon not running, provide helpful error
if (connect(socket) fails) {
    fprintf(stderr, "Error: %s daemon not running\n", daemon_name);
}
```

**Commands:**
- START, STOP, RESTART, RELOAD
- ENABLE, DISABLE (sent to appropriate daemon)
- STATUS, IS_ACTIVE, IS_ENABLED
- LIST_UNITS (queries all daemons, combines results)
- LIST_TIMERS (queries timer daemon)
- DAEMON_RELOAD (sent to appropriate daemon)
- ISOLATE (supervisor only)

**Permissions:**
- Root: full control
- Non-root: read-only queries on system services

**User mode:** `systemctl --user` connects to per-user daemons (if running)

#### 6. journalctl

**Wrapper around syslog**

**Log format in syslog:**
```
Oct  6 12:34:56 hostname supervisor[123]: [nginx.service] Server started
```

**Features:**
- `-u unit` - filter by unit (auto-expands `.service`)
- `-f` - follow logs
- `-r` - reverse (newest first)
- `-n N` - last N lines
- `-p priority` - filter by priority
- Pager support (less/more)

**Unit validation:** Checks unit exists before querying

## Inter-Daemon Communication

### Design Philosophy

Daemons are **independent** but can **optionally communicate** when both are present. No daemon requires another to function.

### Communication Patterns

#### 1. User Control (initctl → daemons)
- initctl routes commands to appropriate daemon based on unit type
- Uses daemon-specific control sockets
- Each daemon implements same control protocol

#### 2. Service Activation (timer/socket → supervisor)
When timer-daemon or socket-activator needs to start a service:

```c
// Optional activation via supervisor
int try_activate_via_supervisor(const char *unit) {
    int fd = connect("/run/initd/supervisor.sock");
    if (fd < 0) {
        // Supervisor not running - use fallback
        return activate_directly(unit);
    }

    // Send activation request to supervisor
    send_activation_request(fd, unit);
    return 0;
}

// Fallback activation without supervisor
int activate_directly(const char *unit) {
    // Option 1: exec systemctl (delegates to host init)
    execl("/usr/bin/systemctl", "systemctl", "start", unit, NULL);

    // Option 2: exec service directly
    execl("/usr/bin/service", "service", unit, "start", NULL);

    // Option 3: parse unit file and exec command directly
    parse_and_exec_unit(unit);
}
```

#### 3. Supervisor Queries (supervisor → timer/socket)
Supervisor doesn't need to talk to timer/socket daemons. They are independent.

For `systemctl list-units`, initctl queries each daemon separately:
```c
// Query all running daemons
units = query_supervisor();
units += query_timer_daemon();
units += query_socket_activator();
// Combine and display
```

### Socket Paths

| Daemon | Control Socket | Purpose |
|--------|---------------|----------|
| supervisor-slave | `/run/initd/supervisor.sock` | Service management |
| timer-daemon | `/run/initd/timer.sock` | Timer control |
| socket-activator | `/run/initd/socket-activator.sock` | Socket control |

### Shared Protocol

All daemons use the same control protocol for consistency:
- Same message header format
- Same command codes (where applicable)
- Same response format

This allows initctl to be unit-type agnostic in most operations.

## Unit File Support

### Format
Standard systemd INI format

### Directories (priority order)
1. `/etc/<name>/system/` - local admin configs
2. `/lib/<name>/system/` - distribution defaults
3. `/etc/systemd/system/` - compatibility
4. `/lib/systemd/system/` - compatibility

### Import on enable
- `systemctl enable foo` finds unit in systemd dirs
- Copies to `/etc/<name>/system/`
- Uses converted copy thereafter

### Supported Sections

**[Unit]:**
- Description
- After, Before
- Requires, Wants
- Conflicts

**[Service]:**
- Type (simple, forking, oneshot)
- ExecStart, ExecStop, ExecReload
- ExecStartPre, ExecStartPost
- User, Group
- WorkingDirectory
- Environment, EnvironmentFile
- Restart (no, always, on-failure)
- RestartSec
- TimeoutStartSec, TimeoutStopSec

**[Timer]:**
- OnCalendar
- OnBootSec
- OnStartupSec
- OnUnitActiveSec
- OnUnitInactiveSec
- Persistent
- RandomizedDelaySec

**[Socket]:**
- ListenStream, ListenDatagram
- (Custom: IdleTimeout)

**[Install]:**
- WantedBy, RequiredBy

## Targets

### Standard Targets

- `rescue.target` - Single-user mode (runlevel 1)
- `multi-user.target` - Full system, no GUI (runlevel 3)
- `graphical.target` - With GUI (runlevel 5)
- `poweroff.target` - Shutdown (runlevel 0)
- `reboot.target` - Reboot (runlevel 6)
- `halt.target` - Halt

### Compatibility Symlinks
- `runlevel1.target → rescue.target`
- `runlevel3.target → multi-user.target`
- `runlevel5.target → graphical.target`
- etc.

### Target Hierarchy

```
sysinit.target
  Requires: local-fs.target
  Wants: swap.target (parallel, non-blocking)
  ↓
basic.target
  Requires: sysinit.target
  Wants: sockets.target, timers.target
  ↓
multi-user.target
  Requires: basic.target
  After: network.target
  ↓
graphical.target
  Requires: multi-user.target
```

## Boot Sequence

1. **Kernel starts init**
2. **Init starts supervisor-master**
3. **Master forks slave (drops privs)**
4. **Slave scans unit directories**
5. **Slave parses unit files**
6. **Slave builds dependency graph**
7. **Slave starts default.target**
   - Resolves dependencies
   - Starts in topological order
   - Parallel where no ordering constraints
8. **Services running, system ready**

### Failure Handling

- `sysinit.target` fails → `rescue.target`
- `basic.target` fails → `rescue.target`
- `graphical.target` fails → fallback to `multi-user.target`
- initramfs fails → shell in initramfs (existing behavior)

## Shutdown Sequence

1. **Shutdown initiated** (systemctl/signal)
2. **Supervisor isolates shutdown target**
3. **Stop services in reverse dependency order**
   - Send SIGTERM to process group
   - Wait TimeoutStopSec (default 90s)
   - Send SIGKILL if needed
4. **Unmount filesystems**
5. **Supervisor signals init: shutdown complete**
6. **Supervisor exits**
7. **Init performs final sync()**
8. **Init calls reboot(RB_POWER_OFF/RB_AUTOBOOT/RB_HALT)**

## Logging

### Architecture
- Services write to stdout/stderr
- Supervisor captures via pipes
- **Early boot:** Buffer in memory (FIFO queue)
- **After syslog starts:** Flush buffer + direct syslog
- Traditional syslog handles rotation

### Early Boot Logging

**Problem:** Syslog isn't running during sysinit.target

**Solution:** Full memory buffering with deferred write

1. **Buffer all logs in FIFO queue**
   - Store with `CLOCK_BOOTTIME` timestamps
   - Queued in order (oldest to newest)
   - Limit to 1000 entries (prevent memory exhaustion)
   - If buffer full, drop oldest entries

2. **Detect when syslog.service starts**
   - Monitor syslog unit state
   - Open syslog when ready

3. **Flush buffer on syslog ready**
   - Calculate boot-time-to-real-time offset
   - Write buffered entries with reconstructed timestamps
   - Mark entries as `[buffered from boot+X.XXXs]`
   - Switch to direct syslog for future logs

**Implementation:**
```c
struct log_entry {
    struct timespec boot_time;  // CLOCK_BOOTTIME
    char unit[256];
    char message[1024];
    int priority;
    struct log_entry *next;     // FIFO queue
};

struct log_buffer {
    struct log_entry *head;     // Oldest (dequeue here)
    struct log_entry *tail;     // Newest (enqueue here)
    size_t count;
    size_t max_entries;         // 1000
    bool syslog_ready;
};
```

**Time conversion on flush:**
```c
// Get current times
clock_gettime(CLOCK_REALTIME, &now_real);
clock_gettime(CLOCK_BOOTTIME, &now_boot);

// Calculate offset
int64_t offset_sec = now_real.tv_sec - now_boot.tv_sec;

// For each buffered entry
time_t log_real_time = entry->boot_time.tv_sec + offset_sec;
```

**Note:** Early boot logs are **only** in memory until syslog starts. If supervisor crashes before syslog starts, early logs are lost. This is acceptable trade-off for simplicity.

### Log Format
```
timestamp hostname supervisor[pid]: [unit.service] message
```

### Benefits
- Use existing syslog infrastructure
- Standard logrotate
- Works with remote syslog
- Plain text, greppable
- journalctl wrapper provides familiar interface

## Platform Support

### Deployment Modes

**Mode 1: PID 1 Init Replacement**
- Full init system replacing traditional init
- Handles boot, shutdown, and process supervision
- Primary use case: Linux replacing sysvinit/systemd
- Also possible: BSD, Hurd (non-standard but supported)

**Mode 2: Standalone Supervisor**
- Runs as a regular service under existing init
- Provides systemd-style unit file management
- No boot/shutdown integration
- Use cases:
  - Running under rc on BSD
  - Testing/development without replacing init
  - Container environments
  - Systems with sysvinit or other non-systemd init

### Platform-Specific Features

**Linux**
- **Cgroups v2** for process tracking
- **Namespaces** for isolation (optional)
- Full feature set in both modes

**BSD and Other Unix-like Systems**
- **Process groups** instead of cgroups
- No namespaces
- Core functionality works
- Can run as PID 1 or standalone supervisor

**GNU Hurd**
- **Process groups**
- Different process model
- Core functionality works
- Can run as PID 1 or standalone supervisor

### Abstraction Layer
```c
#ifdef HAVE_LINUX
  // cgroup implementation
#elif HAVE_BSD
  // process group implementation
#elif HAVE_HURD
  // Hurd-specific implementation
#endif
```

## Build System

### Meson Configuration

**Root meson.build:**
```meson
project('PROJECTNAME', 'c',
  version: '0.1.0',
  license: 'TBD',
  default_options: ['c_std=c23', 'warning_level=3']
)
```

**Options (meson_options.txt):**
- `init-config-path` - Path to init.conf
- `unit-dir-system` - System unit directory
- `unit-dir-user` - User unit directory
- `control-socket` - Control socket path
- `cgroups` - Enable cgroup support (Linux only)
- `systemd-compat` - Install systemd compatibility symlinks
- `dynamic-init` - Build init dynamically linked (default: static)

### Directory Structure

```
project/
├── meson.build
├── meson_options.txt
├── src/
│   ├── init/
│   │   ├── meson.build
│   │   └── init.c
│   ├── supervisor/
│   │   ├── meson.build
│   │   ├── master.c
│   │   ├── slave.c
│   │   ├── service.c
│   │   ├── timer.c
│   │   └── dependency.c
│   ├── systemctl/
│   │   ├── meson.build
│   │   └── systemctl.c
│   ├── socket-activator/
│   │   ├── meson.build
│   │   └── socket-activator.c
│   └── common/
│       ├── meson.build
│       ├── ipc.c
│       ├── protocol.c
│       ├── parser.c
│       └── utils.c
├── units/
│   ├── meson.build
│   ├── rescue.target
│   ├── multi-user.target
│   ├── graphical.target
│   └── ...
├── scripts/
│   ├── meson.build
│   ├── journalctl
│   └── service-scripts/
│       ├── network-configure
│       └── ...
├── tests/
│   ├── meson.build
│   ├── test-calendar.c
│   ├── test-parser.c
│   ├── test-control.c
│   ├── test-socket.c
│   ├── test-ipc.c
│   ├── test-scanner.c
│   ├── test-dependency.c
│   ├── test-state.c
│   ├── test-log.c
│   └── test-integration.c
└── docs/
    └── README.md
```

## Service Scripts

### Network Configuration

**Need to rewrite (no init-functions dependency):**

Scripts in `/lib/services/`:
- `network-configure` - replaces ipv4-static
- `network-route` - replaces ipv4-static-route
- `network-dhcp` - DHCP client wrapper
- Other networking as needed

**Requirements:**
- Standalone (no sourcing init-functions)
- Simple logging (echo or syslog)
- Read config from `/etc/sysconfig/ifconfig.*`
- Called from unit files with `ExecStart=`

**Example unit:**
```ini
[Unit]
Description=Configure %I network interface
After=network-pre.target

[Service]
Type=oneshot
EnvironmentFile=/etc/sysconfig/ifconfig.%I
ExecStart=/lib/services/network-configure %I up
ExecStop=/lib/services/network-configure %I down
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

## Security Model

### Privilege Separation

**Init (root):**
- Minimal code running as root
- Only reaping and supervisor management

**Supervisor Master (root):**
- Small, auditable privileged operations
- Drops capabilities where possible
- Short-lived worker processes

**Supervisor Slave (unprivileged):**
- Bulk of code runs here
- No root privileges
- Limited system access

**Services:**
- Run as specified User/Group
- Drop privileges before exec
- Isolated via cgroups/namespaces (Linux)

### Process Lifecycle

```
init (root, PID 1)
  └─> supervisor-master (root)
      ├─> supervisor-slave (unprivileged)
      └─> privileged worker (root)
          └─> service (drops to user)
              dies → worker dies → master tracks
```

## Dependencies

### Runtime Dependencies
- libc
- syslog daemon (rsyslog, syslog-ng, etc.)
- elogind (for session management)

### Optional Dependencies
- Linux kernel with cgroup v2 support
- p11-kit (if using trust anchors)

### Build Dependencies
- C23-capable compiler (GCC 14+, Clang 18+)
- Meson
- Ninja
- pkg-config

## Development Roadmap

### Phase 1: Minimal Boot
1. Init binary (PID 1, reaping)
2. Supervisor master/slave split
3. Basic unit file parser
4. Start simple services
5. Shutdown handling

### Phase 2: Core Features & Independent Daemons
1. Dependency resolution
2. Target support
3. Service restart/recovery
4. systemctl basic commands
5. Logging integration
6. Timer daemon (independent, cron replacement)
7. Socket activator daemon (independent, with idle timeout)
8. Daemon independence (separate control sockets, optional communication)
9. Full systemctl compatibility (command routing to daemons)
10. journalctl wrapper

### Phase 3: Platform Support & Polishing
1. Cgroup integration (Linux)
2. Platform abstraction layer
3. Standalone supervisor mode (run without replacing init)
4. Multi-platform testing

### Phase 4: Portability & Multi-Mode Support

#### Platform Abstraction
1. Abstract process tracking (cgroups vs process groups)
2. Platform-specific headers and feature detection
3. Conditional compilation for platform features
4. Testing on BSD and Hurd

#### Standalone Supervisor Mode
1. Mode detection (PID == 1 vs regular process)
2. Conditional shutdown behavior (reboot() vs exit)
3. Startup script/unit for running under existing init
4. Documentation for both deployment modes

#### Design Constraints for Phases 1-3
To avoid writing ourselves into a corner, the following must be considered during early phases:

**Init Process (init.c)**
- ✅ Already isolated - only runs as PID 1
- No changes needed for standalone mode

**Supervisor Master**
- ✅ Already mode-agnostic (doesn't check PID)
- ⚠️ TODO: Detect if running as descendant of PID 1 vs direct child
- ⚠️ TODO: Conditional reboot() - only if we ARE the init
- ⚠️ TODO: Platform abstraction for process tracking

**Supervisor Slave**
- ✅ Already unprivileged and mode-agnostic
- ⚠️ TODO: Abstract process supervision (cgroups vs process groups)
- ⚠️ TODO: Platform-specific includes

**Control Protocol**
- ✅ Already Unix socket based - works in both modes
- ⚠️ TODO: Add shutdown/reboot/halt commands to initctl
- ⚠️ TODO: In standalone mode, exec native shutdown command (shutdown, halt, reboot)
- ⚠️ TODO: In PID 1 mode, signal init directly

**Unit File Parser**
- ✅ Already platform-agnostic
- No changes needed

**Key Abstraction Points:**
1. **Process Tracking** - Wrap cgroup operations for BSD/Hurd
   ```c
   // supervisor-master.c
   #ifdef HAVE_CGROUPS
     setup_cgroup(pid, unit);
   #else
     setup_process_group(pid, unit);
   #endif
   ```

2. **Shutdown Handling** - Conditional reboot
   ```c
   // supervisor-master.c - shutdown complete
   if (getpid() == 1) {
     // We are PID 1 init - perform system reboot
     sync(); sync();
     reboot(RB_POWER_OFF);
   } else {
     // Standalone mode - just exit
     exit(0);
   }
   ```

3. **Startup Detection** - Know our mode
   ```c
   // supervisor-master.c
   static bool running_as_init = false;

   int main() {
     running_as_init = (getppid() == 0); // Parent is kernel
     // OR: detect if we were started by init.c vs rc
   }
   ```

4. **Shutdown Commands** - initctl should handle both modes
   ```c
   // initctl.c - systemctl poweroff/reboot/halt
   if (running_as_init_mode()) {
     // Send signal to init/supervisor
     send_shutdown_signal(POWEROFF);
   } else {
     // Standalone mode - exec native command
     execl("/sbin/shutdown", "shutdown", "-h", "now", NULL);
     // OR on BSD: execl("/sbin/halt", "halt", NULL);
   }
   ```

These changes should be made during Phase 2-3 to avoid refactoring later.

### Phase 5: Polish
1. Service script rewrites
2. Documentation
3. Performance optimization
4. Security audit

## Key Design Decisions

### Use syslog, not custom logging
- Leverage existing infrastructure
- Plain text logs
- Standard rotation
- Remote logging support

### Import systemd units on enable
- Copy to local directory
- One-time conversion
- Clear ownership

### Privilege separation from start
- Security by design
- Minimal root code
- Easier to audit

### Socket activator with idle timeout
- Differentiating feature
- Saves resources
- systemd doesn't have this

### No D-Bus dependency
- Simpler
- More portable
- Unix sockets sufficient

### C23 for modern features
- Better type safety
- Cleaner code
- Current standard

## Testing Strategy

### Unit Tests (Implemented)
**11 test suites with 89 individual tests - all passing**

1. **calendar parser** (7 tests) - Calendar expression parsing
2. **unit file parser** (7 tests) - Unit file parsing & validation
3. **control protocol** (9 tests) - IPC protocol serialization
4. **socket activator** (10 tests) - Socket creation & activation
5. **IPC protocol** (6 tests) - Master/slave IPC communication
6. **unit scanner** (10 tests) - Directory scanning & priority
7. **dependency resolution** (10 tests) - Unit dependency handling
8. **state machine** (11 tests) - Unit state transitions
9. **logging system** (10 tests) - Log buffering & syslog
10. **integration** (10 tests) - End-to-end workflows
11. **privileged operations** (6 tests) - Root-only operations (requires sudo)

**Coverage:**
- ✅ Unit file parsing (all types)
- ✅ Dependency resolution (After, Before, Requires, Wants, Conflicts)
- ✅ State machine (all states and transitions)
- ✅ IPC protocol (requests and responses)
- ✅ Control protocol (commands and serialization)
- ✅ Directory scanner (priority, filtering)
- ✅ Logging system (buffering, syslog)
- ✅ Socket activation
- ✅ Calendar expressions
- ✅ Integration workflows
- ✅ Privileged operations (enable, disable, convert systemd units)

**Build and run tests:**
```bash
# Run all non-privileged tests (12 tests)
meson compile -C build
meson test -C build --no-suite privileged

# Run privileged tests (requires root - 6 tests)
sudo meson test -C build --suite privileged

# Run all tests with verbose output
meson test -C build -v
```

**Privileged Test Suite:**
The privileged operations test suite validates critical functionality that requires root:
- Converting systemd unit files to initd format (file creation in `/lib/initd/system/`)
- Enabling units with WantedBy (symlink creation in `/etc/initd/system/*.wants/`)
- Enabling units with RequiredBy (symlink creation in `/etc/initd/system/*.requires/`)
- Disabling units (symlink removal)
- Checking if units are enabled
- Handling units without Install sections

These tests properly skip with exit code 77 when run without root privileges.

### Integration Tests (Planned)
- Boot to rescue.target
- Boot to multi-user.target
- Service start/stop/restart
- Shutdown/reboot

### Platform Tests (Planned)
- Linux (primary)
- FreeBSD
- OpenBSD
- GNU Hurd (if available)

## Security Testing

### Integrated Analysis Tools

The project includes comprehensive static and dynamic analysis integrated into the build system:

**Run all analysis tools**:
```bash
meson compile -C build analyze-all
```

**Individual analysis tools**:
```bash
# Static code analysis
meson compile -C build analyze-cppcheck

# Security-focused static analysis
meson compile -C build analyze-flawfinder

# Clang static analyzer
meson compile -C build analyze-scan

# Runtime memory error detection
meson compile -C build analyze-sanitizers

# Memory leak detection
meson compile -C build analyze-valgrind
```

**Analysis results** are saved to `analysis-output/` with individual log files:
- `cppcheck.log` - Static analysis results
- `flawfinder.log` - Security analysis results
- `scan-build.log` - Clang analyzer results
- `sanitizers.log` - AddressSanitizer/UndefinedBehaviorSanitizer results
- `valgrind.log` - Memory leak detection results
- `analysis-summary.log` - Overall summary

**Tools included**:
- **cppcheck** - Comprehensive static code analysis
- **flawfinder** - Security vulnerability scanner
- **Clang scan-build** - Deep static analysis with clang
- **AddressSanitizer** - Runtime memory error detection
- **UndefinedBehaviorSanitizer** - Undefined behavior detection
- **LeakSanitizer** - Memory leak detection
- **Valgrind** - Comprehensive memory analysis

All analysis tools are configured with dedicated build directories and proper logging.

### Fuzzing (Manual)

**Fuzzing targets** (parsers are primary candidates):

1. **Unit file parser**:
   ```bash
   sudo apt install afl++
   # Create fuzzing harness for parser
   # Feed malformed unit files
   ```

2. **Calendar expression parser**:
   ```bash
   # Fuzz calendar expressions with libFuzzer or AFL
   ```

3. **Control protocol**:
   ```bash
   # Fuzz IPC message handling
   ```

## Documentation Needed

1. **User Documentation**
   - Installation guide
   - Migration from systemd
   - Unit file reference
   - systemctl usage

2. **Developer Documentation**
   - Architecture overview
   - Code structure
   - Building from source
   - Contributing guide

3. **Administrator Documentation**
   - Configuration
   - Troubleshooting
   - Service script writing
   - Security considerations

## Open Questions / TBD

1. **Project name** - initd
2. **License** - MIT
3. **Minimum kernel version** (Linux)
4. **Minimum OS versions** (BSD, Hurd)
5. **Default unit directories** - use project name
6. **Unprivileged user name** - `initd-supervisor`

## Notes for Claude Code

This specification provides complete architecture for implementation. Key points:

- Start with minimal init
- Build supervisor master/slave next
- Implement unit parser
- Add service management
- Everything else follows

The privilege separation is critical - implement from the start, don't bolt on later.

Use C23 features for cleaner, safer code.

Target Linux first, abstract for portability from beginning.

Focus on correctness over performance initially.

## References

- systemd unit file format: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
- POSIX standards for init behavior
- **LFS bootscripts:** https://github.com/lfs-book/lfs/tree/trunk/bootscripts
  - Reference for service script functionality
  - Network configuration approach
  - Traditional init patterns
- **make-ca:** https://github.com/lfs-book/make-ca
  - Reference for shell script argument parsing style
  - `get_args()` and `showhelp()` pattern
  - Clean, maintainable shell scripting approach
- elogind for session management integration

## Included Scripts

### journalctl Wrapper

Complete implementation included in project. Key features:

**Style:** Follows make-ca's argument parsing pattern
- `get_args()` function with comprehensive option handling
- `showhelp()` with aligned, detailed help text
- `check_arg()` validation
- Supports both long and short options
- Getopt-style short arg expansion (`-rf` → `-r -f`)

**Functionality:**
- Unit filtering with auto-expansion (`.service` default)
- Supports all unit types (`.service`, `.timer`, `.socket`, `.target`)
- Unit validation (checks unit file exists)
- Follow mode (`-f`)
- Reverse output (`-r`)
- Priority filtering (`-p`)
- Line limiting (`-n`)
- Time filtering (`--since`, `--until`)
- Boot filtering (`-b`)
- Auto-detects pager (`less` or `more`)

**Location:** `scripts/journalctl`

See implementation in this specification for complete code.

---

## Appendix: journalctl Implementation

Complete shell script implementing journalctl wrapper. Use this as-is in the project.

```bash
#!/bin/bash
# Begin /usr/bin/journalctl
#
# Wrapper script to query system logs with journalctl-compatible interface
# 
# Authors: [Your Name]

VERSION="1.0.0"
LOGFILE="/var/log/messages"
PAGER=""
FOLLOW=0
REVERSE=0
LINES=100
UNIT=""
PRIORITY=""
SINCE=""
UNTIL=""
BOOT=""
UNITDIRS="/etc/CHANGEME/system /lib/CHANGEME/system /etc/systemd/system /lib/systemd/system"

# Detect available pager
if command -v less >/dev/null 2>&1; then
    PAGER="less"
elif command -v more >/dev/null 2>&1; then
    PAGER="more"
fi

function get_args(){
  while test -n "${1}" ; do
    case "${1}" in
      -u | --unit)
        check_arg $1 $2
        UNIT="${2}"
        # Expand short names to .service only if no extension
        if ! echo "${UNIT}" | grep -q '\.' ; then
            UNIT="${UNIT}.service"
        fi
        # Otherwise keep as-is (.timer, .socket, .target, etc.)
        shift 2
      ;;
      -f | --follow)
        FOLLOW=1
        shift 1
      ;;
      -r | --reverse)
        REVERSE=1
        shift 1
      ;;
      -n | --lines)
        check_arg $1 $2
        LINES="${2}"
        shift 2
      ;;
      -p | --priority)
        check_arg $1 $2
        PRIORITY="${2}"
        shift 2
      ;;
      --since)
        check_arg $1 $2
        SINCE="${2}"
        shift 2
      ;;
      --until)
        check_arg $1 $2
        UNTIL="${2}"
        shift 2
      ;;
      -b | --boot)
        BOOT="current"
        shift 1
      ;;
      --no-pager)
        PAGER=""
        shift 1
      ;;
      -h | --help)
        showhelp
        exit 0
      ;;
      -V | --version)
        echo -e "journalctl ${VERSION}\n"
        exit 0
      ;;
      # Handle getopt style short args
      -+([a-z,A-Z]))
        arg="${1}"
        newargs=$( echo ${1} | sed 's@-@@' | \
                                 sed 's/.\{1\}/& /g' | \
                                 sed 's/[^ ]* */-&/g')
        newargs="${newargs} $(echo ${@} | sed "s@${arg}@@")"
        get_args ${newargs}
        break;
      ;;
      *)
        showhelp
        exit 1
      ;;
    esac
  done
}

function check_arg(){
  echo "${2}" | grep "^-" > /dev/null
  if [ "$?" == "0" -o ! -n "$2" ]; then
    echo "Error: $1 requires a valid argument."
    exit 1
  fi
}

function check_unit_exists(){
  local unit="${1}"
  local found=0
  
  for dir in ${UNITDIRS}; do
    if test -f "${dir}/${unit}"; then
      found=1
      break
    fi
  done
  
  if test "${found}" == "0"; then
    echo "Error: Unit ${unit} not found in any unit directory."
    echo "Searched: ${UNITDIRS}"
    exit 1
  fi
}

function showhelp(){
  echo ""
  echo "$(basename ${0}) is a log query utility compatible with systemd's journalctl"
  echo "interface. It queries traditional syslog files with journalctl-style options."
  echo ""
  echo "        -u, --unit [UNIT]"
  echo "                         Show logs for the specified unit. Short names"
  echo "                         without extension default to .service"
  echo "                         (e.g., 'httpd' → 'httpd.service')"
  echo "                         Explicit extensions are preserved"
  echo "                         (e.g., 'backup.timer', 'sshd.socket')"
  echo ""
  echo "        -f, --follow"
  echo "                         Follow the log output (like tail -f)"
  echo ""
  echo "        -r, --reverse"
  echo "                         Show newest entries first"
  echo ""
  echo "        -n, --lines [N]"
  echo "                         Show the last N lines (default: 100)"
  echo ""
  echo "        -p, --priority [PRIORITY]"
  echo "                         Filter by priority (emerg, alert, crit, err,"
  echo "                         warning, notice, info, debug)"
  echo ""
  echo "        --since [TIME]"
  echo "                         Show entries since the specified time"
  echo "                         Format: YYYY-MM-DD HH:MM:SS"
  echo ""
  echo "        --until [TIME]"
  echo "                         Show entries until the specified time"
  echo "                         Format: YYYY-MM-DD HH:MM:SS"
  echo ""
  echo "        -b, --boot"
  echo "                         Show logs from current boot"
  echo ""
  echo "        --no-pager"
  echo "                         Do not pipe output into a pager"
  echo ""
  echo "        -h, --help       Show this help message and exit"
  echo ""
  echo "        -V, --version    Show version information and exit"
  echo ""
  echo "Examples:"
  echo "  $(basename ${0}) -u httpd            # Show logs for httpd.service"
  echo "  $(basename ${0}) -u nginx -f         # Follow nginx.service logs"
  echo "  $(basename ${0}) -u backup.timer     # Show logs for backup.timer"
  echo "  $(basename ${0}) -u sshd.socket      # Show logs for sshd.socket"
  echo "  $(basename ${0}) -r -n 50            # Show last 50 lines, newest first"
  echo "  $(basename ${0}) -p err              # Show only error priority and above"
  echo ""
}

function build_filter(){
  local filter="cat ${LOGFILE}"
  
  # Filter by unit
  if test -n "${UNIT}"; then
    filter="${filter} | grep '\\[${UNIT}\\]'"
  fi
  
  # Filter by priority
  if test -n "${PRIORITY}"; then
    case "${PRIORITY}" in
      emerg|0)   filter="${filter} | grep -i 'emerg'" ;;
      alert|1)   filter="${filter} | grep -i -E '(emerg|alert)'" ;;
      crit|2)    filter="${filter} | grep -i -E '(emerg|alert|crit)'" ;;
      err|3)     filter="${filter} | grep -i -E '(emerg|alert|crit|err|error)'" ;;
      warning|4) filter="${filter} | grep -i -E '(emerg|alert|crit|err|error|warn)'" ;;
      notice|5)  filter="${filter} | grep -i -E '(emerg|alert|crit|err|error|warn|notice)'" ;;
      info|6)    filter="${filter} | grep -i -E '(emerg|alert|crit|err|error|warn|notice|info)'" ;;
      debug|7)   filter="${filter}" ;;
    esac
  fi
  
  # Filter by time (basic implementation)
  if test -n "${SINCE}"; then
    # This is simplified - proper date parsing would be more complex
    filter="${filter} | awk '\$0 >= \"${SINCE}\"'"
  fi
  
  if test -n "${UNTIL}"; then
    filter="${filter} | awk '\$0 <= \"${UNTIL}\"'"
  fi
  
  # Boot filter (simplified - would need boot ID tracking)
  if test -n "${BOOT}"; then
    # Show logs since last boot time
    if test -f /var/run/utmp; then
      BOOTTIME=$(who -b | awk '{print $3, $4}')
      filter="${filter} | awk '\$0 >= \"${BOOTTIME}\"'"
    fi
  fi
  
  echo "${filter}"
}

# Process command line arguments
get_args $@

# Validate unit exists if specified
if test -n "${UNIT}"; then
  check_unit_exists "${UNIT}"
fi

# Check if log file exists
if test ! -f "${LOGFILE}"; then
  echo "Error: Log file ${LOGFILE} not found"
  exit 1
fi

# Build filter command
FILTER=$(build_filter)

# Execute query
if test "${FOLLOW}" == "1"; then
  # Follow mode
  if test -n "${UNIT}"; then
    eval "tail -f ${LOGFILE} | grep --line-buffered '\\[${UNIT}\\]'"
  else
    tail -f ${LOGFILE}
  fi
else
  # Normal query
  if test "${REVERSE}" == "1"; then
    # Show newest first
    eval "${FILTER} | tail -n ${LINES} | tac" | ${PAGER}
  else
    # Show oldest first
    eval "${FILTER} | tail -n ${LINES}" | ${PAGER}
  fi
fi

# End /usr/bin/journalctl
```

**Note:** Replace `CHANGEME` with actual project name during build/install.

