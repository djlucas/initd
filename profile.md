# Init System Project Specification

## Project Overview

A lightweight, portable init system providing systemd unit file compatibility without the systemd ecosystem bloat. Designed for Linux, BSD, and GNU Hurd.

**Version:** 0.1
**Language:** C (C23 standard)
**Build System:** Meson + Ninja
**License:** MIT

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
- Each manages its own control (write) and status (read-only) sockets in dedicated subdirectories
- Each can be packaged/installed separately
- Cross-daemon communication is optional, not required

**Allowed Coupling:**
- Shared IPC protocol definitions (headers)
- Common libraries (parser, etc.)
- Build together with Meson
- Install as a suite when desired

### Components

1. **init** - PID 1, minimal responsibilities (optional - not needed in standalone mode)
2. **supervisor** (master + worker) - service management daemon
3. **timer-daemon** - timer/cron functionality (independent, optional)
4. **socket-activator** - on-demand service activation (independent, optional)
5. **initctl** - control interface (routes to appropriate daemon)
6. **journalctl** - log query wrapper (independent script)

### Component Details

#### 1. Init (PID 1)

**Responsibilities:**
- Reap zombie processes (waitpid loop)
- Start initd-supervisor
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
- Fork initd-supervisor-worker
- Handle privileged requests from worker
- Set up cgroups (Linux only)
- Set up namespaces
- Drop privileges before exec
- Fork service processes

**Privilege operations:**
- `fork()` + `exec()` services
- Create cgroups
- `unshare()` for namespaces
- `setuid()`/`setgid()`

**IPC with worker:**
- Socketpair for requests/responses
- Binary protocol with proper serialization (no raw pointers)

**Request types:**
```c
enum priv_request_type {
    REQ_START_SERVICE,
    REQ_STOP_SERVICE,
    REQ_SHUTDOWN_COMPLETE
};
```

#### 3. Supervisor Worker (unprivileged)

**Responsibilities:**
- Parse unit files with path security validation
- Build dependency graph with cycle detection
- Manage service state with DoS prevention
- Monitor service PIDs via service registry
- Handle timer scheduling
- Accept systemctl connections
- Log to syslog with early boot buffering

**Runs as:** Dedicated unprivileged user (`initd-supervisor`)

**Security Features:**
- Service registry prevents arbitrary kill() attacks (256-service limit)
- DoS prevention via restart rate limiting (5/60s window, 1s min interval)
- Path security with TOCTOU and symlink protection
- Secure IPC with malformed input validation

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
- Own control socket: `/run/initd/socket/socket-activator.sock`
- Own status socket: `/run/initd/socket/socket-activator.status.sock`
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
1. Check if supervisor control socket exists (`/run/initd/supervisor/supervisor.sock`)
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
- Own control socket: `/run/initd/timer/timer.sock`
- Own status socket: `/run/initd/timer/timer.status.sock`
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
2. Check if supervisor control socket exists (`/run/initd/supervisor/supervisor.sock`)
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

**IPC Sockets:**
- Supervisor
  - Control: `/run/initd/supervisor/supervisor.sock` (privileged commands)
  - Status: `/run/initd/supervisor/supervisor.status.sock` (read-only queries; 0666)
- Timer daemon
  - Control: `/run/initd/timer/timer.sock`
  - Status: `/run/initd/timer/timer.status.sock`
- Socket activator
  - Control: `/run/initd/socket/socket-activator.sock`
  - Status: `/run/initd/socket/socket-activator.status.sock`

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
bool readonly = command in {
    CMD_STATUS, CMD_IS_ACTIVE, CMD_IS_ENABLED,
    CMD_LIST_UNITS, CMD_LIST_TIMERS, CMD_LIST_SOCKETS
};

// initctl determines unit type and routes to correct daemon
if (unit ends with ".service" || no extension) {
    socket = readonly
        ? "/run/initd/supervisor/supervisor.status.sock"
        : "/run/initd/supervisor/supervisor.sock";
} else if (unit ends with ".timer") {
    socket = readonly
        ? "/run/initd/timer/timer.status.sock"
        : "/run/initd/timer/timer.sock";
} else if (unit ends with ".socket") {
    socket = readonly
        ? "/run/initd/socket/socket-activator.status.sock"
        : "/run/initd/socket/socket-activator.sock";
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
- Non-root: read-only queries on system services via the daemon-specific `*.status.sock` endpoints (0666)
- Control sockets remain `0600`/`0660`, so mutating commands require root or the dedicated service account

**User Mode Architecture:**
- Per-user supervisor and timer daemons run entirely unprivileged.
- Sockets live in daemon-specific subdirectories under `/run/user/$UID/initd/`:
  - Supervisor: `/run/user/$UID/initd/supervisor/{supervisor.sock,supervisor.status.sock}`
  - Timer: `/run/user/$UID/initd/timer/{timer.sock,timer.status.sock}`
  - Socket: `/run/user/$UID/initd/socket/{socket-activator.sock,socket-activator.status.sock}`
  - All sockets have `0600` perms.
- Runtime directory detection:
  - On Linux: checks `/run/user/$UID/` first (elogind/systemd-logind)
  - Fallback: `$XDG_RUNTIME_DIR/initd`
  - Explicit override: `--runtime-dir=/path` or `INITD_RUNTIME_DIR` env var
- Unit file roots default to `~/.config/initd/user/`; no system directories are consulted.
- `initctl` auto-detects the per-user sockets; `initctl --user` forces user scope, `--system` forces the system instance.
- `initctl user enable/disable` (root-only) populates per-user daemon settings in `~/.config/initd/user-daemons.conf`.
- The `initd-user-manager` helper (oneshot service) reads `/etc/initd/users-enabled/` at boot, creates `/run/user/$UID/initd`, and starts the selected user daemons to provide reboot persistence. On Linux with elogind, administrators can optionally use `loginctl enable-linger` for session-manager persistence; it operates independently of initd's helpers.

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
    int fd = connect("/run/initd/supervisor/supervisor.sock");
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

| Daemon | Control Socket | Status Socket | Purpose |
|--------|---------------|---------------|----------|
| supervisor-worker | `/run/initd/supervisor/supervisor.sock` | `/run/initd/supervisor/supervisor.status.sock` | Service management |
| timer-daemon | `/run/initd/timer/timer.sock` | `/run/initd/timer/timer.status.sock` | Timer control |
| socket-activator | `/run/initd/socket/socket-activator.sock` | `/run/initd/socket/socket-activator.status.sock` | Socket control |

> **Total:** six IPC sockets (three read/write control endpoints plus three read-only status endpoints) when all daemons are running.
>
> **Directory structure:** Each daemon uses its own subdirectory under `/run/initd/` to avoid permission conflicts. The base directory remains owned by root, while each subdirectory is owned by the respective daemon's unprivileged user.

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
1. `/etc/initd/system/` - local admin configs
2. `/lib/initd/system/` - distribution defaults
3. `/etc/systemd/system/` - compatibility
4. `/lib/systemd/system/` - compatibility

### Import on enable
- `systemctl enable foo` finds unit in systemd dirs
- Copies to `/etc/initd/system/`
- Uses converted copy thereafter

### Supported Sections

**[Unit]:**
- Description
- After, Before
- Requires, Wants
- Conflicts

**[Service]:**
- Type (simple, forking, oneshot)
- ExecStart, ExecStartPre, ExecStartPost, ExecStop, ExecStopPost, ExecReload, ExecCondition
- User, Group
- WorkingDirectory
- Environment, EnvironmentFile
- Restart (no, always, on-failure)
- RestartSec, RestartMaxDelaySec
- RestartPreventExitStatus, RestartForceExitStatus
- TimeoutStartSec, TimeoutStopSec, TimeoutAbortSec
- TimeoutStartFailureMode
- StandardInput, StandardOutput, StandardError
- TTYPath
- RemainAfterExit
- PIDFile
- SyslogIdentifier, SyslogFacility, SyslogLevel, SyslogLevelPrefix
- LogLevelMax
- UMask
- KillMode (portable - process groups)
- PrivateTmp (Linux/BSD/Hurd - mount namespaces on Linux, secure temp dirs on BSD/Hurd)
- PrivateDevices (Linux only - private /dev with minimal nodes)
- NoNewPrivileges (Linux/FreeBSD only)
- RootDirectory, RootImage
- ProtectSystem, ProtectHome
- ProtectKernelTunables, ProtectControlGroups (Linux only)
- MountFlags
- DynamicUser
- DeviceAllow (Linux only - cgroup device controller)
- CapabilityBoundingSet, AmbientCapabilities (Linux only)
- RestrictSUIDSGID
- MemoryLimit
- RuntimeMaxSec
- LimitNOFILE, LimitCPU, LimitFSIZE, LimitDATA, LimitSTACK, LimitCORE, LimitRSS, LimitAS, LimitNPROC, LimitMEMLOCK, LimitLOCKS (portable - setrlimit)
- LimitSIGPENDING, LimitMSGQUEUE, LimitNICE, LimitRTPRIO, LimitRTTIME (Linux only - setrlimit)

**[Timer]:**
- OnCalendar (supports multiple entries)
- OnBootSec
- OnStartupSec
- OnUnitActiveSec
- OnUnitInactiveSec
- Persistent
- RandomizedDelaySec
- AccuracySec
- Unit
- FixedRandomDelay
- RemainAfterElapse
- WakeSystem (Linux/FreeBSD/OpenBSD/NetBSD - RTC wake alarms)
- OnClockChange (Linux timerfd, BSD kqueue, Hurd polling)
- OnTimezoneChange (Linux inotify, BSD kqueue, Hurd polling)

**[Socket]:**
- ListenStream, ListenDatagram
- IdleTimeout (custom extension - kill service after idle)
- RuntimeMaxSec (from associated service unit)

**[Install]:**
- WantedBy, RequiredBy

### Service Directive Details

#### PrivateTmp (Linux-only)

**Purpose:** Provides isolated `/tmp` directory per service for security

**Implementation:**
- Uses Linux mount namespaces (`unshare(CLONE_NEWNS)`)
- Creates private tmpfs mount on `/tmp` for the service
- Size limit: 1GB per service
- Permissions: 1777 (world-writable with sticky bit)

**Platform Support:**
- Linux: Full support via mount namespaces
- BSD/Hurd: Creates unique `/tmp/initd-privateXXXXXX` directory with secure ownership and TMPDIR override

**Usage:**
```ini
[Service]
ExecStart=/usr/bin/myapp
PrivateTmp=true    # or false, default: false
```

**Security Benefits:**
- Prevents service from accessing other services' temp files
- Cleans up automatically when service exits
- Reduces attack surface for privilege escalation

#### Resource Limit Directives (Limit*)

**Purpose:** Control resource consumption via POSIX setrlimit(2)

**Implementation:**
- Uses `setrlimit()` (POSIX standard) for all limits
- Applied before dropping privileges
- Both soft and hard limits set to same value
- Supports numeric values or `infinity` for unlimited

**Platform Support:**

*Portable limits (all Unix-like systems):*
- `LimitNOFILE=` - File descriptor limit (RLIMIT_NOFILE)
- `LimitCPU=` - CPU time in seconds (RLIMIT_CPU)
- `LimitFSIZE=` - Maximum file size in bytes (RLIMIT_FSIZE)
- `LimitDATA=` - Data segment size in bytes (RLIMIT_DATA)
- `LimitSTACK=` - Stack size in bytes (RLIMIT_STACK)
- `LimitCORE=` - Core dump size in bytes (RLIMIT_CORE)
- `LimitAS=` - Address space size in bytes (RLIMIT_AS)
- `LimitNPROC=` - Maximum number of processes (RLIMIT_NPROC)
- `LimitMEMLOCK=` - Locked memory in bytes (RLIMIT_MEMLOCK)

*Platform-specific limits:*
- `LimitRSS=` - Resident set size (RLIMIT_RSS, deprecated on Linux)
- `LimitLOCKS=` - File locks (RLIMIT_LOCKS, obsolete on Linux since 2.4.25)
- `LimitSIGPENDING=` - Queued signals (RLIMIT_SIGPENDING, Linux only)
- `LimitMSGQUEUE=` - POSIX message queue bytes (RLIMIT_MSGQUEUE, Linux only)
- `LimitNICE=` - Nice priority (RLIMIT_NICE, Linux only)
- `LimitRTPRIO=` - Real-time priority (RLIMIT_RTPRIO, Linux only)
- `LimitRTTIME=` - Real-time CPU time in microseconds (RLIMIT_RTTIME, Linux only)

**Usage:**
```ini
[Service]
ExecStart=/usr/bin/myapp
LimitNOFILE=65536       # File descriptors
LimitCPU=300            # 5 minutes CPU time
LimitFSIZE=1073741824   # 1GB max file size
LimitCORE=0             # Disable core dumps
LimitNPROC=512          # Max 512 processes
# or
LimitNOFILE=infinity    # Remove limit (sets RLIM_INFINITY)
```

**Values:**
- Numeric: Specific limit (resource-dependent units)
- `infinity`: Unlimited (sets RLIM_INFINITY)
- Default: `-1` (not set, inherits system default)

**Common Use Cases:**
- Database servers: High `LimitNOFILE` for many connections
- Web servers: `LimitNOFILE` for concurrent requests
- Security: `LimitCORE=0` to disable core dumps
- Resource control: `LimitCPU`, `LimitAS`, `LimitNPROC` for containment

#### KillMode (Portable)

**Purpose:** Fine-grained control over process termination

**Implementation:**
- Uses `setsid()` to create process groups (POSIX standard)
- Uses `killpg()` for group termination (POSIX.1-2001/2008)
- Fallback to `kill()` for single process

**Platform Support:**
- Fully portable across all Unix-like systems
- Uses standard POSIX process groups

**Modes:**

1. **process** (default)
   - Only kill main service process
   - Child processes continue running
   - Conservative, compatible with forking services

2. **control-group**
   - Kill entire process group
   - Terminates service + all children
   - Most thorough cleanup

3. **mixed**
   - SIGTERM to main process
   - After 100ms delay: SIGKILL to entire process group
   - Graceful shutdown attempt, then forceful cleanup

4. **none**
   - Don't send any signals
   - Service must exit on its own
   - Useful for services that handle shutdown internally

**Usage:**
```ini
[Service]
ExecStart=/usr/bin/myapp
KillMode=control-group    # process, control-group, mixed, or none
```

**Technical Details:**
- All services run in their own process group via `setsid()`
- Process group ID == main service PID
- `killpg(pid, signal)` kills all processes in group
- Timeout handling: Wait `TimeoutStopSec`, then SIGKILL

**Comparison with systemd:**
- systemd uses cgroups for control-group mode (Linux-only)
- initd uses process groups (portable, POSIX standard)
- Functionally equivalent for most services
- initd's approach works on BSD, Hurd, and other Unix systems

#### NoNewPrivileges (Linux/FreeBSD only)

**Purpose:** Prevent privilege escalation via setuid/setgid on execve()

**Implementation:**
- Linux: Uses `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` (kernel 3.5+)
- FreeBSD: Uses `procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable)`
- Sets kernel flag preventing privilege gain on exec

**Platform Support:**
- Linux/FreeBSD: Full support
- OpenBSD: Not supported - OpenBSD's `pledge()` is fundamentally different, requiring application cooperation and capability-based restrictions rather than just blocking privilege elevation
- GNU Hurd: Not supported - no equivalent mechanism (CVE-2021-43411 race condition in setuid execve handling)

**Usage:**
```ini
[Service]
ExecStart=/usr/bin/myapp
NoNewPrivileges=true    # or false (default)
```

**Security Benefits:**
- Blocks setuid/setgid bits and file capabilities on execve()
- Once set, cannot be unset (inherited across fork/exec)
- Recommended for services that don't need to exec privileged binaries

## Targets

### Standard Targets

The reference implementation includes 17 targets:

**Core Boot Targets:**
- `sysinit.target` - System initialization
- `basic.target` - Basic system services
- `multi-user.target` - Full system, no GUI (runlevel 3)
- `graphical.target` - With GUI (runlevel 5)

**Recovery Targets:**
- `rescue.target` - Single-user mode (runlevel 1)
- `emergency.target` - Minimal recovery shell

**Shutdown Target:**
- `shutdown.target` - Shutdown ordering and conflicts

**Specialty Targets:**
- `network.target` - Network services ready
- `local-fs.target` - Local filesystems mounted
- `remote-fs.target` - Remote filesystems mounted
- `swap.target` - Swap enabled
- `sockets.target` - Socket units active
- `timers.target` - Timer units active
- `paths.target` - Path units active

**Default Symlink:**
- `default.target` → `multi-user.target` (or `graphical.target`)

### Compatibility Symlinks
- `runlevel1.target → rescue.target`
- `runlevel3.target → multi-user.target`
- `runlevel5.target → graphical.target`

**Note:** systemd's poweroff.target, reboot.target, and halt.target are handled
through the shutdown.target mechanism with implicit dependencies.

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
2. **Init starts initd-supervisor**
3. **Master forks worker (drops privs)**
4. **Worker scans unit directories**
5. **Worker parses unit files**
6. **Worker builds dependency graph**
7. **Worker starts default.target**
   - If default.target missing, falls back to emergency.target with warning
   - Resolves dependencies
   - Starts in topological order
   - Parallel where no ordering constraints
8. **Services running, system ready**

### Required Units

The following four units are required and must exist for proper system operation:

- **default.target** - Primary boot target (typically symlinked to multi-user.target or graphical.target). If missing, system falls back to emergency.target with a warning.
- **emergency.target** - Minimal recovery target, used when default.target is missing or boot fails
- **basic.target** - Foundation target that all services implicitly depend on (via DefaultDependencies=yes)
- **shutdown.target** - Shutdown ordering target. Services with DefaultDependencies=yes implicitly conflict with and order before this target.

### Failure Handling

**OnFailure= Directive (Implemented):**

Units can specify fallback units to activate when they fail using the `OnFailure=`
directive in the `[Unit]` section. This applies to both services and targets.

**Target Fallback Chain:**
- `sysinit.target` → OnFailure=emergency.target
- `basic.target` → OnFailure=rescue.target
- `multi-user.target` → OnFailure=basic.target
- `graphical.target` → OnFailure=multi-user.target

**Implementation:**
- `trigger_on_failure()` in supervisor-worker.c activates OnFailure units when any
  unit enters STATE_FAILED
- Called at all failure points: service exits with non-zero status, circular
  dependencies, failed required dependencies, and start_service() failures
- OnFailure units are started via `start_unit_recursive()`, allowing chained
  fallbacks and full dependency resolution

**Missing default.target Fallback:**
- If `default.target` is missing, supervisor falls back to `emergency.target` with
  a warning (hardcoded in supervisor-worker.c:1653-1658)

### Rescue/Emergency Log Dumping

When booting into rescue or emergency modes due to boot failures, buffered log messages may be the only diagnostic information available. If syslog never becomes available (e.g., sysinit.target fails before syslog starts), buffered logs remain in memory and are lost on shutdown.

**Solution:**
- `initctl dump-logs` command available for manual troubleshooting
- Dumps all buffered log entries to console with boot-time timestamps and priority levels
- Allows administrators to see what failed during early boot when in rescue/emergency shell
- Buffered logs include priority (ERROR, WARN, INFO, DEBUG) and unit names for context

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
- **Process groups** as the baseline supervision mechanism (shared with non-Linux platforms)
- **Cgroups v2** planned as an optional enhancement once process-group parity is complete
- **Namespaces** for isolation (optional)
- Full feature set in both modes

**BSD and Other Unix-like Systems**
- **Process groups** supervision (first-class path; ensures parity with Linux baseline)
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

### Installation Targets

**Core Installation:**
```bash
# Build the project
ninja -C build

# Install core components
DESTDIR=/staging/path ninja -C build install

# Install reference units (core system services with symlinks)
DESTDIR=/staging/path ninja -C build install-reference
```

**Optional Service Installation:**

The build system provides 51 individual install targets for optional BLFS services:

```bash
# Install specific optional services
DESTDIR=/staging/path ninja -C build install-acpid
DESTDIR=/staging/path ninja -C build install-samba
DESTDIR=/staging/path ninja -C build install-httpd
DESTDIR=/staging/path ninja -C build install-postgresql
# ... and 47 more

# Or install all optional services at once
DESTDIR=/staging/path ninja -C build install-everything
```

**Available optional services:**
acpid, dhcpcd-at, exim, git-daemon, gpm, haveged, httpd, iptables, kea-ctrl-agent, kea-ddns-server, kea-dhcp4-server, kea-dhcp6-server, krb5-kadmind, krb5-kdc, krb5-kpropd, lightdm, mariadb, named, nfs-client, nfs-server, nfsd, nftables, nmbd, ntpd, php-fpm, postfix, postgresql, proftpd, random-seed, rpc-idmapd, rpc-mountd, rpc-statd-notify, rpc-statd, rsyncd, rsync-at, rsyslog, samba, saslauthd, sendmail, slapd, sm-client, smbd, smbd-at, sshd, ssh-at, svnserve, syslog-ng, sysmond, unbound, vsftpd, winbindd

**Configuration File Protection:**

Optional install targets protect existing configuration files in `/etc/sysconfig/`:

- If config doesn't exist: installed as-is
- If config exists: new version installed with `.new` suffix
- On subsequent installs: `.new-1`, `.new-2`, `.new-3`, etc.

Example progression:
```
/etc/sysconfig/samba          (original, preserved)
/etc/sysconfig/samba.new      (first reinstall)
/etc/sysconfig/samba.new-1    (second reinstall)
/etc/sysconfig/samba.new-2    (third reinstall)
```

This allows administrators to:
- Compare new defaults with their customizations
- Merge changes manually using `diff`
- Never lose configuration customizations
- Audit changes between versions

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
│   │   ├── initd-supervisor.c         (master process)
│   │   └── initd-supervisor-worker.c  (worker process)
│   ├── timer-daemon/
│   │   ├── meson.build
│   │   ├── initd-timer.c              (master process)
│   │   ├── initd-timer-worker.c       (worker process)
│   │   ├── calendar.c
│   │   └── calendar.h
│   ├── socket-activator/
│   │   ├── meson.build
│   │   ├── initd-socket.c             (master process)
│   │   └── initd-socket-worker.c      (worker process)
│   ├── initctl/
│   │   ├── meson.build
│   │   └── initctl.c
│   └── common/
│       ├── meson.build
│       ├── ipc.c                      (supervisor master/worker IPC)
│       ├── ipc.h
│       ├── socket-ipc.c               (socket daemon IPC)
│       ├── socket-ipc.h
│       ├── timer-ipc.c                (timer daemon IPC)
│       ├── timer-ipc.h
│       ├── control.c                  (control protocol)
│       ├── control.h
│       ├── parser.c
│       ├── parser.h
│       ├── scanner.c
│       ├── scanner.h
│       ├── privileged-ops.c
│       ├── privileged-ops.h
│       ├── log.c
│       └── log.h
├── units/
│   ├── meson.build
│   ├── default.target
│   ├── multi-user.target
│   ├── basic.target
│   ├── sysinit.target
│   ├── reference/              (core system units)
│   │   ├── checkfs.service
│   │   ├── console.service
│   │   ├── getty@.service
│   │   └── ...
│   └── optional/               (BLFS optional services)
│       ├── meson.build
│       ├── acpid.service
│       ├── samba.service
│       ├── httpd.service
│       └── ...
├── sysconfig/
│   ├── meson.build
│   ├── reference/              (core system configs)
│   │   ├── console.conf
│   │   ├── createfiles.conf
│   │   ├── modules.conf
│   │   └── ...
│   └── optional/               (BLFS service configs)
│       ├── samba
│       ├── nfs-utils
│       ├── git-daemon
│       └── ...
├── scripts/
│   ├── meson.build
│   ├── journalctl
│   ├── ifup
│   ├── ifdown
│   ├── service-scripts/
│   │   ├── checkfs
│   │   ├── console
│   │   ├── createfiles
│   │   └── ...
│   └── network-services/
│       ├── dhcpcd
│       ├── static
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
│   ├── test-integration.c
│   ├── test-exec-lifecycle.c
│   ├── test-socket-ipc.c
│   ├── test-timer-ipc.c
│   ├── test-privileged-ops.c
│   └── units/                         (test-only unit files)
│       ├── test.service
│       ├── backup.service
│       ├── backup.timer
│       └── ...
├── analysis/
│   ├── meson.build
│   ├── meson-analyze-all.sh
│   ├── meson-cppcheck.sh
│   ├── meson-flawfinder.sh
│   ├── meson-scan-build.sh
│   ├── meson-sanitizers.sh
│   ├── meson-valgrind.sh
│   └── meson-shellcheck.sh
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
- Validates User/Group from unit files (privilege escalation prevention)
- Re-parses unit files and rebuilds ExecStart argv internally (ignores worker-supplied command data)
- Drops capabilities where possible
- Short-lived worker processes

**Supervisor Worker (unprivileged):**
- Bulk of code runs here
- No root privileges
- Limited system access
- Path security validation (TOCTOU prevention)
- Service registry with per-unit DoS prevention (collision-resistant restart tracker)
- Secure IPC with malformed input validation

**Services:**
- Run as specified User/Group
- Drop privileges before exec
- Isolated via cgroups/namespaces (Linux)

### Process Lifecycle

```
init (root, PID 1)
  └─> initd-supervisor (root)
      ├─> supervisor-worker (unprivileged)
      │   └─> manages service registry
      │       └─> enforces DoS prevention
      └─> service processes (root → drops to user)
          └─> tracked in service registry by PID
              dies → master notifies worker → registry updated
```

## Dependencies

### Runtime Dependencies
- libc
- syslog daemon (rsyslog, syslog-ng, etc.)

### Optional Dependencies
- Linux kernel with cgroup v2 support
- p11-kit (if using trust anchors)

### Build Dependencies
- C23-capable compiler (GCC 14+, Clang 18+)
- Meson
- Ninja
- pkg-config

### Commit Message Guidelines

Keep history easy to scan by using a consistent four-part structure. Wrap every
line at 80 characters maximum (72 preferred for the subject line) without
exceeding the limit. The only indentation should be the bullet list; all other
lines begin flush left. Leave a single blank line between the major summary
sentence and the `What Changed:` heading. Place the bullet list immediately
after the `What Changed:` line (no intervening blank line), and keep bullet
items sentence-case without trailing periods.

**Feature commits**
```
Feature: Short title describing the addition

Formerly, single wrapped sentence explaining the missing capability.

This commit single wrapped sentence summarising the solution.

What Changed:
  - bullet for the first change
  - bullet for the next change

Before presenting any commit message, explicitly confirm that every line
is ≤ 80 characters and state that the check passed.
```

**Bugfix commits**
```
Bugfix: Short title describing the fix

Formerly, single wrapped sentence describing the defect.

This commit single wrapped sentence summarising the fix.

What Changed:
  - bullets explaining the code/config updates
Security Benefits (optional):
  - single sentence when relevant
```

**Security commits**
```
Security: Short title describing the mitigation

Formerly, single wrapped sentence describing the risk.

This commit single wrapped sentence summarising the mitigation.

What Changed:
  - bullets describing code/config updates
Security Benefits:
  - bullets highlighting the security impact
```

Notes:
- Bullets use two spaces followed by `-` and a concise, present-tense clause.
- Omit the optional "Security Benefits" section when it does not apply.
- Do not mention updates to markdown documentation files (README.md,
  profile.md, tests/README.md) in the "What Changed" bullets - focus on code
  and configuration changes only.
- Configure `git config commit.template` (project or global) or a prepare-
  commit-msg hook to enforce the template automatically.

## Development Roadmap

### Phase 1: Minimal Boot ✅ COMPLETE
1. ✅ Init binary (PID 1, reaping)
2. ✅ Supervisor master/worker split with privilege separation
3. ✅ Basic unit file parser
4. ✅ Start simple services
5. ✅ Shutdown handling
6. ✅ Process groups (setsid, killpg) - POSIX portable

### Phase 2: Core Features & Security ✅ COMPLETE
1. ✅ Dependency resolution with cycle detection and recursion depth limits
2. ✅ Target support
3. ✅ Service restart/recovery (Restart= policies)
4. ✅ systemctl basic commands (initctl)
5. ✅ Logging integration (syslog with early boot buffering)
6. ✅ **Service registry** - prevents arbitrary kill() attacks with 256-service limit
7. ✅ **DoS prevention** - restart rate limiting (5 restarts/60s window, 1s min interval)
8. ✅ **IPC security** - proper serialization, no raw pointers, malformed input validation
9. ✅ **Privilege escalation prevention** - master validates User/Group from unit files
10. ✅ **TOCTOU and path traversal prevention** - realpath(), O_NOFOLLOW, symlink protection
11. ✅ **File descriptor leak prevention** - SOCK_CLOEXEC on all sockets
12. ✅ **Signal race hardening** - sigprocmask() during critical operations
13. ✅ **Orphaned process cleanup** - kill_remaining_processes() during shutdown
14. ✅ **KillMode support** - using process groups (control-group, process, mixed, none)

### Phase 3: Independent Daemons + Portable Supervision ✅ COMPLETE
1. ✅ Timer daemon (independent, cron replacement) — OnUnitInactiveSec reschedules and persists last-inactive timestamps
2. ✅ Socket activator daemon (independent, idle timeout, RuntimeMaxSec, supervisor adoption)
3. ✅ Daemon independence (separate control sockets, optional communication)
4. ✅ Full systemctl compatibility (command routing to daemons)
   - Added end-to-end integration tests exercising --user/--system routing
5. ✅ journalctl wrapper
6. ✅ Cross-platform process-group supervision parity (Linux/BSD/Hurd) with shared abstraction layer
7. ✅ Platform detection/build plumbing for shared code paths (headers, feature flags, CI coverage)
8. ✅ Shutdown/reboot/halt implementation with PID 1 vs standalone mode detection
9. ✅ Per-user daemon support with reboot persistence (independent of elogind)
10. ✅ **Target-based shutdown ordering**
    - Replaced simple shutdown_requested flag with shutdown.target isolation
    - Added implicit Conflicts=shutdown.target Before=shutdown.target for DefaultDependencies=yes
    - Proper ordering: normal services → early boot services (random-seed) → filesystem operations (swap, mountfs)
    - Full systemd unit compatibility for existing Conflicts/Before directives

#### TODO: Other systemd directives

[Service]
[Timer]

[Socket]
  Accept=
  Service=
  SocketUser=
  SocketGroup=
  SocketMode=
  Backlog=
  BindIPv6Only=
  ListenFIFO=
  ListenNetlink=
  ListenSequentialPacket=
  RemoveOnStop=
  MaxConnections=
  TriggerLimitBurst=
  TriggerLimitIntervalSec=
  PassCredentials=
  PassSecurity=
  FreeBind=
  ReusePort=
  KeepAlive=
  KeepAliveTimeSec=
  KeepAliveIntervalSec=
  KeepAliveProbes=
  NoDelay=
  DeferAcceptSec=
  PipeSize=
  Priority=
  ReceiveBuffer=
  SendBuffer=
  IPTOS=
  IPTTL=
  Mark=
  Transparent=

[Install]

### User-Mode Follow-ups
- ✅ Documented and tested per-user reboot persistence workflows

### Phase 4: Linux-Specific Enhancements (FUTURE)
1. ⬜ Cgroup v2 integration (Linux-only, parallel to process groups)
   - Process tracking (replaces kill(pid, 0) checks)
   - Memory/CPU limits
   - OOM handling
2. ⬜ Linux namespaces (already have PrivateTmp mount namespace)
3. ⬜ Seccomp filters (optional security hardening)

#### Design Constraints for Phases 1-3
To avoid writing ourselves into a corner, the following must be considered during early phases:

**Init Process (init.c)**
- ✅ Already isolated - only runs as PID 1
- No changes needed for standalone mode

**Supervisor Master**
- ✅ Already mode-agnostic (doesn't check PID)
- ✅ PID 1 detection via INITD_MODE environment variable
- 🚩 Consider extending PID 1 detection to support external init handoff (sysvinit/etc.)
- ✅ Conditional reboot() - uses reboot(2) in PID 1 mode, native commands in standalone
- ✅ Shared process-group abstraction (Phase 3 complete) - cgroups deferred to Phase 4
- 🚩 For user instances, join existing elogind user.slice if present instead of creating new initd subtree

**Supervisor Worker**
- ✅ Already unprivileged and mode-agnostic
- ✅ Process supervision via process groups (portable, POSIX-compliant)
- ✅ Platform-specific includes properly abstracted

**Control Protocol**
- ✅ Already Unix socket based - works in both modes
- ✅ Shutdown/reboot/halt commands implemented in initctl
- ✅ Standalone mode execs native shutdown commands (poweroff, reboot, halt)
- ✅ PID 1 mode sends requests through supervisor to init

**Unit File Parser**
- ✅ Already platform-agnostic
- No changes needed

### Pending Work / Known Gaps
- Harden calendar parser (`strtol` with overflow checks) and expand fuzz/edge-case tests.
- Audit remaining file handling for `FD_CLOEXEC`, TOCTOU-safe temp files, and consistent privilege drops.
- Optional: introduce versioned/authenticated IPC for future protocol evolution.

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
**27 test suites, 252 individual tests - all passing**

1. **calendar parser** - Calendar expression parsing
2. **unit file parser** - Unit file parsing & validation
3. **control protocol** - IPC protocol serialization
4. **socket activator** - Socket creation & activation
5. **IPC protocol** - Master/worker IPC communication with malformed input validation
6. **unit scanner** - Directory scanning & priority
7. **dependency resolution** - Unit dependency handling
8. **state machine** - Unit state transitions
9. **logging system** - Log buffering & syslog
10. **integration** - End-to-end workflows
11. **timer IPC protocol** - Timer daemon IPC communication
12. **socket IPC protocol** - Socket daemon IPC communication
13. **service features** - PrivateTmp, all Limit* directives (16 total), KillMode, RemainAfterExit, StandardInput/Output/Error parsing
14. **conditions and assertions** - POSIX-portable Condition*/Assert* directives (8 new + 11 Assert equivalents)
15. **Linux-only conditions** - Linux-specific Condition*/Assert* directives
16. **service registry** - DoS prevention and rate limiting (includes 62s timing test)
17. **timer inactivity notify** - OnUnitInactiveSec rescheduling
18. **socket worker** - Unix stream listeners, IdleTimeout, RuntimeMaxSec
19. **supervisor socket IPC** - CMD_SOCKET_ADOPT control path
20. **isolate closure** - Target isolation and dependency closure
21. **initctl routing** - Command routing to correct daemon sockets
22. **user persistence** - Per-user reboot persistence helpers
23. **offline enable/disable** (privileged) - Unit enable/disable without running daemons
24. **Exec lifecycle** (privileged) - ExecStartPre/Post/Stop/Reload execution
25. **privileged operations** (privileged) - Root-only operations (systemd conversion, symlinks)
26. **chroot confinement** (privileged) - RootDirectory= chroot jail functionality
27. **PrivateDevices security** (privileged) - Device node major/minor validation (prevents kernel memory exposure)

**Coverage:**
- ✅ Unit file parsing (all types)
- ✅ Dependency resolution (After, Before, Requires, Wants, Conflicts)
- ✅ State machine (all states and transitions)
- ✅ IPC protocol (supervisor master/worker, timer, socket daemons)
  - ✅ Malformed input validation (invalid types, oversized fields, many/large args)
- ✅ Control protocol (commands and serialization)
- ✅ Directory scanner (priority, filtering)
- ✅ Logging system (buffering, syslog)
- ✅ Socket activation
- ✅ Calendar expressions
- ✅ Service directives (PrivateTmp, all Limit* directives, KillMode parsing)
- ✅ Service registry (DoS prevention, rate limiting with real timing validation)
- ✅ Integration workflows
- ✅ Privileged operations (enable, disable, convert systemd units)

**Build and run tests:**
```bash
# Build all tests
ninja -C build

# Run all non-privileged tests (22 test suites)
ninja -C build test

# Run privileged tests (requires root - 5 test suites)
sudo ninja -C build test-privileged

# Run all tests with verbose output (using meson for individual control)
meson test -C build -v
```

**Privileged Test Suites (5 total):**
These tests validate critical functionality that requires root:

1. **offline enable/disable** - Unit enable/disable without running daemons
2. **Exec lifecycle** - ExecStartPre/Post/Stop/Reload execution paths
3. **privileged operations** - Converting systemd units, creating symlinks in system directories
4. **chroot confinement** - RootDirectory= chroot jail functionality
5. **PrivateDevices security** - Device node creation security (prevents kernel memory exposure)

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
ninja -C build analyze-all
```

**Individual analysis tools**:
```bash
# Static code analysis
ninja -C build analyze-cppcheck

# Security-focused static analysis
ninja -C build analyze-flawfinder

# Clang static analyzer
ninja -C build analyze-scan

# Runtime memory error detection
ninja -C build analyze-sanitizers

# Memory leak detection
ninja -C build analyze-valgrind

# Shell script static analysis
ninja -C build analyze-shellcheck
```

**Analysis results** are saved to `analysis-output/` with individual log files:
- `cppcheck.log` - Static analysis results
- `flawfinder.log` - Security analysis results
- `scan-build.log` - Clang analyzer results
- `sanitizers.log` - AddressSanitizer/UndefinedBehaviorSanitizer results
- `valgrind.log` - Memory leak detection results
- `shellcheck.log` - Shell script analysis results
- `analysis-summary.log` - Overall summary

**Tools included**:
- **cppcheck** - Comprehensive static code analysis
- **flawfinder** - Security vulnerability scanner
- **Clang scan-build** - Deep static analysis with clang
- **AddressSanitizer** - Runtime memory error detection
- **UndefinedBehaviorSanitizer** - Undefined behavior detection
- **LeakSanitizer** - Memory leak detection
- **Valgrind** - Comprehensive memory analysis
- **shellcheck** - Shell script static analysis

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
- Build supervisor master/worker next
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
UNITDIRS="/etc/initd/system /lib/initd/system /etc/systemd/system /lib/systemd/system"

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

**Note:** The project is now named `initd` and uses `/etc/initd/` and `/lib/initd/` paths.
