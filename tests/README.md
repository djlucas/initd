# initd Test Suite

## Overview

Automated tests for the initd init system components.

## Running Tests

```bash
# Build and run all tests (27 test suites, 267 individual tests; 5 marked privileged)
ninja -C build
ninja -C build test

# Run only non-privileged tests (22 test suites)
ninja -C build test --suite initd

# Run privileged tests (covers offline enable, Exec* lifecycle, privileged ops, chroot, PrivateDevices security)
sudo ninja -C build test-privileged

# Run specific test (using meson for individual tests)
meson test -C build "calendar parser"
meson test -C build "unit file parser"
meson test -C build "control protocol"
meson test -C build "socket activator"
meson test -C build "IPC protocol"
meson test -C build "unit scanner"
meson test -C build "dependency resolution"
meson test -C build "state machine"
meson test -C build "logging system"
meson test -C build "integration"
meson test -C build "timer IPC protocol"
meson test -C build "socket IPC protocol"
meson test -C build "timer inactivity notify"
meson test -C build "socket worker"
meson test -C build "supervisor socket IPC"
meson test -C build "service features"
meson test -C build "service registry"
meson test -C build "isolate closure"
meson test -C build "initctl routing"
meson test -C build "user persistence"
meson test -C build "offline enable/disable"  # Privileged suite
meson test -C build "Exec lifecycle"          # Privileged suite
meson test -C build "privileged operations"   # Privileged suite
meson test -C build "chroot confinement"      # Privileged suite
meson test -C build "PrivateDevices security" # Privileged suite

# Verbose output
meson test -C build -v

# Run tests in parallel
meson test -C build --num-processes 4
```

## Fuzzing (libFuzzer)

The analysis harness builds several libFuzzer targets for parser and protocol
surfaces. Clang with libFuzzer support is required.

```bash
# Build fuzzers (via analysis targets)
ninja -C build analyze-fuzz        # builds and launches all fuzzers

# Or run them individually
meson compile -C build fuzz-calendar
meson compile -C build fuzz-parser
meson compile -C build fuzz-control
meson compile -C build fuzz-ipc

# Execute the unified script manually (optional RUNS override)
analysis/fuzz/run-all-fuzzers.sh build 10000
```

## Test Coverage

### test-calendar
Tests the calendar expression parser for timer units:
- Shortcut validation (daily, hourly, weekly, etc.)
- Full format parsing (weekday, date, time)
- Next run calculation
- Invalid expression rejection

### test-parser
Tests the unit file parser:
- Basic service parsing
- Dependency resolution (After, Requires, Wants, BindsTo, PartOf)
- Service types (simple, forking, oneshot)
- Timer unit parsing (OnCalendar, OnBootSec, Persistent, RandomizedDelaySec, AccuracySec, Unit, FixedRandomDelay, RemainAfterElapse)
- Timer unit default values (AccuracySec defaults to 60 seconds, RemainAfterElapse defaults to true)
- Timer unit with multiple OnCalendar entries
- Timer unit with FixedRandomDelay
- Timer unit with RemainAfterElapse=false (one-shot timers)
- Environment variables
- ConditionPath* directive parsing with negation support
- StopWhenUnneeded and RefuseManualStart/Stop flags
- StartLimit* directives and RestartPrevent/Force exit status lists
- Install section extras (Also, Alias, DefaultInstance)
- Validation rules
- Provides= directive
- AllowIsolate= directive for target units
- DefaultDependencies= directive with implicit Conflicts/Before shutdown.target
- Socket Exec* lifecycle commands (ExecStartPre, ExecStartPost, ExecStopPost)
- Socket Accept= directive (yes/no/default)
- Socket TriggerLimit* directives (custom values and defaults)
- Socket FileDescriptorName= directive (custom and default values)
- Socket ListenFIFO= directive
- Socket ListenMessageQueue= and related directives (custom and default values)
- Socket PipeSize= directive with size suffixes (bytes, K, M, defaults)
- Socket ListenSpecial= and Writable= directives (writable, read-only, default)
- Socket Mark=, PassCredentials=, PassSecurity= (Linux-only directives)
- Socket BindIPv6Only=, NoDelay=, DeferAcceptSec=, Priority= directives (IPv6 values, defaults)
- Socket ListenSequentialPacket= directive (custom path, defaults)
- Socket MaxConnections= directive (custom value, default 64, unlimited)
- Socket SmackLabel=, SmackLabelIPIn=, SmackLabelIPOut= (SMACK labels, all three together, defaults, individual)

### test-control (10 tests)
Tests the control protocol:
- Request/response serialization
- Unit list serialization
- Empty list handling
- State/command string conversion
- Timer list serialization
- Socket list serialization
- Empty timer/socket list handling
- CMD_DUMP_LOGS command

### test-timer-notify
Validates timer inactivity notifications:
- Synthesizes in-memory timer units with UNIT_TEST hooks
- Calls CMD_NOTIFY_INACTIVE and checks rescheduling
- Confirms unrelated services do not affect timers
- Ensures OnUnitInactiveSec delays are applied exactly once

### test-socket
Tests the socket activator:
- Unix stream socket parsing
- TCP socket parsing
- UDP/datagram socket parsing
- Socket validation
- Unix socket creation/binding
- TCP socket creation/binding
- Socket accept mechanism
- FD duplication (socket passing)
- Idle timeout calculation

## Adding New Tests

1. Create `test-<name>.c` in this directory
2. Add to `meson.build`:
   ```meson
   test_name = executable('test-name', 'test-name.c', dependencies: common_dep)
   test('description', test_name)
   ```
3. Use the `TEST()` and `PASS()` macros for consistency

## Test Macros

```c
TEST("test description");
// ... test code with assert() ...
PASS();
```

### test-ipc (15 tests)
Tests master/worker IPC communication with comprehensive edge case coverage:

**Normal operations (8 tests):**
- Request serialization
- Response serialization
- Stop service requests
- Error responses
- Service exited notifications
- Shutdown complete requests
- Exec args serialization
- Empty exec args handling

**Malformed input validation (7 tests):**
- Invalid request type validation (rejects out-of-range types)
- Invalid response type validation (rejects out-of-range types)
- Oversized unit_name handling (256+ chars)
- Oversized paths handling (unit_path, exec_path 1024+ chars)
- Oversized error_msg handling (256+ chars)
- Many exec_args (100 arguments)
- Oversized individual exec_arg (4999 chars)

These tests verify the IPC protocol correctly:
- Validates enum types on receive (DoS prevention)
- Truncates oversized fields safely with null termination
- Handles extreme but valid inputs without corruption
- Prevents buffer overflows with defensive bounds checking

### test-scanner (10 tests)
Tests unit directory scanning:
- Empty directory handling
- Single service scanning
- Unit file priority
- Multiple unit types
- Invalid unit file skipping
- Non-unit file filtering
- Systemd directory filtering
- Unit list linking
- Duplicate unit name handling
- Free units cleanup

### test-dependency (12 tests)
Tests dependency graph resolution:
- After/Before dependency ordering
- Requires/Wants dependencies
- Conflicts handling
- Circular dependency detection
- Dependency chain resolution
- Multiple dependencies per unit
- Target unit dependencies
- Missing dependency handling
- OnFailure= dependency handling
- Multiple OnFailure= units

### test-state (11 tests)
Tests service state transitions:
- Valid state transitions
- Failure state handling
- Simple/forking/oneshot service lifecycles
- Restart policies (always, on-failure, no)
- Timer/socket/target unit states

### test-log (13 tests)
Tests logging system:
- Log initialization
- Early boot log buffering
- Syslog ready notification
- Direct logging to syslog
- Different log priorities
- Log buffer overflow handling
- Logging with NULL unit name
- Syslog detection
- Log message formatting
- Multiple init/close cycles
- Dump empty log buffer (log_dump_buffer with no messages)
- Dump log buffer with messages (verifies format, timestamps, priorities)
- Dump log buffer after syslog ready (tests empty buffer handling)

### test-integration (11 tests)
Tests end-to-end workflows:
- Parse and validate integration
- State/command to string conversion
- Unit type detection from filename
- Dependency/install/environment parsing
- Service types and restart policies
- Timer unit integration
- OnFailure= directive parsing

### test-exec-lifecycle (2 tests)
Exercises the privileged supervisor request handler directly:
- Validates ExecStartPre/Post/Stop/Reload execution via the master with shared path checks, environment setup, and UID/GID handling
- Verifies reload requests fail with `ENOTSUP` when `ExecReload=` is absent

**Note:** Lives in the privileged suite to cover master-only code paths, but does not require root; it uses `/tmp` fixtures and standard user binaries (`sleep`, `touch`).

### test-privileged-ops (6 tests)
Tests privileged operations that require root:
- Converting systemd unit files to initd format
- Enabling units with WantedBy directive
- Enabling units with RequiredBy directive
- Disabling units
- Checking if units are enabled
- Handling units without Install sections

**Note:** This test requires root privileges because it:
- Creates files in system directories (`/lib/initd/system/`, `/etc/initd/system/`)
- Creates symlinks for unit dependencies (`*.wants`, `*.requires`)
- Tests real-world privilege separation scenarios

When run without root, the test properly skips with exit code 77.

Run with: `sudo meson test -C build --suite privileged`

### test-timer-ipc (5 tests)
Tests timer daemon IPC communication:
- Timer add request serialization
- Timer remove request serialization
- Timer list request serialization
- Timer status request serialization
- Timer activation notification serialization

### test-socket-ipc (7 tests)
Tests socket activator IPC communication:
- Socket enable/disable/convert request serialization
- Socket chown request serialization (SocketUser=/SocketGroup= support)
- Socket chown request with numeric UIDs/GIDs
- OK/error response serialization
- Converted unit response with path
- Multiple request/response roundtrips
- Socket activation notification serialization

### test-service-features (36 tests)
Tests service directive parsing:
- **PrivateTmp parsing** - Tests true/false/yes/1 parsing
- **LimitNOFILE parsing** - Tests numeric values, "infinity", and default (-1)
- **All Limit* directives parsing** - Tests all 15 resource limit directives with numeric values, "infinity", and defaults
- **KillMode parsing** - Tests all four modes (process, control-group, mixed, none) and default
- **Combined features** - Tests all three directives together in one service file
- **RemainAfterExit parsing** - Tests yes/no/true/false parsing and default behavior
- **StandardInput parsing** - Tests null, tty, tty-force, and default (inherit) modes
- **StandardOutput parsing** - Tests null, tty, inherit modes
- **StandardError parsing** - Tests null, tty modes
- **TTYPath parsing** - Tests /dev/console and /dev/tty1 paths
- **Combined StandardInput/Output/Error** - Tests all stdio directives with TTYPath together
- **StandardInput/Output/Error=file:path** - Tests file redirection modes
- **StandardInput/Output/Error=socket** - Tests socket activation mode
- **StandardInput=data with StandardInputText=** - Tests embedded text input
- **StandardInput=data with StandardInputData=** - Tests base64-encoded binary input
- **Syslog directives** - Tests SyslogIdentifier, SyslogFacility, SyslogLevel, SyslogLevelPrefix
- **UMask directive** - Tests octal umask values (0022, 0077)
- **NoNewPrivileges directive** - Tests true/false/yes parsing for privilege escalation prevention
- **RootDirectory directive** - Tests absolute path parsing for chroot jails
- **MemoryLimit directive** - Tests numeric values, "infinity", and default (-1)
- **RestrictSUIDSGID directive** - Tests yes/no/true/false parsing for suid/sgid restriction
- **RestartMaxDelaySec directive** - Tests numeric values and default (0 = no exponential backoff)
- **TimeoutAbortSec directive** - Tests numeric values and default (0 = use TimeoutStopSec)
- **TimeoutStartFailureMode directive** - Tests terminate/abort/kill modes and default (terminate)
- **ProtectSystem directive** - Tests no/yes/full/strict modes and default (no)
- **ProtectHome directive** - Tests no/yes/read-only/tmpfs modes and default (no)
- **PrivateDevices directive** - Tests yes/no parsing and default (false)
- **ProtectKernelTunables directive** - Tests yes/no parsing and default (false)
- **ProtectControlGroups directive** - Tests yes/no parsing and default (false)
- **MountFlags directive** - Tests shared/slave/private modes and default (private)
- **DynamicUser directive** - Tests yes/no/true/false parsing and default (false)
- **DeviceAllow directive** - Tests device path and permission parsing (r/w/m), multiple entries, and default (empty)
- **RootImage directive** - Tests absolute path parsing and default (empty)
- **LogLevelMax directive** - Tests named levels, numeric levels, and default (-1)
- **Capability directives** - Tests CapabilityBoundingSet and AmbientCapabilities parsing with single/multiple capabilities

**Key features tested:**
- PrivateTmp=true|false (default: false)
- LimitNOFILE=N|infinity (default: -1 = not set)
- LimitCPU / LimitFSIZE / LimitDATA / LimitSTACK / LimitCORE / LimitRSS / LimitAS / LimitNPROC / LimitMEMLOCK / LimitLOCKS / LimitSIGPENDING / LimitMSGQUEUE / LimitNICE / LimitRTPRIO / LimitRTTIME (all support N|infinity, default: -1)
- KillMode=process|control-group|mixed|none (default: process)
- RemainAfterExit=yes|no (default: false)
- StandardInput=null|tty|tty-force|inherit|file:path|socket|data (default: inherit)
- StandardOutput=null|tty|inherit|file:path|socket (default: inherit)
- StandardError=null|tty|inherit|file:path|socket (default: inherit)
- StandardInputText= / StandardInputData= - embed literal input data
- TTYPath=/dev/console (or other TTY device path)
- SyslogIdentifier= / SyslogFacility= / SyslogLevel= / SyslogLevelPrefix=
- UMask=0022 (octal file creation mask)
- NoNewPrivileges=true|false (default: false)
- RootDirectory=/path/to/chroot (chroot jail path)

### test-conditions (14 tests)
Tests Condition*/Assert* directive parsing:

**POSIX-portable conditions (8 tests):**
- **ConditionFileNotEmpty** - Tests file non-empty check parsing
- **ConditionUser** - Tests user/UID matching (supports numeric UID, username, @system)
- **ConditionGroup** - Tests group/GID matching (supports numeric GID, group name)
- **ConditionHost** - Tests hostname matching
- **ConditionArchitecture** - Tests CPU architecture matching (x86-64, arm64, etc.)
- **ConditionMemory** - Tests memory threshold with K/M/G suffixes
- **ConditionCPUs** - Tests CPU count with comparison operators (>=2, <4, etc.)
- **ConditionEnvironment** - Tests environment variable existence and value matching

**Platform-specific conditions (4 tests):**
- **ConditionVirtualization** - Tests VM/container detection (kvm, docker, vm, etc.)
- **ConditionACPower** - Tests AC power status (true/false)
- **ConditionOSRelease** - Tests /etc/os-release key=value matching (ID=debian, VERSION_ID=12)
- **ConditionKernelVersion** - Tests kernel version comparison (>=5.10, <6.0)

**General tests (2 tests):**
- **Assert* directives** - Tests all Assert equivalents (loud failures vs silent skips)
- **Negation support** - Tests ! prefix for inverted conditions/assertions

**Key features tested:**
- 8 POSIX-portable Condition directives + 8 Assert equivalents
- 4 platform-specific Condition directives + 4 Assert equivalents
- 8 existing path-based Assert* equivalents
- Negation with ! prefix
- is_assert flag distinguishes behavior (LOG_ERR+STATE_FAILED vs LOG_INFO+skip)
- Platform detection using Linux /sys and /proc interfaces

### test-linux-conditions (13 tests)
Tests Linux-only Condition*/Assert* directive parsing:

**Linux-only conditions (13 tests):**
- **ConditionKernelCommandLine** - Tests /proc/cmdline keyword matching
- **ConditionKernelModuleLoaded** - Tests kernel module detection (/proc/modules, /sys/module/)
- **ConditionSecurity** - Tests LSM detection (SELinux, AppArmor, SMACK, IMA, TPM2)
- **ConditionCapability** - Tests Linux capability checks (simplified to root check)
- **ConditionControlGroupController** - Tests cgroup v1/v2 controller availability
- **ConditionMemoryPressure** - Tests PSI memory pressure detection (/proc/pressure/memory)
- **ConditionCPUPressure** - Tests PSI CPU pressure detection (/proc/pressure/cpu)
- **ConditionIOPressure** - Tests PSI I/O pressure detection (/proc/pressure/io)
- **ConditionPathIsEncrypted** - Tests dm-crypt/LUKS detection via /sys/block/dm-*/dm/name
- **ConditionFirmware** - Tests firmware type detection (UEFI vs device-tree)
- **ConditionCPUFeature** - Tests CPU feature flags from /proc/cpuinfo
- **ConditionCredential** - Tests systemd credential system (/run/credentials/)
- **ConditionNeedsUpdate** - Tests systemd update markers (/etc/.updated)

**Key features tested:**
- 16 Linux-only Condition directives + 16 Assert equivalents (32 total)
- All directives parse correctly and store in conditions array
- Non-Linux platforms return false with LOG_WARNING
- Platform guards with #ifdef __linux__ for Linux-specific detection
- /proc and /sys filesystem parsing (cmdline, modules, pressure/, cpuinfo)
- Device-mapper encryption detection
- Firmware type detection (UEFI vs device-tree)
- Security module detection (SELinux, AppArmor, SMACK, IMA, TPM2)
- Cgroup controller detection (v1 and v2)

### test-service-registry (5 tests)
Tests service registry and DoS prevention mechanisms:
- **Lookup by name** - Tests service registration and name-based lookup
- **Registry capacity** - Tests MAX_SERVICES limit (256 services)
- **Restart rate limiting** - Tests minimum restart interval (1 second)
- **Restart window limit** - Tests sliding window rate limiting (5 restarts per 60 seconds)
- **Different services restart tracking** - Tests independent rate limiting per service

**DoS Prevention Features:**
- Service registry with 256-service hard limit
- Minimum 1-second interval between restart attempts
- Sliding 60-second window limiting restarts to 5 per service
- Independent tracking for each service
- Uses CLOCK_MONOTONIC for immunity to system clock changes

**Note:** The restart window test sleeps for ~16 seconds total (4 restarts × 4s).
Test runs in 22 seconds, down from 81 seconds after optimization.

### test-socket-worker
Uses UNIT_TEST hooks in the socket worker to verify:
- Unix stream listeners bind successfully
- IdleTimeout kills idle services exactly once
- RuntimeMaxSec enforcement triggers as expected

### test-supervisor-socket (supervisor socket IPC)
Exercises the supervisor/worker control path:
- Sends `CMD_SOCKET_ADOPT` over the control socket
- Confirms the supervisor marks services active or inactive accordingly

### test-isolate (isolate closure)
Tests the isolate command and dependency closure:
- Validates target isolation stops services not wanted by the target
- Verifies dependency closure calculation for target isolation
- Confirms services required by the target remain running

### test-initctl-routing (initctl routing)
Validates `initctl` command routing logic:
- Verifies service, timer, and socket commands connect to the correct daemon sockets
- Confirms `--user` scope targets the per-user runtime directory and sockets
- Tests routing based on unit type (.service, .timer, .socket)

### test-user-persistence (user persistence)
Checks per-user reboot-persistence helpers:
- Exercises `initctl user enable/disable/status` logic in a sandboxed environment
- Verifies config files under `~/.config/initd/` and marker files in `/etc/initd/users-enabled/`
- Validates user daemon configuration persistence across reboots

### test-offline-enable (offline enable/disable) - PRIVILEGED
Tests offline unit enable/disable without running daemons:
- Validates enabling units when supervisor is not running
- Tests symlink creation in .wants and .requires directories
- Confirms disable removes symlinks correctly
- Verifies WantedBy and RequiredBy handling without IPC

**Note:** This test requires root privileges to create symlinks in system directories.

Run with: `sudo meson test -C build --suite privileged`

### test-chroot (chroot confinement) - PRIVILEGED
Tests RootDirectory= chroot jail functionality:
- Validates chroot actually confines processes to directory tree
- Tests file creation inside chroot
- Verifies chroot is called before dropping privileges
- Confirms processes cannot access files outside the jail

**Note:** This test requires root privileges because chroot() system call requires root.

Run with: `sudo meson test -C build --suite privileged`

### test-private-devices (PrivateDevices security) - PRIVILEGED
Regression test for PrivateDevices device node security vulnerabilities (3 tests):
- Verifies device nodes created with correct major/minor numbers (not sequential)
- Validates /dev/null is (1,3) not (1,0) to prevent /dev/mem exposure
- Confirms dangerous devices (/dev/mem, /dev/kmem, /dev/port) are not created
- Tests device node permissions are appropriate (0666 for null/zero/full/tty, 0644 for random/urandom)
- Detects the old sequential-minor bug that exposed kernel memory

**Security Impact:**
The old implementation used sequential minor numbers starting from 0, which created:
- `/dev/null` as (1,0) - actually /dev/mem (raw kernel memory)
- `/dev/zero` as (1,1) - actually /dev/kmem (kernel virtual memory)
- All other devices shifted incorrectly

With world-writable 0666 permissions, this gave sandboxed services raw access to kernel memory.

**Note:** This test requires root privileges to create device nodes with mknod().

Run with: `sudo meson test -C build --suite privileged`

## Test Statistics

**Total: 27 test suites, 252 individual tests - all passing ✅**

**Regular tests:** 22 suites (no root required)
**Privileged tests:** 5 suites (offline enable/disable, Exec lifecycle, privileged operations, chroot confinement, PrivateDevices security)

## CI Integration

Tests are designed to run in CI environments:
- Most tests require no root privileges
- Privileged tests properly skip when not root (exit code 77)
- No permanent system modification
- Fast execution (< 1 second per test, except service-registry with 62s timing test)
- Clear pass/fail output

**Recommended CI workflow:**
```yaml
- name: Build project
  run: ninja -C build

- name: Run regular tests
  run: ninja -C build test

- name: Run privileged tests
  run: sudo ninja -C build test-privileged
  # or: allow skip if running in unprivileged container
```
