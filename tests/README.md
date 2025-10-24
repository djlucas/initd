# initd Test Suite

## Overview

Automated tests for the initd init system components.

## Running Tests

```bash
# Build and run all tests (23 test suites; 3 marked privileged)
ninja -C build
ninja -C build test

# Run only non-privileged tests (20 test suites)
ninja -C build test --suite initd

# Run privileged tests (covers offline enable, Exec* lifecycle, and privileged ops)
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
- Dependency resolution (After, Requires, Wants)
- Service types (simple, forking, oneshot)
- Timer unit parsing
- Environment variables
- Validation rules
- Provides= directive

### test-control
Tests the control protocol:
- Request/response serialization
- Unit list serialization
- Empty list handling
- State/command string conversion
- Socket communication

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

### test-dependency (10 tests)
Tests dependency graph resolution:
- After/Before dependency ordering
- Requires/Wants dependencies
- Conflicts handling
- Circular dependency detection
- Dependency chain resolution
- Multiple dependencies per unit
- Target unit dependencies
- Missing dependency handling

### test-state (11 tests)
Tests service state transitions:
- Valid state transitions
- Failure state handling
- Simple/forking/oneshot service lifecycles
- Restart policies (always, on-failure, no)
- Timer/socket/target unit states

### test-log (10 tests)
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

### test-integration (10 tests)
Tests end-to-end workflows:
- Parse and validate integration
- State/command to string conversion
- Unit type detection from filename
- Dependency/install/environment parsing
- Service types and restart policies
- Timer unit integration

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

### test-socket-ipc (5 tests)
Tests socket activator IPC communication:
- Socket add request serialization
- Socket remove request serialization
- Socket list request serialization
- Socket status request serialization
- Socket activation notification serialization

### test-service-features (4 tests)
Tests service directive parsing:
- **PrivateTmp parsing** - Tests true/false/yes/1 parsing
- **LimitNOFILE parsing** - Tests numeric values, "infinity", and default (-1)
- **KillMode parsing** - Tests all four modes (process, control-group, mixed, none) and default
- **Combined features** - Tests all three directives together in one service file

**Key features tested:**
- PrivateTmp=true|false (default: false)
- LimitNOFILE=N|infinity (default: -1 = not set)
- KillMode=process|control-group|mixed|none (default: process)

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

**Note:** The restart window test includes a 62-second sleep to validate
the sliding time window. The test displays a user-friendly notice during
this delay. Test timeout is set to 90 seconds.

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

## Test Statistics

**Total: 23 test suites - all passing ✅**

**Regular tests:** 20 suites (no root required)
**Privileged tests:** 3 suites (offline enable/disable, Exec lifecycle, privileged operations)

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
