# initd Test Suite

## Overview

Automated tests for the initd init system components.

## Running Tests

```bash
# Build and run all tests (13 tests, 1 will be skipped without root)
meson compile -C build
meson test -C build

# Run only non-privileged tests (12 tests)
meson test -C build --no-suite privileged

# Run privileged tests (requires root)
sudo meson test -C build --suite privileged

# Run specific test
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
meson test -C build "privileged operations"  # Requires root

# Verbose output
meson test -C build -v

# Run tests in parallel
meson test -C build --num-processes 4
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

### test-ipc (6 tests)
Tests master/slave IPC communication:
- Request serialization
- Response serialization
- Stop service requests
- Error responses
- Service exited notifications
- Shutdown complete requests

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

## Test Statistics

**Total: 11 test suites, 89 individual tests - all passing ✅**

**Regular tests:** 10 suites, 83 tests (no root required)
**Privileged tests:** 1 suite, 6 tests (requires root)

## CI Integration

Tests are designed to run in CI environments:
- Most tests require no root privileges
- Privileged tests properly skip when not root (exit code 77)
- No permanent system modification
- Fast execution (< 1 second per test)
- Clear pass/fail output

**Recommended CI workflow:**
```yaml
- name: Run regular tests
  run: meson test -C build --no-suite privileged

- name: Run privileged tests
  run: sudo meson test -C build --suite privileged
  # or: allow skip if running in unprivileged container
```
