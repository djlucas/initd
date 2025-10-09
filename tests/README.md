# initd Test Suite

## Overview

Automated tests for the initd init system components.

## Running Tests

```bash
# Build and run all tests
meson test -C build

# Run specific test
meson test -C build test-calendar
meson test -C build test-parser
meson test -C build test-control
meson test -C build test-socket

# Verbose output
meson test -C build --verbose

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

## Future Tests

- **test-dependency** - Dependency graph resolution
- **test-scanner** - Unit directory scanning
- **test-ipc** - Master/slave IPC communication
- **test-state** - Service state transitions
- **test-enable** - Enable/disable symlink management
- **test-integration** - End-to-end system tests

## CI Integration

Tests are designed to run in CI environments:
- No root privileges required
- No system modification
- Fast execution (< 1 second per test)
- Clear pass/fail output
