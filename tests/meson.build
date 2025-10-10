test_calendar = executable(
  'test-calendar',
  ['test-calendar.c', '../src/timer-daemon/calendar.c'],
  dependencies: common_dep
)

test_parser = executable(
  'test-parser',
  'test-parser.c',
  dependencies: common_dep
)

test_control = executable(
  'test-control',
  'test-control.c',
  dependencies: common_dep
)

test_socket = executable(
  'test-socket',
  'test-socket.c',
  dependencies: common_dep
)

test_ipc = executable(
  'test-ipc',
  'test-ipc.c',
  dependencies: common_dep
)

test_scanner = executable(
  'test-scanner',
  'test-scanner.c',
  dependencies: common_dep
)

test_dependency = executable(
  'test-dependency',
  'test-dependency.c',
  dependencies: common_dep
)

test_state = executable(
  'test-state',
  'test-state.c',
  dependencies: common_dep
)

test_log = executable(
  'test-log',
  'test-log.c',
  dependencies: common_dep
)

test_integration = executable(
  'test-integration',
  'test-integration.c',
  dependencies: common_dep
)

test_privileged_ops = executable(
  'test-privileged-ops',
  'test-privileged-ops.c',
  dependencies: [common_dep, privileged_ops_dep]
)

test_timer_ipc = executable(
  'test-timer-ipc',
  'test-timer-ipc.c',
  dependencies: [common_dep, timer_ipc_dep]
)

test_socket_ipc = executable(
  'test-socket-ipc',
  'test-socket-ipc.c',
  dependencies: [common_dep, socket_ipc_dep]
)

test('calendar parser', test_calendar)
test('unit file parser', test_parser)
test('control protocol', test_control)
test('socket activator', test_socket)
test('IPC protocol', test_ipc)
test('unit scanner', test_scanner)
test('dependency resolution', test_dependency)
test('state machine', test_state)
test('logging system', test_log)
test('integration', test_integration)
test('timer IPC protocol', test_timer_ipc)
test('socket IPC protocol', test_socket_ipc)

# Privileged tests - run separately with: meson test --suite privileged
test('privileged operations', test_privileged_ops, suite: 'privileged')
