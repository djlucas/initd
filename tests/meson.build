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
  ['test-privileged-ops.c', '../src/supervisor/service-registry.c'],
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

test_service_features = executable(
  'test-service-features',
  'test-service-features.c',
  dependencies: common_dep
)

test_service_registry = executable(
  'test-service-registry',
  ['test-service-registry.c', '../src/supervisor/service-registry.c'],
  dependencies: common_dep,
  c_args: ['-DUNIT_TEST']
)

test_socket_worker = executable(
  'test-socket-worker',
  [
    'test-socket-worker.c',
    '../src/socket-activator/initd-socket-worker.c',
  ],
  dependencies: [common_dep, socket_ipc_dep],
  c_args: ['-DUNIT_TEST']
)

test_timer_notify = executable(
  'test-timer-notify',
  [
    'test-timer-notify.c',
    '../src/timer-daemon/initd-timer-worker.c',
    '../src/timer-daemon/calendar.c',
  ],
  dependencies: [common_dep, privileged_ops_dep, timer_ipc_dep],
  c_args: ['-DUNIT_TEST']
)

test_exec_lifecycle = executable(
  'test-exec-lifecycle',
  [
    'test-exec-lifecycle.c',
    '../src/supervisor/initd-supervisor.c',
    '../src/supervisor/process-tracking.c',
    '../src/supervisor/service-registry.c',
  ],
  dependencies: [common_dep, privileged_ops_dep],
  c_args: ['-DUNIT_TEST']
)

test_supervisor_socket = executable(
  'test-supervisor-socket',
  [
    'test-supervisor-socket.c',
    '../src/supervisor/initd-supervisor-worker.c',
  ],
  dependencies: [common_dep, privileged_ops_dep],
  c_args: ['-DUNIT_TEST']
)

test_isolate = executable(
  'test-isolate',
  [
    'test-isolate.c',
    '../src/supervisor/initd-supervisor-worker.c',
  ],
  dependencies: common_dep,
  c_args: ['-DUNIT_TEST']
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
test('service features', test_service_features)
test('service registry', test_service_registry, timeout: 90)  # DoS tests include 62s sleep
test('socket worker', test_socket_worker)
test('Exec lifecycle', test_exec_lifecycle, suite: 'privileged')
test('isolate closure', test_isolate)
test('supervisor socket IPC', test_supervisor_socket)
test('timer inactivity notify', test_timer_notify)

cc = meson.get_compiler('c')

initctl_route_lib = static_library(
  'initctl-route-lib',
  '../src/initctl/initctl.c',
  dependencies: [common_dep, privileged_ops_dep],
  c_args: [
    '-Dmain=initd_test_initctl_main',
    '-DUSER_MARKER_DIR="/tmp/initd-user-persist-markers"',
    '-DINITD_RUNTIME_DEFAULT="/tmp/initd-routing-system"',
  ],
)

initctl_reboot_lib = static_library(
  'initctl-reboot-lib',
  '../src/initctl/initctl.c',
  dependencies: [common_dep, privileged_ops_dep],
  c_args: [
    '-Dmain=initd_test_initctl_main',
    '-DUSER_MARKER_DIR="/tmp/initd-user-persist-markers"',
    '-Dgetpwnam=initctl_test_getpwnam',
    '-Dgeteuid=initctl_test_geteuid',
    '-Dgetuid=initctl_test_getuid',
    '-Dchown=initctl_test_chown',
    '-Dfchown=initctl_test_fchown',
  ],
)

test_initctl_routing = executable(
  'test-initctl-routing',
  [
    'test-initctl-routing.c',
  ],
  dependencies: common_dep,
  link_with: initctl_route_lib,
)

test('initctl routing', test_initctl_routing)

test_user_persistence = executable(
  'test-user-persistence',
  [
    'test-user-persistence.c',
  ],
  dependencies: common_dep,
  link_with: initctl_reboot_lib,
)

test('user persistence', test_user_persistence)

test_offline_enable = executable(
  'test-offline-enable',
  'test-offline-enable.c',
  dependencies: [common_dep, privileged_ops_dep],
  link_with: initctl_route_lib,
)

test('offline enable/disable', test_offline_enable, suite: 'privileged')

# Privileged tests - run separately with: meson test --suite privileged
test('privileged operations', test_privileged_ops, suite: 'privileged')

# Create a ninja target for privileged tests
bash = find_program('bash')
run_target('test-privileged',
  command: [bash, '-c', 'cd "$MESON_BUILD_ROOT" && meson test --suite initd:privileged']
)
