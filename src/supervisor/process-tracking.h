/* process-tracking.h - Platform abstraction for service process groups
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef PROCESS_TRACKING_H
#define PROCESS_TRACKING_H

#include <sys/types.h>

/* Called in the service child process before exec() to establish an
 * isolated process group/session. Returns 0 on success, -1 on failure. */
int process_tracking_setup_child(void);

/* Send a signal to a single process. Wrapper to allow platform-specific
 * implementations. Returns 0 on success, -1 on failure (errno set). */
int process_tracking_signal_process(pid_t pid, int sig);

/* Send a signal to a process group. Returns 0 on success, -1 on failure. */
int process_tracking_signal_group(pid_t pgid, int sig);

#endif /* PROCESS_TRACKING_H */
