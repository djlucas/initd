/* process-tracking.c - POSIX process group helpers
 *
 * Abstracts the basic process-group management used by the supervisor so
 * that future platform-specific implementations (e.g., cgroups on Linux)
 * can swap in alternative tracking without touching the higher layers.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>

#if defined(_WIN32)
#error "process_tracking not implemented for Windows"
#endif

#include "process-tracking.h"

int process_tracking_setup_child(void) {
#if defined(HAVE_SETSID) || !defined(__APPLE__)
    if (setsid() < 0) {
        return -1;
    }
#endif
    return 0;
}

int process_tracking_signal_process(pid_t pid, int sig) {
    if (kill(pid, sig) < 0) {
        return -1;
    }
    return 0;
}

int process_tracking_signal_group(pid_t pgid, int sig) {
    if (killpg(pgid, sig) < 0) {
        return -1;
    }
    return 0;
}
