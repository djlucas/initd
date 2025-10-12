/* privileged-ops.h - Privileged operations for daemons
 *
 * Operations that require root privileges (file writes, symlink creation)
 * Only linked into privileged daemon processes, NOT workers
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef PRIVILEGED_OPS_H
#define PRIVILEGED_OPS_H

#include <stdbool.h>
#include "unit.h"

/* Convert systemd unit to initd by copying to /lib/initd/system */
int convert_systemd_unit(struct unit_file *unit);

/* Enable a unit (create symlinks in target wants directories) */
int enable_unit(struct unit_file *unit);

/* Disable a unit (remove symlinks) */
int disable_unit(struct unit_file *unit);

/* Check if unit is enabled */
bool is_unit_enabled(struct unit_file *unit);

/* Setup service environment (PrivateTmp, LimitNOFILE, etc.) before exec */
int setup_service_environment(const struct service_section *service);

#endif /* PRIVILEGED_OPS_H */
