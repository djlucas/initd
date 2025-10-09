/* scanner.h - Unit directory scanner interface
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "unit.h"

/* Scan all unit directories and load unit files */
int scan_unit_directories(struct unit_file ***units_out, int *count_out);

/* Scan unit directories with flag to include/exclude systemd dirs */
int scan_unit_directories_filtered(struct unit_file ***units_out, int *count_out, int include_systemd);

/* Free all loaded units */
void free_units(struct unit_file **units, int count);

#endif /* SCANNER_H */
