/* parser.h - Unit file parser interface
 *
 * Copyright (c) 2025 DJ Lucas
 * SPDX-License-Identifier: MIT
 */

#ifndef PARSER_H
#define PARSER_H

#include "unit.h"

/* Parse a unit file from path */
int parse_unit_file(const char *path, struct unit_file *unit);

/* Free resources allocated for unit file */
void free_unit_file(struct unit_file *unit);

/* Validate unit file (basic checks) */
int validate_unit_file(const struct unit_file *unit);

#endif /* PARSER_H */
