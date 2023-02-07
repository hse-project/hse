/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSETTP_FORMAT_H
#define HSETTP_FORMAT_H

#include <stdbool.h>
#include <stddef.h>

enum format {
    FORMAT_INVALID,
    FORMAT_JSON,
    FORMAT_TABULAR,
    FORMAT_PLAIN,
};

enum format
format_from_string(const char *format);

int
format_parse_tabular(const char *format, size_t ncolumns, const char **headers, bool *enabled);

const char *
format_to_string(enum format format);

#endif
