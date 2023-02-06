/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_CLI_TPRINT_H
#define HSE_CLI_TPRINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <hse/error/merr.h>

enum tprint_justify {
    TP_JUSTIFY_LEFT,
    TP_JUSTIFY_RIGHT,
};

merr_t
tprint(FILE *fp, size_t nrow, size_t ncol, const char *const *headers,
    const char **values, const enum tprint_justify *justify, const bool *enabled);

#endif
