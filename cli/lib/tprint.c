/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <hse/cli/tprint.h>
#include <hse/error/merr.h>

#define COLUMN_SEP " "

merr_t
tprint(FILE *const fp, const size_t nrow, const size_t ncol, const char *const *const headers,
    const char **const values, const enum tprint_justify *justify, const bool *const enabled)
{
    size_t *longest = malloc(ncol * sizeof(*longest));
    if (!longest)
        return merr(ENOMEM);

    for (size_t c = 0; c < ncol; c++) {
        size_t max;

        max = strlen(headers[c]);

        for (size_t r = 0; r < nrow; r++) {
            const size_t n = strlen(values[r * ncol + c]);

            if (n > max)
                max = n;
        }

        longest[c] = max;
    }

    for (size_t c = 0; c < ncol; c++) {
        const char *fmt;

        if (enabled && !enabled[c])
            continue;

        if (!justify || justify[c] == TP_JUSTIFY_LEFT) {
            fmt = "%-*s%s";
        } else {
            fmt = "%*s%s";
        }

        fprintf(fp, fmt, (int)longest[c], headers[c], c == ncol - 1 ? "" : COLUMN_SEP);
    }

    fputc('\n', fp);

    for (size_t r = 0; r < nrow; r++) {
        for (size_t c = 0; c < ncol; c++) {
            const char *fmt;

            if (enabled && !enabled[c])
                continue;

            if (!justify || justify[c] == TP_JUSTIFY_LEFT) {
                fmt = "%-*s%s";
            } else {
                fmt = "%*s%s";
            }

            fprintf(fp, fmt, (int)longest[c], values[r * ncol + c], c == ncol - 1 ? "" : COLUMN_SEP);
        }

        fputc('\n', fp);
    }

    free(longest);

    return 0;
}
