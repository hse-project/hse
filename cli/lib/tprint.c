/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <string.h>

#include <cli/tprint.h>

void
tprint(FILE *fp, const size_t nrow, const size_t ncol, const char *const *const headers,
    const char **values, const bool *const enabled)
{
    int longest[ncol];

    for (size_t c = 0; c < ncol; c++) {
        size_t max = 0, n = 0;

        max = strlen(headers[c]);

        for (size_t r = 0; r < nrow; r++) {
            n = strlen(values[r * ncol + c]);

            if (n > max)
                max = n;
        }

        longest[c] = max;
    }

    for (size_t c = 0; c < ncol; c++) {
        if (enabled && !enabled[c])
            continue;

        fprintf(fp, "%-*s\t", longest[c], headers[c]);
    }

    fputs("\b\n", fp);

    for (size_t r = 0; r < nrow; r++) {
        for (size_t c = 0; c < ncol; c++) {
            if (enabled && !enabled[c])
                continue;

            fprintf(fp, "%-*s\t", longest[c], values[r * ncol + c]);
        }

        fputs("\b\n", fp);
    }
}
