/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#include <bsd/stringlist.h>

#include <hse/util/base.h>

#include "format.h"

#define JSON  "json"
#define TAB   "tab"
#define PLAIN "plain"

enum format
format_from_string(const char *const format)
{
    if (!format)
        return FORMAT_INVALID;

    if (strcmp(format, JSON) == 0)
        return FORMAT_JSON;

    if (strncmp(format, TAB, sizeof(TAB) - 1) == 0 && (format[sizeof(TAB) - 1] == ':' ||
            format[sizeof(TAB) - 1] == '\0'))
        return FORMAT_TABULAR;

    if (strcmp(format, PLAIN) == 0)
        return FORMAT_PLAIN;

    return FORMAT_INVALID;
}

int
format_parse_tabular(
    const char *const format,
    const size_t ncolumns,
    const char **const headers,
    bool *const enabled)
{
    int rc = 0;
    char *dup;

    if (!format)
        return EX_USAGE;

    /* If no columns were specified, use the default. */
    if (strlen(format) <= sizeof(TAB))
        return 0;

    dup = strdup(format + sizeof(TAB));
    if (!dup) {
        fprintf(stderr, "Failed to allocate memory\n");
        return EX_OSERR;
    }

    memset(enabled, 0, ncolumns * sizeof(*enabled));

    for (const char *token = strsep(&dup, ","); token; token = strsep(&dup, ",")) {
        bool found = false;

        for (size_t i = 0; i < ncolumns; i++) {
            if (strcasecmp(headers[i], token) == 0) {
                if (enabled[i]) {
                    fprintf(stderr, "Header listed more than once\n");
                    rc = EX_USAGE;
                    goto out;
                }

                enabled[i] = true;
                found = true;
            }
        }

        if (!found) {
            fprintf(stderr, "Unknown header listed in '%s'\n", format);
            rc = EX_USAGE;
            goto out;
        }
    }

out:
    free(dup);

    return rc;
}

const char *
format_to_string(const enum format format)
{
    switch (format) {
    case FORMAT_INVALID:
        return "invalid";
    case FORMAT_JSON:
        return JSON;
    case FORMAT_TABULAR:
        return TAB;
    case FORMAT_PLAIN:
        return PLAIN;
    }

    abort();
}
