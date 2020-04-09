/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/parser.h>

#include "parser_internal.h"

void
match_once(const char *str, const char *ptrn, u32 *matched, u32 *val_found, substring_t *val)
{
    const char *scan = str;
    const char *p, *beg;

    s32 value_len = -1;
    u32 ptrn_prefix_len;

    if (strlen(scan) == 0) {
        if (strlen(ptrn) == 0)
            goto match_no_val;
        else
            goto no_match;
    }

    /* if the pattern doesn't have a conversion specifier, just compare */
    p = strchr(ptrn, '%');
    if (!p) {
        if (strcmp(scan, ptrn) == 0)
            goto match_no_val;
        else
            goto no_match;
    }

    /* pattern has one or more '%', so compare prefix */
    ptrn_prefix_len = p - ptrn;
    if (strncmp(scan, ptrn, ptrn_prefix_len))
        goto no_match;

    /* skip over already matched portion of string & pattern */
    scan = scan + ptrn_prefix_len;
    ptrn = p;

    /* if we have matches for literal %'s, move past them ... */
    while (*scan && *ptrn) {
        if (*ptrn == '%' && *scan == '%') {
            ++ptrn;
            ++scan;
        } else
            break;
    }

    /* if both strings are now exhausted we have a match */
    if (!*ptrn && !*scan)
        goto match_no_val;
    /* otherwise if pattern is empty but scan isn't we have no match */
    if (!*ptrn)
        goto no_match;

    ptrn++;
    if (isdigit(*ptrn))
        value_len = strtoul(ptrn, (char **)&ptrn, 10);

    beg = scan;
    if (*ptrn == 's') {
        u32 scan_len = strlen(scan);

        if (value_len == -1 || value_len > scan_len)
            value_len = scan_len;

        val->from = beg;
        val->to = scan + value_len;

        goto match_val;
    } else {
        char *end;

        errno = 0;
        switch (*ptrn) {
            case 'd':
                strtol(scan, &end, 0);
                break;
            case 'u':
                strtoul(scan, &end, 0);
                break;
            case 'o':
                strtol(scan, &end, 8);
                break;
            case 'x':
                strtol(scan, &end, 16);
                break;
            default:
                goto no_match;
        }
        if (errno || beg == end)
            goto no_match;

        val->from = beg;
        val->to = end;

        goto match_val;
    }

no_match:
    *matched = 0;
    *val_found = 0;
    return;

match_no_val:
    *matched = 1;
    *val_found = 0;
    return;

match_val:
    *matched = 1;
    *val_found = 1;
}

int
match_token(const char *str, const match_table_t table, substring_t *val)
{
    u32 matched;
    u32 val_found;
    int i;

    for (i = 0; table[i].pattern; ++i) {
        if (!str || !val)
            continue;

        match_once(str, table[i].pattern, &matched, &val_found, val);
        if (matched)
            break;
    }

    return table[i].token;
}

int
match_number(substring_t *substr, int *result, int base)
{
    int    rv = 0;
    char * buffer, *endp;
    size_t sz;
    long   value;

    if (!substr || !result)
        return ev(-EINVAL);
    sz = substr->to - substr->from;

    buffer = malloc(sz + 1);
    if (!buffer)
        return ev(-ENOMEM);

    memcpy(buffer, substr->from, sz);
    buffer[sz] = 0;

    errno = 0;
    value = strtol(buffer, &endp, base);

    if (errno || endp != buffer + sz)
        rv = ev(-EINVAL);
    else if (value < (long)INT_MIN || value > (long)INT_MAX)
        rv = ev(-ERANGE);
    else
        *result = (int)value;

    free(buffer);

    return rv;
}

int
match_int(substring_t *substr, int *result)
{
    return match_number(substr, result, 0);
}

int
match_octal(substring_t *substr, int *result)
{
    return match_number(substr, result, 8);
}

int
match_hex(substring_t *substr, int *result)
{
    return match_number(substr, result, 16);
}

size_t
match_strlcpy(char *dest, const substring_t *source, size_t size)
{
    size_t source_len;
    size_t copy_len;

    if (!dest || !source)
        return 0;
    source_len = source->to - source->from;

    if (size == 0)
        return source_len;

    if (size <= source_len)
        copy_len = size - 1;
    else
        copy_len = source_len;

    memcpy(dest, source->from, copy_len);
    dest[copy_len] = 0;

    return source_len;
}

char *
match_strdup(const substring_t *substr)
{
    size_t sz;
    char * p;

    if (!substr)
        return 0;
    sz = substr->to - substr->from + 1;

    p = malloc(sz);
    if (p)
        match_strlcpy(p, substr, sz);

    return p;
}
