/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdlib.h>

#include <hse_util/platform.h>
#include <hse_util/string.h>

static u8
c_to_n(u8 c)
{
    u8 n = 255;

    if ((c >= '0') && ('9' >= c))
        n = c - '0';

    if ((c >= 'a') && ('f' >= c))
        n = c - 'a' + 0xa;

    if ((c >= 'A') && ('F' >= c))
        n = c - 'A' + 0xa;

    return n;
}

u8 *pattern;
u32 pattern_len;

int
pattern_base(char *base)
{
    int i;

    if (!base)
        pattern_len = 16;
    else
        pattern_len = strlen(base);

    pattern = malloc(pattern_len);
    if (pattern == NULL)
        return -1;

    if (!base) { /* No pattern given, so make one up */
        for (i = 0; i < pattern_len; i++)
            pattern[i] = i % 256;
    } else {
        for (i = 0; i < pattern_len; i++) {
            pattern[i] = c_to_n(base[i]);

            if (pattern[i] == 255) {
                free(pattern);
                pattern = NULL;
                return -1;
            }
        }
    }

    return 0;
}

void
pattern_fill(char *buf, u32 buf_sz)
{
    u32 remaining = buf_sz;
    u32 idx;

    while (remaining > 0) {
        idx = buf_sz - remaining;
        buf[idx] = pattern[idx % pattern_len];
        remaining--;
    }
}

int
pattern_compare(char *buf, u32 buf_sz)
{
    u32 remaining = buf_sz;
    u32 idx;

    while (remaining > 0) {
        idx = buf_sz - remaining;

        if (buf[idx] != pattern[idx % pattern_len])
            return -1;

        remaining--;
    }
    return 0;
}
