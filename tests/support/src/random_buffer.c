/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_test_support/random_buffer.h>
#include <hse_test_support/mwc_rand.h>

#include <string.h>

void
randomize_buffer(void *buf, size_t len, unsigned int seed)
{
    unsigned int *  tmp = (unsigned int *)buf;
    u_int           last;
    long int        remain = len;
    int             i;
    struct mwc_rand mwc;

    if (len == 0)
        return;

    mwc_rand_init(&mwc, seed);
    for (i = 0; remain > 0; i++, remain -= sizeof(*tmp)) {
        if (remain > sizeof(*tmp)) { /* likely */
            tmp[i] = mwc_rand32(&mwc);
        } else { /* unlikely */
            last = mwc_rand32(&mwc);
            memcpy(&tmp[i], &last, remain);
        }
    }
}

int
validate_random_buffer(void *buf, size_t len, unsigned int seed)
{
    unsigned int *  tmp = (unsigned int *)buf;
    unsigned int    val;
    char *          expect = (char *)&val;
    char *          found;
    long int        remain = len;
    int             i;
    struct mwc_rand mwc;

    if (len == 0)
        return -1; /* success... */

    mwc_rand_init(&mwc, seed);
    for (i = 0; remain > 0; i++, remain -= sizeof(*tmp)) {
        val = mwc_rand32(&mwc);
        if ((remain >= sizeof(*tmp)) && (val != tmp[i])) { /* Likely */
            return ((int)(len - remain));
        } else if (remain < sizeof(*tmp)) { /* Unlikely */
            found = (char *)&tmp[i];
            if (memcmp(expect, found, remain)) {
                /*
                 * [HSE_REVISIT]
                 * Miscompare offset might be off here
                 */
                return ((int)(len - remain));
            }
        }
    }
    /* -1 is success, because 0..n are valid offsets for an error */
    return -1;
}

u32
generate_random_u32(u32 min, u32 max)
{
    const double r = (double)rand() / (double)RAND_MAX;
    const double tmp = (double)min + r * (double)(max - min);

    return (u32)tmp;
}

void
permute_u32_sequence(u32 *values, u32 num_values)
{
    u32 i, j, tmp_val;

    for (i = num_values - 1; i > 0; --i) {
        j = generate_random_u32(0, i - 1);
        tmp_val = values[i];
        values[i] = values[j];
        values[j] = tmp_val;
    }
}

void
generate_random_u32_sequence(u32 min_value, u32 max_value, u32 *values, u32 num_values)
{
    u32 i;

    for (i = 0; i < num_values; ++i)
        values[i] = generate_random_u32(min_value, max_value);

    permute_u32_sequence(values, num_values);
}
