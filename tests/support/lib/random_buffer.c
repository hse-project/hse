/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>

#include <hse/util/xrand.h>

#include <hse/test/support/random_buffer.h>

void
randomize_buffer(char *buf, size_t len, unsigned int seed)
{
    size_t remain;
    struct xrand xr;
    uint64_t rand_val;

    if (len == 0)
        return;

    xrand_init(&xr, seed);
    for (remain = len; remain >= sizeof(rand_val); remain -= sizeof(rand_val)) {
        rand_val = xrand64(&xr);
        memcpy(buf + len - remain, &rand_val, sizeof(rand_val));
    }

    if (remain != 0) {
        rand_val = xrand64(&xr);
        memcpy(buf + len - remain, &rand_val, remain);
    }
}

int
validate_random_buffer(char *buf, size_t len, unsigned int seed)
{
    size_t remain;
    struct xrand xr;
    uint64_t rand_val;

    if (len == 0)
        return -1; /* success... */

    xrand_init(&xr, seed);
    for (remain = len; remain > sizeof(rand_val); remain -= sizeof(rand_val)) {
        rand_val = xrand64(&xr);
        if (memcmp(&rand_val, buf + len - remain, sizeof(rand_val)) != 0)
            return (int)(len - remain);
    }

    if (remain != 0) {
        rand_val = xrand64(&xr);
        if (memcmp(&rand_val, buf + len - remain, remain) != 0)
            return (int)(len - remain);
    }

    /* -1 is success, because 0..n are valid offsets for an error */
    return -1;
}

/* Get a random value in the range [min, max]. Note that the max is an inclusive upper bound.
 */
uint32_t
generate_random_u32(uint32_t min, uint32_t max)
{
    return (xrand64_tls() % (max - min + 1)) + min;
}

void
permute_u32_sequence(uint32_t *values, uint32_t num_values)
{
    uint32_t i, j, tmp_val;

    for (i = num_values - 1; i > 0; --i) {
        j = generate_random_u32(0, i - 1);
        tmp_val = values[i];
        values[i] = values[j];
        values[j] = tmp_val;
    }
}

void
generate_random_u32_sequence(
    uint32_t min_value,
    uint32_t max_value,
    uint32_t *values,
    uint32_t num_values)
{
    uint32_t i;

    for (i = 0; i < num_values; ++i)
        values[i] = generate_random_u32(min_value, max_value);

    permute_u32_sequence(values, num_values);
}

void
generate_random_u32_sequence_unique(
    uint32_t min_value,
    uint32_t max_value,
    uint32_t *values,
    uint32_t num_values)
{
    uint32_t i;
    uint32_t stride = (max_value - min_value) / num_values;

    assert(stride > 0);

    for (i = 0; i < num_values; ++i) {
        uint32_t min = i * stride;
        uint32_t max = min + stride - 1;

        if (i == num_values - 1)
            max = max_value;

        values[i] = generate_random_u32(min, max);
    }

    permute_u32_sequence(values, num_values);
}
