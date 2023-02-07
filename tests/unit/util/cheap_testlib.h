/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_CHEAP_TESTLIB_H
#define HSE_CHEAP_TESTLIB_H

#include <stddef.h>
#include <stdint.h>

struct cheap;

int
cheap_fill_test(struct cheap *h, size_t size);

int
cheap_verify_test1(struct cheap *h, uint32_t min_size, uint32_t max_size);

int
cheap_zero_test1(struct cheap *h, uint32_t min_size, uint32_t max_size);

enum which_strict_test {
    OVERSIZE_FREE,
    UNDERSIZE_FREE,
    OVERCOUNT_FREE,
    UNDERCOUNT_FREE,
    BOTH_OVER,
    BOTH_UNDER,
};

int
cheap_strict_test1(
    struct cheap *h,
    uint32_t min_size,
    uint32_t max_size,
    enum which_strict_test which);

#endif
