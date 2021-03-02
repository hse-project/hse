/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CHEAP_TESTLIB_H
#define HSE_CHEAP_TESTLIB_H

int
cheap_fill_test(struct cheap *h, size_t size);

int
cheap_verify_test1(struct cheap *h, u32 min_size, u32 max_size);

int
cheap_zero_test1(struct cheap *h, u32 min_size, u32 max_size);

enum which_strict_test {
    OVERSIZE_FREE,
    UNDERSIZE_FREE,
    OVERCOUNT_FREE,
    UNDERCOUNT_FREE,
    BOTH_OVER,
    BOTH_UNDER,
};

int
cheap_strict_test1(struct cheap *h, u32 min_size, u32 max_size, enum which_strict_test which);

#endif
