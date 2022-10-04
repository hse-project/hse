/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOG2_H
#define HSE_LOG2_H

#include <hse_util/assert.h>
#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>

static HSE_ALWAYS_INLINE HSE_CONST
unsigned int
ilog2(unsigned long n)
{
    INVARIANT(n > 0);

    return (CHAR_BIT * sizeof(n) - 1) - __builtin_clzl(n);
}

static HSE_ALWAYS_INLINE HSE_CONST
unsigned long
roundup_pow_of_two(unsigned long n)
{
    if (n < 2)
        return 1;

    return (1UL << (ilog2(n - 1) + 1));
}

static HSE_ALWAYS_INLINE HSE_CONST
unsigned long
rounddown_pow_of_two(unsigned long n)
{
    if (n < 2)
        return 1;

    return (1UL << ilog2(n));
}

#endif /* HSE_LOG2_H */
