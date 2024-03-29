/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_LOG2_H
#define HSE_LOG2_H

#include <limits.h>
#include <stdbool.h>

#include <hse/util/assert.h>
#include <hse/util/compiler.h>

static HSE_ALWAYS_INLINE HSE_CONST unsigned long
ilog2(unsigned long n)
{
    INVARIANT(n > 0);

    return (CHAR_BIT * sizeof(n) - 1) - (unsigned int)__builtin_clzl(n);
}

static HSE_ALWAYS_INLINE HSE_CONST unsigned long
roundup_pow_of_two(unsigned long n)
{
    if (n < 2)
        return 1;

    return (1UL << (ilog2(n - 1) + 1));
}

static HSE_ALWAYS_INLINE HSE_CONST unsigned long
rounddown_pow_of_two(unsigned long n)
{
    if (n < 2)
        return 1;

    return (1UL << ilog2(n));
}

#endif /* HSE_LOG2_H */
