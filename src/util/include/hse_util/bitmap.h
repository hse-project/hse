/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BITMAP_H
#define HSE_PLATFORM_BITMAP_H

#include <hse_util/base.h>
#include <hse_util/inttypes.h>

#define BYTE_SHIFT 3

/**
 * hse_bitmap_test32()
 *
 * Return:
 * %true  - bit is set
 * %false - bit is not set
 */
static __always_inline bool
hse_bitmap_test32(const u8 *bitmap, u32 index)
{
    const u32 byte_num = index >> BYTE_SHIFT;
    const u32 bit_num = index & 7;

    return bitmap[byte_num] & (1 << bit_num);
}

/**
 * hse_bitmap_set32()
 *
 */
static __always_inline void
hse_bitmap_set32(u8 *bitmap, u32 index)
{
    const u32 byte_num = index >> BYTE_SHIFT;
    const u32 bit_num = index & 7;

    bitmap[byte_num] |= (u8)(1 << bit_num);
}

#endif
