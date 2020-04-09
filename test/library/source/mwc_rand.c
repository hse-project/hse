/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_test_support/mwc_rand.h>

void
mwc_rand_init(struct mwc_rand *mwc, u32 seed)
{
    mwc->w = MWC_RAND_DEFAULT_W;
    mwc->z = MWC_RAND_DEFAULT_Z;
    if (seed) {
        mwc->w = mwc->w ^ seed;
        mwc->z = mwc->z ^ seed;
    }
}

u32
mwc_rand32(struct mwc_rand *mwc)
{
    mwc->z = 36969 * (mwc->z & 65535) + (mwc->z >> 16);
    mwc->w = 18000 * (mwc->w & 65535) + (mwc->w >> 16);
    return (mwc->z << 16) + mwc->w;
}

u8
mwc_rand8(struct mwc_rand *mwc)
{
    return (u8)mwc_rand32(mwc);
}

u16
mwc_rand16(struct mwc_rand *mwc)
{
    return (u16)mwc_rand32(mwc);
}

u64
mwc_rand64(struct mwc_rand *mwc)
{
    u64 a = (u64)mwc_rand32(mwc);
    u64 b = (u64)mwc_rand32(mwc);

    return (a << 32) | b;
}

u32
mwc_rand_range32(struct mwc_rand *mwc, u32 lo, u32 hi)
{
    /* compute rv: 0 <= rv < 1  */
    double rand_max = (double)((u32)-1);
    double rv = (double)mwc_rand32(mwc) / (rand_max + 1.0);

    /* scale rv to the desired range */
    return lo + (u32)((double)(hi - lo) * rv);
}

u64
mwc_rand_range64(struct mwc_rand *mwc, u64 lo, u64 hi)
{
    /* compute rv: 0 <= rv < 1  */
    double rand_max = (double)((u64)-1);
    double rv = (double)mwc_rand64(mwc) / (rand_max + 1.0);

    /* scale rv to the desired range */
    return (u64)((double)lo + (double)(hi - lo) * rv);
}
