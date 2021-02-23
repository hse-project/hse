/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_UTIL_MWC_RAND_H
#define HSE_UTIL_MWC_RAND_H

/*
 * Multiply-with-carry psuedorandom number generator
 */

#include <hse_util/inttypes.h>

#define MWC_RAND_DEFAULT_W 0x37ac6e82
#define MWC_RAND_DEFAULT_Z 0x87185abd

#define MWC_RAND_INITIALIZER                   \
    {                                          \
        MWC_RAND_DEFAULT_W, MWC_RAND_DEFAULT_Z \
    }

struct mwc_rand {
    u32 w;
    u32 z;
};

void
mwc_rand_init(struct mwc_rand *m, u32 seed);

u8
mwc_rand8(struct mwc_rand *m);
u16
mwc_rand16(struct mwc_rand *m);
u32
mwc_rand32(struct mwc_rand *m);
u64
mwc_rand64(struct mwc_rand *m);

u32
mwc_rand_range32(struct mwc_rand *mwc, u32 lo, u32 hi);
u64
mwc_rand_range64(struct mwc_rand *mwc, u64 lo, u64 hi);

#endif
