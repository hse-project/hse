/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TOKEN_BUCKET_H
#define HSE_PLATFORM_TOKEN_BUCKET_H

#include <hse/util/arch.h>
#include <hse/util/compiler.h>
#include <hse/util/inttypes.h>
#include <hse/util/spinlock.h>
#include <hse/util/time.h>

/* MTF_MOCK_DECL(token_bucket) */

/* Struct tbkt members should be considered private.  */
struct tbkt {
    u64         tb_rate HSE_ACP_ALIGNED;
    u64         tb_dt_max;
    u64         tb_burst;

    spinlock_t  tb_lock HSE_L1D_ALIGNED;
    u64         tb_delay;
    u64         tb_refill_time;
    u64         tb_balance;
};

static inline void
tbkt_delay(u64 nsec)
{
    struct timespec timespec;

    if (HSE_LIKELY(nsec < NSEC_PER_SEC)) {
        timespec.tv_sec = 0;
        timespec.tv_nsec = nsec;
    } else {
        timespec.tv_sec = nsec / NSEC_PER_SEC;
        timespec.tv_nsec = nsec % NSEC_PER_SEC;
    }

    nanosleep(&timespec, 0);
}

/* MTF_MOCK */
void
tbkt_init(struct tbkt *tb, u64 burst, u64 rate);

/* MTF_MOCK */
u64
tbkt_request(struct tbkt *tb, u64 tokens, u64 *now);

/* MTF_MOCK */
u64
tbkt_burst_get(struct tbkt *self);

/* MTF_MOCK */
u64
tbkt_rate_get(struct tbkt *self);

/* MTF_MOCK */
void
tbkt_adjust(struct tbkt *self, u64 burst, u64 rate);

#if HSE_MOCKING
#include "token_bucket_ut.h"
#endif /* HSE_MOCKING */

#endif
