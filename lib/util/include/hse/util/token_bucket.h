/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TOKEN_BUCKET_H
#define HSE_PLATFORM_TOKEN_BUCKET_H

#include <hse/util/arch.h>
#include <hse/util/compiler.h>
#include <hse/util/spinlock.h>
#include <hse/util/time.h>

/* MTF_MOCK_DECL(token_bucket) */

/* Struct tbkt members should be considered private.  */
struct tbkt {
    uint64_t tb_rate HSE_ACP_ALIGNED;
    uint64_t tb_dt_max;
    uint64_t tb_burst;

    spinlock_t tb_lock HSE_L1D_ALIGNED;
    uint64_t tb_delay;
    uint64_t tb_refill_time;
    uint64_t tb_balance;
};

static inline void
tbkt_delay(uint64_t nsec)
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
tbkt_init(struct tbkt *tb, uint64_t burst, uint64_t rate);

/* MTF_MOCK */
uint64_t
tbkt_request(struct tbkt *tb, uint64_t tokens, uint64_t *now);

/* MTF_MOCK */
uint64_t
tbkt_burst_get(struct tbkt *self);

/* MTF_MOCK */
uint64_t
tbkt_rate_get(struct tbkt *self);

/* MTF_MOCK */
void
tbkt_adjust(struct tbkt *self, uint64_t burst, uint64_t rate);

#if HSE_MOCKING
#include "token_bucket_ut.h"
#endif /* HSE_MOCKING */

#endif
