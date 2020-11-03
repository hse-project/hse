/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TOKEN_BUCKET_H
#define HSE_PLATFORM_TOKEN_BUCKET_H

#include <hse_util/inttypes.h>
#include <hse_util/spinlock.h>

/* MTF_MOCK_DECL(token_bucket) */

/* Struct tbkt members should be considered private.  */
struct tbkt {
    spinlock_t tb_lock;
    u64        tb_balance;
    u64        tb_burst;
    u64        tb_rate;
    u64        tb_refill_time;
    u64        tb_dt_max;
    u64        tb_requests;
};

/* MTF_MOCK */
void
tbkt_init(struct tbkt *tb, u64 burst, u64 rate);

/* MTF_MOCK */
u64
tbkt_request(struct tbkt *tb, u64 tokens);

/* MTF_MOCK */
void
tbkt_delay(u64 nsec);

/* MTF_MOCK */
u64
tbkt_burst_get(struct tbkt *self);

/* MTF_MOCK */
u64
tbkt_rate_get(struct tbkt *self);

/* MTF_MOCK */
void
tbkt_adjust(struct tbkt *self, u64 burst, u64 rate);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "token_bucket_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
