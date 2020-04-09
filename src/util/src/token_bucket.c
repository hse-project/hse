/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_token_bucket

#include <hse_util/timing.h>
#include <hse_util/timer.h>
#include <hse_util/delay.h>
#include <hse_util/token_bucket.h>

/* MTF_MOCK_DECL(token_bucket) */

static void
tbkt_init_impl(struct tbkt *self, u64 burst, u64 rate)
{
    self->tb_burst = burst;
    self->tb_rate = rate;

    self->tb_balance = burst;
    self->tb_dt_max = rate ? U64_MAX / rate : U64_MAX;

    self->tb_refill_time = get_time_ns();
}

void
tbkt_init(struct tbkt *self, u64 burst, u64 rate)
{
    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->tb_lock);
    tbkt_init_impl(self, burst, rate);
}

void
tbkt_reinit(struct tbkt *self, u64 burst, u64 rate)
{
    spin_lock(&self->tb_lock);
    tbkt_init_impl(self, burst, rate);
    spin_unlock(&self->tb_lock);
}

/* Returns the number of nanoseconds the caller should
 * delay to respect the rate limit.
 */
u64
tbkt_request(struct tbkt *self, u64 request)
{
    u64 dt, now;
    u64 burst, rate, balance, deficit;
    u64 refill, refill_max;

    if (self->tb_rate == 0)
        return 0;

    spin_lock(&self->tb_lock);

    /* Balance refill based on elapsed time.  If too much time is
     * has passed, balance will equal burst.
     */
    balance = self->tb_burst;
    now = get_time_ns();
    dt = now - self->tb_refill_time;
    if (dt < self->tb_dt_max) {
        refill = self->tb_rate * dt / NSEC_PER_SEC;
        refill_max = self->tb_burst - self->tb_balance;
        if (refill < refill_max)
            balance = self->tb_balance + refill;
    }

    /* Update balance for request.
     * Note: The internal state of the token bucket uses addition
     * modulo U64_MAX+1.  If (1 <= balance <= burst), the bucket
     * has tokens.  If (burst < balance <= U64_MAX), the bucket
     * has a deficit of (U64_MAX - balance + 1).
     */
    balance = balance - request;

    /* Update token bucket. */
    self->tb_balance = balance;
    self->tb_refill_time = now;

    /* Save rate and burst for use outside lock. */
    rate = self->tb_rate;
    burst = self->tb_burst;

    spin_unlock(&self->tb_lock);

    if (balance < burst)
        return 0;

    deficit = U64_MAX - balance + 1;
    if (deficit < U64_MAX / NSEC_PER_SEC)
        return (deficit * NSEC_PER_SEC) / rate;

    /* Alternative if (*deficit * NSEC_PER_SEC) would overflow. */
    return (deficit / rate) * NSEC_PER_SEC;
}

void
tbkt_delay(u64 nsec)
{
    struct timespec timespec;

    timespec.tv_sec = nsec / NSEC_PER_SEC;
    timespec.tv_nsec = nsec % NSEC_PER_SEC;
    nanosleep(&timespec, 0);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "token_bucket_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
