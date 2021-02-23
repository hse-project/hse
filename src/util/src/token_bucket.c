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

/* Notes:
 * - The token bucket uses addition modulo U64_MAX+1.
 * - If (0 <= balance <= burst), the bucket has credit of (balance) tokens.
 * - If (burst < balance <= U64_MAX), the bucket has a debt of (U64_MAX - balance + 1) tokens.
 */


static inline bool
tbkti_in_debt(struct tbkt *self)
{
    return self->tb_balance > self->tb_burst;
}

static inline bool
tbkti_status(struct tbkt *self, u64 *amount)
{
    bool in_debt = tbkti_in_debt(self);

    if (in_debt)
        *amount = U64_MAX - self->tb_balance + 1;
    else
        *amount = self->tb_balance;

    return in_debt;
}


static void
tbkti_burst_set(struct tbkt *self, u64 burst)
{
    bool had_debt;
    bool still_have_debt;

    had_debt = tbkti_in_debt(self);

    self->tb_burst = burst;

    still_have_debt = tbkti_in_debt(self);

    /* If the new balance is between the old burst size and the new burst
     * size, then the token bucket has flipped from debt to credit or vice
     * versa.  That might not seem bad, but it is deadly because it typically
     * results in a change from normal debt/credit to *huge* credit/debt.
     * The following code detects and mitigates this problem.
     *
     * Note if the new burst == U64_MAX, then the new bucket cannot be in
     * debt.  Hence the extra condition in the assert.
     */
    if (had_debt && !still_have_debt) {
        self->tb_balance = burst + 1u;
        assert(burst == U64_MAX || tbkti_in_debt(self));
    }
    else if (!had_debt && still_have_debt) {
        self->tb_balance = burst;
        assert(!tbkti_in_debt(self));
    }

}

static void
tbkti_rate_set(struct tbkt *self, u64 rate)
{
    /* self->tb_dt_max is used to avoid unsigned int overflow
     * when multiplying a time delta by the rate.   For example
     * let dt be a time delta:
     *
     *   if dt < dt_max, then dt * self->tb_rate will not overflow
     *
     * This is used to efficiently check against overflow when
     * updating the token bucket's balance.
     */
    self->tb_rate = rate;
    self->tb_dt_max = rate ? U64_MAX / rate : U64_MAX;
}

static void
tbkti_init(struct tbkt *self, u64 burst, u64 rate)
{
    tbkti_burst_set(self, burst);
    tbkti_rate_set(self, rate);
    self->tb_balance = burst;
    self->tb_refill_time = get_time_ns();
}

/* Return new balance based on current time as provided by caller via
 * parameter 'now'.  This function has no side effects. Caller is expected to
 * update token bucket's balance and refill time.
 */
static u64
tbkti_balance(struct tbkt *self, u64 now)
{
    u64 dt;
    u64 refill;

    /* Don't expect time to move backward, but if it does just return the
     * current balance.
     */
    if (HSE_UNLIKELY(self->tb_refill_time > now))
        return self->tb_balance;

    /* Compute refill based on dt (ie, elapsed time).  Use tb_dt_max to avoid
     * overflow.  If it would overflow, the elapsed time must be large and we
     * return the max balance (which equals the burst size).
     */
    dt = now - self->tb_refill_time;
    if (HSE_UNLIKELY(dt > self->tb_dt_max))
        return self->tb_burst;

    refill = (u64) ((double) self->tb_rate * dt * 1e-9);

    if (refill > self->tb_burst - self->tb_balance)
        return self->tb_burst;

    return self->tb_balance + refill;
}

static void
tbkti_refill(struct tbkt *self)
{
    u64 now = get_time_ns();

    self->tb_balance = tbkti_balance(self, now);
    self->tb_refill_time = now;
}

void
tbkt_adjust(struct tbkt *self, u64 burst, u64 rate)
{
    spin_lock(&self->tb_lock);
    tbkti_burst_set(self, (u64)burst);
    tbkti_refill(self);
    tbkti_rate_set(self, rate);
    spin_unlock(&self->tb_lock);
}

void
tbkt_init(struct tbkt *self, u64 burst, u64 rate)
{
    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->tb_lock);
    tbkti_init(self, burst, rate);
}

u64
tbkt_burst_get(struct tbkt *self)
{
    return self->tb_burst;
}

u64
tbkt_rate_get(struct tbkt *self)
{
    return self->tb_rate;
}

/*
 * tbkt_request() - returns the number of nanoseconds the caller should
 *                  delay to respect the rate limit.
 *
 * Spinlock thrashing avoidance: The token bucket lock is acquired
 * with spin_trylock instead spin_lock.  When the trylock fails, a
 * small delay is returned without modifying the token bucket state.
 * The seems to eliminate spinlock thrashing which would otherwise
 * occur when many threads make small token requests (e.g., 200+
 * threads "putting" 0-byte values).  Returning a small fixed delay when
 * trylock fails seems not to affect overall rate because:
 *   - Measurements with worst case workloads show this trylock fails
 *     less than 0.5% of the time, so even if the fixed delay is
 *     inaccurate, it does not significantly impact overall rate.
 *   - Trylock failures typically occur when the average delay is
 *     small in the first place (the larger the delay, the more time
 *     between requests, less likely to have lock contention).
 *
 * Preventing a balance inversion: Requests must not reduce balance so
 * much it flips form a negative balance to a positive balance.  In
 * theory this would only happen if 1) the requesters weren't delaying
 * before issuing their next request, or 2) many concurrent threads
 * made huge requests (the number of threads times average request
 * would have to be on the order of U64_MAX).  Balance inversion is
 * avoided by reducing the request size if an update would cause an
 * inversion.
 */
u64
tbkt_request(struct tbkt *self, u64 request)
{
    u64 delay, rate, amount;
    u64 request_max;
    bool debt;

    if (HSE_UNLIKELY(request == 0 || self->tb_rate == 0))
        return 0;

    if (!spin_trylock(&self->tb_lock))
        return 128;

    /* Refill the bucket based on elapsed time. */
    tbkti_refill(self);

    /* Prevent balance inversion */
    request_max = self->tb_balance - self->tb_burst - 1u;
    if (HSE_UNLIKELY(request > request_max))
        request = request_max;

    /* Make the withdrawal */
    self->tb_balance -= request;

    /* Save rate and debt status for use after lock */
    rate = self->tb_rate;
    debt = tbkti_status(self, &amount);

    spin_unlock(&self->tb_lock);

    delay = debt ? amount * NSEC_PER_SEC / rate : 0;

    return delay;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "token_bucket_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
