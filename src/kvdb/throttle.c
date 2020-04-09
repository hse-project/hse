/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/minmax.h>
#include <hse_util/assert.h>
#include <hse_util/inttypes.h>
#include <hse_util/logging.h>
#include <hse_util/delay.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/throttle_perfc.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>

#include <hse/kvdb_perfc.h>

static struct perfc_name throttle_sen_perfc[] = {

    NE(PERFC_DI_THSR_CSCHED, 2, "csched leaf percent sensor", "thsr_csched"),

    NE(PERFC_DI_THSR_C0SK, 2, "c0sk sensor", "thsr_c0sk"),

    NE(PERFC_DI_THSR_C0SKM_DTIME, 2, "c0sk mutation dtime sensor", "thsr_c0skm_dtime"),

    NE(PERFC_DI_THSR_C0SKM_DSIZE, 2, "c0sk mutation dsize sensor", "thsr_c0skm_dsize"),

    NE(PERFC_DI_THSR_MAX, 2, "max sensor", "thsr_max"),

    NE(PERFC_DI_THSR_MAVG, 2, "mavg sensor", "thsr_mavg"),
};

NE_CHECK(throttle_sen_perfc, PERFC_EN_THSR, "perfc table/enum mismatch");

static struct perfc_name throttle_sleep_perfc[] = {
    NE(PERFC_DI_THR_SVAL, 2, "throttle sleep", "thr_sleep"),
};

NE_CHECK(throttle_sleep_perfc, PERFC_EN_THR_MAX, "perfc table/enum mismatch");

void
throttle_perfc_init(void)
{
    struct perfc_ivl *sensor_ivl, *sleep_ivl;
    u64               boundv[PERFC_IVL_MAX];
    merr_t            err;
    int               i;

    /* Intervals for throttle sensors: linear from (0..2*SCALE). */
    for (i = 0; i < PERFC_IVL_MAX; i++)
        boundv[i] = ((i + 1) * 2 * THROTTLE_SENSOR_SCALE / (PERFC_IVL_MAX + 1));

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &sensor_ivl);
    if (ev(err))
        return;

    i = PERFC_IVL_MAX - 1;
    boundv[i] = THROTTLE_DELAY_MAX;

    /* Intervals for sleep. */
    for (i = i - 1; i >= 0; i--)
        boundv[i] = boundv[i + 1] / 2;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &sleep_ivl);
    if (ev(err)) {
        perfc_ivl_destroy(sensor_ivl);
        return;
    }

    throttle_sen_perfc[PERFC_DI_THSR_CSCHED].pcn_ivl = sensor_ivl;
    throttle_sen_perfc[PERFC_DI_THSR_C0SK].pcn_ivl = sensor_ivl;
    throttle_sen_perfc[PERFC_DI_THSR_C0SKM_DTIME].pcn_ivl = sensor_ivl;
    throttle_sen_perfc[PERFC_DI_THSR_C0SKM_DSIZE].pcn_ivl = sensor_ivl;
    throttle_sen_perfc[PERFC_DI_THSR_MAX].pcn_ivl = sensor_ivl;
    throttle_sen_perfc[PERFC_DI_THSR_MAVG].pcn_ivl = sensor_ivl;
    throttle_sleep_perfc[PERFC_DI_THR_SVAL].pcn_ivl = sleep_ivl;
}

void
throttle_perfc_fini(void)
{
    const struct perfc_ivl *ivl;
    int                     i, j;

    /* Order N^2, but N is small and it destroys all 'perfc_ivl'
     * structures correctly regardless of how they were allocated
     * and shared among the perf counters.
     */
    for (i = 0; i < NELEM(throttle_sen_perfc); i++) {
        ivl = throttle_sen_perfc[i].pcn_ivl;
        if (ivl) {
            perfc_ivl_destroy(ivl);
            for (j = i; j < NELEM(throttle_sen_perfc); j++)
                if (ivl == throttle_sen_perfc[j].pcn_ivl)
                    throttle_sen_perfc[j].pcn_ivl = 0;
        }
    }

    for (i = 0; i < NELEM(throttle_sleep_perfc); i++) {
        ivl = throttle_sleep_perfc[i].pcn_ivl;
        if (ivl) {
            perfc_ivl_destroy(ivl);
            for (j = i; j < NELEM(throttle_sleep_perfc); j++)
                if (ivl == throttle_sleep_perfc[j].pcn_ivl)
                    throttle_sleep_perfc[j].pcn_ivl = 0;
        }
    }
}

void
throttle_init(struct throttle *self, struct kvdb_rparams *rp)
{
    uint   i;
    merr_t err;

    assert(IS_ALIGNED((uintptr_t)self, __alignof(*self)));

    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->thr_lock);
    self->thr_rp = rp;

    for (i = 0; i < THROTTLE_SENSOR_CNT; i++)
        atomic_set(&self->thr_sensorv[i].ts_sensor, 0);

    if (throttle_sen_perfc[PERFC_DI_THSR_MAVG].pcn_ivl) {

        err = perfc_ctrseti_alloc(
            COMPNAME,
            "global",
            throttle_sen_perfc,
            NELEM(throttle_sen_perfc),
            "set",
            &self->thr_sensor_perfc);
        ev(err);
    }

    if (throttle_sleep_perfc[PERFC_DI_THR_SVAL].pcn_ivl) {

        err = perfc_ctrseti_alloc(
            COMPNAME,
            "global",
            throttle_sleep_perfc,
            NELEM(throttle_sleep_perfc),
            "set",
            &self->thr_sleep_perfc);
        ev(err);
    }
}

void
throttle_init_params(struct throttle *self, struct kvdb_rparams *rp)
{
    uint time_ms;

    self->thr_delay_raw = THROTTLE_DELAY_START;
    self->thr_state = THROTTLE_NO_CHANGE;
    self->thr_update_ms = rp->throttle_update_ns / 1000000;

    self->thr_inject_cycles = THROTTLE_INJECT_MS / self->thr_update_ms +
                              (THROTTLE_INJECT_MS % self->thr_update_ms ? 1 : 0);

    /* Evaluate if we can go faster every 5 seconds) */
    time_ms = THROTTLE_REDUCE_CYCLES * self->thr_update_ms;
    time_ms = max_t(uint, time_ms, 5000);
    time_ms = min_t(uint, time_ms, 15000);
    self->thr_reduce_cycles = time_ms / self->thr_update_ms;

    /* Skip the first few ms worth of measurements while computing mavg
     * after changing the sleep value. */
    time_ms = THROTTLE_SKIP_CYCLES * self->thr_update_ms;
    time_ms = max_t(uint, time_ms, 250);
    time_ms = min_t(uint, time_ms, 1000);
    self->thr_skip_cycles = time_ms / self->thr_update_ms + (time_ms % self->thr_update_ms ? 1 : 0);

    /* This is the minimum additional time to wait after reducing the sleep
     * value for sensors to respond.
     */
    time_ms = THROTTLE_DELTA_CYCLES * self->thr_update_ms;
    time_ms = max_t(uint, time_ms, 800);
    time_ms = min_t(uint, time_ms, 4000);
    self->thr_delta_cycles =
        time_ms / self->thr_update_ms + (time_ms % self->thr_update_ms ? 1 : 0);

    hse_log(
        HSE_NOTICE "throttle init: delay %d u_ms %d rcycles %d"
                   " icycles %d scycles %d dcycles %d",
        self->thr_delay_raw,
        self->thr_update_ms,
        self->thr_reduce_cycles,
        self->thr_inject_cycles,
        self->thr_skip_cycles,
        self->thr_delta_cycles);
}

void
throttle_fini(struct throttle *self)
{
    perfc_ctrseti_free(&self->thr_sleep_perfc);
    perfc_ctrseti_free(&self->thr_sensor_perfc);
}

static void
throttle_reset_mavg(struct throttle *self)
{
    self->thr_mavg.tm_curr = 0;
    self->thr_mavg.tm_idx = 0;
    self->thr_mavg.tm_sum = 0;
    self->thr_mavg.tm_sample_cnt = 0;

    perfc_rec_sample(&self->thr_sensor_perfc, PERFC_DI_THSR_MAVG, 0);
}

void
throttle_reduce_debug(struct throttle *self, uint sensor, uint mavg)
{
    hse_log(
        HSE_NOTICE "throttle: mred %u icnt %u raw %d prev %d trial %d"
                   " mcnt %d v %d cmavg %d",
        self->thr_try_mreduce,
        self->thr_inject_cnt,
        self->thr_delay_raw,
        self->thr_delay_prev,
        self->thr_delay_test,
        self->thr_monitor_cnt,
        sensor,
        mavg);
}

static void
throttle_increase(struct throttle *self, uint value)
{
    uint  delta = 0;
    ulong debug = self->thr_rp->throttle_debug;

    assert(self->thr_state == THROTTLE_INCREASE);

    if (value >= 2000) {
        if (self->thr_delay_idelta)
            delta = 2 * self->thr_delay_idelta;
        else
            delta = self->thr_delay_raw / 15;

        delta = max_t(uint, delta, 1);

        if (!self->thr_delay_raw)
            delta = THROTTLE_DELAY_MIN;

        self->thr_skip_cnt = 40;
    } else if (value >= 1800) {
        delta = max_t(uint, self->thr_delay_raw / 10, 1);
        self->thr_skip_cnt = 40;
    } else if (value > 1100) {
        delta = max_t(uint, self->thr_delay_raw / 20, 1);
        self->thr_skip_cnt = 32;
    } else if (value >= 1000) {
        delta = max_t(uint, self->thr_delay_raw / 100, 1);
        self->thr_skip_cnt = 24;
    }

    /* Reset the moving average when the sleep time is adjusted. */
    if (self->thr_delay_raw + delta > self->thr_delay_raw) {
        self->thr_delay_idelta = delta;
        self->thr_delay_raw += delta;
        self->thr_delay_raw = min_t(uint, self->thr_delay_raw, THROTTLE_DELAY_MAX);
        throttle_reset_mavg(self);
    } else {
        /* Record the min sleep value that worked in the last 10 s */
        if (!self->thr_delay_min || self->thr_delay_raw >= self->thr_delay_min) {
            self->thr_delay_min = self->thr_delay_raw;
            self->thr_lmin_cycles = self->thr_cycles;
        }

        self->thr_state = THROTTLE_NO_CHANGE;
        self->thr_try_mreduce = false;
        self->thr_monitor_cnt = 0;
        self->thr_delay_idelta = 0;
        self->thr_delay_test = 0;
        self->thr_skip_cnt = 0;
    }

    if (debug & THROTTLE_DEBUG_DELAYV)
        throttle_debug(self);
}

static void
throttle_reset_state(struct throttle *self)
{
    self->thr_state = THROTTLE_NO_CHANGE;
    self->thr_longest_run = 0;
    self->thr_monitor_cnt = 0;
    self->thr_num_tries = 0;
    self->thr_skip_cnt = self->thr_skip_cycles;

    throttle_reset_mavg(self);
}

static void
throttle_decrease(struct throttle *self, uint svalue)
{
    ulong debug = self->thr_rp->throttle_debug;
    int   delta = self->thr_delay_prev - self->thr_delay_test;

    assert(delta > 0);

    /* Don't attempt to go faster if the tree is out of shape */
    if (self->thr_csched >= THROTTLE_SENSOR_SCALE) {
        self->thr_delay_raw = self->thr_delay_prev;
        throttle_reset_state(self);
        return;
    }

    /* Inject a reduced delay for inject_cnt cycles */
    if (self->thr_inject_cnt > 0) {
        self->thr_inject_cnt--;
        if (self->thr_inject_cnt == 0)
            self->thr_delay_raw = self->thr_delay_prev;
    }

    /* Track the longest run of high sensor values */
    if (svalue >= THROTTLE_SENSOR_SCALE) {
        if (self->thr_longest_run > 0)
            self->thr_longest_run++;
        else
            self->thr_longest_run = 1;
    } else {
        self->thr_longest_run = 0;
    }

    if (self->thr_longest_run >= THROTTLE_MAX_RUN) {
        /*
         * Since the reduced delay isn't sustainable, attempt to
         * reduce the delay by only half as much the next time around.
         */
        self->thr_delay_raw = self->thr_delay_prev;
        self->thr_delay_test = self->thr_delay_prev - delta / 2;

        /*
         * Turn off the multiplicative decrease in sleep time.
         */
        if (unlikely(self->thr_try_mreduce)) {
            self->thr_try_mreduce = false;
            self->thr_delay_test = 0;
        }

        if (debug & THROTTLE_DEBUG_REDUCE)
            throttle_reduce_debug(self, svalue, 0);

        throttle_reset_state(self);
    } else {
        /* This trial succeeded and didn't report a long run of high
         * sensor values. Repeat THROTTLE_TRIAL times.
         */
        self->thr_monitor_cnt++;
        if (self->thr_monitor_cnt >=
            (self->thr_inject_cycles * (self->thr_num_tries + 1) + self->thr_delta_cycles)) {
            self->thr_longest_run = 0;
            self->thr_monitor_cnt = 0;
            self->thr_num_tries++;
            self->thr_delay_raw = self->thr_delay_test;

            if (self->thr_num_tries < self->thr_max_tries) {
                self->thr_inject_cnt = self->thr_inject_cycles * (self->thr_num_tries + 1);
            } else {
                /*
                 * Set the sleep value to the reduced one.
                 * Try a multiplicative decrease next time so
                 * long as the mavg sensor value remains below
                 * THROTTLE_SENSOR_SCALE/2.
                 */
                self->thr_try_mreduce = true;
                if (self->thr_delay_test >= delta)
                    self->thr_delay_test -= delta;

                if (debug & THROTTLE_DEBUG_REDUCE)
                    throttle_reduce_debug(self, svalue, 0);

                throttle_reset_state(self);
            }
        }
    }
}

static void
throttle_switch_state(struct throttle *self, enum throttle_state state, uint max)
{
    assert(max <= 2 * THROTTLE_SENSOR_SCALE);

    if (self->thr_state != state) {
        assert(self->thr_state == THROTTLE_NO_CHANGE);
        self->thr_state = state;
    }

    assert(self->thr_state == state);
    if (state == THROTTLE_DECREASE) {
        throttle_decrease(self, max);
    } else {
        assert(state == THROTTLE_INCREASE);
        if (self->thr_mavg.tm_sample_cnt >= THROTTLE_SMAX_CNT)
            throttle_increase(self, self->thr_mavg.tm_curr);
    }
}

void
throttle_update(struct throttle *self)
{
    struct throttle_mavg *mavg = &self->thr_mavg;
    uint                  max_val = 0;
    int                   i, diff;
    ulong                 debug = self->thr_rp->throttle_debug;

    for (i = 0; i < THROTTLE_SENSOR_CNT; i++) {
        uint tmp = atomic_read(&self->thr_sensorv[i].ts_sensor);
        uint cidx = UINT_MAX;
        bool ignore = false;

        tmp = min_t(uint, tmp, 2 * THROTTLE_SENSOR_SCALE);

        switch (i) {
            case THROTTLE_SENSOR_CSCHED:
                ignore = true;
                self->thr_csched = tmp;
                cidx = PERFC_DI_THSR_CSCHED;
                break;
            case THROTTLE_SENSOR_C0SK:
                cidx = PERFC_DI_THSR_C0SK;
                break;
            case THROTTLE_SENSOR_C0SKM_DTIME:
                cidx = PERFC_DI_THSR_C0SKM_DTIME;
                break;
            case THROTTLE_SENSOR_C0SKM_DSIZE:
                cidx = PERFC_DI_THSR_C0SKM_DSIZE;
                break;
        }

        /* Ignore csched sensor while calculating mavg. */
        if (tmp > max_val && !ignore)
            max_val = tmp;

        assert(cidx != UINT_MAX);
        perfc_rec_sample(&self->thr_sensor_perfc, cidx, tmp);
    }

    perfc_rec_sample(&self->thr_sensor_perfc, PERFC_DI_THSR_MAX, max_val);

    if (self->thr_skip_cnt > 0) {
        /*
         * Skip the read sensor values for thr_skip_cnt cycles.
         * This is done when the sleep value has just been reduced.
         */
        self->thr_skip_cnt--;
    } else {
        /* Compute the moving average of max sensor values. */
        int idx = mavg->tm_idx;

        assert(idx >= 0 && idx < THROTTLE_SMAX_CNT);

        if (mavg->tm_sample_cnt >= THROTTLE_SMAX_CNT) {
            assert(mavg->tm_sample_cnt == THROTTLE_SMAX_CNT);
            assert(mavg->tm_sum >= mavg->tm_samples[idx]);
            mavg->tm_sum -= mavg->tm_samples[idx];
        } else {
            assert(mavg->tm_sample_cnt < THROTTLE_SMAX_CNT);
            mavg->tm_sample_cnt++;
        }

        assert(idx < THROTTLE_SMAX_CNT);
        mavg->tm_samples[idx] = max_val;
        mavg->tm_sum += max_val;

        mavg->tm_idx++;
        if (mavg->tm_idx >= THROTTLE_SMAX_CNT)
            mavg->tm_idx = 0;

        assert(mavg->tm_sample_cnt > 0);
        assert(mavg->tm_sample_cnt <= THROTTLE_SMAX_CNT);
        mavg->tm_curr = mavg->tm_sum / mavg->tm_sample_cnt;

        perfc_rec_sample(&self->thr_sensor_perfc, PERFC_DI_THSR_MAVG, mavg->tm_curr);
    }

    if (self->thr_state != THROTTLE_NO_CHANGE) {
        throttle_switch_state(self, self->thr_state, max_val);
    } else if (mavg->tm_sample_cnt >= THROTTLE_SMAX_CNT) {
        assert(mavg->tm_sample_cnt == THROTTLE_SMAX_CNT);
        assert(self->thr_skip_cnt == 0);

        if (mavg->tm_curr >= THROTTLE_SENSOR_SCALE) {
            throttle_switch_state(self, THROTTLE_INCREASE, max_val);
        } else {
            uint cmavg;
            bool reduce = false;

            if (self->thr_monitor_cnt)
                self->thr_reduce_sum += max_val;
            else
                self->thr_reduce_sum = mavg->tm_curr;

            self->thr_monitor_cnt++;
            cmavg = self->thr_reduce_sum / self->thr_monitor_cnt;

            /* Switch off multiplicative acceleration when
             * the cmavg exceeds a threshold. */
            if (self->thr_try_mreduce && cmavg >= THROTTLE_SENSOR_SCALE / 2)
                self->thr_try_mreduce = false;

            if (self->thr_monitor_cnt >= self->thr_reduce_cycles &&
                cmavg < THROTTLE_SENSOR_SCALE * 9 / 10) {
                reduce = true;
                self->thr_max_tries = 5;
            } else if (
                cmavg < THROTTLE_SENSOR_SCALE / 4 &&
                self->thr_monitor_cnt >= self->thr_reduce_cycles / 4) {
                reduce = true;
                self->thr_max_tries = 2;
            }

            /*
             * If the moving average has remained low for at least
             * thr_reduce_cycles, attempt to reduce the
             * sleep value.
             */
            if (reduce && self->thr_csched < THROTTLE_SENSOR_SCALE) {
                int del = self->thr_delay_raw - self->thr_delay_test;

                if (unlikely(self->thr_try_mreduce))
                    del *= 2;

                if (del <= 0 || del >= self->thr_delay_raw) {
                    diff = THROTTLE_SENSOR_SCALE - cmavg;
                    diff *= 100;
                    diff /= THROTTLE_SENSOR_SCALE;

                    if (diff >= 90)
                        del = self->thr_delay_raw / 2;
                    else if (diff >= 15)
                        del = self->thr_delay_raw / 10;
                    else if (diff > 5 && diff < 15)
                        del = self->thr_delay_raw / 100;
                }

                if (del > 0) {
                    self->thr_delay_prev = self->thr_delay_raw;
                    self->thr_delay_raw -= del;
                    self->thr_delay_test = self->thr_delay_raw;
                    self->thr_inject_cnt = self->thr_inject_cycles;
                    self->thr_num_tries = 0;
                    self->thr_monitor_cnt = 0;

                    if (debug & THROTTLE_DEBUG_REDUCE)
                        throttle_reduce_debug(self, 0, cmavg);

                    throttle_switch_state(self, THROTTLE_DECREASE, max_val);

                    throttle_reset_mavg(self);
                }
            }
        }
    }

    perfc_rec_sample(&self->thr_sleep_perfc, PERFC_DI_THR_SVAL, self->thr_delay_raw);

    if (debug & THROTTLE_DEBUG_DELAYV) {
        if (self->thr_cycles % 24000 == 0)
            throttle_debug(self);
    }
}

void
throttle_debug(struct throttle *self)
{
    hse_log(
        HSE_NOTICE "throttle: delay %d min %d mavg %d cnt %d state %d"
                   " sensors %d %d %d",
        self->thr_delay_raw,
        self->thr_delay_min,
        self->thr_mavg.tm_curr,
        self->thr_monitor_cnt,
        self->thr_state,
        atomic_read(&self->thr_sensorv[0].ts_sensor),
        atomic_read(&self->thr_sensorv[1].ts_sensor),
        atomic_read(&self->thr_sensorv[2].ts_sensor));
}

long
throttle(struct throttle *self, u64 start, u32 len)
{
    struct timespec timespec;

    long target, elapsed, now, delay;
    u64  frac, calls, cycles;
    uint pct;

    target = (u64)self->thr_delay_raw * len / 1024;

    now = get_time_ns();
    elapsed = now - start;
    delay = target - elapsed;
    if (delay < 128)
        return 0;

    if (now >= atomic64_read(&self->thr_next) && spin_trylock(&self->thr_lock)) {
        ulong debug = 0;

        /* Update thr_next ASAP to stave off trylock attempts.
         */
        atomic64_set(&self->thr_next, now + NSEC_PER_SEC / 7);

        /* Compute and update the percentage of requests
         * that should skip the call to nanosleep().
         */
        calls = atomic64_read(&self->thr_data);
        atomic64_sub(calls, &self->thr_data);

        frac = calls >> 32;
        calls &= 0xffffffff;
        pct = frac / (calls | 1);
        pct = clamp_t(uint, pct, 0, 126); /* limit to 98% */
        atomic_set(&self->thr_pct, pct);

        if (now > self->thr_update) {
            self->thr_nslpmin = self->thr_rp->throttle_sleep_min_ns;
            self->thr_update = now + NSEC_PER_SEC;
            debug = self->thr_rp->throttle_debug;
        }
        spin_unlock(&self->thr_lock);

        if (debug & THROTTLE_DEBUG_DELAYV)
            throttle_debug(self);

        if (!(debug & THROTTLE_DEBUG_DELAY))
            return 0;

        hse_log(
            HSE_NOTICE "%s: nslpmin %lu target %ld elapsed %ld delay %ld "
                       "calls %lu pct %u",
            __func__,
            self->thr_rp->throttle_sleep_min_ns,
            target,
            elapsed,
            delay,
            (ulong)calls,
            pct);

        return 0;
    }

    cycles = get_cycles(); /* Use TSC as an RNG */

    if (cycles % 128 < atomic_read(&self->thr_pct))
        return 0;

    /* The system adds an additional 50us to each nanosleep() request,
     * and an additional 50us for requests larger than roughly 400us.
     * thr_nslpmin is the minimum overhead we measured in
     * c0sk_calibrate().  We subtract nslpmin from only a fraction
     * of the requests smaller than nslpmin to avoid boxcarring of
     * threads in the next timer slot.
     */
    if (delay > self->thr_nslpmin) {
        if (delay > self->thr_nslpmin * 8)
            delay -= self->thr_nslpmin;
        delay -= self->thr_nslpmin;
        delay = min(delay, NSEC_PER_SEC - 1);
    } else if (cycles % 64 < 8) {
        delay = 100;
    }

    timespec.tv_nsec = delay;
    timespec.tv_sec = 0;
    nanosleep(&timespec, 0);

    /* Compute the requested delay time vs actual response time
     * as a percentage (scaled to 128).
     */
    elapsed = get_time_ns() - now;
    frac = (delay * 128) / (elapsed | 1);
    if (frac > 128)
        frac = 128;
    frac = 128 - frac;

    /* Add frac to the cumulative frac count in the upper 32 bits,
     * and add 1 to the cumulative call count in the lower 32 bits.
     */
    atomic64_add(frac << 32 | 1, &self->thr_data);

    return elapsed;
}

bool
throttle_active(struct throttle *self)
{
    return (self->thr_rp->throttle_disable) ? false : (self->thr_delay_raw != 0);
}
