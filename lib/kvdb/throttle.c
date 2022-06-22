/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/minmax.h>
#include <hse_util/assert.h>
#include <hse_util/inttypes.h>
#include <hse/logging/logging.h>
#include <hse_util/perfc.h>
#include <hse_util/page.h>

#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/throttle_perfc.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>

#include <hse/kvdb_perfc.h>

/* clang-format off */

static struct perfc_name throttle_sen_perfc[] _dt_section = {
    NE(PERFC_BA_THSR_CNROOT,   1, "csched root sensor",         "thsr_cnroot"),
    NE(PERFC_BA_THSR_C0SK,     1, "c0sk ingest queue sensor",   "thsr_c0sk"),
    NE(PERFC_BA_THSR_WAL,      1, "wal buffer length sensor",   "thsr_wal"),
    NE(PERFC_BA_THSR_MAX,      1, "max sensor",                 "thsr_max"),
    NE(PERFC_BA_THSR_MAVG,     1, "mavg sensor",                "thsr_mavg"),
};

NE_CHECK(throttle_sen_perfc, PERFC_EN_THSR, "perfc table/enum mismatch");

static struct perfc_name throttle_sleep_perfc[] _dt_section = {
    NE(PERFC_BA_THR_SVAL, 2, "throttle sleep", "thr_sleep"),
};

NE_CHECK(throttle_sleep_perfc, PERFC_EN_THR_MAX, "perfc table/enum mismatch");

/* clang-format on */

void
throttle_init(struct throttle *self, struct kvdb_rparams *rp, const char *kvdb_alias)
{
    char group[128];
    int i;

    assert(IS_ALIGNED((uintptr_t)self, __alignof__(*self)));

    snprintf(group, sizeof(group), "kvdbs/%s", kvdb_alias);

    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->thr_lock);
    self->thr_rp = rp;

    for (i = 0; i < THROTTLE_SENSOR_CNT; i++)
        atomic_set(&self->thr_sensorv[i].ts_sensor, 0);

    perfc_alloc(throttle_sen_perfc, group, "set", rp->perfc_level, &self->thr_sensor_perfc);
    perfc_alloc(throttle_sleep_perfc, group, "set", rp->perfc_level, &self->thr_sleep_perfc);
}

void
throttle_init_params(struct throttle *self, struct kvdb_rparams *rp)
{
    u32 time_ms;

    self->thr_delay = rp->throttle_init_policy;

    if (self->thr_rp->throttle_debug_intvl_s == 0) {
        log_warn("Invalid setting for throttle_debug_intvl_s: %u, using 1",
                 self->thr_rp->throttle_debug_intvl_s);
        self->thr_rp->throttle_debug_intvl_s = 1U;
    }

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

    log_info(
        "delay %d u_ms %d rcycles %d icycles %d scycles %d dcycles %d",
        self->thr_delay,
        self->thr_update_ms,
        self->thr_reduce_cycles,
        self->thr_inject_cycles,
        self->thr_skip_cycles,
        self->thr_delta_cycles);
}

void
throttle_fini(struct throttle *self)
{
    perfc_free(&self->thr_sleep_perfc);
    perfc_free(&self->thr_sensor_perfc);
}

static void
throttle_reset_mavg(struct throttle *self)
{
    self->thr_mavg.tm_curr = 0;
    self->thr_mavg.tm_idx = 0;
    self->thr_mavg.tm_sum = 0;
    self->thr_mavg.tm_sample_cnt = 0;

    perfc_set(&self->thr_sensor_perfc, PERFC_BA_THSR_MAVG, 0);
}

void
throttle_reduce_debug(struct throttle *self, uint sensor, uint mavg)
{
    log_info(
        "icnt %u raw %d prev %d trial %d mcnt %d v %d cmavg %d",
        self->thr_inject_cnt,
        self->thr_delay,
        self->thr_delay_prev,
        self->thr_delay_test,
        self->thr_monitor_cnt,
        sensor,
        mavg);
}

static void
throttle_increase(struct throttle *self, uint value)
{
    uint delta = 0;

    assert(self->thr_state == THROTTLE_INCREASE);

    if (value >= 2000) {
        if (self->thr_delay_idelta)
            delta = 2 * self->thr_delay_idelta;
        else
            delta = self->thr_delay / 15;

        delta = max_t(uint, delta, 1);

        if (!self->thr_delay)
            delta = THROTTLE_DELAY_MIN;

        self->thr_skip_cnt = 40;
    } else if (value >= 1800) {
        delta = max_t(uint, self->thr_delay / 10, 1);
        self->thr_skip_cnt = 40;
    } else if (value > 1100) {
        delta = max_t(uint, self->thr_delay / 20, 1);
        self->thr_skip_cnt = 32;
    } else if (value >= 1000) {
        delta = max_t(uint, self->thr_delay / 100, 1);
        self->thr_skip_cnt = 24;
    }

    /* Reset the moving average when the sleep time is adjusted. */
    if (self->thr_delay + delta > self->thr_delay) {
        self->thr_delay_idelta = delta;
        self->thr_delay += delta;
        self->thr_delay = min_t(uint, self->thr_delay, THROTTLE_DELAY_MAX);
        throttle_reset_mavg(self);
    } else {
        /* Record the min sleep value that worked in the last 10 s */
        if (!self->thr_delay_min || self->thr_delay >= self->thr_delay_min) {
            self->thr_delay_min = self->thr_delay;
            self->thr_lmin_cycles = self->thr_cycles;
        }

        self->thr_state = THROTTLE_NO_CHANGE;
        self->thr_monitor_cnt = 0;
        self->thr_delay_idelta = 0;
        self->thr_delay_test = 0;
        self->thr_skip_cnt = 0;
    }
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

    /* Inject a reduced delay for inject_cnt cycles */
    if (self->thr_inject_cnt > 0) {
        self->thr_inject_cnt--;
        if (self->thr_inject_cnt == 0)
            self->thr_delay = self->thr_delay_prev;
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
        self->thr_delay = self->thr_delay_prev;
        self->thr_delay_test = self->thr_delay_prev - delta / 2;

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
            self->thr_delay = self->thr_delay_test;

            if (self->thr_num_tries < self->thr_max_tries) {
                self->thr_inject_cnt = self->thr_inject_cycles * (self->thr_num_tries + 1);
            } else {
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

    if (self->thr_rp->throttle_disable)
        return;

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

uint
throttle_update(struct throttle *self)
{
    struct throttle_mavg *mavg = &self->thr_mavg;
    u32                   max_val = 0;
    u64                   debug = self->thr_rp->throttle_debug;

    for (int i = 0; i < THROTTLE_SENSOR_CNT; i++) {
        u32  tmp = atomic_read(&self->thr_sensorv[i].ts_sensor);
        u32  cidx = UINT_MAX;

        tmp = min_t(uint, tmp, 2 * THROTTLE_SENSOR_SCALE);

        switch (i) {
            case THROTTLE_SENSOR_CNROOT:
                cidx = PERFC_BA_THSR_CNROOT;
                break;
            case THROTTLE_SENSOR_C0SK:
                cidx = PERFC_BA_THSR_C0SK;
                break;
            case THROTTLE_SENSOR_WAL:
                cidx = PERFC_BA_THSR_WAL;
                break;
        }

        /* Ignore csched sensor while calculating mavg. */
        if (tmp > max_val)
            max_val = tmp;

        assert(cidx != UINT_MAX);
        perfc_set(&self->thr_sensor_perfc, cidx, tmp);
    }

    perfc_set(&self->thr_sensor_perfc, PERFC_BA_THSR_MAX, max_val);

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

        perfc_set(&self->thr_sensor_perfc, PERFC_BA_THSR_MAVG, mavg->tm_curr);
    }

    if (HSE_UNLIKELY(self->thr_rp->throttle_disable))
        return 0;

    if (self->thr_state != THROTTLE_NO_CHANGE) {
        throttle_switch_state(self, self->thr_state, max_val);
    } else if (mavg->tm_sample_cnt >= THROTTLE_SMAX_CNT) {
        assert(mavg->tm_sample_cnt == THROTTLE_SMAX_CNT);
        assert(self->thr_skip_cnt == 0);

        if (mavg->tm_curr >= THROTTLE_SENSOR_SCALE) {
            throttle_switch_state(self, THROTTLE_INCREASE, max_val);
        } else {
            const uint cmavg_hi  = THROTTLE_SENSOR_SCALE * 90 / 100;
            const uint cmavg_mid = THROTTLE_SENSOR_SCALE * 25 / 100;
            const uint cmavg_lo  = THROTTLE_SENSOR_SCALE * 10 / 100;
            bool reduce = false;
            uint cmavg;

            if (self->thr_monitor_cnt)
                self->thr_reduce_sum += max_val;
            else
                self->thr_reduce_sum = mavg->tm_curr;

            self->thr_monitor_cnt++;
            cmavg = self->thr_reduce_sum / self->thr_monitor_cnt;

            if (cmavg < cmavg_hi && self->thr_monitor_cnt >= self->thr_reduce_cycles) {
                reduce = true;
                self->thr_max_tries = 5;
            } else if (cmavg < cmavg_mid && self->thr_monitor_cnt >= self->thr_reduce_cycles / 4) {
                reduce = true;
                self->thr_max_tries = 2;
            }

            /*
             * If the moving average has remained low for at least
             * thr_reduce_cycles and the csched sensor is in good
             * shape, then attempt to reduce the trial delay.  Set
             * delay based on where cmavg is in the range 0..1000 as
             * follows:
             *
             *    0..100      reduce delay by pmax (40%)
             *    101..950    scale from pmax down to pmin (1%)
             *    951..1000   do not start trials (system is happy)
             *
             * Reducing delay by p < 1.0 increases rate by a factor of
             * 1/(1-p), so p=0.40 increases rate by factor of 1.66 and
             * p=0.01 increases rate by 1%.
             */
            if (reduce) {
                int delta = self->thr_delay - self->thr_delay_test;
                const double pmax = 0.31; /* max percent reduce when cmavg==lo */
                const double pmin = 0.01; /* min percent reduce when cmavg==hi */
                double p;

                assert(cmavg <= cmavg_hi);

                if (delta <= 0 || delta >= self->thr_delay) {
                    if (cmavg > cmavg_lo)
                        p = pmax - (pmax - pmin) * (cmavg - cmavg_lo) / (cmavg_hi - cmavg_lo);
                    else
                        p = pmax;
                    delta = p * self->thr_delay;
                }

                if (delta > 0) {
                    self->thr_delay_prev = self->thr_delay;
                    self->thr_delay -= delta;
                    self->thr_delay_test = self->thr_delay;
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

    perfc_set(&self->thr_sleep_perfc, PERFC_BA_THR_SVAL, self->thr_delay);

    self->thr_cycles++;
    if (debug & THROTTLE_DEBUG_DELAYV) {
        u32 debug_intvl_cycles = 40U * self->thr_rp->throttle_debug_intvl_s;

        if (self->thr_cycles % debug_intvl_cycles == 0)
            throttle_debug(self);
    }

    return self->thr_delay;
}

void
throttle_debug(struct throttle *self)
{
    log_info(
        "delay %d min %d mavg %d cnt %d state %d sensors %d %d",
        self->thr_delay,
        self->thr_delay_min,
        self->thr_mavg.tm_curr,
        self->thr_monitor_cnt,
        self->thr_state,
        atomic_read(&self->thr_sensorv[0].ts_sensor),
        atomic_read(&self->thr_sensorv[1].ts_sensor));
}
