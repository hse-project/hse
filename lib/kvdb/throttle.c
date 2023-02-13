/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <sys/resource.h>

#include <hse/kvdb_perfc.h>

#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/rparam_debug_flags.h>
#include <hse/ikvdb/throttle.h>
#include <hse/ikvdb/throttle_perfc.h>
#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/event_counter.h>
#include <hse/util/minmax.h>
#include <hse/util/page.h>
#include <hse/util/perfc.h>

/* clang-format off */

static struct perfc_name throttle_sen_perfc[] _dt_section = {
    NE(PERFC_BA_THSR_KVDB,     1, "kvdb put-rate sensor",       "thsr_kvdb"),
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

thread_local struct throttle_tls hse_throttle_tls;

void
throttle_init(struct throttle *self, struct kvdb_rparams *rp, const char *kvdb_alias)
{
    char group[128];

    assert(IS_ALIGNED((uintptr_t)self, __alignof__(*self)));

    snprintf(group, sizeof(group), "kvdbs/%s", kvdb_alias);

    memset(self, 0, sizeof(*self));
    self->thr_rp = rp;

    atomic_set(&self->thr_cntrgen, 0);
    self->thr_tprev = get_time_ns();

    for (uint i = 0; i < THROTTLE_SENSOR_CNT; i++) {
        struct throttle_sensor *ts = self->thr_sensorv + i;

        ts->ts_cntrgenp = &self->thr_cntrgen;
        ts->ts_pspbptp = &self->thr_c0fill_pspbpt;

        for (uint j = 0; j < NELEM(ts->ts_cntrv); ++j)
            atomic_set(&ts->ts_cntrv[j], 0);

        atomic_set(&self->thr_sensorv[i].ts_sensor, 0);
    }

    perfc_alloc(throttle_sen_perfc, group, "set", rp->perfc_level, &self->thr_sensor_perfc);
    perfc_alloc(throttle_sleep_perfc, group, "set", rp->perfc_level, &self->thr_sleep_perfc);
}

void
throttle_init_params(struct throttle *self, struct kvdb_rparams *rp)
{
    self->thr_delay = rp->throttle_init_policy;

    self->thr_c0fill_avg = throttle_raw_to_rate(self->thr_delay);
    if (self->thr_c0fill_avg > rp->throttle_rate_limit)
        self->thr_c0fill_avg = rp->throttle_rate_limit;
    self->thr_c0fill_tdcnt = 32 * 1024;
    self->thr_c0fill_pspbpt = (NSEC_PER_SEC * self->thr_c0fill_tdcnt) / self->thr_c0fill_avg;

    self->thr_c0spill_peak = (self->thr_c0fill_avg * 100) / 85;
    self->thr_c0spill_avg = self->thr_c0spill_peak;
    self->thr_c0spill_avgv[0] = self->thr_c0spill_peak;
    self->thr_c0spill_avgv[1] = self->thr_c0spill_peak;

    if (self->thr_rp->throttle_debug_intvl_s == 0) {
        log_warn(
            "Invalid setting for throttle_debug_intvl_s: %u, using 1",
            self->thr_rp->throttle_debug_intvl_s);
        self->thr_rp->throttle_debug_intvl_s = 1U;
    }

    self->thr_state = THROTTLE_NO_CHANGE;
    self->thr_update_ms = rp->throttle_update_ns / 1000000;

    if (self->thr_update_ms < NSEC_PER_JIFFY / 1000000)
        self->thr_update_ms = NSEC_PER_JIFFY / 1000000;

    if (self->thr_update_ms > THROTTLE_INJECT_MS)
        self->thr_update_ms = THROTTLE_INJECT_MS;

    if (self->thr_update_ms > THROTTLE_REDUCE_MS)
        self->thr_update_ms = THROTTLE_REDUCE_MS;

    if (self->thr_update_ms > THROTTLE_SKIP_MS)
        self->thr_update_ms = THROTTLE_SKIP_MS;

    if (self->thr_update_ms > THROTTLE_DELTA_MS)
        self->thr_update_ms = THROTTLE_DELTA_MS;

    self->thr_inject_cycles = THROTTLE_INJECT_MS / self->thr_update_ms;

    /* Evaluate if we can go faster every 5 seconds) */
    self->thr_reduce_cycles = THROTTLE_REDUCE_MS / self->thr_update_ms;

    /* Skip the first few ms worth of measurements while computing mavg
     * after changing the sleep value.
     */
    self->thr_skip_cycles = THROTTLE_SKIP_MS / self->thr_update_ms;

    /* This is the minimum additional time to wait after reducing the sleep
     * value for sensors to respond.
     */
    self->thr_delta_cycles = THROTTLE_DELTA_MS / self->thr_update_ms;

    log_info(
        "delay %d u_ms %d rcycles %d icycles %d scycles %d dcycles %d", //dnl
        self->thr_delay, self->thr_update_ms, self->thr_reduce_cycles, self->thr_inject_cycles,
        self->thr_skip_cycles, self->thr_delta_cycles);

    hse_timer_cb_register(throttle_update, self, self->thr_update_ms);
}

void
throttle_fini(struct throttle *self)
{
    hse_timer_cb_register(NULL, NULL, 0);
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
        "icnt %u raw %d prev %d trial %d mcnt %d v %d cmavg %d", self->thr_inject_cnt,
        self->thr_delay, self->thr_delay_prev, self->thr_delay_test, self->thr_monitor_cnt, sensor,
        mavg);
}

static void
throttle_increase(struct throttle *self, uint value)
{
    uint delta = 0;

    assert(self->thr_state == THROTTLE_INCREASE);
    assert(self->thr_delay > 0);

    /* The throttle decrease step size increases exponentially
     * with each step of 100 of the sensor value above 1000.
     */
    if (value >= 1000) {
        if (value >= 2000) {
            if (self->thr_delay_idelta)
                delta = 2 * self->thr_delay_idelta;
            else
                delta = self->thr_delay / 15;

            delta = max_t(uint, delta, 1);

        } else if (value >= 1800) {
            delta = max_t(uint, self->thr_delay / 16, 1);
        } else if (value > 1500) {
            delta = max_t(uint, self->thr_delay / 32, 1);
        } else if (value > 1400) {
            delta = max_t(uint, self->thr_delay / 64, 1);
        } else if (value > 1300) {
            delta = max_t(uint, self->thr_delay / 128, 1);
        } else if (value > 1200) {
            delta = max_t(uint, self->thr_delay / 256, 1);
        } else if (value > 1100) {
            delta = max_t(uint, self->thr_delay / 512, 1);
        } else if (value >= 1000) {
            delta = max_t(uint, self->thr_delay / 1024, 1);
        }

        /* Apply smaller steps more frequently than larger steps.
         */
        self->thr_skip_cnt = (self->thr_skip_cycles * (value - 1000)) / 1000;
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
    int delta = self->thr_delay_prev - self->thr_delay_test;

    assert(delta >= 0);

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
            (self->thr_inject_cycles * (self->thr_num_tries + 1) + self->thr_delta_cycles))
        {
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

void
throttle_update(void *arg)
{
    struct throttle *self = arg;
    const struct kvdb_rparams *rp = self->thr_rp;
    struct throttle_mavg *mavg = &self->thr_mavg;
    uint64_t fill_rate = 0, c0spill_rate = 0;
    uint64_t now, tdelta, gen, pspbpt, rate;
    uint c0spill_tdcnt = 0;
    uint c0spill_sval = 0;
    uint fill_tdcnt = 0;
    uint c0sk_sval = 0;
    uint max_sval = 0;

    /* Advance the put-counter generation, then read the number of bytes
     * put and number of threads active in the last generation.  We use
     * this info to compute the current and average app thread put-rate.
     */
    gen = atomic_inc_return(&self->thr_cntrgen);
    gen %= NELEM(((struct throttle_sensor *)0)->ts_cntrv);

    now = get_time_ns();
    tdelta = now - self->thr_tprev;
    self->thr_tprev = now;

    for (int i = 0; i < THROTTLE_SENSOR_CNT; i++) {
        struct throttle_sensor *ts = self->thr_sensorv + i;
        atomic_uint_fast64_t *cntrp;
        uint64_t cntr_val;
        uint32_t cidx;
        uint sval;

        cntrp = &ts->ts_cntrv[gen];
        cntr_val = atomic_read(cntrp);
        atomic_sub_rel(cntrp, cntr_val);

        sval = atomic_read(&ts->ts_sensor);
        sval = min_t(uint, sval, 2 * THROTTLE_SENSOR_SCALE);

        switch (i) {
        case THROTTLE_SENSOR_KVDB:
            cidx = PERFC_BA_THSR_KVDB;
            fill_rate = ((cntr_val >> 20) * NSEC_PER_SEC) / tdelta;
            fill_tdcnt = cntr_val & 0xfffffu;
            break;

        case THROTTLE_SENSOR_CNROOT:
            cidx = PERFC_BA_THSR_CNROOT;
            break;

        case THROTTLE_SENSOR_C0SK:
            cidx = PERFC_BA_THSR_C0SK;
            c0spill_rate = ((cntr_val >> 20) * NSEC_PER_SEC) / tdelta;
            c0spill_tdcnt = cntr_val & 0xfffffu;
            c0sk_sval = sval;

            self->thr_c0spill_sval =
                (self->thr_c0spill_sval * 255 + min_t(uint, sval, 1051) * 1024) / 256;
            c0spill_sval = self->thr_c0spill_sval / 1024;
            assert(c0spill_sval <= 1051);
            if (sval < c0spill_sval)
                sval = c0spill_sval;
            break;

        case THROTTLE_SENSOR_WAL:
            cidx = PERFC_BA_THSR_WAL;
            break;

        default:
            assert(0);
            continue;
        }

        if (sval > max_sval)
            max_sval = sval;

        perfc_set(&self->thr_sensor_perfc, cidx, sval);
    }

    perfc_set(&self->thr_sensor_perfc, PERFC_BA_THSR_MAX, max_sval);

    self->thr_c0fill_tdcnt = (self->thr_c0fill_tdcnt * 31 + fill_tdcnt * 1024) / 32;
    self->thr_c0fill_avg = (self->thr_c0fill_avg * 31 + fill_rate) / 32;

    if (c0spill_rate > 0) {
        uint idx = (c0spill_tdcnt > 1);

        if (c0spill_rate > self->thr_c0spill_peak) {
            self->thr_c0spill_peak = c0spill_rate;
            self->thr_c0spill_avg = (self->thr_c0spill_avg + c0spill_rate) / 2;
            self->thr_report = now;
        } else {
            uint64_t div = (c0sk_sval < 900) ? 1024 : 128;

            self->thr_c0spill_avg = (self->thr_c0spill_avg * (div - 1) + c0spill_rate) / div;
        }

        self->thr_c0spill_avgv[idx] = (self->thr_c0spill_avgv[idx] * 31 + c0spill_rate) / 32;

        if (c0sk_sval >= 951 && c0sk_sval < 1000) {
            if (self->thr_c0spill_avg > self->thr_c0spill_high) {
                self->thr_c0spill_high = self->thr_c0spill_avg;
                self->thr_report = now;
            }
        }
    }

    rate = throttle_raw_to_rate(self->thr_delay);

    if (self->thr_c0fill_tdcnt > 0) {
        uint64_t clamp, lwm;

        clamp = self->thr_c0spill_high ? self->thr_c0spill_high : self->thr_c0spill_peak;

        /* Reduce limit to allow for WAL, c0 spill, and cN spill
         * all simultaneously writing to media.
         */
        if (clamp < rp->throttle_rate_fastmedia) {
            if (c0sk_sval < 1000) {
                uint64_t avg = self->thr_c0spill_avg;
                uint x = (c0sk_sval / 100) + 1;

                clamp = ((avg * x) + (clamp * (10 - x))) / 10;
            }
        }

        if (clamp > rp->throttle_rate_limit)
            clamp = rp->throttle_rate_limit;

        if (c0sk_sval > 1000) {
            clamp = clamp * (1851 - c0sk_sval) / 1000;

            if (clamp > self->thr_c0spill_high && self->thr_c0spill_high > 0) {
                clamp = self->thr_c0spill_high;
                self->thr_report = now;
                ev_debug(1);
            }

            if (c0sk_sval >= 1051 && rate > clamp) {
                clamp = rate;
                ev_debug(1);
            }
            ev_debug(1);
        }

        clamp = max_t(uint64_t, clamp, 10000000);
        lwm = (clamp * 75) / 100;

        if (now >= self->thr_report) {
            const uint64_t report_ns = NSEC_PER_SEC * 1;

            self->thr_report = roundup(now + report_ns, report_ns) - report_ns;

            log_info(
                "%4u %3u  avg %4lu -> %lu (%lu,%lu)  c0 %lu %lu %4lu  thr %4lu %4lu  dly %6lu %u",
                c0sk_sval, c0spill_sval, self->thr_c0fill_avg / 1000000,
                self->thr_c0spill_avg / 1000000, self->thr_c0spill_avgv[0] / 1000000,
                self->thr_c0spill_avgv[1] / 1000000, self->thr_c0spill_peak / 1000000,
                self->thr_c0spill_high / 1000000, c0spill_rate / 1000000, rate / 1000000,
                clamp / 1000000, self->thr_c0fill_pspbpt, self->thr_delay);
        }

        /* Apply the clamped resource rate limit only if the application's
         * average put rate exceeds both it and the throttle sensor rate
         * limit.
         */
        if (self->thr_c0fill_avg > lwm) {
            if (self->thr_c0fill_avg >= clamp && rate >= clamp) {
                rate = (rate * 31 + clamp) / 32;

                self->thr_delay = throttle_rate_to_raw(rate);
                self->thr_delay_prev = self->thr_delay;
                self->thr_delay_test = self->thr_delay;
                throttle_reset_state(self);

                if (max_sval < THROTTLE_SENSOR_SCALE)
                    max_sval = THROTTLE_SENSOR_SCALE;
                ev_debug(1);
            } else {
                if (rate > lwm && max_sval < 900) {
                    uint sval;

                    /* Reduce the throttle decrease rate as we approach the clamp rate.
                     */
                    sval = min_t(uint, (rate * 900) / clamp, 900);

                    if (max_sval < sval)
                        max_sval = sval;
                    ev_debug(1);
                }
            }
        }

        assert(rate > 0);

        /* If the put rate in the last interval is less than half the throttle rate
         * then reduce the per-byte delay amount.
         */
        if (c0spill_sval < THROTTLE_SENSOR_SCALE / 2 && self->thr_c0fill_avg < rate / 2) {
            ev_debug(1);
            rate *= 2;
        }
    }

    /* Convert rate to picoseconds-per-byte-per-thread (scaling 1000 picoseconds
     * to 1024 via tdcnt for conversion efficiency).  The extra precision allows
     * combinations tdcnt and rate that would otherwise yield zero nanoseconds.
     */
    pspbpt = (NSEC_PER_SEC * self->thr_c0fill_tdcnt) / rate;

    self->thr_c0fill_pspbpt = (self->thr_c0fill_pspbpt * 31 + pspbpt) / 32;

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
        mavg->tm_samples[idx] = max_sval;
        mavg->tm_sum += max_sval;

        mavg->tm_idx++;
        if (mavg->tm_idx >= THROTTLE_SMAX_CNT)
            mavg->tm_idx = 0;

        assert(mavg->tm_sample_cnt > 0);
        assert(mavg->tm_sample_cnt <= THROTTLE_SMAX_CNT);
        mavg->tm_curr = mavg->tm_sum / mavg->tm_sample_cnt;

        perfc_set(&self->thr_sensor_perfc, PERFC_BA_THSR_MAVG, mavg->tm_curr);
    }

    if (HSE_UNLIKELY(rp->throttle_disable))
        return;

    if (self->thr_state != THROTTLE_NO_CHANGE) {
        throttle_switch_state(self, self->thr_state, max_sval);
    } else if (mavg->tm_sample_cnt >= THROTTLE_SMAX_CNT) {
        assert(mavg->tm_sample_cnt == THROTTLE_SMAX_CNT);
        assert(self->thr_skip_cnt == 0);

        if (mavg->tm_curr >= THROTTLE_SENSOR_SCALE) {
            throttle_switch_state(self, THROTTLE_INCREASE, max_sval);
        } else {
            const uint cmavg_hi = THROTTLE_SENSOR_SCALE * 90 / 100;
            const uint cmavg_mid = THROTTLE_SENSOR_SCALE * 25 / 100;
            const uint cmavg_lo = THROTTLE_SENSOR_SCALE * 10 / 100;
            bool reduce = false;
            uint cmavg;

            if (self->thr_monitor_cnt)
                self->thr_reduce_sum += max_sval;
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
             *    0..100      reduce delay by pmax (23%)
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
                    if (self->thr_delay - delta < THROTTLE_DELAY_MIN)
                        delta = self->thr_delay - THROTTLE_DELAY_MIN;

                    self->thr_delay_prev = self->thr_delay;
                    self->thr_delay -= delta;
                    self->thr_delay_test = self->thr_delay;
                    self->thr_inject_cnt = self->thr_inject_cycles;
                    self->thr_num_tries = 0;
                    self->thr_monitor_cnt = 0;

                    if (rp->throttle_debug & THROTTLE_DEBUG_REDUCE)
                        throttle_reduce_debug(self, 0, cmavg);

                    throttle_switch_state(self, THROTTLE_DECREASE, max_sval);

                    throttle_reset_mavg(self);
                }
            }
        }
    }

    perfc_set(&self->thr_sleep_perfc, PERFC_BA_THR_SVAL, self->thr_delay);

    self->thr_cycles++;
    if (rp->throttle_debug & THROTTLE_DEBUG_DELAYV) {
        uint32_t debug_intvl_cycles = 40U * rp->throttle_debug_intvl_s;

        if (self->thr_cycles % debug_intvl_cycles == 0)
            throttle_debug(self);
    }
}

void
throttle(struct throttle_sensor *self, struct throttle_tls *tls, uint64_t bytes)
{
    uint64_t delay, gen, now, lag;

    tls->bytes += bytes;

    /* If the throttle task has advanced the put-counter generation
     * then we need to update the current generation with this thread's
     * cumulative byte count and presence since the previous generation.
     * The cumulative byte count is added to the upper 44 bits and the
     * the lower 20 bits is incremented to inform the throttle task
     * of this thread's presence within the generation window.
     */
    gen = atomic_read_acq(self->ts_cntrgenp);
    if (gen > tls->cntrgen) {
        atomic_ulong *cntrp = &self->ts_cntrv[gen % NELEM(self->ts_cntrv)];

        /* Average out the byte count if we missed a generation.
         */
        if (gen - tls->cntrgen > 1)
            tls->bytes /= (gen - tls->cntrgen);

        if (tls->bytes > 1024)
            atomic_add(cntrp, (tls->bytes << 20) | 1);

        tls->bytes = 0;
        tls->cntrgen = gen;
        tls->slack = timer_slack;
    }

    /* Convert from picoseconds-per-byte-per-thread to nanoseconds
     * (throttle task scales 1000 picoseconds to 1024 picoseconds).
     */
    delay = (bytes * *self->ts_pspbptp) / 1024 + tls->resid;

    now = get_time_ns();

    lag = now - tls->tprev;
    tls->resid = delay;
    tls->tprev = now;

    if (delay > lag) {
        delay -= lag;

        if (delay > tls->slack * 16) {
            struct timespec req;

            tls->resid = 0;
            delay -= tls->slack;

            req.tv_sec = delay / NSEC_PER_SEC;
            req.tv_nsec = delay % NSEC_PER_SEC;

            nanosleep(&req, NULL);
        }
    }
}

void
throttle_debug(struct throttle *self)
{
    log_info(
        "delay %d min %d mavg %d cnt %d state %d sensors %d %d", self->thr_delay,
        self->thr_delay_min, self->thr_mavg.tm_curr, self->thr_monitor_cnt, self->thr_state,
        atomic_read(&self->thr_sensorv[0].ts_sensor), atomic_read(&self->thr_sensorv[1].ts_sensor));
}
