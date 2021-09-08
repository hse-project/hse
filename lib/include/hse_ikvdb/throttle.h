/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_THROTTLE_H
#define HSE_KVDB_THROTTLE_H

#include <hse_util/atomic.h>
#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>
#include <hse_util/arch.h>
#include <hse_util/spinlock.h>
#include <hse_util/perfc.h>
#include <hse_util/condvar.h>

/* clang-format off */

enum {
    THROTTLE_SENSOR_CSCHED_ROOT,
    THROTTLE_SENSOR_C0SK,
    THROTTLE_SENSOR_WAL,
    THROTTLE_SENSOR_CNT
};

/* Raw delay values.
 * Use throttle_raw_to_rate to convert to byte rate.
 * Comments show the corresponding rate.
 */
#define THROTTLE_DELAY_MAX           268435456  /*        500,000  bytes/sec */
#define THROTTLE_DELAY_START_DEFAULT   4194303  /*     32,000,007  bytes/sec */
#define THROTTLE_DELAY_START_MEDIUM     731241  /*    183,547,869  bytes/sec */
#define THROTTLE_DELAY_START_LIGHT      251137  /*    534,440,277  bytes/sec */
#define THROTTLE_DELAY_MIN                8192  /* 16,384,000,000  bytes/sec */

#define THROTTLE_SMAX_CNT          24
#define THROTTLE_REDUCE_CYCLES    200
#define THROTTLE_INJECT_MS        200
#define THROTTLE_SKIP_CYCLES       20
#define THROTTLE_DELTA_CYCLES      32
#define THROTTLE_LMAX_CYCLES      400
#define THROTTLE_SENSOR_SCALE    1000
#define THROTTLE_MAX_RUN            6

/* clang-format on */

/**
 * struct throttle_sensor - throttle sensor
 *
 * Modules that provide throttler input (e.g., c0 and cn) should
 * periodically update their respective sensors to indicate their workload.
 * Sensors should be set to a value between 0 and 2 * THROTTLE_SENSOR_SCALE.
 *
 * Guidelines for setting sensor values:
 *
 *  - The value should reflect the current workload and should not include
 *    hysteresis (hysteresis is implemented in the throttler code that reads
 *    sensors).
 *
 *  - A value of 0 indicates a workload below a low water mark.
 *
 *  - Values between 0 and THROTTLE_SENSOR_SCALE indicate a workload between
 *    low and high water marks.
 *
 *  - Values between THROTTLE_SENSOR_SCALE and 2*THROTTLE_SENSOR_SCALE
 *    indicate a workload between a high water mark and ceiling.
 *
 *  - The value should be a linear indication of workload, for example, a
 *    value of THROTTLE_SENSOR_SCALE / 10 should indicate a workload 10% into
 *    the range between the low and high water marks.
 *
 * For example, suppose c0's workload is determined by the amount of memory
 * (M) consumed by c0 kvms that have not yet been ingested to cN, and that c0
 * is configured with three thresholds for memory consumption: LOW, HIGH, and
 * MAX.  Then c0 might set the sensor value as follows:
 *
 *    if (M < LOW)
 *        sensor = 0;
 *
 *    if (LOW <= M < HIGH)
 *        sensor = THROTTLE_SENSOR_SCALE * (M - LOW) / (HIGH - LOW);
 *
 *    if (HIGH <= M < MAX)
 *        sensor = THROTTLE_SENSOR_SCALE * (M - HIGH) / (MAX - HIGH);
 *
 * Note, this throttling approach is based on c0sk throttling behavior prior
 * implementation of 'struct throttle'.
 */
struct throttle_sensor {
    atomic_t ts_sensor;
} HSE_ALIGNED(SMP_CACHE_BYTES);

static inline void
throttle_sensor_set(struct throttle_sensor *ts, int value)
{
    atomic_set(&ts->ts_sensor, value);
}

static inline int
throttle_sensor_get(struct throttle_sensor *ts)
{
    return atomic_read(&ts->ts_sensor);
}

enum throttle_state { THROTTLE_NO_CHANGE, THROTTLE_DECREASE, THROTTLE_INCREASE };

/**
 * struct throttle_mavg - throttle mavg
 * @thr_samples   :     array of last THROTTLE_SAMPLE_CNT max sensor values
 * @thr_idx       :     index into thr_samples vector
 * @thr_sum       :     current sum
 * @thr_curr      :     current moving average
 * @thr_sample_cnt:     number of samples in mavg
 */

struct throttle_mavg {
    uint tm_samples[THROTTLE_SMAX_CNT];
    uint tm_idx;
    uint tm_sum;
    uint tm_sample_cnt;
    uint tm_curr;
};

/**
 * struct throttle - throttle state
 * @thr_next:           time at which to recompute %thr_pct (nsecs)
 * @thr_pct:            percentage of requests not to throttle
 * @thr_delay:      raw throttle delay amount
 * @thr_lock:           lock for updating %thr_pct
 * @thr_mavg:           struct to compute mavg
 * @thr_reduce_sum:     sum to compute cumulative mavg while reducing sleep
 * @thr_delay_min:      minimum sleep value to use (updated every lmax_cycles)
 * @thr_update_ms:      read sensors every thr_update_ms
 * @thr_reduce_cycles:  min cycles before attempting to reduce sleep value
 * @thr_inject_cycles:  insert sleep val for inject cycles and monitor response
 * @thr_delta_cycles:   cycles to wait after changing sleep to see a change
 * @thr_skip_cycles:    cycles to skip (to compute mavg) after changing sleep
 * @thr_cycles:         counter of throttle_update calls
 * @thr_update:         time at which to make periodic adjustments
 * @thr_state:          current throttling state (increase/reduce/no change)
 * @thr_csched:         current sensor value for csched
 * @thr_delay_prev:     previous sleep value (prior to attempting reduction)
 * @thr_delay_idelta:   next delta to try to increase sleep value by
 * @thr_delay_test:     next sleep value to test (while reducing sleep)
 * @thr_inject_cnt:     inject a reduced sleep value for inject_cnt cycles
 * @thr_skip_cnt:       skip next skip_cnt cycles while computing mavg
 * @thr_monitor_cnt:    reduce sleep value and monitor for monitor_cnt cycles
 * @thr_longest_run:    longest run of sensor values seen
 * @thr_num_tries:      number of trials in current reduction cycle
 * @thr_max_tries:      max number of trials
 * @thr_rp:
 * @thr_perfc:
 * @thr_data:           raw nanosleep performance metrics
 * @thr_sensorv:        vector of throttle sensors
 */
struct throttle {
    atomic_t             thr_pct;
    atomic64_t           thr_next;
    uint                 thr_delay;
    spinlock_t           thr_lock;

    HSE_ALIGNED(SMP_CACHE_BYTES)
    struct throttle_mavg thr_mavg;
    ulong                thr_reduce_sum;
    uint                 thr_delay_min;
    uint                 thr_lmin_cycles;
    uint                 thr_update_ms;
    uint                 thr_reduce_cycles;
    uint                 thr_inject_cycles;
    uint                 thr_delta_cycles;
    uint                 thr_skip_cycles;
    uint                 thr_cycles;
    ulong                thr_update;
    enum throttle_state  thr_state;
    uint                 thr_delay_prev;
    uint                 thr_delay_idelta;
    uint                 thr_delay_test;
    uint                 thr_inject_cnt;
    uint                 thr_skip_cnt;
    uint                 thr_monitor_cnt;
    uint                 thr_longest_run;
    uint                 thr_num_tries;
    uint                 thr_max_tries;
    struct kvdb_rparams *thr_rp;
    struct perfc_set     thr_sensor_perfc;
    struct perfc_set     thr_sleep_perfc;

    HSE_ALIGNED(SMP_CACHE_BYTES) atomic64_t thr_data;

    struct throttle_sensor thr_sensorv[THROTTLE_SENSOR_CNT];
};

void
throttle_init(struct throttle *self, struct kvdb_rparams *rp);

void
throttle_init_params(struct throttle *self, struct kvdb_rparams *rp);

void
throttle_fini(struct throttle *self);

uint
throttle_update(struct throttle *self);

static inline uint
throttle_delay(struct throttle *self)
{
    return self->thr_delay;
}

static inline struct throttle_sensor *
throttle_sensor(struct throttle *self, uint index)
{
    return (index < THROTTLE_SENSOR_CNT ? self->thr_sensorv + index : 0);
}

void
throttle_debug(struct throttle *self);

void
throttle_reduce_debug(struct throttle *self, uint value, uint mavg);

static inline
u64
throttle_raw_to_rate(unsigned raw_delay)
{
    if (HSE_UNLIKELY(raw_delay == 0))
        return U64_MAX;

    return (500000ul * THROTTLE_DELAY_MAX) / raw_delay;
}

#endif
