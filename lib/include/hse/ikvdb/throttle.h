/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_THROTTLE_H
#define HSE_KVDB_THROTTLE_H

/**
 * Throttling subsystem overview.
 *
 * The throttling subsystem moderates the application "put" rate to prevent
 * the ingest of data into HSE faster than it can be written to non-volatile
 * media.  This is necessitated by the enomormous impedence mismatch between
 * c0 and cN, wherein c0 implements an ephemeral in-memory write-back cache
 * which can ingest application data orders of magnitude faster than cN can
 * process and persist said data.
 *
 * There are three primary components to the throttling subsystem:
 *
 * 1) throttle_update() - called once every 10ms to recompute the current
 *    throttle delay amount.
 *
 * 2) struct throttle_sensor - used by WAL, ikvdb_kvs_put, c0sk (for both
 *    c0kvms count and c0spill rate), and cNroot to provide input to
 *    throttle_update().
 *
 * 3) throttle() - called in the context of application insert threads
 *    (via ikvdb_kvs_put()) to inform throttle_update() of the number
 *    of bytes inserted into c0sk/WAL, and then to sleep for an amount
 *    of time proportional to the size of the insert.
 *
 * There are two types of throttle sensors.  The original type is a "sensor
 * value" which informs throttle_update() (to varying degrees) that it should
 * either increase the throttle delay, decrease the throttle delay, or leave
 * the throttle at its current rate.  The second and newest sensor type is
 * rate based, which allows the throttle to monitor the ingest rates at
 * various points in the ingest pipeline and to adjust the throttle delay
 * to quickly respond to differences in rates.
 *
 * WAL, c0sk, and cNroot use sensor-value based sensors (V1, V2, and V3,
 * respectively) that are managed out-of-band, while kvdb and c0spill
 * employ rate-based sensors (R1 and R2) that are managed in-band.
 * Ingest data flows from application "put" threads into HSE past these
 * sensors as shown below, where ">>>" denotes a decoupling of the
 * write-back cache and the persistence layer (i.e., "put" threads
 * do not cross the ">>>" barrier).
 *
 *          V1      V2                                                 V3
 *   put -> WAL -> c0sk -> R1 -> throttle()   >>>   c0spill -> R2 -> cNroot
 *          [wb-cache]                              [-----persistence-----]
 *
 * where V1 reflects WAL buffer usage, V2 reflects c0kvms buffer count,
 * and V3 reflects cNroot kvset count and related cN maintenance costs.
 *
 * In order to prevent application threads from filling the write-back
 * cache faster than it can be drained, throttle_update() analyzes the
 * data rates observed at both R1 and R2 and adjusts the throttle delay
 * to keep the rate at R1 less than or equal to the rate at R2.
 */

#include <stdint.h>

#include <hse/util/arch.h>
#include <hse/util/atomic.h>
#include <hse/util/compiler.h>
#include <hse/util/condvar.h>
#include <hse/util/perfc.h>
#include <hse/util/spinlock.h>

/* clang-format off */

enum {
    THROTTLE_SENSOR_KVDB,
    THROTTLE_SENSOR_CNROOT,
    THROTTLE_SENSOR_C0SK,
    THROTTLE_SENSOR_WAL,
    THROTTLE_SENSOR_CNT
};

/* Raw delay values.
 * Use throttle_raw_to_rate to convert to byte rate.
 * Comments show the corresponding rate.
 */
#define THROTTLE_DELAY_MAX           268435456  /*        500,000  bytes/sec */
#define THROTTLE_DELAY_START_HEAVY     2097151  /*     64,000,030  bytes/sec */
#define THROTTLE_DELAY_START_MEDIUM    1342177  /*    100,000,020  bytes/sec */
#define THROTTLE_DELAY_START_LIGHT      251137  /*    534,440,277  bytes/sec */
#define THROTTLE_DELAY_MIN                1000  /*           134G  bytes/sec */

/* AUTO indicates that the stack picks a delay value based on the KVDB config.
 * THROTTLE_DELAY_START_LIGHT for a pmem-only KVDB, otherwise THROTTLE_DELAY_START_HEAVY.
 */
#define THROTTLE_DELAY_START_AUTO    (THROTTLE_DELAY_MAX)

#define THROTTLE_SMAX_CNT          60
#define THROTTLE_REDUCE_MS       5000
#define THROTTLE_INJECT_MS        200
#define THROTTLE_SKIP_MS          500
#define THROTTLE_DELTA_MS         800
#define THROTTLE_SENSOR_SCALE    1000
#define THROTTLE_MAX_RUN           15

/* struct throttle_tls - thread-local-storage for managing per-thread throttling
 */
struct throttle_tls {
    uint64_t bytes;     // bytes accumulated in current generation
    uint64_t cntrgen;   // current generation
    uint64_t resid;     // accumulated residual delay
    uint64_t tprev;     // time in ns of last throttle update
    uint64_t slack;     // timer slack (cached from last update)
};

/* clang-format on */

/**
 * struct throttle_sensor - throttle sensor
 *
 * Modules that provide throttler input (e.g., WAL and cN) should
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
 * Guidelines for setting sensor rates:
 *
 *  - See throttle() in throttle.c.
 *
 *  - See c0sk_cningest_cb() in c0sk_internal.c.
 */
struct throttle_sensor {
    atomic_uint_fast64_t *ts_cntrgenp HSE_ACP_ALIGNED;
    volatile uint64_t *ts_pspbptp;

    atomic_uint_fast64_t ts_cntrv[2] HSE_L1D_ALIGNED;
    atomic_uint ts_sensor;
};

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
 * @thr_delay:          raw throttle delay amount
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
 * @thr_sensorv:        vector of throttle sensors
 */
struct throttle {
    atomic_uint_fast64_t thr_cntrgen HSE_L1D_ALIGNED;
    volatile uint64_t thr_c0fill_pspbpt;

    uint64_t thr_tprev HSE_L1D_ALIGNED;
    uint thr_c0spill_sval;
    uint thr_c0fill_tdcnt;
    uint64_t thr_c0fill_avg;
    uint64_t thr_c0spill_peak;
    uint64_t thr_c0spill_high;
    uint64_t thr_c0spill_avg;
    uint64_t thr_c0spill_avgv[2];
    uint64_t thr_report;

    uint thr_delay HSE_L1D_ALIGNED;
    struct throttle_mavg thr_mavg;
    ulong thr_reduce_sum;
    uint thr_delay_min;
    uint thr_lmin_cycles;
    uint thr_update_ms;
    uint thr_reduce_cycles;
    uint thr_inject_cycles;
    uint thr_delta_cycles;
    uint thr_skip_cycles;
    uint thr_cycles;
    ulong thr_update;
    enum throttle_state thr_state;
    uint thr_delay_prev;
    uint thr_delay_idelta;
    uint thr_delay_test;
    uint thr_inject_cnt;
    uint thr_skip_cnt;
    uint thr_monitor_cnt;
    uint thr_longest_run;
    uint thr_num_tries;
    uint thr_max_tries;
    struct kvdb_rparams *thr_rp;
    struct perfc_set thr_sensor_perfc;
    struct perfc_set thr_sleep_perfc;

    struct throttle_sensor thr_sensorv[THROTTLE_SENSOR_CNT];
};

void
throttle_init(struct throttle *self, struct kvdb_rparams *rp, const char *kvdb_alias);

void
throttle_init_params(struct throttle *self, struct kvdb_rparams *rp);

void
throttle_fini(struct throttle *self);

void
throttle_update(void *arg);

void
throttle(struct throttle_sensor *self, struct throttle_tls *tls, uint64_t bytes);

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

static inline uint64_t
throttle_raw_to_rate(unsigned raw_delay)
{
    return (500000ul * THROTTLE_DELAY_MAX) / (raw_delay | 1);
}

static inline uint64_t
throttle_rate_to_raw(uint64_t rate)
{
    return (500000ul * THROTTLE_DELAY_MAX) / (rate | 1);
}

extern thread_local struct throttle_tls hse_throttle_tls;

#endif
