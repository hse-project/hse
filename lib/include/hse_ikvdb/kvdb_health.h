/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_HEALTH_H
#define HSE_KVDB_HEALTH_H

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>

struct kvdb_health_stat {
    atomic64_t khs_odometer;
    atomic64_t khs_tripped;
    atomic64_t khs_err; /* first merr since last clear */
};

struct kvdb_health {
    atomic_t                krx_tripped_mask;
    struct kvdb_health_stat krx_nomem;
    struct kvdb_health_stat krx_nospace;
    struct kvdb_health_stat krx_delblkfail;
    struct kvdb_health_stat krx_cndbfail;
    struct kvdb_health_stat krx_io;
};

#define KVDB_HEALTH_FLAG_NONE 0x0000u
#define KVDB_HEALTH_FLAG_NOMEM 0x0001u
#define KVDB_HEALTH_FLAG_NOSPACE 0x0002u
#define KVDB_HEALTH_FLAG_DELBLKFAIL 0x0004u
#define KVDB_HEALTH_FLAG_CNDBFAIL 0x0008u
#define KVDB_HEALTH_FLAG_IO 0x0010u
#define KVDB_HEALTH_FLAG_ALL 0x001fu

/**
 * kvdb_health_event() - specify a kvdb health event, with error
 * @health:      pointer to a kvdb health structure
 * @event:       the event to record
 * @healtherr:   the error that caused this health event
 */
merr_t
kvdb_health_event(struct kvdb_health *health, uint event, merr_t healtherr);

/**
 * kvdb_health_error() - automatically translate an error to a kvdb health event
 * @health:      pointer to a kvdb health structure
 * @healtherr:   the error to record
 */
merr_t
kvdb_health_error(struct kvdb_health *health, merr_t healtherr);

/**
 * kvdb_health_check() - check a kvdb for health events
 * @health:        pointer to a kvdb health structure
 * @event_mask:    bitmask of events to check
 *
 * In debug builds invalid events generate an assert while
 * in non-debug builds invalid events are silently ignored.
 *
 * Return: merr(EL2HLT) if any indicated event is tripped,
 *         0 otherwise.
 */
merr_t
kvdb_health_check(struct kvdb_health *health, uint event_mask);

/**
 * kvdb_health_clear() - clear a health event for a kvdb
 * @health:        pointer to a kvdb health structure
 * @event:       the event to clear
 */
merr_t
kvdb_health_clear(struct kvdb_health *health, uint event);

#endif
