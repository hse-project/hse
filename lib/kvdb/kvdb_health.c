/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/atomic.h>

#include <hse_ikvdb/kvdb_health.h>

static bool
get_atomics(
    struct kvdb_health *health,
    uint                event,
    atomic_ulong      **tpp,
    atomic_ulong      **opp,
    atomic_long       **epp)
{
    switch (event) {
    case KVDB_HEALTH_FLAG_NOMEM:
        *tpp = &health->krx_nomem.khs_tripped;
        *opp = &health->krx_nomem.khs_odometer;
        *epp = &health->krx_nomem.khs_err;
        break;

    case KVDB_HEALTH_FLAG_NOSPACE:
        *tpp = &health->krx_nospace.khs_tripped;
        *opp = &health->krx_nospace.khs_odometer;
        *epp = &health->krx_nospace.khs_err;
        break;

    case KVDB_HEALTH_FLAG_DELBLKFAIL:
        *tpp = &health->krx_delblkfail.khs_tripped;
        *opp = &health->krx_delblkfail.khs_odometer;
        *epp = &health->krx_delblkfail.khs_err;
        break;

    case KVDB_HEALTH_FLAG_CNDBFAIL:
        *tpp = &health->krx_cndbfail.khs_tripped;
        *opp = &health->krx_cndbfail.khs_odometer;
        *epp = &health->krx_cndbfail.khs_err;
        break;

    case KVDB_HEALTH_FLAG_IO:
        *tpp = &health->krx_io.khs_tripped;
        *opp = &health->krx_io.khs_odometer;
        *epp = &health->krx_io.khs_err;
        break;

    default:
        *tpp = NULL;
        *opp = NULL;
        *epp = NULL;
        return false;
    }

    return true;
}

static int
merr_to_event(merr_t err)
{
    int e = merr_errno(err);

    switch (e) {
    case 0:
        return KVDB_HEALTH_FLAG_NONE;

    case ENOMEM:
        return KVDB_HEALTH_FLAG_NOMEM;

    case ENOSPC:
        return KVDB_HEALTH_FLAG_NOSPACE;

    case EROFS:
    case EFBIG:
    case EMLINK:
        return KVDB_HEALTH_FLAG_CNDBFAIL;

    default:
        return KVDB_HEALTH_FLAG_IO;
    }

    return KVDB_HEALTH_FLAG_IO;
}

merr_t
kvdb_health_event(struct kvdb_health *health, uint event, merr_t healtherr)
{
    atomic_ulong *tp, *op;
    atomic_long *ep;
    bool valid;

    if (event == KVDB_HEALTH_FLAG_NONE)
        return 0;

    valid = get_atomics(health, event, &tp, &op, &ep);

    if (ev(!valid))
        return merr(EINVAL);

    atomic_or_rel(&health->krx_tripped_mask, event);
    atomic_cas(ep, 0, healtherr);

    atomic_set(tp, 1);
    atomic_inc(op);

    return 0;
}

merr_t
kvdb_health_error(struct kvdb_health *health, merr_t healtherr)
{
    uint event = merr_to_event(healtherr);

    return kvdb_health_event(health, event, healtherr);
}

merr_t
kvdb_health_check(struct kvdb_health *health, uint mask)
{
    atomic_ulong *tp, *op;
    atomic_long *ep;
    uint event;

    assert(!(mask & ~KVDB_HEALTH_FLAG_ALL));

    mask &= atomic_read_acq(&health->krx_tripped_mask);

    for (event = 1; HSE_UNLIKELY(mask); event <<= 1) {
        if (mask & event) {
            (void)get_atomics(health, event, &tp, &op, &ep);

            return atomic_read(ep);

            mask &= ~event;
        }
    }

    return 0;
}

merr_t
kvdb_health_clear(struct kvdb_health *health, uint event)
{
    atomic_ulong *tp, *op;
    atomic_long *ep;
    bool valid;

    valid = get_atomics(health, event, &tp, &op, &ep);

    if (ev(!valid))
        return merr(EINVAL);

    atomic_and_rel(&health->krx_tripped_mask, ~event);

    atomic_set(tp, 0);
    atomic_set(ep, 0);

    return 0;
}
