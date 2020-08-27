/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_C0SKM_INTERNAL_H
#define HSE_KVS_C0SKM_INTERNAL_H
#include <hse_util/arch.h>
#include <hse_util/mtx_pool.h>
#include <hse_util/cds_list.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/c0sk.h>

#include "c0sk_internal.h"

struct c0sk_impl;
struct c1;

/**
 * enum c0skm_ingest_type -
 *
 * @C0SKM_TIMER:  start timer thread for periodic syncs
 * @C0SKM_TSYNC:  sync work from the timer thread
 * @C0SKM_FLUSH:  flush request from the app. thread
 * @C0SKM_SYNC:   sync request from the app. thread
 * @C0SKM_FREEZE: freeze request from c0sk_ingest_worker
 */
enum c0skm_ingest_type {
    C0SKM_TIMER = 0,
    C0SKM_TSYNC = 1,
    C0SKM_FLUSH = 2,
    C0SKM_SYNC = 3,
    C0SKM_FREEZE = 4,
};

/**
 * struct c0skm_work -
 * @c0skmw_ws:     work struct
 * @c0skmw_it:     enum c0skm_ingest_type
 * @c0skmw_mut:    c0sk mutation handle
 * @c0skmw_tseqno: kvdb seqno. addr.
 * @c0skmw_sync:   used for TSYNC work to indicate flush/sync
 * @c0skmw_freeze: used for TFREEZE work to indicate freeze
 */
struct c0skm_work {
    struct work_struct     c0skmw_ws;
    enum c0skm_ingest_type c0skmw_it;
    struct c0sk_mutation * c0skmw_mut;
    struct kvdb_rparams *  c0skmw_rp;
    u64                    c0skmw_tseqno;
    bool                   c0skmw_sync;
};

/**
 * struct c0sk_mutation -
 * @c0skm_c1h:          c1 handle
 * @c0skm_c0skh:        c0sk handle
 * @c0skm_dtime:        durability time
 * @c0skm_dsize:        durability size
 * @c0skm_pcset_op:     perfc instance for c0skm
 * @c0skm_closing:      close in progress
 * @c0skm_err:          hard c1 error, stops any further c1 ingests.
 *
 * @c0skm_wq_mut:       mutation workqueue
 * @c0skm_timerw:       timer work
 * @c0skm_tsyncw:       timer flush/sync work
 * @c0skm_syncw:        kvdb sync work
 * @c0skm_flushw:       kvdb flush work
 *
 * @c0skm_sync_waiters: kvdb sync waiters list
 * @c0skm_sync_mutex:   kvdb sync mutex
 * @c0skm_syncgen:      kvdb sync generation
 * @c0skm_syncpend:     kvdb sync pending
 * @c0skm_syncing:      sync in progress
 * @c0skm_tsyncing:     timer sync in progress
 *
 * @c0skm_mutgen:       c0sk mutation generation
 * @c0skm_flushing:     flush in progress
 * @c0skm_throttle:     throttle parameters
 * @c0skm_tseqno:       seqno of highest committed transaction
 *
 * @c0skm_reqtime:      arrival time of put/get request. The inaccuracy arising
 *                      from concurrent updates to arrival time is fine, as the
 *                      cocurrent put threads are close to each other in time.
 *                      Having this field as volatile ensures that the timer
 *                      thread can see this update. Atomic reqtime is expensive.
 *
 * %c0skm_tseqno is heavily read/written by all cpus and hence lives
 * in it's own cacheline (see kvdb_ctxn_commit()).
 */
struct c0sk_mutation {
    struct c1          *c0skm_c1h;
    struct c0sk_impl   *c0skm_c0skh;
    u64                 c0skm_dtime;
    u64                 c0skm_dsize;
    struct perfc_set    c0skm_pcset_op;
    struct perfc_set    c0skm_pcset_kv;

    struct workqueue_struct    *c0skm_wq_mut;
    struct throttle_sensor     *c0skm_dtime_sensor;
    struct throttle_sensor     *c0skm_dsize_sensor;
    atomic_t                    c0skm_flushing;
    atomic_t                    c0skm_closing;
    atomic64_t                  c0skm_err;
    struct c0_kvmultiset      **c0skm_c0kvmsv;
    size_t                      c0skm_c0kvmsv_sz;

    __aligned(SMP_CACHE_BYTES)
    struct c0skm_work           c0skm_timerw;
    struct c0skm_work           c0skm_tsyncw;
    struct c0skm_work           c0skm_syncw;
    struct c0skm_work           c0skm_flushw;

    __aligned(SMP_CACHE_BYTES)
    struct mutex        c0skm_sync_mutex;
    struct list_head    c0skm_sync_waiters;
    u64                 c0skm_syncgen;

    bool                c0skm_syncpend;
    atomic_t            c0skm_syncing;
    atomic_t            c0skm_tsyncing;

    atomic64_t          c0skm_mutgen;
    atomic64_t          c0skm_ingest_start;
    atomic64_t          c0skm_ingest_end;
    atomic64_t          c0skm_ingest_sz;

    atomic64_t      c0skm_tseqno   __aligned(SMP_CACHE_BYTES);
    volatile u64    c0skm_reqtime  __aligned(SMP_CACHE_BYTES);

    u8 c0skm_cnid[HSE_KVS_COUNT_MAX]  __aligned(SMP_CACHE_BYTES);
};

_Static_assert(HSE_KVS_COUNT_MAX <= 256, "c0skm_cnid type too small");

/**
 * c0skm_reqtime_set() - sets request arrival time
 * @self:
 * @start:
 */
static inline void
c0skm_reqtime_set(struct c0sk_mutation *c0skm, u64 start)
{
    if (!c0skm)
        return;

    if (c0skm->c0skm_reqtime == 0)
        c0skm->c0skm_reqtime = start;
}

/**
 * c0skm_reqtime_get() - get request arrival time
 * @c0skm:
 */
static inline u64
c0skm_reqtime_get(struct c0sk_mutation *c0skm)
{
    if (!c0skm)
        return 0;

    return c0skm->c0skm_reqtime;
}

/**
 * c0skm_reqtime_reset() - resets request arrival time
 * @c0skm:
 */
static inline void
c0skm_reqtime_reset(struct c0sk_mutation *c0skm)
{
    if (!c0skm)
        return;

    c0skm->c0skm_reqtime = 0;
}

/**
 * c0skm_get_perfc_kv() - Returns the perfc cset instance for kv.
 * @c0skm: c0sk mutation handle
 */
static inline struct perfc_set *
c0skm_get_perfc_kv(struct c0sk_mutation *c0skm)
{
    if (!c0skm)
        return NULL;

    return &c0skm->c0skm_pcset_kv;
}

/**
 * c0skm_ingest_worker() - ingests mutations from c0sk to c1.
 * @work:
 */
void
c0skm_ingest_worker(struct work_struct *work);

/**
 * c0skm_timer_worker() - periodically queues TSYNC work
 * @work:
 */
void
c0skm_timer_worker(struct work_struct *work);

/**
 * c0skm_perfc_alloc() - perfc initialization routine for c0skm
 * @c0skm:
 * @mpname:
 */
void
c0skm_perfc_alloc(struct c0sk_mutation *c0skm, const char *mpname);

/**
 * c0skm_perfc_free() - Free perfc counter sets for this c0skm instance.
 * @c0skm:
 */
void
c0skm_perfc_free(struct c0sk_mutation *c0skm);

/**
 * c0skm_skidx_register() - Adds a mapping from skidx to cnid
 * @self:  c0sk handle
 * @skidx:
 * @cn:    cn handle
 */
void
c0skm_skidx_register(struct c0sk_impl *self, u32 skidx, struct cn *cn);

/**
 * c0skm_skidx_deregister() - Removes mapping for the specified skidx
 * @self:  c0sk handle
 * @skidx:
 */
void
c0skm_skidx_deregister(struct c0sk_impl *self, u32 skidx);

/**
 * c0skm_get_cnid() - Returns cnid for the specified skidx.
 * @c0skm: c0sk mutation handle
 * @skidx:
 */
u64
c0skm_get_cnid(struct c0sk_mutation *c0skm, u32 skidx);

/**
 * c0skm_dtime_throttle_set_sensor() - Retain c0skm throttle delay
 * @c0skm: c0sk mutation handle
 */
void
c0skm_dtime_throttle_set_sensor(struct c0sk_mutation *c0skm, u64 synctime);

/**
 * c0skm_dsize_throttle_set_sensor() - Retain c0skm throttle delay
 * @c0skm: c0sk mutation handle
 */
void
c0skm_dsize_throttle_set_sensor(struct c0sk_mutation *c0skm, u64 syncsize);

#endif /* HSE_KVS_C0SKM_INTERNAL_H */
