/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_C0SK_INTERNAL_H
#define HSE_KVS_C0SK_INTERNAL_H

#include <urcu/rculist.h>

#include <hse/limits.h>

#include <hse_util/arch.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>
#include <hse_util/perfc.h>
#include <hse_util/workqueue.h>

#include <hse_ikvdb/kvdb_rparams.h>

#include <mpool/mpool.h>

#include <semaphore.h>

/* clang-format off */

/* MTF_MOCK_DECL(c0sk_internal) */

struct rcu_head;
struct c0_kvmultiset;
struct csched;
struct kvs_ktuple;
struct kvs_vtuple;

#define TOMBSPAN_INVALIDATE_COUNT 256
#define c0sk_h2r(handle)          container_of(handle, struct c0sk_impl, c0sk_handle)

struct c0sk {
};

/**
 * struct c0sk_impl - private representation of c0sk
 * @c0sk_handle:          opaque handle for users of a struct c0sk
 * @c0sk_kvdb_rp:         configuration data
 * @c0sk_ds:              mpool dataset
 * @c0sk_wq_ingest        workqueue for ingest processing (one thread)
 * @c0sk_wq_maint         workqueue for concurrent maintenance tasks
 * @c0sk_kvdb_seq:        kvdb seqno
 * @c0sk_closing:         set to %true when c0sk is closing
 * @c0sk_pc_op:           perf counter for c0sk
 * @c0sk_pc_ingest:       perf counter for c0sk ingests
 * @c0sk_kvms_mutex:      mutex protecting the list of c0_kvmultisets
 * @c0sk_kvmultisets:     list of struct c0_kvmultiset's
 * @c0sk_release_gen:     generation count of most recently released multiset
 * @c0sk_kvmultisets_sz:  size in bytes consumed by all kvms pending ingest
 * @c0sk_kvmultisets_cnt: how many struct c0_kvmultiset's does this c0sk have
 * @c0sk_ingest_ctime:    new/empty kvms buffer create time (milliseconds)
 * @c0sk_ingest_finlat:   average ingest finish latency (milliseconds)
 * @c0sk_kvms_cv:         used for kvms state change signaling
 * @c0sk_rcu_pending:     list of kvmultisets pending RCU synchronization
 * @c0sk_rcu_active:      list of kvmultisets to be ingested or released
 * @c0sk_rcu_work:        work struct for rcu sync
 * @c0sk_sync_mutex:      mutex protecting the c0sk_waiters list
 * @c0sk_sync_waiters:    list of waiters for specific c0_kvmultisets
 * @c0sk_ingest_gen:      ingest generation count
 * @c0sk_ingest_ldrcnt:   used to elect ingest leader
 * @c0sk_sync_sema:       used to serialize kvs_close() calls c0sk_queue_ingest(0
 * @c0sk_ingest_width:    ingest width hint/suggestion to use for next kvms
 * @c0sk_kvdb_alias:      kvdb alias
 * @c0sk_stash:           storage for caching a recently freed c0kvms
 * @c0sk_ingest_refv:     vector of ingest synchronization ref counts
 */
struct c0sk_impl {
    struct c0sk              c0sk_handle;
    struct kvdb_rparams     *c0sk_kvdb_rp; /* not owned by c0sk */
    struct mpool            *c0sk_ds;      /* not owned by c0sk */
    struct workqueue_struct *c0sk_wq_ingest;
    struct workqueue_struct *c0sk_wq_maint;
    struct kvdb_health      *c0sk_kvdb_health;
    struct kvdb_callback    *c0sk_cb;
    struct csched           *c0sk_csched;
    struct throttle_sensor  *c0sk_sensor;
    struct lc               *c0sk_lc;
    struct kvdb_ctxn_set    *c0sk_ctxn_set;
    atomic_ulong            *c0sk_kvdb_seq;
    bool                     c0sk_closing;
    bool                     c0sk_syncing;
    atomic_int               c0sk_replaying;
    struct perfc_set         c0sk_pc_op;
    struct perfc_set         c0sk_pc_ingest;

    struct mutex         c0sk_kvms_mutex HSE_ACP_ALIGNED;
    struct cds_list_head c0sk_kvmultisets;
    u64                  c0sk_release_gen;
    s32                  c0sk_kvmultisets_cnt;
    uint                 c0sk_ingest_finlat;
    ulong                c0sk_ingest_ctime;
    atomic_ulong         c0sk_ingest_order_curr;
    atomic_ulong         c0sk_ingest_order_next;
    atomic_ulong         c0sk_ingest_min;
    struct cv            c0sk_kvms_cv;
    struct list_head     c0sk_rcu_pending;
    bool                 c0sk_rcu_active;
    struct work_struct   c0sk_rcu_work;

    struct mutex       c0sk_sync_mutex HSE_L1D_ALIGNED;
    struct list_head   c0sk_sync_waiters;

    atomic_ulong c0sk_ingest_gen HSE_L1D_ALIGNED;
    atomic_int   c0sk_ingest_ldrcnt;
    sem_t        c0sk_sync_sema;

    u32        c0sk_ingest_width HSE_L1D_ALIGNED;
    int        c0sk_boost;
    char      *c0sk_kvdb_alias;
    void * _Atomic c0sk_stash;

    struct {
        atomic_int refcnt HSE_ACP_ALIGNED;
    } c0sk_ingest_refv[32];

    /* HSE_REVISIT: must track ALL c0sk cursors, so can invalidate them */

    struct cn *c0sk_cnv[HSE_KVS_COUNT_MAX] HSE_L1D_ALIGNED;
};

/**
 * struct c0sk_waiter - context for waiting on a kvms to be ingested
 * @c0skw_link:  wait list linkage
 * @c0skw_gen:   mutation/kvms gen count to wait for ingest completion
 * @c0skw_cv:    condvar on which to sleep
 * @c0skw_err:   to communicate sync error to app. thread.
 */
struct c0sk_waiter {
    struct list_head c0skw_link;
    u64              c0skw_gen;
    struct cv        c0skw_cv;
    merr_t           c0skw_err;
};

/* clang-format on */

/**
 * c0sk_install_c0kvms() - make the given new kvms the current/active kvms
 * @c0sk:   struct c0sk on which to operate
 * @old:    the existing kvms to replace
 * @new:    the new kvms to install
 *
 * Return: %true only if the new kvms was successfully installed
 */
bool
c0sk_install_c0kvms(struct c0sk_impl *self, struct c0_kvmultiset *old, struct c0_kvmultiset *new);

/**
 * release_multiset() - schedule the teardown of a struct c0_kvmultiset
 * @self:     struct c0sk owning the struct c0_kvmultiset
 * @multiset: struct c0_kvmultiset to be torn down
 *
 */
/* MTF_MOCK */
void
c0sk_release_multiset(struct c0sk_impl *self, struct c0_kvmultiset *multiset);

/**
 * sync_current_multiset() - enqueue current kvmultiset for ingest
 * @self:   struct c0sk owning the struct c0_kvmultiset
 * @genp:   the gen count of the kvms enqueued for ingest is stored here
 *
 */
merr_t
c0sk_flush_current_multiset(struct c0sk_impl *self, u64 *genp, bool destroywaitflag);

/**
 * c0sk_merge_impl() - merge the 'from' kvms into the 'first' kvms
 * @self:     struct c0sk into which to merge
 * @src:      source kvms
 *
 */
merr_t
c0sk_merge_impl(
    struct c0sk_impl *     self,
    struct c0_kvmultiset * src,
    struct c0_kvmultiset **dstp,
    uintptr_t **           refp);

enum c0sk_op {
    C0SK_OP_PUT,
    C0SK_OP_DEL,
    C0SK_OP_PREFIX_DEL,
};

/**
 * c0sk_putdel() - put a key/value or tombstone
 * @self:        struct c0sk_impl in which to put
 * @skidx:       which kvs is the insert targeted to
 * @op:
 * @kt:          key tuple
 * @vt:          value tuple
 * @seqnoref:    seqnoref of kvtuple
 *
 * The function c0sk_putdel() embodies the primary functionality of c0sk.
 * There are two implementations in user-space and one in kernel-space. The
 * kernel-space code is very simple and serves as a placeholder pending a
 * more thorough concurrent design tailored to the kernel's special runtime
 * environment.
 *
 * Return: [HSE_REVISIT]
 */
merr_t
c0sk_putdel(
    struct c0sk_impl *       self,
    u32                      skidx,
    enum c0sk_op             op,
    struct kvs_ktuple       *kt,
    const struct kvs_vtuple *vt,
    uintptr_t                seqnoref);

struct cn *
c0sk_get_cn(struct c0sk_impl *c0sk, u64 skidx);

#if HSE_MOCKING
#include "c0sk_internal_ut.h"
#endif

#endif /* HSE_KVS_C0SK_INTERNAL_H */
