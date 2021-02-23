/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_TXN_INTERNAL_H
#define HSE_KVDB_TXN_INTERNAL_H

#include <hse_ikvdb/kvdb_ctxn.h>

/**
 * struct kvdb_ctxn_impl -
 * @ctxn_inner_handle:
 * @ctxn_lock:                thread-thread API call serialization
 * @ctxn_can_insert:          true when txn can accept puts
 * @ctxn_cursors_max:
 * @ctxn_commit_abort_pct:    percent of txn commits to abort (for testing)
 * @ctxn_seqref:              transaction seqref
 * @ctxn_kvdb_keylock:        address of the KVDB keylock
 * @ctxn_locks_handle:        container to store acquired write locks
 * @ctxn_view_seqno:          seqno at time of transaction begin call
 * @ctxn_kvms:                buffer which stores transaction data
 * @ctxn_bind:
 * @ctxn_viewset:
 * @ctxn_c0sk:                address of underlying c0sk
 * @ctxn_kvdb_ctxn_set:       address of the KVDB txns struct
 * @ctxn_kvdb_seq_addr:       address of atomic used to generate seqnos
 * @ctxn_alloc_link:          used to queue onto KVDB allocated txn list
 * @ctxn_tseqno_head:
 * @ctxn_tseqno_tail:
 * @ctxn_ingest_width:
 * @ctxn_ingest_delay:
 * @ctxn_heap_sz:
 * @ctxn_begin_ts:
 * @ctxn_viewset_cookie:
 * @ctxn_alloc_link:
 * @ctxn_free_link:           used to queue onto the list of txns to be freed
 * @ctxn_abort_link:
 */
struct kvdb_ctxn_impl {
    struct kvdb_ctxn        ctxn_inner_handle;
    atomic_t                ctxn_lock;
    u8                      ctxn_can_insert;
    u8                      ctxn_cursors_max;
    u16                     ctxn_commit_abort_pct;
    uintptr_t               ctxn_seqref;
    struct kvdb_keylock *   ctxn_kvdb_keylock;
    struct kvdb_ctxn_locks *ctxn_locks_handle;
    u64                     ctxn_view_seqno;
    struct c0_kvmultiset *  ctxn_kvms;
    struct kvdb_ctxn_bind * ctxn_bind;

    struct viewset       *ctxn_viewset HSE_ALIGNED(SMP_CACHE_BYTES);
    struct c0sk *         ctxn_c0sk;
    struct kvdb_ctxn_set *ctxn_kvdb_ctxn_set;
    atomic64_t *          ctxn_kvdb_seq_addr;
    atomic64_t *          ctxn_tseqno_head;
    atomic64_t *          ctxn_tseqno_tail;

    u32 ctxn_ingest_width;
    u32 ctxn_ingest_delay;
    u64 ctxn_heap_sz;

    u64                  ctxn_begin_ts HSE_ALIGNED(SMP_CACHE_BYTES);
    void                *ctxn_viewset_cookie;
    struct cds_list_head ctxn_alloc_link;
    struct list_head     ctxn_free_link;
    struct list_head     ctxn_abort_link;
};

#define kvdb_ctxn_h2r(handle) container_of(handle, struct kvdb_ctxn_impl, ctxn_inner_handle)

static inline enum kvdb_ctxn_state
seqnoref_to_state(uintptr_t seqnoref)
{
    switch (seqnoref) {
        case HSE_SQNREF_UNDEFINED:
            return KVDB_CTXN_ACTIVE;

        case HSE_SQNREF_ABORTED:
            return KVDB_CTXN_ABORTED;

        case HSE_SQNREF_INVALID:
            return KVDB_CTXN_INVALID;
    }

    if (HSE_SQNREF_ORDNL_P(seqnoref))
        return KVDB_CTXN_COMMITTED;

    assert(HSE_SQNREF_INDIRECT_P(seqnoref));

    return KVDB_CTXN_ACTIVE;
}

void
kvdb_ctxn_deactivate(struct kvdb_ctxn_impl *ctxn);

merr_t
kvdb_ctxn_merge(
    struct kvdb_ctxn_impl *ctxn,
    int *                  num_retries,
    uintptr_t **           priv,
    struct c0_kvmultiset **dstp);

#endif
