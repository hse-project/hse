/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_TXN_INTERNAL_H
#define HSE_KVDB_TXN_INTERNAL_H

#include <urcu-bp.h>

#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_util/mutex.h>

/* clang-format off */

#define kvdb_ctxn_h2r(_ctxn_handle) \
    container_of(_ctxn_handle, struct kvdb_ctxn_impl, ctxn_inner_handle)

/**
 * struct kvdb_ctxn_impl -
 * @ctxn_inner_handle:
 * @ctxn_lock:                thread-thread API and async abort serialization
 * @ctxn_can_insert:          true when txn can accept puts
 * @ctxn_seqref:              transaction seqref
 * @ctxn_view_seqno:          seqno at time of transaction begin call
 * @ctxn_kvdb_pfxlock:        address of the KVDB pfxlock
 * @ctxn_kvdb_keylock:        address of the KVDB keylock
 * @ctxn_locks_handle:        container to store acquired write locks
 * @ctxn_bind:
 * @ctxn_c0sk:                address of underlying c0sk
 * @ctxn_kvdb_ctxn_set:       address of the KVDB txns struct
 * @ctxn_kvdb_seq_addr:       address of atomic used to generate seqnos
 * @ctxn_viewset:             horizon tracking
 * @ctxn_viewset_cookie:      horizon tracking
 * @ctxn_begin_ts:            txn begin start time
 * @ctxn_alloc_link:          used to queue onto KVDB allocated txn list
 * @ctxn_free_link:           used to queue onto the list of txns to be freed
 * @ctxn_abort_link:
 */
struct kvdb_ctxn_impl {
    struct kvdb_ctxn        ctxn_inner_handle;
    struct mutex            ctxn_lock;
    bool                    ctxn_can_insert;
    uintptr_t               ctxn_seqref;
    u64                     ctxn_view_seqno;

    struct kvdb_keylock      *ctxn_kvdb_keylock;
    struct kvdb_ctxn_locks   *ctxn_locks_handle;
    struct kvdb_pfxlock      *ctxn_kvdb_pfxlock;
    struct kvdb_ctxn_pfxlock *ctxn_pfxlock_handle;

    struct c0sk            *ctxn_c0sk;
    struct kvdb_ctxn_set   *ctxn_kvdb_ctxn_set;
    atomic_ulong           *ctxn_kvdb_seq_addr;
    struct c0snr_set       *ctxn_c0snr_set;
    struct kvdb_ctxn_bind   ctxn_bind;

    struct wal             *ctxn_wal HSE_ACP_ALIGNED;
    int64_t                 ctxn_wal_cookie;
    struct viewset         *ctxn_viewset;
    void                   *ctxn_viewset_cookie;

    struct cds_list_head    ctxn_alloc_link HSE_ALIGNED(CAA_CACHE_LINE_SIZE);
    struct list_head        ctxn_free_link;
    struct list_head        ctxn_abort_link;
    u64                     ctxn_begin_ts;
    bool                    ctxn_expired;
};

/* clang-format on */

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

#endif
