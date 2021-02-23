/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVSET_INTERNAL_H
#define HSE_CORE_C0_KVSET_INTERNAL_H

#include <hse_util/bonsai_tree.h>

#define c0_kvset_h2r(handle) container_of(handle, struct c0_kvset_impl, c0s_handle)

/**
 * c0_kvset_impl - private representation of a c0 kvset
 * @c0s_handle:            handle for users of struct c0_kvset_impl's
 * @c0s_cheap:             handle to cheap (may be nil)
 * @c0s_broot:             bonsai tree instance
 * @c0s_alloc_sz:          client requested cursor heap size
 * @c0s_ingesting:         kvset ready-for or currently-is ingesting
 * @c0s_finalized:         kvset is frozen and undergoing c0 ingest
 * @c0s_reset_sz:          size of cheap used by fully setup c0kkvs
 * @c0s_next:              cheap cache linkage
 * @c0s_kvdb_seqno:        pointer to kvdb seqno
 * @c0s_kvms_seqno:        pointer to kvms seqno
 * @c0s_total_key_bytes:   total # of key bytes
 * @c0s_total_value_bytes: total # of value bytes
 * @c0s_num_entries:       how many entries (doesn't include tombstones)
 * @c0s_num_keys:          how many keys (includes tombstones)
 * @c0s_num_tombstones:    how many tombstones
 * @c0s_mutex:             mutex for bonsai tree updates
 *
 * Note:  To improve performance in the face of heavy contention, %c0s_mutex
 * is laid out so that it straddles two cache lines:  The lock word and other
 * bits in %c0s_mutex reside in the line with the lower address, while the
 * wait list in %c0s_mutex resides in the line with the higher address.
 *
 * Note also that the first cache line is primarily composed of read-only
 * fields to ameliorate cache line thrashing while the c0kvset is part
 * of the active kvms.
 */
struct c0_kvset_impl {
    struct c0_kvset       c0s_handle;
    struct cheap *        c0s_cheap;
    struct bonsai_root *  c0s_broot;
    size_t                c0s_alloc_sz;
    atomic_t *            c0s_ingesting;
    atomic_t              c0s_finalized;
    u32                   c0s_reset_sz;
    struct c0_kvset_impl *c0s_next;

    /* these apply only to non-txn operations. */
    atomic64_t *c0s_kvdb_seqno;
    atomic64_t *c0s_kvms_seqno;

    HSE_ALIGNED(SMP_CACHE_BYTES) u64 c0s_total_key_bytes;
    u64          c0s_total_value_bytes;
    u32          c0s_num_entries;
    u32          c0s_num_keys;
    u32          c0s_num_tombstones;
    u64          c0s_pad;
    struct mutex c0s_mutex;
};

#endif
