/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
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
 * @c0s_ccache_sz:         cheap's RAM footprint in the cheap cache
 * @c0s_reset_sz:          size of cheap used by fully setup c0kkvs
 * @c0s_finalized:         kvset is frozen and undergoing c0 ingest
 * @c0s_next:              cheap cache linkage
 * @c0s_kvdb_seqno:        pointer to kvdb seqno
 * @c0s_kvms_seqno:        pointer to kvms seqno
 * @c0s_mutex:             mutex for bonsai tree updates
 * @c0s_num_entries:       how many entries (includes tombstones)
 * @c0s_num_tombstones:    how many tombstones
 * @c0s_keyb:              total key bytes
 * @c0s_valb:              total value bytes (not including replaced values)
 * @c0s_memsz:             minimum RAM consumed by all keys, values, tombs.
 * @c0s_height:            current max tree height
 * @c0s_keyvals:           max number of values in any key
 *
 * Note that the first two cache lines are primarily composed of read-only
 * fields to ameliorate cache line thrashing while the c0kvset is part
 * of the active kvms.
 */
struct c0_kvset_impl {
    struct c0_kvset       c0s_handle;
    struct cheap         *c0s_cheap;
    struct bonsai_root   *c0s_broot;
    u32                   c0s_alloc_sz;
    u32                   c0s_ccache_sz;
    u32                   c0s_reset_sz;
    atomic_int            c0s_finalized;
    struct c0_kvset_impl *c0s_next;

    /* these apply only to non-txn operations. */
    atomic_ulong *c0s_kvdb_seqno;
    atomic_ulong *c0s_kvms_seqno;

    struct mutex c0s_mutex HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    u32 c0s_num_entries HSE_ALIGNED(SMP_CACHE_BYTES);
    u32 c0s_num_tombstones;
    u32 c0s_keyb;
    u32 c0s_valb;
    u32 c0s_memsz;
    u32 c0s_height;
    u32 c0s_keyvals;
};

merr_t
c0kvs_pfx_probe_cmn(
    struct bonsai_root      *root,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq,
    u64                      max_seq);

#endif
