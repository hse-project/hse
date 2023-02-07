/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_C0_CURSOR_H
#define HSE_KVS_C0_CURSOR_H

#include <stdint.h>

#include <hse/limits.h>

#include <hse/ikvdb/c0_kvset_iterator.h>
#include <hse/ikvdb/cursor.h>
#include <hse/ikvdb/limits.h>

/**
 * struct - c0_kvmultset_cursor - structure to iterate over one c0kvms
 *
 * There is one c0_kvmultiset_cursor for each c0kvms.
 * Each c0kvms may have 1..HSE_C0_INGEST_WIDTH_MAX c0_kvsets.
 */
struct c0_kvmultiset_cursor {
    struct element_source c0mc_es; /* must be first */
    union {
        struct c0_kvmultiset *c0mc_kvms;
        struct c0_kvmultiset_cursor *c0mc_next;
    };
    struct bin_heap *     c0mc_bh;
    int                   c0mc_iterc;
    int                   c0mc_skidx;
    int                   c0mc_reverse;
    const void *          c0mc_pfx;
    size_t                c0mc_pfx_len;
    size_t                c0mc_ct_pfx_len;
    /* HSE_REVISIT: split apart like c0_cursor_arrays */
    struct element_source *  c0mc_esrcv[HSE_C0_INGEST_WIDTH_MAX];
    struct c0_kvset_iterator c0mc_iterv[HSE_C0_INGEST_WIDTH_MAX];
};

/**
 * struct - c0_cursor - structure to allow iterating over a single kvs in c0
 *
 * There is one c0_cursor per cursor instance.  Each c0_cursor
 * has one or more c0_kvmultiset_cursors iterating over the in-memory
 * kvmultisets.  The binheap in this cursor merges all the kvms iterators
 * into a single c0 iterator value, which should then be merged with cN.
 *
 * @c0cur_bh:       binheap2 merge structure
 * @c0cur_c0sk:     the c0sk for this cursor
 * @c0cur_summary:  concise summary of cursor state (diagnostic)
 * @c0cur_seqno:    view seqno for this cursor
 * @c0cur_inv_gen:  last kvms gen that triggered an invalidate
 * @c0cur_inv_cnt:  number of invalidates at inv_gen (used to sync)
 * @c0cur_merr:     if this cursor is in error state
 * @c0cur_reverse:  true if reverse iteration
 * @c0cur_skidx:    index of the kvs for this cursor
 * @c0cur_ct_pfx_len: cn tree's prefix length
 * @c0cur_pfx_len:   length of the prefix, if any
 * @c0cur_cnt:      number of active elements in the arrays
 * @c0cur_prefix:   restrict this cursor to keys with this prefix
 * @c0cur_ctxn:     set if bound cursor
 * @c0cur_free:     list of freed kvms cursors, ready for reuse
 * @c0cur_ptomb_key:    cached ptomb used to hide appropriate values
 * @c0cur_ptomb_klen:   cached ptomb's keylen
 * @c0cur_ptomb_seq:    cached ptomb's seqno
 * @c0cur_ptomb_es:     cached ptomb's element source
 */
struct c0_cursor {
    struct element_source         c0cur_es;
    struct bin_heap *             c0cur_bh;
    struct c0sk *                 c0cur_c0sk;
    struct cursor_summary *       c0cur_summary;
    struct kvs_cursor_element     c0cur_elem;
    uint64_t                      c0cur_seqno;
    uint64_t                      c0cur_inv_gen;
    uint32_t                      c0cur_inv_cnt;
    merr_t                        c0cur_merr;
    int                           c0cur_debug;
    int                           c0cur_reverse;
    int                           c0cur_skidx;
    uint32_t                      c0cur_ct_pfx_len;
    int                           c0cur_pfx_len;
    int                           c0cur_cnt;
    int                           c0cur_alloc_cnt;
    const void *                  c0cur_prefix;
    struct kvdb_ctxn *            c0cur_ctxn;
    struct c0_kvmultiset_cursor  *c0cur_free;
    struct element_source       **c0cur_esrcv;
    struct c0_kvmultiset_cursor **c0cur_curv;
    void *                        c0cur_ptomb_key;
    size_t                        c0cur_ptomb_klen;
    uint64_t                      c0cur_ptomb_seq;
    struct element_source *       c0cur_ptomb_es;
    struct kc_filter *            c0cur_filter;
};

#endif
