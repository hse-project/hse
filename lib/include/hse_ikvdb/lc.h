/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_LC_H
#define HSE_CORE_LC_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/workqueue.h>

#include <lc/bonsai_iter.h>

#define LC_SOURCE_CNT_MAX 2

struct lc {
};

/* MTF_MOCK_DECL(lc) */

struct kvdb_ctxn_set;
struct cursor_summary;
struct kc_filter;
struct kvs_buf;
struct kvs_ktuple;
struct bonsai_skey;
struct bonsai_sval;
struct bonsai_kv;
struct lc_cursor;
struct query_ctx;
struct kvs_cursor_element;
enum key_lookup_res;

/* MTF_MOCK */
merr_t
lc_create(struct lc **handle, struct kvdb_ctxn_set *ctxn_set);

/* MTF_MOCK */
merr_t
lc_destroy(struct lc *lc);

struct lc_builder;

/* MTF_MOCK */
merr_t
lc_builder_create(struct lc *lc, struct lc_builder **builder);

/* MTF_MOCK */
void
lc_builder_destroy(struct lc_builder *lcb);

/* MTF_MOCK */
merr_t
lc_builder_add(struct lc_builder *bldr, struct bonsai_kv *kv, struct bonsai_val *val_list);

/* MTF_MOCK */
merr_t
lc_builder_finish(struct lc_builder *bldr);

/* MTF_MOCK */
merr_t
lc_get(
    struct lc *              handle,
    u16                      skidx,
    u32                      pfxlen,
    const struct kvs_ktuple *kt,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf);

/* MTF_MOCK */
merr_t
lc_pfx_probe(
    struct lc *              handle,
    const struct kvs_ktuple *kt,
    u16                      skidx,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    uint                     pfxlen,
    uint                     sfxlen,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf);

/**
 * lc_ingest_seqno_set() - Notify the LC about the max ingested seqno once an ingest has finished.
 *
 * @handle: Handle to the LC object
 * @seq:    Highest seqno that has beenn ingested into cn
 */
/* MTF_MOCK */
void
lc_ingest_seqno_set(struct lc *handle, u64 seq);

/**
 * lc_ingest_window_get() - Get the min and max seqnos that may be ingested
 *
 * @handle:     Handle to the LC object
 * @seqno_addr: KVDB seqno address
 * @view:       (output) view seqno, i.e. upper bound
 * @horizon:    (output) horizon seqno, i.e. lower bound
 */
/* MTF_MOCK */
void
lc_ingest_window_get(struct lc *handle, atomic64_t *seqno_addr, u64 *view, u64 *horizon);

/**
 * lc_cursor_create() - Creates a new cursor object to iterate over LC
 *
 * @handle:        Handle to the LC object
 * @skidx:         KVS index
 * @seqno:         View seqno for this cursor
 * @seqnoref:      Seqnoref of the associated txn
 * @reverse:       Whether or not this is a reverse cursor
 * @pfx_padded:    Prefix. The caller must pad this to HSE_KVS_KLEN_MAX with 0xff if reverse.
 * @pfxlen:        Length of the actual prefix (excluding padding if there is any)
 * @tree_pfxlen:   Length of the KVS's pfxlen
 * @summary:
 * @lccur:         (output) Cursor handle
 */
/* MTF_MOCK */
merr_t
lc_cursor_create(
    struct lc *            handle,
    u16                    skidx,
    u64                    seqno,
    uintptr_t              seqnoref,
    bool                   reverse,
    const void *           pfx_padded,
    size_t                 pfxlen,
    size_t                 tree_pfxlen,
    struct cursor_summary *summary,
    struct lc_cursor **    lccur);

/* MTF_MOCK */
merr_t
lc_cursor_destroy(struct lc_cursor *lccur);

/* MTF_MOCK */
void
lc_cursor_read(struct lc_cursor *lccur, struct kvs_cursor_element *elem, bool *eof);

/* MTF_MOCK */
merr_t
lc_cursor_seek(struct lc_cursor *lccur, const void *seek, size_t seeklen, struct kc_filter *filter);

/* MTF_MOCK */
merr_t
lc_cursor_update(struct lc_cursor *lccur, const void *key, size_t klen, u64 seqno);

/* MTF_MOCK */
struct element_source *
lc_cursor_es_make(struct lc_cursor *lccur);

/* MTF_MOCK */
struct element_source *
lc_cursor_es_get(struct lc_cursor *lccur);

struct lc_ingest_iter {
    struct bonsai_ingest_iter lcing_iter;
};

/**
 * lc_ingest_iterv_init() - Initialize iterators for LC
 *
 * @lc:          Handle to the LC object
 * @iterv:       Vector of iterators
 * @srcv:        Vector of element sources
 * @view_seq:    View seqno for the ingest; i.e. upper bound
 * @horizon_seq: Horizon seqno for the ingest; i.e. lower bound
 * @iter_cnt:    (output) Number of iterators initialized
 */
/* MTF_MOCK */
void
lc_ingest_iterv_init(
    struct lc *             lc,
    struct lc_ingest_iter * iterv,
    struct element_source **srcv,
    u64                     view_seq,
    u64                     horizon_seq,
    uint *                  iter_cnt);

/**
 * lc_gc_worker_start() - Enqueue Garbage collection work on the specified workqueue
 *
 * @handle: Handle to the LC object
 * @wq:     Workqueue on which Garbage collection would be queued
 */
/* MTF_MOCK */
void
lc_gc_worker_start(struct lc *handle, struct workqueue_struct *wq);

/* MTF_MOCK */
merr_t
lc_init(void);

/* MTF_MOCK */
void
lc_fini(void);

#if HSE_MOCKING
#include "lc_ut.h"
#endif

#endif
