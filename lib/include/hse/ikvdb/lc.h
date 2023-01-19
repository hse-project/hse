/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_LC_H
#define HSE_CORE_LC_H

#include <stdint.h>

#include <lc/bonsai_iter.h>

#include <hse/error/merr.h>
#include <hse/util/workqueue.h>

/* Max number of bonsai trees in LC - includes one ptomb tree. */
#define LC_SOURCE_CNT_MAX 2

struct lc {};

struct lc_builder;
struct lc_cursor;

/* MTF_MOCK_DECL(lc) */

struct cursor_summary;
struct kc_filter;
struct kvs_buf;
struct kvs_ktuple;
struct bonsai_kv;
struct query_ctx;
struct kvs_cursor_element;
struct kvdb_health;
enum key_lookup_res;

/* MTF_MOCK */
merr_t
lc_create(struct lc **handle, struct kvdb_health *health);

/* MTF_MOCK */
void
lc_destroy(struct lc *lc);

/* MTF_MOCK */
merr_t
lc_builder_create(struct lc *lc, struct lc_builder **builder);

/* MTF_MOCK */
void
lc_builder_destroy(struct lc_builder *lcb);

/* MTF_MOCK */
merr_t
lc_builder_add(struct lc_builder *lcb, struct bonsai_kv *kv, struct bonsai_val *val_list);

/* MTF_MOCK */
merr_t
lc_builder_finish(struct lc_builder *lcb);

/* MTF_MOCK */
merr_t
lc_get(
    struct lc *handle,
    uint16_t skidx,
    uint32_t pfxlen,
    const struct kvs_ktuple *kt,
    uint64_t view_seqno,
    uintptr_t seqnoref,
    enum key_lookup_res *res,
    struct kvs_buf *vbuf);

/* MTF_MOCK */
merr_t
lc_pfx_probe(
    struct lc *handle,
    const struct kvs_ktuple *kt,
    uint16_t skidx,
    uint64_t view_seqno,
    uintptr_t seqnoref,
    uint pfxlen,
    enum key_lookup_res *res,
    struct query_ctx *qctx,
    struct kvs_buf *kbuf,
    struct kvs_buf *vbuf);

/**
 * lc_ingest_seqno_set() - Notify the LC about the max ingested seqno once an ingest has finished.
 *
 * @handle: Handle to the LC object
 * @seq:    Highest seqno that has beenn ingested into cn
 */
/* MTF_MOCK */
void
lc_ingest_seqno_set(struct lc *handle, uint64_t seq);

/**
 * lc_ingest_seqno_get() - Get the min_seqno that may be ingested to cn
 *
 * @handle:    LC handle
 */
/* MTF_MOCK */
uint64_t
lc_ingest_seqno_get(struct lc *handle);

/**
 * lc_cursor_create() - Creates a new cursor object to iterate over LC
 *
 * @handle:        Handle to the LC object
 * @skidx:         KVS index
 * @seqno:         View seqno for this cursor
 * @seqnoref:      Seqnoref of the associated txn
 * @reverse:       Whether or not this is a reverse cursor
 * @pfx_padded:    Prefix. The caller must pad this to HSE_KVS_KEY_LEN_MAX with 0xff if reverse.
 * @pfxlen:        Length of the actual prefix (excluding padding if there is any)
 * @tree_pfxlen:   Length of the KVS's pfxlen
 * @summary:
 * @lccur:         (output) Cursor handle
 */
/* MTF_MOCK */
merr_t
lc_cursor_create(
    struct lc *handle,
    uint16_t skidx,
    uint64_t seqno,
    uintptr_t seqnoref,
    bool reverse,
    const void *pfx_padded,
    size_t pfxlen,
    size_t tree_pfxlen,
    struct cursor_summary *summary,
    struct lc_cursor **lccur);

/* MTF_MOCK */
merr_t
lc_cursor_destroy(struct lc_cursor *lccur);

/* This is an internal function, but lc_test.c uses it to avoid creating a binheap to test LC. */
void
lc_cursor_read(struct lc_cursor *lccur, struct kvs_cursor_element *elem, bool *eof);

/* MTF_MOCK */
merr_t
lc_cursor_seek(struct lc_cursor *lccur, const void *seek, size_t seeklen, struct kc_filter *filter);

/* MTF_MOCK */
merr_t
lc_cursor_update(struct lc_cursor *lccur, const void *key, size_t klen, uint64_t seqno);

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
 * lc_ingest_iterv_init() - Initialize iterators for LC so it returns a bkv only if it has at
 *                          least one value with an ordinal seqno in the range [%min_seq, %max_seq]
 *
 * @lc:          Handle to the LC object
 * @iterv:       Vector of iterators
 * @srcv:        Vector of element sources
 * @min_seq:     Min seqno of the ingest's view
 * @max_seq:     Max seqno of the ingest's view
 * @iter_cnt:    (output) Number of iterators initialized
 */
/* MTF_MOCK */
void
lc_ingest_iterv_init(
    struct lc *lc,
    struct lc_ingest_iter *iterv,
    struct element_source **srcv,
    uint64_t min_seq,
    uint64_t max_seq,
    uint *iter_cnt);

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
