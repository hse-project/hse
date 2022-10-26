/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C0_C0_H
#define HSE_C0_C0_H

#include <urcu-bp.h>

#include <hse/util/inttypes.h>
#include <hse/error/merr.h>
#include <hse/util/mutex.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cursor.h>

#define CURSOR_FLAG_SEQNO_CHANGE 1
#define CURSOR_FLAG_TOMBS_INV_KVMS 2
#define CURSOR_FLAG_TOMBS_INV_PUTS 4
#define CURSOR_FLAG_TOMBS_FLUSH 8

struct c0;
struct c0_cursor;
struct cn;

struct query_ctx;
struct kvdb_ctxn;
struct kc_filter;

struct mpool;

extern struct perfc_set c0_metrics_pc;

merr_t
c0_init(size_t c0kvs_ccache_sz, size_t c0kvs_cheap_sz);

void
c0_fini(void);

/* MTF_MOCK_DECL(c0) */

/*
 * Functions relating to using a struct c0
 */

/**
 * c0_open() - create and prepare a c0 for use
 * @kvdb:   KVDB handle
 * @cn:     struct cn that the struct c0 should consider as its backing store
 * @c0:     (out) pointer to created struct c0 on success, unchanged otherwise
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_open(struct ikvdb *kvdb, struct cn *cn, struct c0 **c0);

/**
 * c0_close() - transition a struct c0 into an offline state
 * @c0: Instance of struct c0 to transition
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_close(struct c0 *c0);

/**
 * c0_index() - retrieve the index identifier of the c0
 * @c0: Instance of struct c0
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
u16
c0_index(struct c0 *handle);

/**
 * c0_get_width() - get the parallel width for a struct c0
 * @self: Instance of struct c0 to probe
 *
 * Return: [HSE_REVISIT]
 */
u32
c0_get_width(struct c0 *self);

/* MTF_MOCK */
s32
c0_get_pfx_len(struct c0 *c0);

/**
 * c0_put() - insert a key/value pair into the struct c0
 * @self:      Instance of struct c0 into which to insert
 * @key:       Key for insertion
 * @value:     Value for insertion
 * @seqnoref:  seqnoref for insertion
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_put(struct c0 *self, struct kvs_ktuple *key, const struct kvs_vtuple *value, uintptr_t seqnoref);

/**
 * c0_get() - retrieve the value associated with the given key,
 *            no newer than seqno
 * @self:      Instance of struct c0 from which to retrieve
 * @key:       Key to retrieve
 * @seqno:     Seqno to use for get
 * @res:       Status of lookup
 * @vbuf:      Ptr to callers buffer
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_get(
    struct c0 *              self,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf);

/**
 * c0_del() - delete any value associated with the given key
 * @self:      Instance of struct c0 from which to delete
 * @key:       Key to delete
 * @seqnoref:  seqnoref for deletion
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_del(struct c0 *self, struct kvs_ktuple *key, uintptr_t seqnoref);

merr_t
c0_pfx_probe(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf);

/**
 * c0_prefix_del() - delete any value with the prefix key
 * @self:      Instance of struct c0 from which to delete
 * @key:       prefix key to delete
 * @seqnoref:  seqnoref for prefix delete
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0_prefix_del(struct c0 *self, struct kvs_ktuple *key, uintptr_t seqnoref);

/**
 * c0_sync() - force ingest of existing c0 data and waits until ingest complete
 * @self:      Instance of struct c0 to flush
 */
/* MTF_MOCK */
merr_t
c0_sync(struct c0 *self);

/**
 * c0_cursor_create() - create a cursor over c0
 * @self:      Instance of struct c0
 */
/* MTF_MOCK */
merr_t
c0_cursor_create(
    struct c0 *            self,
    u64                    seqno,
    bool                   dir,
    const void *           prefix,
    size_t                 pfx_len,
    struct cursor_summary *summary,
    struct c0_cursor **    c0cur);

/**
 * c0_cursor_bind_txn() - Assign ctxn to c0 cursor
 * @c0cur:      Instance of struct c0_cursor
 * @ctxn:       The transaction to bind.
 */
/* MTF_MOCK */
void
c0_cursor_bind_txn(struct c0_cursor *c0cur, struct kvdb_ctxn *ctxn);

/**
 * c0_cursor_seek() - move cursor read point
 * @c0cur:     Instance of struct c0_cursor
 */
/* MTF_MOCK */
merr_t
c0_cursor_seek(
    struct c0_cursor * c0cur,
    const void *       prefix,
    size_t             pfx_len,
    struct kc_filter * filter);

/**
 * c0_cursor_read() - read key/value at current position
 * @c0cur:     Instance of struct c0_cursor
 * @kvt:       Key/value that was read, if any
 * @eof:       (out) True if no more data to read (kvt is empty)
 */
/* MTF_MOCK */
merr_t
c0_cursor_read(struct c0_cursor *c0cur, struct kvs_cursor_element *elem, bool *eof);

/**
 * c0_cursor_update() - update existing iterators over c0
 * @c0cur:      Instance of struct c0_cursor
 * @seqno:      Sequence number of the cursor
 * @flags_out:  (out) flags to update tombstone span/cursor stats
 */
/* MTF_MOCK */
merr_t
c0_cursor_update(
    struct c0_cursor *       cur,
    u64                      seqno,
    u32 *                    flags_out);

/**
 * c0_cursor_destroy() - destroy existing iterators over c0
 * @c0cur:     Instance of struct c0_cursor
 */
/* MTF_MOCK */
merr_t
c0_cursor_destroy(struct c0_cursor *c0cur);

/* MTF_MOCK */
struct element_source *
c0_cursor_es_make(struct c0_cursor *c0cur);

/* MTF_MOCK */
struct element_source *
c0_cursor_es_get(struct c0_cursor *c0cur);

#if HSE_MOCKING
#include "c0_ut.h"
#endif /* HSE_MOCKING */

#endif
