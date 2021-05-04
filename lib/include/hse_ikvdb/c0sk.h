/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0SK_H
#define HSE_CORE_C0SK_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/rcu.h>
#include <hse_util/mutex.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>

struct c0_kvmultiset;
struct c0sk;
struct c0_cursor;
struct cn;
struct mpool;
struct kvdb_rparams;
struct kvs_rparams;
struct kvs_cursor_element;
struct cursor_summary;
struct kvset_builder;
struct csched;
struct throttle_sensor;
struct query_ctx;

merr_t
c0sk_init(void);

void
c0sk_fini(void);

/* MTF_MOCK_DECL(c0sk) */

/*
 * Functions relating to using a struct c0sk
 */

/**
 * c0sk_open() - create a structured key c0sk (c0sk)
 * @kvdb_rp:    default kvdb rparams for c0sk
 * @mp_dataset  used for ingest
 * @kvdb_home   kvdb home
 * @health:     reference to the container kvdb's health struct
 * @c0sk:       (out) c0sk handle
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_open(
    struct kvdb_rparams *kvdb_rp,
    struct mpool *       mp_dataset,
    const char *         kvdb_home,
    struct kvdb_health * health,
    struct csched *      csched,
    atomic64_t *         kvdb_seq,
    struct c0sk **       c0sk);

/**
 * c0sk_close() - transition a struct c0sk into an offline state
 * @c0sk: Instance of struct c0sk to transition
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_close(struct c0sk *self);

/* MTF_MOCK */
void
c0sk_lc_set(struct c0sk *self, struct lc *lc);

/* MTF_MOCK */
struct lc *
c0sk_lc_get(struct c0sk *self);

/* MTF_MOCK */
u64
c0sk_ingest_order_register(struct c0sk *self);

/**
 * c0sk_throttle_sensor() - configure c0sk with a throttle sensor
 * @handle: c0sk handle
 * @sensor: throttle_sensor
 */
/* MTF_MOCK */
void
c0sk_throttle_sensor(struct c0sk *self, struct throttle_sensor *sensor);

/**
 * c0sk_c0_register() - request an index that will be associated with a
 *                      particular cN backing store
 *
 * No ownership of the struct cn handle is transferred with this call.
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_c0_register(struct c0sk *self, struct cn *cn, u16 *skidx);

/**
 * c0sk_c0_deregister() - release an index that is associated with a
 *                        particular cN backing store
 *
 * The particular c0 instance will call deregister while the cn is still valid
 * and the c0sk will guarantee that after this call returns the cn handle will
 * no longer be used for any purpose.
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_c0_deregister(struct c0sk *self, u16 skidx);

/**
 * c0sk_get_mhandle() - Return the c0sk mutation handle.
 * @self:    c0sk handle
 */
struct c0sk_mutation *
c0sk_get_mhandle(struct c0sk *self);

/**
 * c0sk_put() - insert a key/value pair into the struct c0sk
 * @self:      Instance of struct c0sk into which to insert
 * @skidx:     Structured key index
 * @key:       Key for insertion
 * @value:     Value for insertion
 * @seq:       Sequence number for insertion
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_put(
    struct c0sk *            self,
    u16                      skidx,
    const struct kvs_ktuple *key,
    const struct kvs_vtuple *value,
    u64                      seq);

/**
 * c0sk_get() - retrieve the value associated with the given key
 * @self:      Instance of struct c0sk from which to retrieve
 * @skidx:     Structured key index
 * @pfx_len:    Prefix length to use for this get
 * @key:       Key to retrieve
 * @view_seq:  View sequence number
 * @seqref:    Caller's sequence number reference (may be 0)
 * @res:       Status of lookup
 * @vbuf:      Ptr to callers buffer
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_get(
    struct c0sk *            self,
    u16                      skidx,
    u32                      pfx_len,
    const struct kvs_ktuple *key,
    u64                      view_seq,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf);

/**
 * c0sk_del() - delete any value associated with the given key
 * @self:       Instance of struct c0sk from which to delete
 * @skidx:      Structured key index
 * @key:        Key to delete
 * @seq:        Sequence number for insertion
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_del(struct c0sk *self, u16 skidx, const struct kvs_ktuple *key, u64 seq);

merr_t
c0sk_pfx_probe(
    struct c0sk *            handle,
    u16                      skidx,
    u32                      pfx_len,
    u32                      sfx_len,
    const struct kvs_ktuple *kt,
    u64                      view_seq,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf);

/**
 * c0sk_prefix_del() - delete any value with the prefix key
 * @self:      Instance of struct c0sk from which to delete
 * @skidx:     Structured key index
 * @key:       Prefix key to delete
 * @seq:       Sequence number for insertion
 *
 * Return: [HSE_REVISIT]
 */
/* MTF_MOCK */
merr_t
c0sk_prefix_del(struct c0sk *self, u16 skidx, const struct kvs_ktuple *key, u64 seq);

/**
 * c0sk_flush() - Start ingest of existing c0sk data
 * @self:       Instance of struct c0sk to flush
 *
 * Start ingest of existing c0sk data, returns to caller without waiting
 * for ingest to complete.
 */
/* MTF_MOCK */
merr_t
c0sk_flush(struct c0sk *self);

/**
 * c0sk_rparams() - Get a ptr to c0sk kvdb rparams
 * @self:       Instance of struct c0sk
 *
 */
struct kvdb_rparams *
c0sk_rparams(struct c0sk *self);

/**
 * c0sk_sync() - Force immediate ingest of existing c0sk data
 * @self:       Instance of struct c0sk to flush
 *
 * Force immediate ingest of existing c0sk data and waits until
 * it has been ingested by cn before returning to caller.
 */
/* MTF_MOCK */
merr_t
c0sk_sync(struct c0sk *self);

/**
 * c0sk_cursor_create() - create a cursor over c0
 * @self:      Instance of struct c0sk to flush
 */
merr_t
c0sk_cursor_create(
    struct c0sk *          self,
    u64                    seqno,
    int                    skidx,
    bool                   dir,
    u32                    ct_pfx_len,
    const void *           prefix,
    size_t                 pfx_len,
    struct cursor_summary *summary,
    struct c0_cursor **    cur);

/**
 * c0sk_cursor_save() - prepare cursor to be cached
 * @cur:        The existing cursor
 */
merr_t
c0sk_cursor_save(struct c0_cursor *cur);

/**
 * c0sk_cursor_restore() - reinit a cached cursor
 * @cur:        The existing cursor
 */
merr_t
c0sk_cursor_restore(struct c0_cursor *cur);

/**
 * c0sk_cursor_bind_txn() - bind a txn kvms to iterable c0
 * @c0cur:      The existing cursor.
 * @ctxn:       The transaction to bind.
 */
struct kvdb_ctxn;

void
c0sk_cursor_bind_txn(struct c0_cursor *cur, struct kvdb_ctxn *ctxn);

/**
 * c0sk_cursor_seek() - update existing iterators over c0
 * @c0cur:      The existing cursor.
 */
merr_t
c0sk_cursor_seek(
    struct c0_cursor * cur,
    const void *       prefix,
    size_t             pfx_len,
    struct kc_filter * filter);

/**
 * c0sk_cursor_read() - read key/value at current position
 * @c0cur:      The existing cursor.
 */
merr_t
c0sk_cursor_read(struct c0_cursor *cur, struct kvs_cursor_element *elem, bool *eof);

/**
 * c0sk_cursor_update() - update existing iterators over c0
 * @c0cur:      The existing cursor.
 * @seqno:      Sequence number of the cursor
 * @flags_out:  (out) flags to update tombspan and cursor stats
 */
merr_t
c0sk_cursor_update(
    struct c0_cursor *       cur,
    u64                      seqno,
    u32 *                    flags_out);

/**
 * c0sk_cursor_destroy() - destroy existing iterators over c0
 * @c0cur:      The existing cursor.
 */
merr_t
c0sk_cursor_destroy(struct c0_cursor *cur);

/**
 * c0sk_get_first_c0kvms - return a ptr to the first kvms
 * @c0sk:   struct c0sk from which to retrieve the first kvms
 *
 * Return: ptr to the first kvms on the list of kvmultisets
 */
/* MTF_MOCK */
struct c0_kvmultiset *
c0sk_get_first_c0kvms(struct c0sk *handle);

struct c0_kvmultiset *
c0sk_get_last_c0kvms(struct c0sk *handle);

#if HSE_MOCKING
#include "c0sk_ut.h"
#endif /* HSE_MOCKING */

#endif
