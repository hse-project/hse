/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVMULTISET_H
#define HSE_CORE_C0_KVMULTISET_H

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/throttle.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/workqueue.h>
#include <hse_util/bin_heap.h>
#include <hse_util/condvar.h>

/* MTF_MOCK_DECL(c0kvms) */

struct c0;
struct cn;
struct c0_kvmultiset_cursor;
struct c0sk_impl;
struct c0_kvmultiset_impl;

/**
 * c0_kvmultiset - container for struct c0_kvset's
 * @c0ms_link: element to allow struct c0_kvmultiset's to be on a cds_list
 * @c0ms_rcu:  c0sk_rcu_pending list linkage
 *
 * A struct c0_kvmultiset is a collection of struct c0_kvset's to allow
 * parallel ingest of key/value pairs.
 *
 */
struct c0_kvmultiset {
    struct cds_list_head c0ms_link;
    struct list_head     c0ms_rcu;
};

/**
 * c0kvms_create() - allocate/initialize a struct c0_kvmultiset
 * @num_sets:        Max number of c0_kvsets to create
 * @alloc_sz:        Maximum cheap or malloc allocation size
 * @kvdb_seq:        ptr to kvdb seqno. Used only by non-txn KVMS.
 * @multiset:        Returned struct c0_kvset (on success)
 *
 * Passing HSE_C0KVS_ALLOC_MALLOC tells the implementation to use
 * malloc to allocate space to hold the key/value pairs, while
 * HSE_C0KVS_ALLOC_CURSOR causes the cursor heap allocator to be used.
 *
 * c0kvms is a reference counted object born with a reference count of 1.
 * It will be automatically destroyed via c0kvms_putref() when the
 * reference count reaches zero.
 *
 * Return: 0 on success, merr_t otherwise
 */
merr_t
c0kvms_create(
    u32                    num_sets,
    size_t                 alloc_sz,
    atomic64_t *           kvdb_seq,
    struct c0_kvmultiset **multiset);

void
c0kvms_seqno_set(struct c0_kvmultiset *handle, uint64_t kvdb_seq);

/**
 * c0kvms_reset() - reset the struct c0_kvmultiset to its original state
 * @mset: struct c0_kvset to reset
 */
void
c0kvms_reset(struct c0_kvmultiset *handle);

/**
 * c0kvms_getref() - obtain a ref against a struct c0_kvmultiset
 * @mset: struct c0_kvset to obtain a ref against
 */
void
c0kvms_getref(struct c0_kvmultiset *mset);

/**
 * c0kvms_putref() - release a ref against a struct c0_kvmultiset
 * @mset: struct c0_kvset to release a ref against
 */
/* MTF_MOCK */
void
c0kvms_putref(struct c0_kvmultiset *mset);

/**
 * c0kvms_thresholds_get() - get txn thresholds of the kvms. Used for deciding
 *                           between merging a transaction and flushing it.
 * @mset: struct c0_kvmultiset handle.
 */
/* MTF_MOCK */
void
c0kvms_thresholds_get(struct c0_kvmultiset *handle, size_t *thresh_lo, size_t *thresh_hi);

/**
 * c0kvms_gen_read() - return the given c0kvms' generation count
 * @mset:       struct c0_kvset from which to obtain the gen count
 */
u64
c0kvms_gen_read(struct c0_kvmultiset *mset);

u64
c0kvms_gen_current(struct c0_kvmultiset *mset);

/**
 * c0kvms_gen_update() - update the kvms generation count
 * @mset:       struct c0_kvset to update
 *
 * Updates the given kvms' generation count to a new, unique generation
 * count that is younger than any kvms generation count currently in use.
 *
 * Return: The new kvms generation count
 */
u64
c0kvms_gen_update(struct c0_kvmultiset *mset);

struct c0_kvset *
c0kvms_ptomb_c0kvset_get(struct c0_kvmultiset *handle);

size_t
c0kvms_size(struct c0_kvmultiset *handle);

/**
 * c0kvms_get_hashed_c0kvset() - obtain the c0_kvset at the given index
 * @mset:  Struct c0_kvmultiset to lookup in
 * @hash:  Hash value for the lookup
 *
 * Return: Struct c0_kvset pointer
 */
struct c0_kvset *
c0kvms_get_hashed_c0kvset(struct c0_kvmultiset *mset, u64 hash);

/**
 * c0kvms_get_c0kvset() - obtain the c0_kvset at the absolute index
 * @mset:  Struct c0_kvmultiset to lookup in
 * @index: absolute index
 *
 * Return: Struct c0_kvset pointer
 */
struct c0_kvset *
c0kvms_get_c0kvset(struct c0_kvmultiset *mset, u32 index);

/**
 * c0kvms_finalize() - freeze the elements of the c0_kvmultiset
 * @mset:  struct c0_kvmultiset to freeze
 * @wq:    workqueue to enable c0kvms_destroy() offload
 *
 * This function is invoked on a kvms at the end of the RCU grace
 * period during which it ceased being the active kvms.
 */
void
c0kvms_finalize(struct c0_kvmultiset *mset, struct workqueue_struct *wq);

/**
 * c0kvms_is_finalized() - return 'true' if finalized/frozen
 * @mset:  struct c0_kvmultiset
 *
 */
/* MTF_MOCK */
bool
c0kvms_is_finalized(struct c0_kvmultiset *mset);

/**
 * c0kvms_rsvd_sn_get() - get reserved seqno
 * @mset:   struct c0_kvmultiset
 */
/* MTF_MOCK */
u64
c0kvms_rsvd_sn_get(struct c0_kvmultiset *mset);

/**
 * c0kvms_rsvd_sn_set() - set reserved seqno
 * @mset:   struct c0_kvmultiset
 *
 * The reserved seqno is acquired and set immediately after a kvms is
 * activated.  It is guaranteed to be higher than any seqno in any older
 * kvms, and lower than any seqno in any younger kvms.  Additionally, it
 * is guaranteed to be the lowest seqno associated with any transaction
 * in the kvms, and hence this property is exploited by both c1 and cn.
 *
 * The reserved seqno is most often not bound to any transaction, but
 * it is reserved for use only by kvdb_ctxn_commit() in the context of
 * a kvms flush operation.
 */
/* MTF_MOCK */
void
c0kvms_rsvd_sn_set(struct c0_kvmultiset *mset, u64 seqno);

/**
 * c0kvms_ingesting() - mark the c0_kvmultiset as ingesting
 * @mset:  Struct c0_kvmultiset to mark
 *
 */
void
c0kvms_ingesting(struct c0_kvmultiset *mset);

/**
 * c0kvms_ingested() - mark the c0_kvmultiset as ingested (on media)
 * @mset:  struct c0_kvmultiset
 */
/* MTF_MOCK */
void
c0kvms_ingested(struct c0_kvmultiset *mset);

/**
 * c0kvms_is_ingested() - return 'true' if the kvms is on media
 * @mset:  Struct c0_kvmultiset
 *
 */
/* MTF_MOCK */
bool
c0kvms_is_ingested(struct c0_kvmultiset *mset);

/**
 * c0kvms_is_ingesting() - return 'true' if the kvms is ingesting
 * @mset:  Struct c0_kvmultiset
 *
 * A thread trying to update the active kvms must acquire the RCU read
 * lock, acquire the active kvms, and then test the kvms for ingesting.
 * If the kvms is in the ingesting state, the trhead must drop the RCU
 * read lock and retry.  If not, it may safely call c0kvs_put() (and
 * friends) up until it releases the RCU read lock.
 *
 * Note that the ingesting flag says nothing about where the kvms is w.r.t
 * ingest processing.  It may or may not be the active kvms, it may or may
 * may not be finalized, and it may or may not have been ingested.
 */
/* MTF_MOCK */
bool
c0kvms_is_ingesting(struct c0_kvmultiset *mset);

/**
 * c0kvms_get_element_count - obtain the total number of elements
 * @mset:        Struct c0_kvmultiset to query
 *
 * Return: The total number of entries and tombstones
 */
u64
c0kvms_get_element_count(struct c0_kvmultiset *mset);

/**
 * c0kvms_usage() - sample and retrieve usage metrics of the given kvms
 * @mset:       struct c0_kvmultiset to probe
 * @usage:      filled with usage metrics on return
 */
void
c0kvms_usage(struct c0_kvmultiset *mset, struct c0_usage *usage);

size_t
c0kvms_used(struct c0_kvmultiset *mset);

size_t
c0kvms_used_get(struct c0_kvmultiset *mset);

void
c0kvms_used_set(struct c0_kvmultiset *mset, size_t used);

size_t
c0kvms_avail(struct c0_kvmultiset *mset);

bool
c0kvms_should_ingest(struct c0_kvmultiset *handle);

void
c0kvms_abort_active(struct c0_kvmultiset *handle);

/**
 * c0kvms_width() - obtain the number of contained struct c0_kvset's
 * @mset:     Struct c0_kvmultiset to query
 *
 * Return: Number of contained sets
 */
u32
c0kvms_width(struct c0_kvmultiset *mset);

merr_t
c0kvms_pfx_probe_rcu(
    struct c0_kvmultiset *   kvms,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seqno);

merr_t
c0kvms_pfx_probe_excl(
    struct c0_kvmultiset *   kvms,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seqno);

/**
 * c0kvms_cursor_seek() - move iteration cursor
 * @cursor:   Handle for c0kvms cursor
 * @prefix:   Key/prefix to seek towards
 * @pfx_len:   Length of key/prefix
 *
 * Moves the current iteration point for this @mset.
 */
void
c0kvms_cursor_seek(
    struct c0_kvmultiset_cursor *cursor,
    const void *                 prefix,
    u32                          pfx_len,
    u32                          ct_pfx_len);

struct element_source *
c0kvms_cursor_skip_pfx(struct c0_kvmultiset_cursor *cur, struct bonsai_kv *pt_bkv);

/**
 * c0kvms_cursor_update() - update this cursor
 * @cursor:   Handle for c0kvms cursor
 * @seek:     Key to position new elements same as existing
 * @seeklen:  Length of seek key.
 *
 * Return: true if added a new source
 *
 * Update this @mset for iteration via a c0_cursor.
 */
bool
c0kvms_cursor_update(struct c0_kvmultiset_cursor *cursor, const void *seek, u32 seeklen, u32 ct_pfx_len);

/**
 * c0kvms_cursor_get_source() - get the element source for this cursor
 * @cursor:   Handle for c0kvms cursor
 *
 * Prepares this @mset for iteration via a c0_cursor.
 */
struct element_source *
c0kvms_cursor_get_source(struct c0_kvmultiset_cursor *cursor);

/**
 * c0kvms_cursor_create() - create a c0kvms cursor for iteration
 * @mset:     The kvms to prepare.
 * @cursor:   Handle for c0kvms cursor.
 * @skidx:    Which kvs within the kvms is desired.
 * @reverse:  cursor direction
 *
 * Prepares this @mset for iteration via a c0_cursor.
 */
merr_t
c0kvms_cursor_create(
    struct c0_kvmultiset *       kvms,
    struct c0_kvmultiset_cursor *cursor,
    int                          skidx,
    const void *                 pfx,
    size_t                       pfx_len,
    size_t                       ct_pfx_len,
    bool                         reverse);

/**
 * c0kvms_cursor_destroy() - release the c0kvms cursor memory
 * @cursor:   Handle for c0kvms cursor
 *
 * Cleans up and releases resources gained by this cursor.
 */
void
c0kvms_cursor_destroy(struct c0_kvmultiset_cursor *cursor);

/**
 * c0kvms_ingest_work_prepare() - prepare for ingest
 * @mset:     Struct c0_kvmultiset to query
 *
 * Return: pointer to the c0_kvmultiset's embedded struct c0_ingest_work
 */
struct c0_ingest_work *
c0kvms_ingest_work_prepare(struct c0_kvmultiset *mset, struct c0sk_impl *c0sk);

/**
 * c0kvms_c0snr_alloc() - alloc space to record a txn's c0snr
 * @mset:     Struct c0_kvmultiset
 *
 * Return: pointer to a uintptr_t
 */
uintptr_t *
c0kvms_c0snr_alloc(struct c0_kvmultiset *handle);

/**
 * c0kvms_ctime() - retrieve the kvms creation time (get_time_ns() semantics)
 * @mset: struct c0_kvset
 */
u64
c0kvms_ctime(struct c0_kvmultiset *handle);

/**
 * c0kvms_init() - called to initialize c0kvms subsystem
 */
merr_t
c0kvms_init(void) HSE_COLD;

/**
 * c0kvms_fini() - called when c0kvms is no longer needed
 */
void
c0kvms_fini(void) HSE_COLD;

#if HSE_MOCKING
#include "c0_kvmultiset_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_CORE_C0_KVMULTISET_H */
