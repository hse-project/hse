/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
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
 * @ingest_delay:    Max ingest coalesce wait time (in seconds)
 * @kvdb_seq:        ptr to kvdb seqno. Used only by non-txn KVMS.
 * @tracked:         indicates whether to track mutations for this kvms.
 * @multiset:        Returned struct c0_kvset (on success)
 *
 * Passing HSE_C0KVS_ALLOC_MALLOC tells the implementation to use
 * kmalloc/malloc to allocate space to hold the key/value pairs, while
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
    u64                    ingest_delay,
    atomic64_t *           kvdb_seq,
    bool                   tracked,
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

size_t
c0kvms_get_mut_sz(struct c0_kvmultiset *handle);

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
 *
 * A kvms that is finalized is a guarantee that the kvms is stable and may
 * no longer be modified by put or delete operations, including updates to
 * the priv buffer.  However, there remains a case where the priv buffer
 * could be modified after finalization, and that can occur only as a reult
 * of a ctxn flush operation.
 *
 * So, until we fix the flush aberration, one must call c0vksm_priv_wait()
 * or check that c0kvms_priv_busy() returns false to be assured that the
 * contents of a given kvms are completely stable.
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
 * c0kvms_ingest_delay_set() - set ingest delay
 * @mset:   struct c0_kvmultiset
 * @delay:  delay in seconds
 */
void
c0kvms_ingest_delay_set(struct c0_kvmultiset *mset, u64 delay);

/**
 * c0kvms_ingest_delay_get() - get ingest delay
 * @mset:   struct c0_kvmultiset
 *
 * Return: delay in seconds
 */
u64
c0kvms_ingest_delay_get(struct c0_kvmultiset *mset);

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
 * c0kvms_is_tracked() - return 'true' if mutations are tracked in this kvms
 * @handle:  Struct c0_kvmultiset
 *
 */
bool
c0kvms_is_tracked(struct c0_kvmultiset *handle);

/**
 * c0kvms_enable_mutation() - enable mutation tracking for this kvms.
 * @handle:  Struct c0_kvmultiset
 *
 */
void
c0kvms_enable_mutation(struct c0_kvmultiset *handle);

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
 * c0kvms_is_mutating() - return 'true' if the kvms is mutating
 *                        applicable iff the kvms is ingesting
 * @mset:  Struct c0_kvmultiset
 *
 */
bool
c0kvms_is_mutating(struct c0_kvmultiset *mset);

/**
 * c0kvms_unset_mutating() - unset mutating field
 * @mset:  Struct c0_kvmultiset
 *
 */
void
c0kvms_unset_mutating(struct c0_kvmultiset *mset);

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
c0kvms_mut_sz_get(struct c0_kvmultiset *mset);

void
c0kvms_mut_sz_set(struct c0_kvmultiset *mset, size_t mut_sz);

size_t
c0kvms_avail(struct c0_kvmultiset *mset);

bool
c0kvms_should_ingest(struct c0_kvmultiset *handle);

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
c0kvms_cursor_update(struct c0_kvmultiset_cursor *cursor, void *seek, u32 seeklen, u32 ct_pfx_len);

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
c0kvms_ingest_work_prepare(struct c0_kvmultiset *mset, void *c0);

/**
 * c0kvms_priv_alloc() - allocate a ptr to private storage within the kvms
 * @handle:     kvms on which to operate
 *
 * c0kvms_priv_alloc() returns a unique ptr to storage guaranteed to hold
 * at least a uintptr_t.  The lifetime of the storage is tied to the kvms
 * from which it was allocated, and hence the caller must relinquish its
 * reference to storage before the kvms can be ingested.
 *
 * c0kvms_priv_alloc() synchronizes with kvms ingest processing such that
 * full ingest will be delayed until each successful call to
 * c0kvms_priv_alloc() made on a given kvms has been balanced by a call
 * to c0kvms_priv_release().
 *
 * This interface is primarily used by the ctxn layer, but may be used
 * for other nefarious purposes.  Note that the storage pool dedicated to
 * this facility is limited:  It will not be grown or replenished once it
 * consumed and there is no way to return allocated storage to the pool.
 *
 * The caller of c0kvms_priv_alloc() must hold a reference on the kvms.
 *
 * Return: A ptr to unique kvms private storage on success, NULL on failure.
 */
void *
c0kvms_priv_alloc(struct c0_kvmultiset *handle);

/**
 * c0kvms_priv_release() - relinquish control of kvms private storage
 * @handle:     kvms on which to operate
 *
 * c0kvms_priv_release() notifies the kvms that no further accesses to
 * storage allocated via c0kvms_priv_alloc() will occur.  The caller
 * must call c0kvms_priv_release() exactly once for each successful
 * call to c0kvms_priv_alloc().
 *
 * Note that the release does not free or in any way perturb the data,
 * which will remain intact until the kvms is destroyed.
 *
 * The caller of must hold a reference on the kvms.
 */
/* MTF_MOCK */
void
c0kvms_priv_release(struct c0_kvmultiset *handle);

/**
 * c0kvms_priv_wait() - for for all priv allocations to be relinquished
 * @handle:     kvms on which to operate
 *
 * The caller of must hold a reference on the kvms.
 */
void
c0kvms_priv_wait(struct c0_kvmultiset *handle);

bool
c0kvms_priv_busy(struct c0_kvmultiset *handle);

/**
 * c0kvms_preserve_tombspan() - check whether the tombspan can be
 * preserved (no mutations to the interval).
 * @handle:     kvms on which to operate
 * @kmin:        min tomb key
 * @kmin_len:    min tomb key length
 * @kmax:        max tomb key
 * @kmax_len:    max tomb key length
 *
 * The caller must hold a reference on the kvms.
 */
bool
c0kvms_preserve_tombspan(
    struct c0_kvmultiset *handle,
    u16                   index,
    const void *          kmin,
    u32                   kmin_len,
    const void *          kmax,
    u32                   kmax_len);
/**
 * c0kvms_mlock() - acquire c0kvms mutation lock.
 * @handle:     kvms on which to operate
 */
void
c0kvms_mlock(struct c0_kvmultiset *handle);

/**
 * c0kvms_munlock() - release c0kvms mutation lock.
 * @handle:     kvms on which to operate
 */
void
c0kvms_munlock(struct c0_kvmultiset *handle);

/**
 * c0kvms_mwait() - wait on c0kvms mutation cv.
 * @handle:     kvms on which to operate
 */
void
c0kvms_mwait(struct c0_kvmultiset *handle);

/**
 * c0kvms_msignal() - signal c0kvms mutation cv.
 * @handle:     kvms on which to operate
 */
void
c0kvms_msignal(struct c0_kvmultiset *handle);

/**
 * c0kvms_init() - called to initialize c0kvms subsystem
 */
merr_t
c0kvms_init(void);

/**
 * c0kvms_fini() - called when c0kvms is no longer needed
 */
void
c0kvms_fini(void);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c0_kvmultiset_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_CORE_C0_KVMULTISET_H */
