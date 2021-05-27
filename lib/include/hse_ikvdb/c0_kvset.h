/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVSET_H
#define HSE_CORE_C0_KVSET_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/rcu.h>

#include <hse_ikvdb/kvs.h>

struct c0_kvset {
};

struct c0kvs_ingest_ctx;
struct c0_kvset_iterator;

struct c0_usage {
    size_t u_alloc;
    size_t u_free;
    size_t u_used_min;
    size_t u_used_max;
    ulong  u_keys;
    ulong  u_tombs;
    size_t u_keyb;
    size_t u_valb;
    int    u_count;
};

/**
 * c0kvs_reinit() - reinitialize global c0kvs state
 * @cc_max:   set max cache size (bytes)
 *
 * Must be called at least once before calling c0kvs APIs.  Subsequent
 * calls are idempotent.
 */
void
c0kvs_reinit(size_t cc_max);

/**
 * c0kvs_init() - initialize global c0kvs state
 *
 * Must be called at least once before calling c0kvs APIs.  Subsequent
 * calls are idempotent.
 */
void
c0kvs_init(void);

/**
 * c0kvs_fini() - clean up global c0kvs state
 *
 * Call at least once to reset c0kvs global state and free cached objects.
 * Subsequent calls are idempotent.
 */
void
c0kvs_fini(void);

/**
 * c0kvs_create() - allocate/initialize a struct c0_kvset
 * @alloc_sz:   Maximum cheap or malloc allocation size
 * @kvdb_seq:   Ptr to kvdb seqno
 * @kvms_seq:   Ptr to kvms seqno.
 * @handlep:    Returned struct c0_kvset (on success)
 *
 * Passing HSE_C0KVS_ALLOC_MALLOC tells the implementation to use
 * malloc to allocate space to hold the key/value pairs, while
 * HSE_C0KVS_ALLOC_CURSOR causes the cursor heap allocator to be used.
 *
 * Return: 0 on success, <0 otherwise
 */
merr_t
c0kvs_create(
    size_t            alloc_sz,
    atomic64_t *      kvdb_seq,
    atomic64_t *      kvms_seq,
    struct c0_kvset **handlep);

/**
 * c0kvs_destroy() - free a c0kvs
 * @set:        c0kvs handle
 *
 * This function frees a c0kvs, but in most cases it winds
 * up on the c0kvs cheap cache for subsequent reuse rather
 * than be completely destroyed.
 */
void
c0kvs_destroy(struct c0_kvset *set);

/**
 * c0kvs_used() - return bytes used in c0kvs cheap
 * @set:        c0kvs handle
 */
size_t
c0kvs_used(struct c0_kvset *set);

/**
 * c0kvs_avail() - return bytes free in c0kvs cheap
 * @set:        c0kvs handle
 */
size_t
c0kvs_avail(struct c0_kvset *set);

/**
 * c0kvs_reset() - return a cursor allocated c0_kvset to an as-new state
 * @set:        struct c0_kvset to reset
 * @sz:         additional bytes from c0kvset base size to preserve
 */
void
c0kvs_reset(struct c0_kvset *set, size_t sz);

/**
 * c0kvs_alloc() - allocate storage from the c0kvs' cheap
 * @set:        c0kvs handle
 * @align:      alignment
 * @sz:         size
 *
 * This function allows external callers to allocate memory from
 * the c0kvs' private cheap.  It is safe to call on a c0kvs that
 * is part of the active kvms.
 */
void *
c0kvs_alloc(struct c0_kvset *handle, size_t align, size_t sz);

/**
 * c0kvs_put() - insert a key/value pair into the struct c0_kvset
 * @set:   Struct c0_kvset to insert the key/value into
 * @key:   Key
 * @value: Value
 * @seqno: Seqno of key-value pair
 *
 * Insert an kvs_ktuple, kvs_vtuple pair into a c0_kvset. The
 * c0_kvset takes ownership of the tuples and will delete them when
 * it is itself deleted. A put with a kvs_ktuple key that is already
 * present in the c0_kvset causes the old kvs_vtuple value to be
 * destroyed and the new one installed in its place.
 *
 * Return: [HSE_REVISIT]
 */
merr_t
c0kvs_put(
    struct c0_kvset *        set,
    u16                      skidx,
    struct kvs_ktuple       *key,
    const struct kvs_vtuple *value,
    uintptr_t                seqnoref);

/**
 * c0kvs_del() - delete the key/value pair matching the given key
 * @set:   Struct c0_kvset to delete the key/value from
 * @key:   Key
 * @seqno: seqno to use for deletion
 *
 * Delete the value kvs_vtuple associated with the given key
 * kvs_ktuple.  The kvs_vtuple is destroyed and a tombstone is
 * associated with the key. No ownership is assumed of the key
 * kvs_ktuple.
 *
 * Return: [HSE_REVISIT]
 */
merr_t
c0kvs_del(struct c0_kvset *set, u16 skidx, struct kvs_ktuple *key, const uintptr_t seqno);

/**
 * c0kvs_prefix_del() - delete the key/value pair matching the given key
 * @set:   Struct c0_kvset to delete the key/value from
 * @key:   Key
 * @seqno: seqno to use for prefix delete
 *
 * Insert a prefix tombstone for the particular key, which replaces
 * any prior value associated with the key/inserts a new value (if absent).
 *
 * Return: [HSE_REVISIT]
 */
merr_t
c0kvs_prefix_del(
    struct c0_kvset *        set,
    u16                      skidx,
    struct kvs_ktuple       *key,
    const uintptr_t          seqno);

/**
 * c0kvs_get_rcu() - given a key, retrieve a value from a struct c0_kvset
 * @handle:     Struct c0_kvset to search
 * @key:        Key
 * @view_seqno: Get the latest value with seqno not newer than view_seqno
 * @res:        Result of lookup
 * @vbuf:       (out) Value (if return value == 0 and *res == FOUND_VAL)
 *                    If vbuf->b_buf is NULL, a buffer large enough to hold the
 *                    value will be allocated.
 * @oseqnoref:  (out) Sequence # reference of the key's value, if found
 *
 * Find the value associated with given key and copy the value into caller's
 * buffer.  No ownership is assumed of the key kvs_ktuple.
 *
 * Caller must be within an rcu read-side critical section to call this
 * function.  If the given kvset is private or otherwise exclusively
 * locked caller should call c0kvs_get_excl().
 *
 * Return:
 *
 * If the returned value is 0, then @res indicates the lookup
 * status as follows:
 *
 *     FOUND_VAL:  the key was found and the associated value
 *                 was copied into @vbuf.
 *
 *     FOUND_TMB:  a tombstone entry was found.
 *
 *     NOT_FOUND:  no matching entry was found.
 *
 * If the returned value, err, is not 0, then merr_errno(err) is one of:
 *
 *     EMSGSIZE:   value was found but does not fit into callers buffer.
 */
merr_t
c0kvs_get_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf,
    uintptr_t *              oseqnoref);

merr_t
c0kvs_get_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf,
    uintptr_t *              oseqnoref);

merr_t
c0kvs_pfx_probe_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq);

merr_t
c0kvs_pfx_probe_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq);

/**
 * c0kvs_prefix_get_rcu() - given a key, retrieve a value from a struct c0_kvset
 * @handle:    Struct c0_kvset to search
 * @key:       Key
 * @iseqno:    Get the latest value with seqno not newer than iseqno
 * @pfx_len:   Prefix length
 * @oseqnoref: (out) Sequence # reference of matching prefix tombstone if found
 *
 * Check if there is a prefix tombstone associated with the key.
 *
 * Caller must be within an rcu read-side critical section to call this
 * function.  If the given kvset is private or otherwise exclusively
 * locked call should call c0kvs_prefix_get_excl().
 */
void
c0kvs_prefix_get_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    u32                      pfx_len,
    uintptr_t *              oseqnoref);

void
c0kvs_prefix_get_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    u32                      pfx_len,
    uintptr_t *              oseqnoref);

/**
 * c0kvs_findval() - the One True Way to get the correct value for a key
 * @kv:           the bonsai kv to search
 * @view_seqno:   the view seqno for this search context
 * @seqnoref:     a seqnoref if this is within a transaction context
 *
 * Return: pointer to a bonsai value, else null if no plausible value
 */

struct bonsai_val;
struct bonsai_kv;

struct bonsai_val *
c0kvs_findval(struct bonsai_kv *kv, u64 view_seqno, uintptr_t seqnoref);

/**
 * c0kvs_get_content_metrics() - retrieve metrics for the struct c0_kvset
 * @set:                  Struct c0_kvset to insert the key/value into
 * @num_entries:          Number of entries in the struct c0_kvset
 * @num_tombstones:       Number of tombstone entries in the struct c0_kvset
 * @total_key_bytes:      Total number of bytes for all the keys
 * @total_value_bytes:    Total number of bytes for all the values
 *
 * Retrieve metrics associated with the c0_kvset, particularly its
 * number of entries, number of tombstones, total size of all keys,
 * and total size of all values. Note that the latter two are not
 * inclusive of the in-memory overhead of the kvs_ktuple and
 * kvs_vtuple structures. Only the actual key data and value data are
 * counted. Additionally, a deleted element's tombstone counts as an
 * entry and has 8 bytes of value data.
 *
 * Return: [HSE_REVISIT]
 */
void
c0kvs_get_content_metrics(
    struct c0_kvset *set,
    u64 *            num_entries,
    u64 *            num_tombstones,
    u64 *            total_key_bytes,
    u64 *            total_value_bytes);

/**
 * c0kvs_get_element_count() - return the number of elements in the c0_kvset
 * @set:   Struct c0_kvset to inspect
 *
 * Return: sum of the number of key/value entries and tombstones
 */
u64
c0kvs_get_element_count(struct c0_kvset *set);

u64
c0kvs_get_element_count2(struct c0_kvset *set, uint *heightp, uint *keyvalsp);

void
c0kvs_usage(struct c0_kvset *handle, struct c0_usage *usage);

/**
 * c0kvs_finalize() - transition a struct c0_kvset to a read-only state
 * @set:   c0kvs handle
 *
 * This function marks the c0kvs as finalized and then runs code to
 * determine the longest common prefix of all the keys in the c0kvs.
 * All callers inserting/deleting keys from an active c0kvs must do
 * so under the RCU read lock, which holds off finalization until the
 * end of the grace period.  Attempts to insert/delete a key after the
 * c0kvs has been finalized is a grievous error that could lead to data
 * integrity issues.
 *
 * This restriction does not apply to private c0kvs, such as those that
 * are part of a transaction's private kvms.  Owners of a private c0kvs
 * need never call c0kvs_finalize().
 */
void
c0kvs_finalize(struct c0_kvset *set);

/**
 * c0kvs_iterator_init() - initialize a forward iterator
 * @set:   Struct c0_kvset to be traversed
 * @iter:
 * @flags: input flags
 * @index: index to filter on if flags indicates to filter on index
 *
 * Initialize an iterator for traversing the data elements (i.e., cb_kv)
 * of the specified container from lowest to highest key.
 */
void
c0kvs_iterator_init(struct c0_kvset *set, struct c0_kvset_iterator *iter, uint flags, int index);

/**
 * c0kvs_debug - print the bonsai tree kv list
 * @set:  Struct c0_kvset to dump
 * @key:  optional: show only this key
 * @klen: optional: length of key to find, 0 = all keys
 */
void
c0kvs_debug(struct c0_kvset *set, void *key, int klen);

#endif /* HSE_CORE_C0_KVSET_H */
