/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/slab.h>
#include <hse_util/log2.h>
#include <hse_util/fmt.h>
#include <hse_util/compression_lz4.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>

#include "c0_kvset_internal.h"
#include "c0_cursor.h"
#include "c0_kvsetm.h"

/*
 * A struct c0_kvset contains a Bonsai tree that is used in a RCU style.
 * In userspace this is part of the Bonsai tree library. The kernel space
 * implementation is TBD.
 */
#include <hse_util/bonsai_tree.h>

static void
c0kvs_destroy_impl(struct c0_kvset_impl *set);

/* c0kvs_ingesting provides a sane default for c0s_ingesting, primarily
 * for unit tests.  It is overridden via c0kvs_ingesting_init() in
 * normal use.
 */
static atomic_t c0kvs_ingesting = ATOMIC_INIT(0);

/**
 * struct c0kvs_cbkt - cheap cache bucket
 * @cb_lock:    bucket lock
 * @cb_head:    cheap cache list head
 * @cb_size:    current size of cache (bytes)
 * @cb_max:     max size of cache (bytes)
 */
struct c0kvs_cbkt {
    spinlock_t            cb_lock;
    struct c0_kvset_impl *cb_head;
    size_t                cb_size;
    size_t                cb_max;
} __aligned(SMP_CACHE_BYTES);

/**
 * struct c0kvs_ccache - cache of initialized cheap-based c0kvs objects
 * @cc_cbktv:   vector of cache buckets
 * @cc_init:    set to %true if initialized
 *
 * Creating and destroying cheap-backed c0kvsets is relatively expensive,
 * so we keep a small cache of them ready for immediate use.  The cache
 * is accessed on a per-cpu basis, but we'll check all buckets in order
 * to satisfy each alloc/free request before resorting to full-on c0kvms
 * create/destroy operation.
 */
struct c0kvs_ccache {
    struct c0kvs_cbkt cc_bktv[8];
    bool              cc_init;
};

static struct c0kvs_ccache c0kvs_ccache;
static atomic_t            c0kvs_init_ref;

#define C0KVS_CBKT_MAX NELEM(c0kvs_ccache.cc_bktv)

static struct c0_kvset_impl *
c0kvs_ccache_alloc(size_t sz)
{
    struct c0_kvset_impl *set = NULL;
    struct c0kvs_cbkt *   bkt;
    uint                  idx;
    int                   i;

    idx = raw_smp_processor_id() / 4;

    for (i = 0; i < C0KVS_CBKT_MAX + 1; ++i, ++idx) {
        bkt = c0kvs_ccache.cc_bktv + (idx % C0KVS_CBKT_MAX);

        spin_lock(&bkt->cb_lock);
        set = bkt->cb_head;
        if (set) {
            bkt->cb_size -= HSE_C0_CCACHE_TRIMSZ;
            bkt->cb_head = set->c0s_next;

            set->c0s_alloc_sz = sz;
        }
        spin_unlock(&bkt->cb_lock);

        if (set)
            break;
    }

    return set;
}

static void
c0kvs_ccache_free(struct c0_kvset_impl *set)
{
    struct c0kvs_cbkt *bkt;
    uint               idx;
    int                i;

    c0kvs_reset(&set->c0s_handle, 0);
    cheap_trim(set->c0s_cheap, HSE_C0_CCACHE_TRIMSZ);

    idx = raw_smp_processor_id() / 4;

    for (i = 0; i < C0KVS_CBKT_MAX + 1; ++i, ++idx) {
        bkt = c0kvs_ccache.cc_bktv + (idx % C0KVS_CBKT_MAX);

        spin_lock(&bkt->cb_lock);
        if (bkt->cb_size + HSE_C0_CCACHE_TRIMSZ < bkt->cb_max) {
            bkt->cb_size += HSE_C0_CCACHE_TRIMSZ;
            set->c0s_next = bkt->cb_head;
            bkt->cb_head = set;
            set = NULL;
        }
        spin_unlock(&bkt->cb_lock);

        if (!set)
            return;
    }

    c0kvs_destroy_impl(set);
}

/**
 * c0kvs_ior_stats() - method to update stats on insert/replace
 * @c0kvs:         struct c0_kvset whose stats will be updated
 * @code:          Was the operation an insert or replace
 * @old_key:       Address of old key
 * @old_key_len:   Length of old key
 * @old_value:     Address of old value
 * @old_value_len: Length of old value
 * @new_key:       Address of new key
 * @new_key_len:   Length of new key
 * @new_value:     Address of new value
 * @new_value_len: Length of new value
 */
static void
c0kvs_ior_stats(
    struct c0_kvset_impl *c0kvs,
    u32                   code,
    const void *          old_key,
    u32                   old_key_len,
    const void *          old_value,
    u32                   old_value_len,
    const void *          new_key,
    u32                   new_key_len,
    const void *          new_value,
    u32                   new_value_len)
{
    if (IS_IOR_INS(code)) {
        /* first insert for this key ... */
        ++c0kvs->c0s_num_keys;
        if (!HSE_CORE_IS_TOMB(new_value))
            ++c0kvs->c0s_num_entries;
        else
            ++c0kvs->c0s_num_tombstones;
        c0kvs->c0s_total_key_bytes += new_key_len;
        c0kvs->c0s_total_value_bytes += new_value_len;

    } else if (IS_IOR_REP(code)) {
        /* replaced existing value for this key ... */

        if (!HSE_CORE_IS_TOMB(old_value)) {
            if (HSE_CORE_IS_TOMB(new_value)) {
                --c0kvs->c0s_num_entries;
                ++c0kvs->c0s_num_tombstones;
            }
            c0kvs->c0s_total_value_bytes -= old_value_len;
            c0kvs->c0s_total_value_bytes += new_value_len;
        } else {
            if (!HSE_CORE_IS_TOMB(new_value)) {
                ++c0kvs->c0s_num_entries;
                --c0kvs->c0s_num_tombstones;
            }
            c0kvs->c0s_total_value_bytes += new_value_len;
        }
    } else {
        assert(IS_IOR_ADD(code));
        if (!HSE_CORE_IS_TOMB(new_value))
            ++c0kvs->c0s_num_entries;
        else
            ++c0kvs->c0s_num_tombstones;
        c0kvs->c0s_total_value_bytes += new_value_len;
    }
}

/*
 * This path (put) can potentially race with the installation of a new kvms. So
 * we maintain an additional seqno - one that is local to a kvms. This seqno
 * is set to HSE_SQNREF_INVALID while the kvms is active. It is assigned the
 * kvdb_seqno right before it is frozen.
 *
 * To avoid unordered seqno, we follow these steps in the two places:
 *
 * install:
 *   kvms_seqno = kvdb_seqno
 *   kvdb_seqno += 2
 *
 * put:
 *   s = kvdb_seqno
 *   if (kvms_seqno != HSE_SQNREF_INVALID):
 *     use kvms_seqno
 *   else
 *     use s
 */
static u64
c0kvs_seqno_set(struct c0_kvset_impl *c0kvs, struct bonsai_val *bv)
{
    u64         seq;
    atomic64_t *sref = c0kvs->c0s_kvdb_seqno;

    /* [HSE_REVISIT]
     * If an operation (such as txBegin or cursorCreate) obtains a view
     * after the KVDB seqno is read..
     *
     * ..AND, reads the value in 'bv' in either of the below two cases:
     * (i) Before 'bv->bv_seqnoref' is updated at the end of this
     * function for newly inserted keys.
     * (ii) Before rcu_assign pointer() in 'c0kvs_ior_cb()' for updates
     * to an existing key...
     *
     * ..AND, then reads the same 'bv' after 'bv->bv_seqnoref' is updated
     * or after the rcu grace period ends respectively, it will see two
     * different values for the same key. In other words, the view will
     * have changed.
     */
    seq = bv->bv_valuep == HSE_CORE_TOMB_PFX ? atomic64_add_return(1, sref) : atomic64_read(sref);

    /* If KVMS seqno is valid, use it. */
    if (unlikely(atomic64_read(c0kvs->c0s_kvms_seqno) != HSE_SQNREF_INVALID)) {
        sref = c0kvs->c0s_kvms_seqno;

        seq =
            bv->bv_valuep == HSE_CORE_TOMB_PFX ? atomic64_add_return(1, sref) : atomic64_read(sref);
    }

    bv->bv_seqnoref = HSE_ORDNL_TO_SQNREF(seq);

    return seq;
}

static inline bool
c0kvsm_insert_bkv_nontx(struct c0_kvsetm *ckm, struct bonsai_kv *kv, u8 idx)
{
    if (s_list_empty(&kv->bkv_mnext[idx])) {
        s_list_add_tail(&kv->bkv_mnext[idx], &ckm->c0m_tail);
        ++ckm->c0m_kcnt;

        return false;
    }

    return true;
}

static inline bool
c0kvsm_insert_bkv_tx(struct c0_kvsetm *ckm, struct bonsai_kv *kv, u8 idx)
{
    ckm->c0m_minseqno = 0;

    if (s_list_empty(&kv->bkv_txmnext[idx])) {
        s_list_add_tail(&kv->bkv_txmnext[idx], &ckm->c0m_tail);
        ++ckm->c0m_kcnt;

        return false;
    }

    return true;
}

static inline void
c0kvsm_update_seqno(struct c0_kvsetm *ckm, u64 seqno)
{
    if (seqno < ckm->c0m_minseqno)
        ckm->c0m_minseqno = seqno;

    if (seqno > ckm->c0m_maxseqno)
        ckm->c0m_maxseqno = seqno;
}

static void
c0kvsm_insert_bkv(
    struct c0_kvset * handle,
    u32               code,
    struct bonsai_kv *kv,
    u64               seqno,
    u64               klen,
    u64               vlen,
    u64               ovlen,
    bool              istxn)
{
    struct c0_kvset_impl *c0kvs;
    struct c0_kvsetm *    ckm;

    bool found = false;
    u8   idx;

    c0kvs = c0_kvset_h2r(handle);

    mutex_lock(&c0kvs->c0s_mlock);

    idx = c0kvsm_get_mindex(handle);

    if (istxn) {
        ckm = &c0kvs->c0s_txm[idx];
        found = c0kvsm_insert_bkv_tx(ckm, kv, idx);
    } else {
        ckm = &c0kvs->c0s_m[idx];
        found = c0kvsm_insert_bkv_nontx(ckm, kv, idx);
        c0kvsm_update_seqno(ckm, seqno);
    }

    /* Include key size in the mutation list only if the key gets added
     * to the list.
     * */
    if (!found)
        ckm->c0m_ksize += klen;

    ckm->c0m_vsize += vlen;
    ++ckm->c0m_vcnt;

    /* If:
     *     1. bonsai_kv is already part of mutation list AND
     *     2. The value is replaced and the replaced value element
     *     has a sequence number in the range
     *     [c0m_minseqref, c0m_maxseqref] or an invalid sequence no.
     *     in the case of a transaction.
     * then:
     *     deduct the old value length.
     */
    if (IS_IOR_REP(code) && found &&
        (istxn || (seqno >= ckm->c0m_minseqno && seqno <= ckm->c0m_maxseqno)) &&
        ckm->c0m_vsize >= ovlen) {
        ckm->c0m_vsize -= ovlen;
        --ckm->c0m_vcnt;
    }

    mutex_unlock(&c0kvs->c0s_mlock);
}

/**
 * c0kvs_ior_cb() - Callback method to update stats on insert/replace and
 *                  attach a value element to the values list.
 * @cli_rock:  client's private pointer
 * @code:      enum bonsai_ior_code
 * @kv:        bonsai_kv instance of the bonsai node where the value element
 *             needs to be attached
 * @new_val:   allocated and initialized value element
 * @old_val:   old value element to be freed, if replaced (output)
 *
 * Called by the Bonsai tree code to insert a new value in an appropriate
 * position in the bkv_values list and update stats.
 */
void
c0kvs_ior_cb(
    void *                cli_rock,
    enum bonsai_ior_code *code,
    struct bonsai_kv *    kv,
    struct bonsai_val *   new_val,
    struct bonsai_val **  old_val)
{
    struct c0_kvset_impl *c0kvs;
    struct bonsai_val *   old;
    struct bonsai_val **  prevp;
    enum hse_seqno_state  state;

    uintptr_t    seqnoref;
    u64          seqno = 0;
    u64          mut_seqno = 0;
    const void * o_val;
    unsigned int o_vlen;
    const void * n_val;
    unsigned int n_vlen;
    bool         tracked;
    bool         txn_op, txn_merge, txn_put;
    u16          klen;

    state = HSE_SQNREF_STATE_UNDEFINED;
    c0kvs = c0_kvset_h2r(cli_rock);
    txn_op = false;
    txn_merge = false;
    txn_put = false;
    tracked = c0kvs->c0s_mut_tracked;
    klen = key_imm_klen(&kv->bkv_key_imm);

    seqnoref = IS_IOR_INS(*code) ? kv->bkv_values->bv_seqnoref : new_val->bv_seqnoref;
    state = seqnoref_to_seqno(seqnoref, &seqno);

    txn_merge = state == HSE_SQNREF_STATE_INVALID;
    txn_put = state == HSE_SQNREF_STATE_UNDEFINED;
    txn_op = txn_put || txn_merge;

    if (IS_IOR_INS(*code)) {
        struct bonsai_val *val;

        assert(new_val == NULL);

        val = kv->bkv_values;
        n_vlen = bonsai_val_len(val);
        n_val = (n_vlen == 0) ? val->bv_valuep : val->bv_value;

        if (state == HSE_SQNREF_STATE_SINGLE)
            seqno = c0kvs_seqno_set(c0kvs, val);

        c0kvs_ior_stats(c0kvs, *code, NULL, 0, NULL, 0, kv->bkv_key, klen, n_val, n_vlen);

        if (!tracked)
            return;

        /* Flag the value as transaction mutation. */
        if (txn_op)
            bv_set_txn(val);
        else
            mut_seqno = seqno;

        c0kvsm_insert_bkv(cli_rock, *code, kv, mut_seqno, klen, n_vlen, 0, txn_op);

        return;
    }

    assert(IS_IOR_REPORADD(*code));

    /* Search for an existing value with the given seqnoref */
    prevp = &kv->bkv_values;
    SET_IOR_ADD(*code);

    assert(kv->bkv_values);

    /* The seqno must be assigned before the while loop that follows.
     * This allows replacements in the value list and thus prevents
     * the list from growing out of control. Having a long list affects
     * put and ingest latencies.
     */
    if (state == HSE_SQNREF_STATE_SINGLE) {
        seqno = c0kvs_seqno_set(c0kvs, new_val);
        seqnoref = new_val->bv_seqnoref;
    }

    old = kv->bkv_values;

    /* For a transaction merge, values can be added directly to the head
     * of the bonsai values list without traversal because:
     *
     * 1. Values come with a seqnoref of HSE_SQNREF_INVALID, which is
     * greater than any other seqnoref that will be found in the values
     * list. This optimization avoid an unnecessary traversal.
     *
     * 2. There can't be a value in the list with a seqnoref of
     * HSE_SQNREF_INVALID, as the same key cannot be modified by more
     * than one transaction.
     */
    while (old && !txn_merge) {
        if (seqnoref == old->bv_seqnoref) {
            SET_IOR_REP(*code);
            break;
        }

        if (seqnoref_gt(seqnoref, old->bv_seqnoref))
            break;

        prevp = &old->bv_next;
        old = old->bv_next;
    }

    if (IS_IOR_REP(*code)) {
        /* in this case we'll just replace the old list element */
        new_val->bv_next = old->bv_next;
    } else if (HSE_SQNREF_ORDNL_P(seqnoref)) {
        /* slot the new element just in front of the next older one */
        new_val->bv_next = old;
    } else {
        /* rewind & slot the new element at the front of the list */
        prevp = &kv->bkv_values;
        new_val->bv_next = *prevp;
    }

    /* Publish the new value node.  New readers will see the new node,
     * while existing readers may continue to use the old node until
     * the end of the current grace period.
     */
    rcu_assign_pointer(*prevp, new_val);

    o_vlen = 0;
    o_val = NULL;

    if (old) {
        o_vlen = bonsai_val_len(old);
        o_val = (o_vlen == 0) ? old->bv_valuep : old->bv_value;
    }

    n_vlen = bonsai_val_len(new_val);
    n_val = (n_vlen == 0) ? new_val->bv_valuep : new_val->bv_value;

    c0kvs_ior_stats(
        c0kvs, *code, kv->bkv_key, klen, o_val, o_vlen, kv->bkv_key, klen, n_val, n_vlen);

    if (IS_IOR_REP(*code))
        *old_val = old;

    if (!tracked)
        return;

    /* Flag the value as transaction mutation. */
    if (txn_op)
        bv_set_txn(new_val);
    else
        mut_seqno = seqno;

    c0kvsm_insert_bkv(cli_rock, *code, kv, mut_seqno, klen, n_vlen, o_vlen, txn_op);
}

static __always_inline bool
c0kvs_should_ingest(struct c0_kvset *handle, u32 nvals)
{
    struct c0_kvset_impl *self;

    size_t total;
    size_t free;

    /* [HSE_REVISIT]: Based on experiments, read performance suffers if
     * a get thread traverses more than 3K nodes in the values list.
     * This limit needs to be configurable.
     */
    if (likely(nvals < 3072 || !handle))
        return false;

    self = c0_kvset_h2r(handle);
    total = self->c0s_alloc_sz;
    free = c0kvs_avail(handle);

    /* If free space is less than 75% of total space, then ingest. This
     * is to guard against pathological cases that could result in
     * frequent ingests.
     */
    return (free < (total * 3) / 4);
}

/**
 * c0kvs_findval() - Method to pick a value element from the bkv_values list,
 *                   based on seqno.
 * @kv:         bonsai_kv instance of the bonsai node matching a searched key
 * @view_seqno:
 * @seqnoref:
 */
struct bonsai_val *
c0kvs_findval(struct c0_kvset *handle, struct bonsai_kv *kv, u64 view_seqno, uintptr_t seqnoref)
{
    struct bonsai_val *val_ge, *val;
    u64                diff_ge, diff;
    u32                nvals;

    diff_ge = ULONG_MAX;
    val_ge = NULL;
    nvals = 0;

    for (val = kv->bkv_values; val; val = rcu_dereference(val->bv_next)) {
        diff = seqnoref_ext_diff(view_seqno, val->bv_seqnoref);
        if (diff < diff_ge) {
            diff_ge = diff;
            val_ge = val;
        }

        ++nvals;

        if (!seqnoref) {
            if (diff_ge == 0)
                break;
            continue;
        }

        if (seqnoref == val->bv_seqnoref) {
            val_ge = val;
            break;
        }

        diff = seqnoref_diff(seqnoref, val->bv_seqnoref);
        if (diff < diff_ge) {
            diff_ge = diff;
            val_ge = val;
        }
    }

    if (c0kvs_should_ingest(handle, nvals))
        atomic_inc((c0_kvset_h2r(handle))->c0s_ingesting);

    return val_ge;
}

/**
 * c0kvs_findpfxval() - Method to check whether a prefix tombstone exists in
 *                      the values list.
 * @kv:        bonsai_kv instance of the bonsai node matching a searched key
 * @seqnoref:
 */
static struct bonsai_val *
c0kvs_findpfxval(struct bonsai_kv *kv, uintptr_t seqnoref)
{
    struct bonsai_val *val;

    val = kv->bkv_values;
    while (val) {
        if (val->bv_valuep == HSE_CORE_TOMB_PFX) {
            if ((val->bv_seqnoref == seqnoref) || seqnoref_ge(seqnoref, val->bv_seqnoref))
                break;
        }
        val = rcu_dereference(val->bv_next);
    }

    return val;
}

void
c0kvsm_reset(struct c0_kvsetm *ckm)
{
    if (ev(!ckm))
        return;

    INIT_S_LIST_HEAD(&ckm->c0m_head);
    ckm->c0m_tail = &ckm->c0m_head;
    ckm->c0m_minseqno = U64_MAX;
    ckm->c0m_maxseqno = 0;
    ckm->c0m_ksize = 0;
    ckm->c0m_vsize = 0;
    ckm->c0m_kcnt = 0;
    ckm->c0m_vcnt = 0;
}

static void
c0kvsm_init(struct c0_kvset *handle)
{
    struct c0_kvset_impl *set;

    int i;

    if (ev(!handle))
        return;

    set = c0_kvset_h2r(handle);

    for (i = 0; i < BONSAI_MUT_LISTC; i++) {
        c0kvsm_reset(&set->c0s_m[i]);
        c0kvsm_reset(&set->c0s_txm[i]);
    }
    c0kvsm_reset(&set->c0s_txpend);

    set->c0s_mindex = 0;
}

merr_t
c0kvs_create(
    size_t            alloc_sz,
    atomic64_t *      kvdb_seqno,
    atomic64_t *      kvms_seqno,
    bool              tracked,
    struct c0_kvset **handlep)
{
    struct c0_kvset_impl *set;
    struct cheap *        cheap;
    merr_t                err;

    *handlep = NULL;

    alloc_sz = max_t(size_t, alloc_sz, HSE_C0_CHEAP_SZ_MIN);
    alloc_sz = min_t(size_t, alloc_sz, HSE_C0_CHEAP_SZ_MAX);

    set = c0kvs_ccache_alloc(alloc_sz);
    if (set)
        goto created;

    cheap = cheap_create(sizeof(void *) * 2, HSE_C0_CHEAP_SZ_MAX);
    if (ev(!cheap))
        return merr(ENOMEM);

    set = cheap_memalign(cheap, __alignof(*set), sizeof(*set));
    if (ev(!set)) {
        cheap_destroy(cheap);
        return merr(ENOMEM);
    }

    set->c0s_alloc_sz = alloc_sz;
    set->c0s_cheap = cheap;
    set->c0s_ingesting = &c0kvs_ingesting;
    atomic_set(&set->c0s_finalized, 0);
    mutex_init(&set->c0s_mutex);
    mutex_init(&set->c0s_mlock);

    err = bn_create(cheap, HSE_C0_BNODE_SLAB_SZ, c0kvs_ior_cb, set, &set->c0s_broot);
    if (ev(err)) {
        c0kvs_destroy_impl(set);
        return err;
    }

    set->c0s_reset_sz = cheap_used(cheap);

created:
    set->c0s_kvdb_seqno = kvdb_seqno;
    set->c0s_kvms_seqno = kvms_seqno;
    set->c0s_mut_tracked = tracked;

    *handlep = &set->c0s_handle;

    c0kvsm_init(*handlep);

    return 0;
}

static void
c0kvs_destroy_impl(struct c0_kvset_impl *set)
{
    mutex_destroy(&set->c0s_mutex);
    mutex_destroy(&set->c0s_mlock);

    cheap_destroy(set->c0s_cheap);
}

void
c0kvs_destroy(struct c0_kvset *handle)
{
    struct c0_kvset_impl *set;

    if (ev(!handle))
        return;

    set = c0_kvset_h2r(handle);

    c0kvs_ccache_free(set);
}

size_t
c0kvs_used(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return cheap_used(self->c0s_cheap);
}

size_t
c0kvs_avail(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    size_t                used;

    used = cheap_used(self->c0s_cheap);
    used = min_t(size_t, self->c0s_alloc_sz, used);

    return self->c0s_alloc_sz - used;
}

void
c0kvs_reset(struct c0_kvset *handle, size_t sz)
{
    struct c0_kvset_impl *set;

    set = c0_kvset_h2r(handle);

    assert(set->c0s_cheap);

    cheap_reset(set->c0s_cheap, max_t(size_t, sz, set->c0s_reset_sz));

    bn_reset(set->c0s_broot);

    atomic_set(&set->c0s_finalized, 0);
    set->c0s_ingesting = &c0kvs_ingesting;
    set->c0s_num_entries = 0;
    set->c0s_num_tombstones = 0;
    set->c0s_total_key_bytes = 0;
    set->c0s_total_value_bytes = 0;
    set->c0s_num_keys = 0;

    c0kvsm_init(handle);
}

void
c0kvs_ingesting_init(struct c0_kvset *handle, atomic_t *ingesting)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    self->c0s_ingesting = ingesting;
}

static __always_inline void
c0kvs_lock(struct c0_kvset_impl *self)
{
    mutex_lock(&self->c0s_mutex);
}

static __always_inline void
c0kvs_unlock(struct c0_kvset_impl *self)
{
    mutex_unlock(&self->c0s_mutex);
}

void *
c0kvs_alloc(struct c0_kvset *handle, size_t align, size_t sz)
{
    struct c0_kvset_impl *impl = c0_kvset_h2r(handle);
    void *                mem;

    c0kvs_lock(impl);
    mem = cheap_memalign(impl->c0s_cheap, align, sz);
    c0kvs_unlock(impl);

    return mem;
}

static merr_t
c0kvs_putdel(
    struct c0_kvset_impl *self,
    struct bonsai_skey *  skey,
    struct bonsai_sval *  sval,
    size_t                sz,
    bool                  tomb)
{
    merr_t err;
    u64    avail;

    sz += HSE_C0_BNODE_SLAB_SZ + PAGE_SIZE;

    c0kvs_lock(self);
    avail = c0kvs_avail(&self->c0s_handle);

    if (likely(sz < avail))
        err = bn_insert_or_replace(self->c0s_broot, skey, sval, tomb);
    else
        err = (sz > self->c0s_alloc_sz) ? merr(EFBIG) : merr(ENOMEM);
    c0kvs_unlock(self);

    /* Callers putting keys into the active kvms must hold the
     * RCU read lock.  As such, a c0kvset undergoing ingest will
     * be finalized (i.e., frozen) the end of the grace period,
     * after which c0 ingest may proceed.  It is a grievous error
     * for a caller to insert a new key into a frozen c0kvset.
     */
    assert(atomic_read(&self->c0s_finalized) == 0);

    return err;
}

merr_t
c0kvs_put(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    const struct kvs_vtuple *value,
    uintptr_t                seqnoref)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey;
    struct bonsai_sval    sval;

    bn_skey_init(key->kt_data, key->kt_len, skidx, &skey);
    bn_sval_init(value->vt_data, value->vt_xlen, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, key->kt_len + kvs_vtuple_len(value), false);
}

merr_t
c0kvs_del(struct c0_kvset *handle, u16 skidx, const struct kvs_ktuple *key, uintptr_t seqnoref)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey;
    struct bonsai_sval    sval;

    bn_skey_init(key->kt_data, key->kt_len, skidx, &skey);
    bn_sval_init(HSE_CORE_TOMB_REG, 0, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, key->kt_len, true);
}

merr_t
c0kvs_prefix_del(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    uintptr_t                seqnoref)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey;
    struct bonsai_sval    sval;

    bn_skey_init(key->kt_data, key->kt_len, skidx, &skey);
    bn_sval_init(HSE_CORE_TOMB_PFX, 0, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, key->kt_len, false);
}

void
c0kvs_get_content_metrics(
    struct c0_kvset *handle,
    u64 *            num_entries,
    u64 *            num_tombstones,
    u64 *            total_key_bytes,
    u64 *            total_value_bytes)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    *num_entries = self->c0s_num_entries;
    *num_tombstones = self->c0s_num_tombstones;
    *total_key_bytes = self->c0s_total_key_bytes;
    *total_value_bytes = self->c0s_total_value_bytes;
}

u64
c0kvs_get_element_count(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return self->c0s_num_entries + self->c0s_num_tombstones;
}

void
c0kvs_usage(struct c0_kvset *handle, struct c0_usage *usage)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    size_t                free;

    free = c0kvs_avail(handle);
    assert(free < self->c0s_alloc_sz);

    usage->u_alloc = self->c0s_alloc_sz;
    usage->u_free = free;
    usage->u_used_min = self->c0s_alloc_sz - free;
    usage->u_used_max = self->c0s_alloc_sz - free;
    usage->u_keys = self->c0s_num_entries;
    usage->u_tombs = self->c0s_num_tombstones;
    usage->u_keyb = self->c0s_total_key_bytes;
    usage->u_valb = self->c0s_total_value_bytes;
    usage->u_count = 1;
}

/*
 * If key is found:
 *     return value == 0 && *res == FOUND_VAL && *oseqnoref == seqnoref of match
 * If tombstone is found:
 *     return value == 0 && *res == FOUND_TMB && *oseqnoref == seqnoref of match
 * If key is not found:
 *     return value == 0 && *res == NOT_FOUND &&
 *         *oseqnoref = HSE_ORDNL_TO_SQNREF(0) (invalid ordinal)
 */
merr_t
c0kvs_get_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf,
    uintptr_t *              oseqnoref)
{
    struct c0_kvset_impl *self;
    struct bonsai_skey    skey;
    struct bonsai_val    *val;
    struct bonsai_kv     *kv;
    uint copylen, outlen, clen, ulen;
    bool found;
    merr_t err;

    *oseqnoref = HSE_ORDNL_TO_SQNREF(0);
    *res = NOT_FOUND;

    self = c0_kvset_h2r(handle);
    bn_skey_init(key->kt_data, key->kt_len, skidx, &skey);
    kv = NULL;

    found = bn_find(self->c0s_broot, &skey, &kv);
    if (!found)
        return 0;

    val = c0kvs_findval(handle, kv, view_seqno, seqnoref);
    if (!val)
        return 0;

    *oseqnoref = val->bv_seqnoref;

    if (HSE_CORE_IS_TOMB(val->bv_valuep)) {
        *res = FOUND_TMB;
        return 0;
    }

    vbuf->b_len = bonsai_val_len(val);
    copylen = vbuf->b_len;

    if (copylen > vbuf->b_buf_sz)
        copylen = vbuf->b_buf_sz;

    if (copylen > 0 && vbuf->b_buf) {
        clen = bonsai_val_clen(val);
        ulen = bonsai_val_ulen(val);

        if (clen > 0) {
            err = compress_lz4_ops.cop_decompress(
                val->bv_value, clen, vbuf->b_buf, vbuf->b_buf_sz, &outlen);
            if (ev(err))
                return err;

            if (ev(outlen != min_t(uint, ulen, vbuf->b_buf_sz)))
                return merr(EBUG);

            vbuf->b_len = outlen;
        } else {
            memcpy(vbuf->b_buf, val->bv_value, copylen);
        }
    }

    *res = FOUND_VAL;

    return 0;
}

merr_t
c0kvs_get_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf,
    uintptr_t *              oseqnoref)
{
    assert(rcu_read_ongoing());

    return c0kvs_get_excl(handle, skidx, key, view_seqno,
                          seqnoref, res, vbuf, oseqnoref);
}

merr_t
c0kvs_pfx_probe_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_root *  root = self->c0s_broot;
    struct bonsai_skey    skey;
    struct bonsai_kv *    kv;
    struct bonsai_val *   val;
    bool                  found;
    u64                   val_seq;
    merr_t                err = 0;

    bn_skey_init(key->kt_data, key->kt_len, skidx, &skey);

    found = bn_findGE(root, &skey, &kv);
    if (!found) {
        *res = NOT_FOUND;
        return 0;
    }

    /* Bonsai nodes are never deleted. The next node can then be either
     *  1. unchanged, or
     *  2. a new node inserted between the old next and current. In this
     *     case, seqno filtering should take care of skipping the newly
     *     added node.
     */
    assert(kv);

    /* found a key with the requested pfx */
    for (; kv != &root->br_kv; kv = rcu_dereference(kv->bkv_next)) {
        u32 klen = key_imm_klen(&kv->bkv_key_imm);

        if (keycmp_prefix(key->kt_data, key->kt_len, kv->bkv_key, klen))
            break; /* eof */

        if (qctx->seen &&
            !keycmp(kv->bkv_key, klen,
                    kbuf->b_buf, min_t(size_t, kbuf->b_len, kbuf->b_buf_sz)))
            continue; /* duplicate */

        /* Skip key if there is a matching tomb */
        if (qctx_tomb_seen(qctx, kv->bkv_key + key->kt_len, klen))
            continue;

        val = c0kvs_findval(handle, kv, view_seqno, seqnoref);
        if (!val)
            continue;

        /* add to tomblist if a tombstone was encountered */
        if (HSE_CORE_IS_TOMB(val->bv_valuep)) {
            err = qctx_tomb_insert(qctx, kv->bkv_key + key->kt_len, klen);
            if (ev(err))
                break;

            continue;
        }

        if (seqnoref_to_seqno(val->bv_seqnoref, &val_seq) != HSE_SQNREF_STATE_DEFINED) {
            /* This kv is from a txn. In a txn, a ptomb doesn't
             * hide mutations local to txn. So fallthrough and
             * count this key
             */
        } else {
            if (val_seq < pt_seq)
                continue;
        }

        if (++qctx->seen == 1) {
            uint copylen, outlen, clen, ulen;

            /* copyout key and value */
            kbuf->b_len = klen;
            copylen = min_t(size_t, kbuf->b_len, kbuf->b_buf_sz);
            memcpy(kbuf->b_buf, kv->bkv_key, copylen);

            vbuf->b_len = bonsai_val_len(val);
            copylen = vbuf->b_len;

            if (copylen > vbuf->b_buf_sz)
                copylen = vbuf->b_buf_sz;

            if (copylen > 0 && vbuf->b_buf) {
                clen = bonsai_val_clen(val);
                ulen = bonsai_val_ulen(val);

                if (clen > 0) {
                    err = compress_lz4_ops.cop_decompress(
                        val->bv_value, clen, vbuf->b_buf, vbuf->b_buf_sz, &outlen);
                    if (ev(err))
                        return err;

                    if (ev(outlen != min_t(uint, ulen, vbuf->b_buf_sz)))
                        return merr(EBUG);

                    vbuf->b_len = outlen;
                } else {
                    memcpy(vbuf->b_buf, val->bv_value, copylen);
                }
            }
        }
    }

    return err;
}

merr_t
c0kvs_pfx_probe_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq)
{
    assert(rcu_read_ongoing());

    return c0kvs_pfx_probe_excl(handle, skidx, key, view_seqno, seqnoref,
                                res, qctx, kbuf, vbuf, pt_seq);
}

/*
 * Search whether a prefix tombstone exists for the key.
 * If a prefix tombstone is found: *oseqnoref == seqnoref of match
 * If key is not found: *oseqnoref = HSE_ORDNL_TO_SQNREF(0) (invalid ordinal)
 */
void
c0kvs_prefix_get_excl(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    u32                      pfx_len,
    uintptr_t *              oseqnoref)
{
    struct c0_kvset_impl *self;
    struct bonsai_val *   val;
    struct bonsai_skey    skey;
    struct bonsai_kv *    kv;
    bool                  found;

    *oseqnoref = HSE_ORDNL_TO_SQNREF(0);

    self = c0_kvset_h2r(handle);
    bn_skey_init(key->kt_data, pfx_len, skidx, &skey);
    kv = NULL;

    found = bn_find(self->c0s_broot, &skey, &kv);
    if (found) {
        uintptr_t view_seqnoref = HSE_ORDNL_TO_SQNREF(view_seqno);

        val = c0kvs_findpfxval(kv, view_seqnoref);
        if (val) {
            assert(val->bv_valuep == HSE_CORE_TOMB_PFX);
            *oseqnoref = val->bv_seqnoref;
        }
    }
}

void
c0kvs_prefix_get_rcu(
    struct c0_kvset *        handle,
    u16                      skidx,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    u32                      pfx_len,
    uintptr_t *              oseqnoref)
{
    assert(rcu_read_ongoing());

    return c0kvs_prefix_get_excl(handle, skidx, key, view_seqno, pfx_len, oseqnoref);
}

void
c0kvs_finalize(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    atomic_inc(&self->c0s_finalized);
    bn_finalize(self->c0s_broot);
}

void
c0kvs_iterator_init(struct c0_kvset *handle, struct c0_kvset_iterator *iter, uint flags, int skidx)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    c0_kvset_iterator_init(iter, self->c0s_broot, flags, skidx);
}

void
c0kvs_debug(struct c0_kvset *handle, void *key, int klen)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    struct bonsai_kv * kv, *end;
    struct bonsai_val *v;

    char   disp[256];
    size_t max = sizeof(disp);

    printf("%p nkey %d ntomb %d\n", self, self->c0s_num_keys, self->c0s_num_tombstones);

    rcu_read_lock();
    end = &self->c0s_broot->br_kv;

    for (kv = end->bkv_next; kv != end; kv = rcu_dereference(kv->bkv_next)) {
        char *comma = "";

        if (klen && memcmp(key, kv->bkv_key, klen) != 0)
            continue;

        fmt_hex(disp, max, kv->bkv_key, key_imm_klen(&kv->bkv_key_imm));
        printf("\t%s: ", disp);

        for (v = kv->bkv_values; v; v = rcu_dereference(v->bv_next)) {
            u64   seqno = HSE_SQNREF_TO_ORDNL(v->bv_seqnoref);
            char *label = HSE_CORE_IS_TOMB(v->bv_valuep) ? "tomb" : "len";

            printf("%sseqnoref %p seqno %lu %s %u",
                   comma, (void *)v->bv_seqnoref,
                   seqno, label, bonsai_val_len(v));
            comma = ", ";
        }
        printf("\n");
    }

    rcu_read_unlock();
}

void
c0kvs_reinit(size_t cb_max)
{
    struct c0_kvset_impl *head, *next;
    struct c0kvs_cbkt *   bkt;
    int                   i;

    if (!c0kvs_ccache.cc_init)
        return;

    cb_max = cb_max / C0KVS_CBKT_MAX;

    for (i = 0; i < C0KVS_CBKT_MAX; ++i) {
        bkt = c0kvs_ccache.cc_bktv + i;

        spin_lock(&bkt->cb_lock);
        bkt->cb_max = cb_max;
        head = bkt->cb_head;
        bkt->cb_head = NULL;
        bkt->cb_size = 0;
        spin_unlock(&bkt->cb_lock);

        for (; head; head = next) {
            next = head->c0s_next;
            c0kvs_destroy_impl(head);
        }
    }
}

void
c0kvs_init(void)
{
    struct c0kvs_cbkt *bkt;
    int                i;

    if (atomic_inc_return(&c0kvs_init_ref) > 1)
        return;

    for (i = 0; i < C0KVS_CBKT_MAX; ++i) {
        bkt = c0kvs_ccache.cc_bktv + i;

        spin_lock_init(&bkt->cb_lock);
        bkt->cb_max = HSE_C0_CCACHE_SZ_MAX / C0KVS_CBKT_MAX;
    }

    c0kvs_ccache.cc_init = true;
}

void
c0kvs_fini(void)
{
    if (atomic_dec_return(&c0kvs_init_ref) > 0)
        return;

    c0kvs_reinit(0);
}

bool
c0kvs_preserve_tombspan(
    struct c0_kvset *handle,
    u16              index,
    const void *     kmin,
    u32              kmin_len,
    const void *     kmax,
    u32              kmax_len)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey_min;
    struct bonsai_kv *    kv = 0;
    bool                  found;
    int                   cmp = 0;

    /*
     * The tombspan interval can be preserved if the next key with a value
     * other than a tombstone doesn't fall within the tombstone span.
     */
    assert(index < HSE_KVS_COUNT_MAX);

    bn_skey_init(kmin, kmin_len, index, &skey_min);

    rcu_read_lock();
    found = bn_skiptombs_GE(self->c0s_broot, &skey_min, &kv);
    if (found) {
        assert(kv);
        cmp = keycmp(kv->bkv_key, key_imm_klen(&kv->bkv_key_imm), kmax, kmax_len);
    }
    rcu_read_unlock();

    return cmp >= 0;
}

void
c0kvs_enable_mutation(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    self->c0s_mut_tracked = true;
}

u8
c0kvsm_get_mindex(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return self->c0s_mindex;
}

void
c0kvsm_switch(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    u8                    idx;

    idx = c0kvsm_get_mindex(handle) ^ 1;

    assert(s_list_empty(&self->c0s_m[idx].c0m_head));
    assert(s_list_empty(&self->c0s_txm[idx].c0m_head));

    mutex_lock(&self->c0s_mlock);
    self->c0s_mindex = idx;
    mutex_unlock(&self->c0s_mlock);
}

struct c0_kvsetm *
c0kvsm_get(struct c0_kvset *handle, u8 mindex)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return &self->c0s_m[mindex];
}

struct c0_kvsetm *
c0kvsm_get_tx(struct c0_kvset *handle, u8 mindex)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return &self->c0s_txm[mindex];
}

struct c0_kvsetm *
c0kvsm_get_txpend(struct c0_kvset *handle)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);

    return &self->c0s_txpend;
}
