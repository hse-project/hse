/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>

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

/* The minimum c0 cheap size should be at least 2MB and large enough to accomodate
 * at least one max-sized kvs value plus associated overhead.
 */
_Static_assert(HSE_C0_CHEAP_SZ_MIN >= (2ul << 20), "min c0 cheap size too small");
_Static_assert(HSE_C0_CHEAP_SZ_MIN >= HSE_KVS_VLEN_MAX + (1ul << 20), "min c0 cheap size too small");
_Static_assert(HSE_C0_CHEAP_SZ_DFLT >= HSE_C0_CHEAP_SZ_MIN, "default c0 cheap size too small");
_Static_assert(HSE_C0_CHEAP_SZ_MAX >= HSE_C0_CHEAP_SZ_DFLT, "max c0 cheap size too small");

/*
 * A struct c0_kvset contains a Bonsai tree that is used in a RCU style.
 * In userspace this is part of the Bonsai tree library. The kernel space
 * implementation is TBD.
 */
#include <hse_util/bonsai_tree.h>

static void
c0kvs_destroy_impl(struct c0_kvset_impl *set);

/**
 * struct c0kvs_ccache - cache of initialized cheap-based c0kvs objects
 * @cb_lock:    bucket lock
 * @cb_head:    cheap cache list head
 * @cb_size:    current size of cache (bytes)
 * @cc_init:    set to %true if initialized
 *
 * Creating and destroying cheap-backed c0kvsets is relatively expensive,
 * so we keep a small cache of them ready for immediate use.  The cache
 * is accessed on a per-cpu basis, but we'll check all buckets in order
 * to satisfy each alloc/free request before resorting to full-on c0kvms
 * create/destroy operation.
 */
struct c0kvs_ccache {
    spinlock_t  cc_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    void       *cc_head HSE_ALIGNED(SMP_CACHE_BYTES);
    size_t      cc_size;
    bool        cc_init;
};

static struct c0kvs_ccache c0kvs_ccache;
static atomic_t            c0kvs_init_ref;

static struct c0_kvset_impl *
c0kvs_ccache_alloc(size_t sz)
{
    struct c0kvs_ccache *cc = &c0kvs_ccache;
    struct c0_kvset_impl *set;

    spin_lock(&cc->cc_lock);
    set = cc->cc_head;
    if (set) {
        cc->cc_size -= HSE_C0_CHEAP_SZ_MAX;
        cc->cc_head = set->c0s_next;

        set->c0s_alloc_sz = sz;
    }
    spin_unlock(&cc->cc_lock);

    return set;
}

static void
c0kvs_ccache_free(struct c0_kvset_impl *set)
{
    struct c0kvs_ccache *cc = &c0kvs_ccache;

    c0kvs_reset(&set->c0s_handle, 0);

    spin_lock(&cc->cc_lock);
    if (cc->cc_size + HSE_C0_CHEAP_SZ_MAX < HSE_C0_CCACHE_SZ_MAX) {
        cc->cc_size += HSE_C0_CHEAP_SZ_MAX;
        set->c0s_next = cc->cc_head;
        cc->cc_head = set;
        set = NULL;
    }
    spin_unlock(&cc->cc_lock);

    if (set)
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
    u32                   new_value_len,
    uint                  height,
    uint                  keyvals)
{
    if (IS_IOR_INS(code)) {
        /* first insert for this key ... */
        ++c0kvs->c0s_num_entries;
        if (HSE_CORE_IS_TOMB(new_value))
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

    if (height > c0kvs->c0s_height)
        c0kvs->c0s_height = height;

    if (keyvals > c0kvs->c0s_keyvals)
        c0kvs->c0s_keyvals = keyvals;
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
 *     s = kvms_seqno
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
    seq = bv->bv_value == HSE_CORE_TOMB_PFX ? atomic64_add_return(1, sref) : atomic64_read(sref);

    /* If KVMS seqno is valid, use it. */
    if (HSE_UNLIKELY(atomic64_read(c0kvs->c0s_kvms_seqno) != HSE_SQNREF_INVALID)) {
        sref = c0kvs->c0s_kvms_seqno;

        seq =
            bv->bv_value == HSE_CORE_TOMB_PFX ? atomic64_add_return(1, sref) : atomic64_read(sref);
    }

    bv->bv_seqnoref = HSE_ORDNL_TO_SQNREF(seq);

    return seq;
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
    struct bonsai_val **  old_val,
    uint                  height)
{
    struct c0_kvset_impl *c0kvs;
    struct bonsai_val *   old;
    struct bonsai_val **  prevp;
    enum hse_seqno_state  state;

    uintptr_t    seqnoref;
    u64          seqno = 0;
    const void * o_val;
    unsigned int o_vlen;
    const void * n_val;
    unsigned int n_vlen;
    u16          klen;

    c0kvs = c0_kvset_h2r(cli_rock);
    klen = key_imm_klen(&kv->bkv_key_imm);

    if (IS_IOR_INS(*code)) {
        struct bonsai_val *val;

        assert(new_val == NULL);

        val = kv->bkv_values;
        n_vlen = bonsai_val_vlen(val);
        n_val = val->bv_value;

        seqnoref = kv->bkv_values->bv_seqnoref;
        state = seqnoref_to_seqno(seqnoref, &seqno);

        if (state == HSE_SQNREF_STATE_SINGLE)
            seqno = c0kvs_seqno_set(c0kvs, val);

        assert(kv->bkv_valcnt == 1);
        c0kvs_ior_stats(c0kvs, *code, NULL, 0, NULL, 0,
                        kv->bkv_key, klen, n_val, n_vlen, height, 1);

        return;
    }

    assert(IS_IOR_REPORADD(*code));

    /* Search for an existing value with the given seqnoref */
    prevp = &kv->bkv_values;
    SET_IOR_ADD(*code);

    assert(kv->bkv_values);

    seqnoref = new_val->bv_seqnoref;
    state = seqnoref_to_seqno(seqnoref, &seqno);

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

    /*
     * The new value belongs to an active transaction or has a well defined
     * ordinal value.
     * Active transaction elements (HSE_SQNREF_STATE_UNDEFINED) are always at the
     * head of the list. There is at most one active transaction writing to this
     * key (write collision detection). If the value belongs to the same active
     * transaction or has the same seqno, replace it with the updated value.
     * If the new value has a well defined seqno, traverse the list to
     * find its position in the ordered (by seqno) list. Note that existing
     * elements on the list may not have well defined seqnos (active/aborted).
     */
    while (old) {
        /* Replace a value from the same transaction or with the same seqno. */
        if (seqnoref == old->bv_seqnoref) {
            SET_IOR_REP(*code);
            break;
        }

        /*
         * If the new value belongs to an active transaction, break and
         * insert at head.
         * If the new value has a seqno, find its position in the ordered list
         * and ignore elements with active (undefined) seqnos, those that were
         * aborted.
         */
        if (seqnoref_gt(seqnoref, old->bv_seqnoref))
            break;

        prevp = &old->bv_next;
        old = old->bv_next;
    }

    if (IS_IOR_REP(*code)) {
        /* in this case we'll just replace the old list element */
        new_val->bv_next = old->bv_next;
        *old_val = old;
    } else if (HSE_SQNREF_ORDNL_P(seqnoref)) {
        /* slot the new element just in front of the next older one */
        new_val->bv_next = old;
        kv->bkv_valcnt++;
    } else {
        /* rewind & slot the new element at the front of the list */
        prevp = &kv->bkv_values;
        new_val->bv_next = *prevp;
        kv->bkv_valcnt++;
    }

    /* Publish the new value node.  New readers will see the new node,
     * while existing readers may continue to use the old node until
     * the end of the current grace period.
     */
    rcu_assign_pointer(*prevp, new_val);

    o_vlen = 0;
    o_val = NULL;

    if (old) {
        o_vlen = bonsai_val_vlen(old);
        o_val = old->bv_value;
    }

    n_vlen = bonsai_val_vlen(new_val);
    n_val = new_val->bv_value;

    c0kvs_ior_stats(c0kvs, *code, kv->bkv_key, klen, o_val, o_vlen,
                    kv->bkv_key, klen, n_val, n_vlen, height, kv->bkv_valcnt);
}

/**
 * c0kvs_findval() - Method to pick a value element from the bkv_values list,
 *                   based on seqno.
 * @kv:         bonsai_kv instance of the bonsai node matching a searched key
 * @view_seqno:
 * @seqnoref:
 */
struct bonsai_val *
c0kvs_findval(struct bonsai_kv *kv, u64 view_seqno, uintptr_t seqnoref)
{
    struct bonsai_val *val_ge, *val;
    u64                diff_ge, diff;

    diff_ge = ULONG_MAX;
    val_ge = NULL;

    for (val = kv->bkv_values; val; val = rcu_dereference(val->bv_next)) {
        diff = seqnoref_ext_diff(view_seqno, val->bv_seqnoref);
        if (diff < diff_ge) {
            diff_ge = diff;
            val_ge = val;
        }

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
        if (val->bv_value == HSE_CORE_TOMB_PFX) {
            if ((val->bv_seqnoref == seqnoref) || seqnoref_ge(seqnoref, val->bv_seqnoref))
                break;
        }
        val = rcu_dereference(val->bv_next);
    }

    return val;
}

merr_t
c0kvs_create(
    size_t            alloc_sz,
    atomic64_t *      kvdb_seqno,
    atomic64_t *      kvms_seqno,
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

    set = cheap_memalign(cheap, alignof(*set), sizeof(*set));
    if (ev(!set)) {
        cheap_destroy(cheap);
        return merr(ENOMEM);
    }

    set->c0s_alloc_sz = alloc_sz;
    set->c0s_cheap = cheap;
    atomic_set(&set->c0s_finalized, 0);
    mutex_init(&set->c0s_mutex);

    err = bn_create(cheap, HSE_C0_BNODE_SLAB_SZ, c0kvs_ior_cb, set, &set->c0s_broot);
    if (ev(err)) {
        c0kvs_destroy_impl(set);
        return err;
    }

    set->c0s_reset_sz = cheap_used(cheap);

created:
    set->c0s_kvdb_seqno = kvdb_seqno;
    set->c0s_kvms_seqno = kvms_seqno;

    *handlep = &set->c0s_handle;

    return 0;
}

static void
c0kvs_destroy_impl(struct c0_kvset_impl *set)
{
    mutex_destroy(&set->c0s_mutex);
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
    set->c0s_num_entries = 0;
    set->c0s_num_tombstones = 0;
    set->c0s_total_key_bytes = 0;
    set->c0s_total_value_bytes = 0;
    set->c0s_height = 0;
    set->c0s_keyvals = 0;
}

static HSE_ALWAYS_INLINE void
c0kvs_lock(struct c0_kvset_impl *self)
{
    mutex_lock(&self->c0s_mutex);
}

static HSE_ALWAYS_INLINE void
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
    size_t                sz)
{
    merr_t err;

    c0kvs_lock(self);
    err = bn_insert_or_replace(self->c0s_broot, skey, sval);
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
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt,
    uintptr_t                seqnoref)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey;
    struct bonsai_sval    sval;

    assert(kt->kt_flags == 0);

    bn_skey_init(kt->kt_data, kt->kt_len, kt->kt_flags, skidx, &skey);
    bn_sval_init(vt->vt_data, vt->vt_xlen, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, kt->kt_len + kvs_vtuple_vlen(vt));
}

merr_t
c0kvs_del(struct c0_kvset *handle, u16 skidx, const struct kvs_ktuple *key, uintptr_t seqnoref)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    struct bonsai_skey    skey;
    struct bonsai_sval    sval;

    bn_skey_init(key->kt_data, key->kt_len, 0, skidx, &skey);
    bn_sval_init(HSE_CORE_TOMB_REG, 0, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, key->kt_len);
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

    bn_skey_init(key->kt_data, key->kt_len, 0, skidx, &skey);
    bn_sval_init(HSE_CORE_TOMB_PFX, 0, seqnoref, &sval);

    return c0kvs_putdel(self, &skey, &sval, key->kt_len);
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

u64
c0kvs_get_element_count2(struct c0_kvset *handle, uint *heightp, uint *keyvalsp)
{
    struct c0_kvset_impl *self = c0_kvset_h2r(handle);
    u64 cnt;

    cnt = self->c0s_num_entries + self->c0s_num_tombstones;

    *heightp = self->c0s_height;
    *keyvalsp = self->c0s_keyvals;

    return cnt;
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

    bn_skey_init(key->kt_data, key->kt_len, 0, skidx, &skey);
    kv = NULL;

    found = bn_find(self->c0s_broot, &skey, &kv);
    if (!found)
        return 0;

    val = c0kvs_findval(kv, view_seqno, seqnoref);
    if (!val)
        return 0;

    *oseqnoref = val->bv_seqnoref;

    if (HSE_CORE_IS_TOMB(val->bv_value)) {
        *res = FOUND_TMB;
        return 0;
    }

    vbuf->b_len = bonsai_val_vlen(val);
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
    u32                      sfx_len,
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

    bn_skey_init(key->kt_data, key->kt_len, 0, skidx, &skey);

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

        /* We ensure that klen is atleast pfx_len + sfx_len bytes long during put/delete. */
        assert(klen >= sfx_len);
        /* Skip key if there is a matching tomb */
        if (qctx_tomb_seen(qctx, kv->bkv_key + klen - sfx_len, sfx_len))
            continue;

        val = c0kvs_findval(kv, view_seqno, seqnoref);
        if (!val)
            continue;

        /* add to tomblist if a tombstone was encountered */
        if (HSE_CORE_IS_TOMB(val->bv_value)) {
            err = qctx_tomb_insert(qctx, kv->bkv_key + klen - sfx_len, sfx_len);
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

            vbuf->b_len = bonsai_val_vlen(val);
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
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seq)
{
    assert(rcu_read_ongoing());

    return c0kvs_pfx_probe_excl(handle, skidx, key, sfx_len, view_seqno, seqnoref,
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
    bn_skey_init(key->kt_data, pfx_len, 0, skidx, &skey);
    kv = NULL;

    found = bn_find(self->c0s_broot, &skey, &kv);
    if (found) {
        uintptr_t view_seqnoref = HSE_ORDNL_TO_SQNREF(view_seqno);

        val = c0kvs_findpfxval(kv, view_seqnoref);
        if (val) {
            assert(val->bv_value == HSE_CORE_TOMB_PFX);
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

    printf("%p nentries %d ntomb %d\n", self, self->c0s_num_entries, self->c0s_num_tombstones);

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
            char *label = HSE_CORE_IS_TOMB(v->bv_value) ? "tomb" : "len";

            printf("%sseqnoref %p seqno %lu %s %u",
                   comma, (void *)v->bv_seqnoref,
                   seqno, label, bonsai_val_vlen(v));
            comma = ", ";
        }
        printf("\n");
    }

    rcu_read_unlock();
}

void
c0kvs_reinit(size_t cb_max)
{
    struct c0kvs_ccache *cc = &c0kvs_ccache;
    struct c0_kvset_impl *head, *next;

    if (!cc->cc_init)
        return;

    spin_lock(&cc->cc_lock);
    head = cc->cc_head;
    cc->cc_head = NULL;
    cc->cc_size = 0;
    spin_unlock(&cc->cc_lock);

    for (; head; head = next) {
        next = head->c0s_next;
        c0kvs_destroy_impl(head);
    }
}

void
c0kvs_init(void)
{
    struct c0kvs_ccache *cc = &c0kvs_ccache;

    if (atomic_inc_return(&c0kvs_init_ref) > 1)
        return;

    spin_lock_init(&cc->cc_lock);
    cc->cc_init = true;
}

void
c0kvs_fini(void)
{
    if (atomic_dec_return(&c0kvs_init_ref) > 0)
        return;

    c0kvs_reinit(0);
}
