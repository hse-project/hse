/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 *
 * Late Commit (LC) sits between c0 and cn. The ingest thread is responsible for adding kv-tuples
 * to LC. It establishes a view seqno upfront and only considers ingesting kv-tuples to cn if they
 * have a seqno less than this view seqno.
 *
 * A kv-tuples is added to LC in one of these cases:
 *   1. The kv-tuple belongs to an active txn.
 *   2. The kv-tuple belongs to a committed txn, but there are other entries from the txn in newer
 *      KVMSes.
 *   3. The seqno of the kv-tuple was not within in the ingest's view.
 *
 * The LC is made up of 2 bonsai trees. The first bonsai tree holds ptombs, and the other bonsai
 * tree holds all the other kv-tuples. Unlike c0, there won't be multiple threads adding kv-tuples
 * to LC - just the ingest worker thread. So only one bonsai tree for the keys is enough. Nodes
 * may be added to (during ingest) or deleted from (during garbage collection) the bonsai trees.
 *
 * Since bonsai nodes may be deleted, cursor operations need to be careful about walking the tree
 * and lists. This is done by using a combination of rcu semantics and tracking of a horizon seqno.
 *
 * All quesries - point gets, prefix probe and cursors will have to look at LC as well.
 *
 * Definitions
 * -----------
 * LC horizon: The oldest seqno that is safe to be deleted.
 * Cursor horizon: The oldest seqno that a cursor will return until the cursor is updated.
 *
 * Ingest Batch
 * ------------
 * At the end of every ingest operation, the highest seqno ingested into cn by the ingest worker
 * is published to lc. lc creates an ingest batch object at this point and adds it to the front of
 * an ingest batch list. This is a refcounted object used to track the lc horizon. There must always
 * be at least one ingest batch object on the list.
 *
 * Everytime a cursor is created, it bumps the refcount on the first object in the ingest batch
 * list. The cursor also fetches the seqno of this ingest batch and sets it as its cursor horizon.
 *
 * Garbage Collection and Cursors
 * ------------------------------
 * The lc_gc_worker_start() function enqueues a garbage collector job on the ingest workqueue.
 * The garbage collector worker thread walks the ingest batch list and finds the oldest ingest
 * batch on the list with a non-zero refcount. The seqno of this ingest batch is the lc horizon.
 *
 * The garbage collector walks the bonsai trees in an rcu read lock and marks values for deletion
 * only if their seqnos are older than the horizon. The actual delete happens after the ongoing rcu
 * grace period.
 *
 * A cursor read acquires an rcu read lock and repeatedly reads the next key. It doesn't release
 * the rcu read lock until it finds a kv-tuple with a seqno larger than the horizon. This way there
 * is no fear of the ndoe getting deleted from under the cursor.
 *
 * A cursor seek acquires an rcu read lock and then seeks each bonsai tree iterator to the desired
 * key. This key may not be in the cursor's view. The subsequent bin heap prepare performs a cursor
 * read on each bonsai iterator which ensures that before the rcu read lock is released, the cursor
 * has landed on a safe node.
 */

#define MTF_MOCK_IMPL_lc

#include <hse_ikvdb/lc.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0snr_set.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/vlb.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/compression_lz4.h>
#include <hse_util/rmlock.h>
#include <hse_util/bin_heap.h>

#include <c0/c0_kvset_internal.h>

#include "bonsai_iter.h"

static struct kmem_cache *lc_cursor_cache;

/**
 * struct ingest_batch -
 * @ib_seqno:  Highest seqno that has been ingested to cN
 * @ib_refcnt: Number of cursors created with this seqno as horizon
 * @ib_next:   Next batch
 */
struct ingest_batch {
    u64                  ib_seqno;
    atomic64_t           ib_refcnt;
    struct ingest_batch *ib_next;
};

/**
 * struct lc_impl - Private representation of LC
 * @lc_handle:        lc handle
 * @lc_kvdb_ctxn_set: kvdb's ctxn set
 * @lc_mutex:         mutex protecting updates to the bonsai trees
 * @lc_nsrc:          number of bonsai trees
 * @lc_broot:         array of bonsai tree roots
 * @lc_gc:            lc's garbage collector
 * @lc_ib_rmlock:     reader/writer lock for the ingest batch list
 * @lc_ib_head:       ingest batch list
 */
struct lc_impl {
    struct lc             lc_handle;
    struct kvdb_ctxn_set *lc_kvdb_ctxn_set;
    struct mutex          lc_mutex;
    uint                  lc_nsrc;

    struct bonsai_root *lc_broot[LC_SOURCE_CNT_MAX];
    struct lc_gc *      lc_gc;

    struct rmlock        lc_ib_rmlock;
    struct ingest_batch *lc_ib_head;
};

#define lc_h2r(HANDLE) container_of(HANDLE, struct lc_impl, lc_handle)
#define lc_r2h(REAL)   (&(REAL)->lc_handle)

void
lc_ingest_seqno_set(struct lc *handle, u64 seq)
{
    struct lc_impl *     self;
    struct ingest_batch *ib;

    if (ev(!handle))
        return;

    ib = alloc_aligned(sizeof(*ib), alignof(*ib));
    if (!ib)
        return;

    self = lc_h2r(handle);

    ib->ib_seqno = seq;
    atomic64_set(&ib->ib_refcnt, 0);

    /* Install ib as the new head */
    rmlock_wlock(&self->lc_ib_rmlock);
    ib->ib_next = self->lc_ib_head;
    self->lc_ib_head = ib;
    rmlock_wunlock(&self->lc_ib_rmlock);
}

static u64
lc_ib_head_seqno(struct lc_impl *self)
{
    struct ingest_batch *first;
    void *               lock;
    u64                  seqno;

    /* If this function is called very often, it would make sense to have an atomic in lc_impl
     * that tracks the ingest seqno and is updated after each ingest operation in
     * lc_ingest_seqno_set()
     */
    rmlock_rlock(&self->lc_ib_rmlock, &lock);
    first = self->lc_ib_head;
    assert(first);
    seqno = first->ib_seqno;
    rmlock_runlock(lock);

    return seqno;
}

u64
lc_ingest_seqno_get(struct lc *handle)
{
    struct lc_impl *self = lc_h2r(handle);

    /* [HSE_REVISIT] This should be done by c0sk_ingest_worker - the caller.
     */
    kvdb_ctxn_set_wait_commits(self->lc_kvdb_ctxn_set);
    return lc_ib_head_seqno(self);
}

static u64
lc_horizon_register(struct lc_impl *self, void **cookie)
{
    struct ingest_batch *first;
    void *               lock;

    rmlock_rlock(&self->lc_ib_rmlock, &lock);
    first = self->lc_ib_head;
    assert(first);
    atomic64_inc(&first->ib_refcnt);
    rmlock_runlock(lock);

    *cookie = first;
    return first->ib_seqno;
}

static void
lc_horizon_deregister(void *cookie)
{
    struct ingest_batch *ib = cookie;

    atomic64_dec(&ib->ib_refcnt);
}

/* [HSE_REVISIT] This is almost identical to c0kvs_ior_cb(). Consider unifying the two.
 */
static void
lc_ior_cb(
    void *                cli_rock,
    enum bonsai_ior_code *code,
    struct bonsai_kv *    kv,
    struct bonsai_val *   new_val,
    struct bonsai_val **  old_val,
    uint                  height)
{
    struct bonsai_val *  old;
    struct bonsai_val ** prevp;
    enum hse_seqno_state state;

    uintptr_t seqnoref;
    u64       seqno = 0;

    if (IS_IOR_INS(*code)) {
        struct bonsai_val *val;

        assert(new_val == NULL);

        val = rcu_dereference(kv->bkv_values);

        seqnoref = val->bv_seqnoref;
        state = seqnoref_to_seqno(seqnoref, &seqno);

        /* Get a ref on c0snr if this val belongs/belonged to a txn */
        if (HSE_SQNREF_INDIRECT_P(seqnoref))
            c0snr_getref_lc((uintptr_t *)seqnoref);

        kv->bkv_valcnt++;
        assert(state != HSE_SQNREF_STATE_SINGLE);
        return;
    }

    assert(IS_IOR_REPORADD(*code));

    /* Search for an existing value with the given seqnoref */
    prevp = &kv->bkv_values;
    SET_IOR_ADD(*code);

    seqnoref = new_val->bv_seqnoref;
    state = seqnoref_to_seqno(seqnoref, &seqno);

    assert(state != HSE_SQNREF_STATE_SINGLE);

    /* Get a ref on c0snr if this val belongs/belonged to a txn */
    if (HSE_SQNREF_INDIRECT_P(seqnoref))
        c0snr_getref_lc((uintptr_t *)seqnoref);

    old = rcu_dereference(kv->bkv_values);
    assert(old);

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
        old = rcu_dereference(old->bv_next);
    }

    if (IS_IOR_REP(*code)) {
        /* in this case we'll just replace the old list element */
        new_val->bv_next = rcu_dereference(old->bv_next);
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
}

static void
lc_wlock(struct lc_impl *self)
{
    mutex_lock(&self->lc_mutex);
}

static void
lc_wunlock(struct lc_impl *self)
{
    mutex_unlock(&self->lc_mutex);
}

merr_t
lc_create(struct lc **handle, struct kvdb_ctxn_set *ctxn_set)
{
    struct lc_impl *self;
    merr_t          err;
    int             i;

    self = calloc(1, sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    self->lc_nsrc = 2;
    assert(self->lc_nsrc <= LC_SOURCE_CNT_MAX);

    for (i = 0; i < self->lc_nsrc; i++) {
        err = bn_create(NULL, lc_ior_cb, NULL, &self->lc_broot[i]);
        if (ev(err)) {
            lc_destroy(&self->lc_handle);
            return err;
        }
    }

    self->lc_kvdb_ctxn_set = ctxn_set;
    rmlock_init(&self->lc_ib_rmlock);
    mutex_init(&self->lc_mutex);
    *handle = lc_r2h(self);
    return 0;
}

/* lc_destroy() must be called after destroying the GC workqueue
 */
merr_t
lc_destroy(struct lc *handle)
{
    struct lc_impl *     self;
    struct ingest_batch *ib;
    int                  i;

    if (!handle)
        return 0;

    self = lc_h2r(handle);
    mutex_destroy(&self->lc_mutex);

    for (i = 0; i < self->lc_nsrc; i++) {
        if (self->lc_broot[i])
            bn_destroy(self->lc_broot[i]);
    }

    rmlock_destroy(&self->lc_ib_rmlock);

    /* Don't need a lock. Since GC's workqueue has been destroyed, there's no ongoing GC thread.
     * So this is the only thread reading this list.
     */
    while ((ib = self->lc_ib_head)) {
        self->lc_ib_head = ib->ib_next;
        free_aligned(ib);
    }

    free(self);

    return 0;
}

#define LC_BUILDER_CNT (1UL << 20)

struct lc_builder_entry {
    struct bonsai_kv * bkv;
    struct bonsai_val *vlist;
};

struct lc_builder {
    uint                     lcb_cnt;
    size_t                   lcb_cnt_max;
    struct lc_impl *         lcb_lc;
    struct lc_builder_entry *lcb_entry;
};

merr_t
lc_builder_create(struct lc *lc, struct lc_builder **builder)
{
    struct lc_builder *lcb;
    size_t             max_cnt = LC_BUILDER_CNT;
    size_t             sz;

    /* [HSE_REVISIT] Maybe use kmem_cache here. Or add lc_builder as a member of lc and reuse the
     * same one (since there's only ever one thread writing to LC).
     */
    lcb = malloc(sizeof(*lcb));
    if (ev(!lcb))
        return merr(ENOMEM);

    sz = (max_cnt * sizeof(*lcb->lcb_entry));
    lcb->lcb_entry = malloc(sz);
    if (ev(!lcb->lcb_entry)) {
        free(lcb);
        return merr(ENOMEM);
    }

    lcb->lcb_cnt_max = max_cnt;
    lcb->lcb_cnt = 0;
    lcb->lcb_lc = lc_h2r(lc);

    *builder = lcb;
    return 0;
}

void
lc_builder_destroy(struct lc_builder *lcb)
{
    free(lcb->lcb_entry);
    free(lcb);
}

merr_t
lc_builder_add(struct lc_builder *bldr, struct bonsai_kv *bkv, struct bonsai_val *val_list)
{
    struct lc_builder_entry *entry;

    if (HSE_UNLIKELY(bldr->lcb_cnt >= bldr->lcb_cnt_max)) {
        size_t newsz;

        bldr->lcb_cnt_max += LC_BUILDER_CNT;
        newsz = bldr->lcb_cnt_max * sizeof(*bldr->lcb_entry);
        bldr->lcb_entry = realloc(bldr->lcb_entry, newsz);
        if (ev(!bldr->lcb_entry))
            return merr(ENOMEM);
    }

    entry = &bldr->lcb_entry[bldr->lcb_cnt++];
    entry->bkv = bkv;
    entry->vlist = val_list;

    return 0;
}

merr_t
lc_builder_finish(struct lc_builder *bldr)
{
    struct lc_impl *lc = bldr->lcb_lc;
    int             i;
    merr_t          err = 0;

    lc_wlock(lc);
    rcu_read_lock();
    for (i = 0; i < bldr->lcb_cnt; i++) {
        struct lc_builder_entry *e = &bldr->lcb_entry[i];
        struct bonsai_kv *       bkv = e->bkv;
        struct bonsai_val *      val = e->vlist;
        u16                      skidx = key_immediate_index(&bkv->bkv_key_imm);
        uint                     klen = key_imm_klen(&bkv->bkv_key_imm);
        struct bonsai_skey       skey;

        bn_skey_init(bkv->bkv_key, klen, 0, skidx, &skey);

        assert(val); /* There should be at least one value */

        while (val) {
            struct bonsai_root *root;
            struct bonsai_sval  sval;

            bn_sval_init(val->bv_value, val->bv_xlen, val->bv_seqnoref, &sval);
            root = sval.bsv_val == HSE_CORE_TOMB_PFX ? lc->lc_broot[0] : lc->lc_broot[1];

            err = bn_insert_or_replace(root, &skey, &sval);
            if (ev(err))
                goto exit;

            val = val->bv_priv;
        }
    }

exit:
    rcu_read_unlock();
    lc_wunlock(lc);

    return err;
}

static void
lc_get_pfx(struct lc_impl *self, struct bonsai_skey *skey, u64 view_seqno, uintptr_t *oseqnoref)
{
    struct bonsai_val * val;
    struct bonsai_kv *  kv = NULL;
    bool                found;
    struct bonsai_root *root = self->lc_broot[0];
    uintptr_t           view_seqnoref;

    *oseqnoref = HSE_ORDNL_TO_SQNREF(0);

    found = bn_find(root, skey, &kv);
    if (!found)
        return;

    view_seqnoref = HSE_ORDNL_TO_SQNREF(view_seqno);
    val = c0kvs_findpfxval(kv, view_seqnoref);
    if (val) {
        assert(val->bv_value == HSE_CORE_TOMB_PFX);
        *oseqnoref = val->bv_seqnoref;
    }
}

static void
lc_get_main(
    struct lc_impl *     self,
    struct bonsai_skey * skey,
    u64                  view_seqno,
    uintptr_t            seqnoref,
    enum key_lookup_res *res,
    struct bonsai_val ** val_out,
    uintptr_t *          oseqnoref)
{
    struct bonsai_val * val;
    struct bonsai_kv *  kv = NULL;
    bool                found;
    struct bonsai_root *root = self->lc_broot[1];

    assert(rcu_read_ongoing());

    *res = NOT_FOUND;
    *oseqnoref = HSE_ORDNL_TO_SQNREF(0);
    found = bn_find(root, skey, &kv);
    if (!found)
        return;

    /* Need not bother with using a lower bound for seqno based on the last ingest as
     * long as the value is copied out under the rcu lock.
     */
    val = c0kvs_findval(kv, view_seqno, seqnoref);
    if (!val)
        return;

    *val_out = val;
    *oseqnoref = val->bv_seqnoref;

    if (HSE_CORE_IS_TOMB(val->bv_value)) {
        *res = FOUND_TMB;
        return;
    }

    *res = FOUND_VAL;
}

static merr_t
copy_val(struct kvs_buf *vbuf, struct bonsai_val *val)
{
    merr_t err;
    uint   copylen;

    vbuf->b_len = bonsai_val_vlen(val);
    copylen = vbuf->b_len;

    if (copylen > vbuf->b_buf_sz)
        copylen = vbuf->b_buf_sz;

    if (copylen > 0 && vbuf->b_buf) {
        uint outlen, clen, ulen;

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

    return 0;
}

merr_t
lc_get(
    struct lc *              handle,
    u16                      skidx,
    u32                      pfxlen,
    const struct kvs_ktuple *kt,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct lc_impl *   self;
    struct bonsai_val *val = NULL;
    struct bonsai_skey skey;
    merr_t             err = 0;
    u64                ptomb_seq, val_seq;
    uintptr_t          seqref = 0;

    assert(handle);

    self = lc_h2r(handle);

    bn_skey_init(kt->kt_data, kt->kt_len, 0, skidx, &skey);
    val_seq = ptomb_seq = 0;

    rcu_read_lock();
    if (pfxlen && pfxlen <= kt->kt_len) {
        struct bonsai_skey pfx_skey;

        seqref = 0;

        bn_skey_init(kt->kt_data, pfxlen, 0, skidx, &pfx_skey);
        lc_get_pfx(self, &pfx_skey, view_seqno, &seqref);
        ptomb_seq = HSE_SQNREF_TO_ORDNL(seqref);
    }

    lc_get_main(self, &skey, view_seqno, seqnoref, res, &val, &seqref);

    val_seq = HSE_SQNREF_TO_ORDNL(seqref);

    if (*res == NOT_FOUND)
        goto exit;

    if (ptomb_seq > val_seq) {
        *res = FOUND_PTMB;
        vbuf->b_len = 0;
        goto exit;
    }

    err = copy_val(vbuf, val);

exit:
    rcu_read_unlock();

    return err;
}

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
    struct kvs_buf *         vbuf)
{
    struct lc_impl *    self;
    struct bonsai_root *root;
    merr_t              err;
    u64                 pt_seq = 0;
    uintptr_t           pt_seqref = 0;

    assert(handle);

    self = lc_h2r(handle);

    *res = NOT_FOUND;

    rcu_read_lock();
    if (pfxlen && pfxlen <= kt->kt_len) {
        struct bonsai_skey pfx_skey;

        bn_skey_init(kt->kt_data, pfxlen, 0, skidx, &pfx_skey);
        lc_get_pfx(self, &pfx_skey, view_seqno, &pt_seqref);

        pt_seq = HSE_SQNREF_TO_ORDNL(pt_seqref);
    }

    root = self->lc_broot[1];
    err = c0kvs_pfx_probe_cmn(
        root, skidx, kt, sfxlen, view_seqno, seqnoref, res, qctx, kbuf, vbuf, pt_seq);

    if (pt_seq)
        *res = FOUND_PTMB;

    rcu_read_unlock();
    return err;
}

/* Cursors
 */
struct lc_cursor {
    struct lc_impl *          lcc_lc;
    u16                       lcc_skidx;
    struct kvs_cursor_element lcc_elem;
    struct key_obj            lcc_filter_max;
    struct key_obj            lcc_ptomb;
    u64                       lcc_ptomb_seq;
    size_t                    lcc_tree_pfxlen;

    /* Cursors should only read kv-tuples in (lcc_seq_horizon, lcc_seq_view] */
    u64       lcc_seq_view;
    u64       lcc_seq_horizon;
    uintptr_t lcc_seqnoref;
    void *    lcc_ib_cookie;

    /* Binheap from kci_cursor */
    struct element_source lcc_es;

    /* Binheap */
    struct bin_heap2 *     lcc_bh;
    struct bonsai_iter     lcc_it[LC_SOURCE_CNT_MAX];
    struct element_source *lcc_esrcv[LC_SOURCE_CNT_MAX];

    /* Flags */
    u32 lcc_reverse : 1;
    u32 lcc_filter_set : 1;
    u32 lcc_ptomb_set : 1;

    /* Cursor's prefix. Owned by kvs_cursor_impl. */
    struct key_obj lcc_pfx;
};

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
    struct lc_cursor **    lccur)
{
    struct lc_impl *  self = lc_h2r(handle);
    struct lc_cursor *cur;
    int               i;
    merr_t            err;

    if (!handle)
        return 0;

    cur = kmem_cache_zalloc(lc_cursor_cache);
    if (ev(!cur))
        return merr(ENOMEM);

    if (pfx_padded)
        key2kobj(&cur->lcc_pfx, pfx_padded, pfxlen);

    cur->lcc_reverse = reverse;
    cur->lcc_skidx = skidx;
    cur->lcc_tree_pfxlen = tree_pfxlen;
    cur->lcc_lc = self;

    cur->lcc_seq_view = seqno; /* For a bound cursor, this is the ctxn's view seqno */
    cur->lcc_seq_horizon = lc_horizon_register(self, &cur->lcc_ib_cookie);
    cur->lcc_seqnoref = seqnoref;
    if (cur->lcc_seq_view < cur->lcc_seq_horizon) {
        hse_log(
            HSE_DEBUG "LC cursor will be empty, view (%lu) < horizon (%lu)",
            cur->lcc_seq_view,
            cur->lcc_seq_horizon);
    }

    /* HSE_REVISIT Consider using comparators that use key_obj_cmp_spl() */
    err = bin_heap2_create(
        LC_SOURCE_CNT_MAX, reverse ? kvs_cursor_cmp_rev : kvs_cursor_cmp, &cur->lcc_bh);
    if (ev(err))
        goto err_out;

    /* HSE_REVISIT Skip ptomb tree if tree_pfxlen is 0.
     */
    rcu_read_lock();
    for (i = 0; i < self->lc_nsrc; i++) {
        uint minlen = min_t(size_t, pfxlen, tree_pfxlen);
        uint len = i == 0 ? minlen : pfxlen;

        bonsai_iter_init(
            &cur->lcc_it[i],
            self->lc_broot[i],
            cur->lcc_skidx,
            cur->lcc_seq_view,
            cur->lcc_seq_horizon,
            seqnoref,
            cur->lcc_reverse,
            i == 0 ? true : false);

        bonsai_iter_position(&cur->lcc_it[i], pfx_padded, reverse ? HSE_KVS_KLEN_MAX : len);
        cur->lcc_esrcv[i] = bonsai_iter_es_make(&cur->lcc_it[i]);
    }

    err = bin_heap2_prepare(cur->lcc_bh, self->lc_nsrc, cur->lcc_esrcv);
    if (ev(err)) {
        rcu_read_unlock();
        goto err_out;
    }

    rcu_read_unlock();

    *lccur = cur;
    return 0;

err_out:
    if (cur->lcc_bh)
        bin_heap2_destroy(cur->lcc_bh);

    kmem_cache_free(lc_cursor_cache, cur);
    return err;
}

merr_t
lc_cursor_destroy(struct lc_cursor *cur)
{
    assert(cur);

    assert(cur->lcc_bh);
    bin_heap2_destroy(cur->lcc_bh);

    lc_horizon_deregister(cur->lcc_ib_cookie);
    kmem_cache_free(lc_cursor_cache, cur);

    return 0;
}

void
lc_cursor_read(struct lc_cursor *cur, struct kvs_cursor_element *lc_elem, bool *eof)
{
    struct kvs_cursor_element *elem;
    uint                       cur_pfxlen;

    assert(cur);
    assert(rcu_read_ongoing());

    cur_pfxlen = key_obj_len(&cur->lcc_pfx);

    while (bin_heap2_peek(cur->lcc_bh, (void **)&elem)) {
        uint klen = key_obj_len(&elem->kce_kobj);
        bool is_ptomb = elem->kce_is_ptomb;

        /* If this is a prefixed cursor, check whether key has the right pfx */
        if (cur_pfxlen) {
            uint len = min_t(uint, klen, cur_pfxlen);
            int  rc = key_obj_ncmp(&elem->kce_kobj, &cur->lcc_pfx, len);

            if ((cur->lcc_reverse && rc < 0) || (!cur->lcc_reverse && rc > 0))
                break; /* eof */

            /* Skip this key if either,
             *   1. we haven't yet reached pfx, or
             *   2. key is shorter than pfx, but key is NOT a ptomb.
             */
            if (HSE_UNLIKELY(rc != 0 || (len != cur_pfxlen && !is_ptomb))) {
                bin_heap2_pop(cur->lcc_bh, (void **)&elem);
                continue;
            }
        }

        if (cur->lcc_filter_set) {
            if (HSE_UNLIKELY(key_obj_cmp_spl(&elem->kce_kobj, &cur->lcc_filter_max) > 0))
                break; /* eof; key is larger than lcc_filter_max */
        }

        if (cur->lcc_ptomb_set) {
            int rc = key_obj_cmp_prefix(&cur->lcc_ptomb, &elem->kce_kobj);
            if (rc == 0) {
                /* Note that c0kvs_findval() will return a value only if either
                 *   1. it has a concrete seqno or
                 *   2. it belongs to this cursor's bound txn.
                 *
                 * i.e. it should never be the case that elem and ptomb belong to separate
                 * active transactions.
                 */
                if (elem->kce_seqnoref != cur->lcc_seqnoref) {
                    u64 seq = HSE_SQNREF_TO_ORDNL(elem->kce_seqnoref);

                    assert(seqnoref_to_seqno(elem->kce_seqnoref, NULL) == HSE_SQNREF_STATE_DEFINED);

                    if (seq < cur->lcc_ptomb_seq) {
                        bin_heap2_pop(cur->lcc_bh, (void **)&elem);
                        continue;
                    }
                } else {
                    /* This kv-tuple belongs to the bound txn. Fallthrough. */
                }

            } else {
                cur->lcc_ptomb_set = 0;
            }
        }

        /* Discard current key */
        *lc_elem = *elem;
        bin_heap2_pop(cur->lcc_bh, (void **)&elem);

        /* Do not use elem after this point to refer to the current kv, use lc_elem. */

        /* Just get the first occurrence of a ptomb */
        if (is_ptomb && !cur->lcc_ptomb_set) {
            cur->lcc_ptomb = lc_elem->kce_kobj;
            cur->lcc_ptomb_set = 1;
            /* If ptomb belongs to bound txn, set its seqno to that of the
             * cursor (which in turn is the bound txn's seqno).
             */
            cur->lcc_ptomb_seq = (cur->lcc_seqnoref == lc_elem->kce_seqnoref)
                                     ? cur->lcc_seq_view
                                     : HSE_SQNREF_TO_ORDNL(lc_elem->kce_seqnoref);
        } else if (cur->lcc_lc->lc_nsrc > 2) {
            /* If LC has a single bonsai tree (excluding the ptomb tree), There should never be
             * any dups. Process dups only when we have more than one non-ptomb bonsai tree.
             */
            struct kvs_cursor_element *dup;

            while (bin_heap2_peek(cur->lcc_bh, (void **)&dup)) {
                if (key_obj_cmp_spl(&lc_elem->kce_kobj, &dup->kce_kobj))
                    break; /* not a dup */

                bin_heap2_pop(cur->lcc_bh, (void **)&dup);
            }
        }

        *eof = false;
        return;
    }

    *eof = true;
}

static bool
lc_cursor_next(struct element_source *es, void **element)
{
    struct lc_cursor *cur = container_of(es, struct lc_cursor, lcc_es);
    bool              eof;

    rcu_read_lock();
    lc_cursor_read(cur, &cur->lcc_elem, &eof);
    rcu_read_unlock();

    if (eof)
        return false;

    *element = &cur->lcc_elem;
    return true;
}

struct element_source *
lc_cursor_es_make(struct lc_cursor *cur)
{
    cur->lcc_es = es_make(lc_cursor_next, 0, 0);
    return &cur->lcc_es;
}

struct element_source *
lc_cursor_es_get(struct lc_cursor *cur)
{
    return &cur->lcc_es;
}

merr_t
lc_cursor_seek(struct lc_cursor *cur, const void *seek, size_t seeklen, struct kc_filter *filter)
{
    merr_t err;
    int    i;

    assert(cur);

    cur->lcc_filter_set = filter ? 1 : 0;
    if (filter) {
        assert(!cur->lcc_reverse);
        key2kobj(&cur->lcc_filter_max, filter->kcf_maxkey, filter->kcf_maxklen);
    }

    cur->lcc_ptomb_set = 0;

    rcu_read_lock();
    for (i = 0; i < cur->lcc_lc->lc_nsrc; i++) {
        uint minlen = min_t(size_t, seeklen, cur->lcc_tree_pfxlen);
        uint len = i == 0 ? minlen : seeklen;

        bonsai_iter_seek(&cur->lcc_it[i], seek, len);
    }

    err = bin_heap2_prepare(cur->lcc_bh, cur->lcc_lc->lc_nsrc, cur->lcc_esrcv);
    rcu_read_unlock();

    return err;
}

merr_t
lc_cursor_update(struct lc_cursor *cur, const void *key, size_t klen, u64 seqno)
{
    struct lc_impl *lc = cur->lcc_lc;
    int             i;

    assert(cur);

    /* Update cursor's view window */
    lc_horizon_deregister(cur->lcc_ib_cookie);

    cur->lcc_seq_view = seqno;
    cur->lcc_seq_horizon = lc_horizon_register(cur->lcc_lc, &cur->lcc_ib_cookie);

    for (i = 0; i < lc->lc_nsrc; i++)
        bonsai_iter_update(&cur->lcc_it[i], cur->lcc_seq_view, cur->lcc_seq_horizon);

    /* In order to maintain positional stability of a cursor, the calling layer will seek this
     * cursor to its last position before reading from it.
     * Don't seek bonsai iters or prepare the binheap. Leave that to lc_cursor_seek.
     */

    return 0;
}

/* Ingest */
void
lc_ingest_iterv_init(
    struct lc *             handle,
    struct lc_ingest_iter * iterv,
    struct element_source **srcv,
    u64                     view_seq,
    u64                     horizon_seq,
    uint *                  iter_cnt)
{
    struct lc_impl *self;
    int             i;

    if (!handle)
        return;

    self = lc_h2r(handle);
    *iter_cnt = self->lc_nsrc;
    for (i = 0; i < self->lc_nsrc; i++) {
        struct bonsai_ingest_iter *iter = &iterv[i].lcing_iter;
        struct bonsai_root *       root = rcu_dereference(self->lc_broot[i]);

        srcv[i] = bonsai_ingest_iter_init(iter, root, view_seq, horizon_seq);
    }
}

/* Garbage Collection */
struct lc_gc {
    struct work_struct lgc_work;
    struct lc_impl *   lgc_lc;
    merr_t             lgc_err;
};

static u64
lc_gc_horizon(struct lc_impl *self)
{
    struct ingest_batch *ib, *next, **prevp;
    struct ingest_batch *ib_list;
    u64                  horizon;
    void *               lock;

    rmlock_rlock(&self->lc_ib_rmlock, &lock);
    if (!self->lc_ib_head || !self->lc_ib_head->ib_next) {
        rmlock_runlock(lock);
        return 0;
    }

    /* Do not remove the head of this list since it's active. This also allows us to work on the
     * remaining list without a lock as long as this is the only thread that ever walks the list.
     */
    ib_list = self->lc_ib_head->ib_next;
    prevp = &self->lc_ib_head->ib_next;
    horizon = self->lc_ib_head->ib_seqno;
    rmlock_runlock(lock);

    for (ib = ib_list; ib; ib = next) {
        next = ib->ib_next;

        if (!atomic64_read(&ib->ib_refcnt)) {
            assert(!horizon || horizon > ib->ib_seqno);
            horizon = horizon ?: ib->ib_seqno;
            *prevp = next;
            free_aligned(ib);
            continue;
        }

        horizon = 0;
        prevp = &ib->ib_next;
    }

    return horizon;
}

static void
lc_gc_worker(struct work_struct *work)
{
    struct lc_gc *     gc = container_of(work, struct lc_gc, lgc_work);
    struct lc_impl *   lc = gc->lgc_lc;
    int                i;
    u64                horizon;
    struct bonsai_val *val;

    horizon = lc_gc_horizon(lc);
    if (!horizon)
        return; /* Nothing to do. */

    lc_wlock(lc);
    rcu_read_lock();
    for (i = 0; i < lc->lc_nsrc; i++) {
        struct bonsai_root *root = lc->lc_broot[i];
        struct bonsai_kv *  bkv = &root->br_kv;

        while (1) {
            struct bonsai_val **prevp;
            bool                deleted = false;

            bkv = rcu_dereference(bkv->bkv_next);
            if (bkv == &root->br_kv)
                break; /* eof */

            prevp = &bkv->bkv_values;
            for (val = rcu_dereference(bkv->bkv_values); val; val = rcu_dereference(val->bv_next)) {
                u64                  seqno;
                enum hse_seqno_state state;
                uintptr_t            seqnoref = val->bv_seqnoref;
                bool                 keepval;

                state = seqnoref_to_seqno(seqnoref, &seqno);

                /* Keep val if it's either
                 *  1. from an aborted txn, or
                 *  2. has a seqno newer than the horizon.
                 */
                keepval = (state == HSE_SQNREF_STATE_DEFINED && seqno > horizon) ||
                          (state == HSE_SQNREF_STATE_UNDEFINED);
                if (keepval) {
                    if (deleted)
                        rcu_assign_pointer(*prevp, val);

                    prevp = &val->bv_next;
                    deleted = false;
                    continue;
                }

                if (HSE_SQNREF_INDIRECT_P(seqnoref))
                    c0snr_dropref_lc((uintptr_t *)seqnoref);

                /* Mark value for deletion */
                deleted = true;
                bkv->bkv_valcnt--;
                bn_val_rcufree(bkv, val);
            }

            rcu_assign_pointer(*prevp, NULL);

            if (!bkv->bkv_valcnt) {
                struct bonsai_skey skey;
                uint               klen = key_imm_klen(&bkv->bkv_key_imm);
                u16                skidx = key_immediate_index(&bkv->bkv_key_imm);
                merr_t             err;

                bn_skey_init(bkv->bkv_key, klen, 0, skidx, &skey);

                err = bn_delete(root, &skey);
                if (err)
                    hse_elog(
                        HSE_ERR "LC garbage collection: Failed to delete bonsai node: @@e", err);
            }
        }
    }

    rcu_read_unlock();
    lc_wunlock(lc);

    free(gc);
}

void
lc_gc_worker_start(struct lc *handle, struct workqueue_struct *wq)
{
    struct lc_impl *self;
    struct lc_gc *  gc;

    if (!handle)
        return;

    self = lc_h2r(handle);

    gc = calloc(1, sizeof(*gc));
    if (!gc)
        return;

    gc->lgc_lc = self;
    INIT_WORK(&gc->lgc_work, lc_gc_worker);
    queue_work(wq, &gc->lgc_work);
}

/* Init/Fini */
merr_t
lc_init(void)
{
    struct kmem_cache *cache;
    size_t             sz = sizeof(struct lc_cursor);

    cache = kmem_cache_create("lc_cursor", sz, alignof(struct lc_cursor), SLAB_PACKED, NULL);
    if (ev(!cache))
        return merr(ENOMEM);

    lc_cursor_cache = cache;
    return 0;
}

void
lc_fini(void)
{
    kmem_cache_destroy(lc_cursor_cache);
    lc_cursor_cache = NULL;
}

#if HSE_MOCKING
#include "lc_ut_impl.i"
#endif
