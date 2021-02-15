/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c0kvms

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/condvar.h>
#include <hse_util/perfc.h>
#include <hse_util/fmt.h>
#include <hse_util/rcu.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/kvdb_perfc.h>

#include "c0_cursor.h"
#include "c0_ingest_work.h"

#include <hse_util/bonsai_tree.h>

#define c0_kvmultiset_cursor_es_h2r(handle) \
    container_of(handle, struct c0_kvmultiset_cursor, c0mc_es)

#define c0_kvmultiset_h2r(handle) container_of(handle, struct c0_kvmultiset_impl, c0ms_handle)

/**
 * struct c0_kvmultiset_impl - managed collection of c0 kvsets
 * @c0ms_handle:
 * @c0ms_gen:           kvms unique generation count
 * @c0ms_seqno:
 * @c0ms_rsvd_sn:       reserved at kvms activation for txn flush and ingestid
 * @c0ms_ingest_delay:  Max ingest coalesce wait time (seconds)
 * @c0ms_ingesting:     kvms is being ingested (no longer active)
 * @c0ms_ingested:
 * @c0ms_finalized:     kvms guaranteed to be frozen (no more updates)
 * @c0ms_txn_thresh_lo:
 * @c0ms_txn_thresh_hi:
 * @c0ms_ingest_work:   data used to orchestrate c0+cn ingest
 * @c0ms_destroy_work   work struct for c0kvms_destroy() offload
 * @c0ms_wq:            workqueue for c0kvms_destroy() offload
 * @c0ms_refcnt:        used to manage the lifetime of the kvms
 * @c0ms_c0snr_cur:      current offset into c0snr memory pool
 * @c0ms_c0snr_max:      max elements in c0snr memory pool
 * @c0ms_c0snr_base:     base of c0snr memory pool dedicated
 * @c0ms_c0snr_cnt:      count of distinct c0snrs (txns) in kvms
 * @c0ms_resetsz:       size used by fully set up c0kvms
 * @c0ms_sets:          vector of c0 kvset pointers
 */
struct c0_kvmultiset_impl {
    struct c0_kvmultiset c0ms_handle;
    u64                  c0ms_gen;
    atomic64_t           c0ms_seqno;
    u64                  c0ms_rsvd_sn;
    u64                  c0ms_ingest_delay;
    u64                  c0ms_ctime;

    HSE_ALIGNED(SMP_CACHE_BYTES) atomic_t c0ms_ingesting;
    bool                     c0ms_ingested;
    bool                     c0ms_finalized;
    size_t                   c0ms_txn_thresh_lo;
    size_t                   c0ms_txn_thresh_hi;
    struct c0_ingest_work *  c0ms_ingest_work;
    struct workqueue_struct *c0ms_wq;
    struct work_struct       c0ms_destroy_work;

    HSE_ALIGNED(SMP_CACHE_BYTES) atomic_t c0ms_refcnt;

    HSE_ALIGNED(SMP_CACHE_BYTES) atomic_t c0ms_c0snr_cur;

    size_t              c0ms_c0snr_max;
    uintptr_t          *c0ms_c0snr_base;

    HSE_ALIGNED(SMP_CACHE_BYTES) atomic_t c0ms_c0snr_cnt;

    HSE_ALIGNED(SMP_CACHE_BYTES) size_t c0ms_used;

    HSE_ALIGNED(SMP_CACHE_BYTES) u32 c0ms_num_sets;
    u32              c0ms_resetsz;
    struct c0_kvset *c0ms_sets[HSE_C0_INGEST_WIDTH_MAX];
};

static atomic64_t         c0kvms_gen = ATOMIC_INIT(0);
static struct kmem_cache *c0kvms_cache;
static atomic_t           c0kvms_init_ref;

void
c0kvms_thresholds_get(struct c0_kvmultiset *handle, size_t *thresh_lo, size_t *thresh_hi)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    *thresh_lo = self->c0ms_txn_thresh_lo;
    *thresh_hi = self->c0ms_txn_thresh_hi;
}

struct c0_kvset *
c0kvms_ptomb_c0kvset_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_sets[0];
}

struct c0_kvset *
c0kvms_get_hashed_c0kvset(struct c0_kvmultiset *handle, u64 hash)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    u32                        set_idx;

    /* skip ptomb c0kvset - c0ms_sets[0] */
    set_idx = 1 + (hash % (self->c0ms_num_sets - 1));

    return self->c0ms_sets[set_idx];
}

struct c0_kvset *
c0kvms_get_c0kvset(struct c0_kvmultiset *handle, u32 index)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    assert(index < self->c0ms_num_sets);

    return self->c0ms_sets[index];
}

void
c0kvms_finalize(struct c0_kvmultiset *handle, struct workqueue_struct *wq)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    int                        i;

    self->c0ms_finalized = true;

    for (i = 0; i < self->c0ms_num_sets; ++i)
        c0kvs_finalize(self->c0ms_sets[i]);

    self->c0ms_wq = wq;
}

bool
c0kvms_is_finalized(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_finalized;
}

void
c0kvms_ingested(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_ingested = true;
}

bool
c0kvms_is_ingested(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_ingested;
}

void
c0kvms_ingest_delay_set(struct c0_kvmultiset *handle, u64 delay)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_ingest_delay = delay;
}

u64
c0kvms_ingest_delay_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_ingest_delay;
}

u64
c0kvms_rsvd_sn_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_rsvd_sn;
}

void
c0kvms_rsvd_sn_set(struct c0_kvmultiset *handle, u64 seqno)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    assert(self->c0ms_rsvd_sn == HSE_SQNREF_INVALID);

    self->c0ms_rsvd_sn = seqno;
}

void
c0kvms_ingesting(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    atomic_inc(&self->c0ms_ingesting);

    self->c0ms_ingest_work->c0iw_tingesting = get_time_ns();
}

bool
c0kvms_is_ingesting(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return atomic_read(&self->c0ms_ingesting) > 0;
}

u64
c0kvms_get_element_count(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    u64                        element_count = 0;
    u32                        i;

    for (i = 0; i < self->c0ms_num_sets; ++i)
        element_count += c0kvs_get_element_count(self->c0ms_sets[i]);

    return element_count;
}

void
c0kvms_usage(struct c0_kvmultiset *handle, struct c0_usage *usage)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    struct c0_usage            u;

    u32 i, n;

    memset(usage, 0, sizeof(*usage));
    usage->u_used_min = ULONG_MAX;

    n = self->c0ms_num_sets;

    for (i = 0; i < n; ++i) {
        c0kvs_usage(self->c0ms_sets[i], &u);

        usage->u_keys += u.u_keys;
        usage->u_tombs += u.u_tombs;
        usage->u_keyb += u.u_keyb;
        usage->u_valb += u.u_valb;

        if (i == 0)
            continue;

        usage->u_alloc += u.u_alloc;
        usage->u_free += u.u_free;
        if (u.u_used_max > usage->u_used_max)
            usage->u_used_max = u.u_used_max;
        if (u.u_used_min < usage->u_used_min)
            usage->u_used_min = u.u_used_min;
    }

    usage->u_count = n;
}

size_t
c0kvms_used(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    size_t                     sz = 0;
    u32                        i;

    for (i = 1; i < self->c0ms_num_sets; ++i)
        sz += c0kvs_used(self->c0ms_sets[i]);

    return sz; /* excludes ptomb */
}

size_t
c0kvms_used_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_used;
}

void
c0kvms_used_set(struct c0_kvmultiset *handle, size_t used)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_used = used;
}

size_t
c0kvms_avail(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    size_t                     sz = 0;
    u32                        i;

    for (i = 1; i < self->c0ms_num_sets; ++i)
        sz += c0kvs_avail(self->c0ms_sets[i]);

    return sz; /* excludes ptomb */
}

bool
c0kvms_should_ingest(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    int                        width, cnt, n;
    uint                       r;

    if (atomic_read(&self->c0ms_ingesting) > 0)
        return true;

    r = get_cycles() >> 1;

    if (r % 64 > 2)
        return false;

    /* Sample half of the available c0 kvsets, and return true
     * if the average number of entries exceeds the threshold
     * or there isn't enough space to accommodate a large value.
     * This helps keeps the bonsai trees from growing too deep.
     */
    assert(self->c0ms_num_sets > 1);
    width = self->c0ms_num_sets;
    n = width / 2;
    r %= (width - n);

    cnt = (HSE_C0KVMS_C0SNR_MAX / width) * n;
    cnt = (cnt * 768) / 1024; /* 75% */

    while (n-- > 0 && cnt >= 0) {
        if (c0kvs_avail(self->c0ms_sets[r]) < HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX)
            return true;

        cnt -= c0kvs_get_element_count(self->c0ms_sets[r++]);
    }

    return (cnt < 0);
}

u32
c0kvms_width(struct c0_kvmultiset *handle)
{
    return c0_kvmultiset_h2r(handle)->c0ms_num_sets;
}

static bool
c0kvms_cursor_next(struct element_source *es, void **element)
{
    struct c0_kvmultiset_cursor *cur = c0_kvmultiset_cursor_es_h2r(es);
    int                          skidx = cur->c0mc_skidx;

    while (bin_heap2_pop(cur->c0mc_bh, element)) {
        struct bonsai_kv *kv = *element;

        if (key_immediate_index(&kv->bkv_key_imm) == skidx) {
            kv->bkv_es = es;
            if (es == cur->c0mc_esrcv[0])
                kv->bkv_flags |= BKV_FLAG_PTOMB;
            break;
        }
    }
    return !!*element;
}

static bool
c0kvms_cursor_unget(struct element_source *es)
{
    struct c0_kvmultiset_cursor *cur = c0_kvmultiset_cursor_es_h2r(es);

    /*
     * Sources already at EOF remain at EOF - these have been removed
     * from the bin_heap already - thus we only need to unget the
     * sources still in the bin_heap2.  A subsequent prepare will then
     * reload the bin_heap2 with the same results for the existing
     * sources, and the new results for the new sources.
     */

    bin_heap2_remove_all(cur->c0mc_bh);
    return true;
}

static void
c0kvms_cursor_prepare(struct c0_kvmultiset_cursor *cur)
{
    bin_heap2_prepare(cur->c0mc_bh, cur->c0mc_iterc, cur->c0mc_esrcv);
}

struct element_source *
c0kvms_cursor_skip_pfx(struct c0_kvmultiset_cursor *cur, struct bonsai_kv *pt_bkv)
{
    struct element_source *   pt_es = pt_bkv->bkv_es;
    struct c0_kvset_iterator *iter;
    u32                       klen;
    int                       i;
    s64                       rc;

    /* skip pfx only if KVMS is strictly older than current. */
    rc = bin_heap2_age_cmp(0, pt_es, &cur->c0mc_es);
    if (rc >= 0)
        return 0; /* nothing to update */

    /* [HSE_REVISIT] Check if the key contributed by this c0kvms has a pfx
     * that matches. If not, skip seeking this kvms.
     */

    klen = key_imm_klen(&pt_bkv->bkv_key_imm);
    iter = cur->c0mc_iterv;

    for (i = 0; i < cur->c0mc_iterc; ++i)
        c0_kvset_iterator_skip_pfx(iter++, pt_bkv->bkv_key, klen, 0);

    c0kvms_cursor_prepare(cur);

    return &cur->c0mc_es;
}

void
c0kvms_cursor_seek(struct c0_kvmultiset_cursor *cur, const void *seek, u32 seeklen, u32 ct_pfx_len)
{
    struct c0_kvset_iterator *iter = cur->c0mc_iterv;
    int                       i;

    for (i = 0; i < cur->c0mc_iterc; ++i) {
        u32 len = seeklen;

        if (i == 0 && seeklen >= ct_pfx_len)
            len = ct_pfx_len;

        c0_kvset_iterator_seek(iter++, seek, len, 0);
    }

    c0kvms_cursor_prepare(cur);
}

merr_t
c0kvms_pfx_probe_rcu(
    struct c0_kvmultiset *   handle,
    u16                      skidx,
    const struct kvs_ktuple *kt,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seqno)
{
    struct c0_kvset *c0kvs;
    merr_t           err;

    c0kvs = c0kvms_get_hashed_c0kvset(handle, kt->kt_hash);

    err = c0kvs_pfx_probe_rcu(c0kvs, skidx, kt, sfx_len, view_seqno, seqref, res, qctx, kbuf, vbuf, pt_seqno);
    return ev(err);
}

merr_t
c0kvms_pfx_probe_excl(
    struct c0_kvmultiset *   handle,
    u16                      skidx,
    const struct kvs_ktuple *kt,
    u32                      sfx_len,
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seqno)
{
    struct c0_kvset *c0kvs;
    merr_t           err;

    c0kvs = c0kvms_get_hashed_c0kvset(handle, kt->kt_hash);

    err = c0kvs_pfx_probe_excl(c0kvs, skidx, kt, sfx_len, view_seqno, seqref, res, qctx, kbuf, vbuf, pt_seqno);
    return ev(err);
}

static inline bool
c0kvms_cursor_new_iter(
    struct c0_kvmultiset_cursor *cur,
    struct c0_kvset_iterator *   iter,
    struct c0_kvmultiset_impl *  self,
    int                          i,
    bool                         reverse)
{
    uint flags = C0_KVSET_ITER_FLAG_INDEX;
    u32  seeklen = cur->c0mc_pfx_len;
    bool empty;

    if (reverse)
        flags |= C0_KVSET_ITER_FLAG_REVERSE;

    /*
     * [HSE_REVISIT] - Should probably rework this so the ptomb c0kvset is
     * more explicitly modeled.
     */
    if (i == 0) {
        flags |= C0_KVSET_ITER_FLAG_PTOMB;

        if (seeklen > cur->c0mc_ct_pfx_len)
            seeklen = cur->c0mc_ct_pfx_len;
    }

    c0kvs_iterator_init(self->c0ms_sets[i], iter, flags, cur->c0mc_skidx);

    empty = c0_kvset_iterator_empty(iter);
    if (!empty) {
        /*
         * cur->c0mc_pfx buffer is initialized in kvs.c.
         * Forward cursor prefix buffer is cur->c0mc_pfx_len bytes long.
         * Reverse cursor prefix buffer is initialized to pfx bytes
         * followed by FF for a total len of HSE_KVS_KLEN_MAX.
         */
        if (cur->c0mc_reverse)
            seeklen = HSE_KVS_KLEN_MAX;

        c0_kvset_iterator_seek(iter, cur->c0mc_pfx, seeklen, 0);
    }

    return !empty;
}

static void
c0kvms_cursor_discover(struct c0_kvmultiset_cursor *cur, struct c0_kvmultiset_impl *self)
{
    struct c0_kvset_iterator *iter = cur->c0mc_iterv;
    struct element_source **  esrc = cur->c0mc_esrcv;
    int                       num = self->c0ms_num_sets;
    bool                      reverse = cur->c0mc_reverse;
    int                       i;

    /* HSE_REVISIT: why zero everything? */
    memset(cur->c0mc_iterv, 0, sizeof(cur->c0mc_iterv));
    memset(cur->c0mc_esrcv, 0, sizeof(cur->c0mc_esrcv));

    for (i = 0; i < num; ++i, ++esrc, ++iter) {
        if (c0kvms_cursor_new_iter(cur, iter, self, i, reverse))
            *esrc = c0_kvset_iterator_get_es(iter);
    }

    cur->c0mc_iterc = num;
}

bool
c0kvms_cursor_update(struct c0_kvmultiset_cursor *cur, void *key, u32 klen, u32 ct_pfx_len)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(cur->c0mc_kvms);
    struct c0_kvset_iterator * iter;
    struct element_source **   esrc;
    struct bonsai_kv *         bkv;
    int                        num = self->c0ms_num_sets;
    bool                       rev = cur->c0mc_reverse;
    bool                       added = false;

    int i;

    /* HSE_REVISIT: if ingested, should release asap and track in cn */

    if (c0kvms_is_ingested(cur->c0mc_kvms))
        hse_log(
            HSE_ERR "c0kvms_cursor_update: "
                    "holding ref of ingested kvms %p",
            cur->c0mc_kvms);

    /*
     * c0_kvsets can become non-empty, or be extended past eof.
     * Updated c0_kvsets must be positioned, because the iteration
     * point must not see keys earlier than current.
     */

    iter = cur->c0mc_iterv;
    esrc = cur->c0mc_esrcv;

    for (i = 0; i < num; ++i, ++esrc, ++iter) {
        if (!*esrc) {
            if (!c0kvms_cursor_new_iter(cur, iter, self, i, rev))
                continue;
            *esrc = c0_kvset_iterator_get_es(iter);
        } else {
            if (!(*esrc)->es_eof)
                continue;
            if (c0_kvset_iterator_eof(iter))
                continue;
        }

        if (klen) {
            u32 len = klen;

            if (i == 0 && klen > ct_pfx_len)
                len = ct_pfx_len;

            c0_kvset_iterator_seek(iter, key, len, 0);
        }

        bin_heap2_insert_src(cur->c0mc_bh, *esrc);
        added = true;
    }

    if (!added)
        return false;

    /*
     * If an existing kvset was extended, and the last key seen
     * was from that kvset, the seek repositioned the kvset to
     * return the duplicate.  Fix that here.
     */
    if (bin_heap2_peek(cur->c0mc_bh, (void **)&bkv)) {
        if (bkv->bkv_es != cur->c0mc_esrcv[0] &&
            !keycmp(key, klen, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm)))
            bin_heap2_pop(cur->c0mc_bh, (void **)&bkv);
    }

    return true;
}

struct element_source *
c0kvms_cursor_get_source(struct c0_kvmultiset_cursor *cur)
{
    return &cur->c0mc_es;
}

merr_t
c0kvms_cursor_create(
    struct c0_kvmultiset *       handle,
    struct c0_kvmultiset_cursor *cur,
    int                          skidx,
    const void *                 pfx,
    size_t                       pfx_len,
    size_t                       ct_pfx_len,
    bool                         reverse)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    merr_t                     err;

    cur->c0mc_kvms = handle;
    cur->c0mc_skidx = skidx;
    cur->c0mc_es = es_make(c0kvms_cursor_next, c0kvms_cursor_unget, 0);
    cur->c0mc_es.es_sort = 0;
    cur->c0mc_reverse = reverse;
    cur->c0mc_pfx = pfx;
    cur->c0mc_pfx_len = pfx_len;
    cur->c0mc_ct_pfx_len = ct_pfx_len;

    c0kvms_cursor_discover(cur, self);

    err =
        bin_heap2_create(HSE_C0_KVSET_ITER_MAX, reverse ? bn_kv_cmp_rev : bn_kv_cmp, &cur->c0mc_bh);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "c0kvms_cursor_create: "
                    "cannot create binheap: @@e",
            err);
        return err;
    }

    c0kvms_cursor_prepare(cur);
    return 0;
}

BullseyeCoverageSaveOff

HSE_USED HSE_COLD
static void
c0kvms_cursor_debug(struct c0_kvmultiset *handle, int skidx)
{
    struct c0_kvmultiset_cursor cur;
    struct element_source *     es;
    void *                      item;
    merr_t                      err;

    char disp[256];
    int  max = sizeof(disp);

    /*
    // really want to know:
    // - which bonsai trees have data (addr, index)
    // - which tree sources the data (index)
    // - when keys are skipped by skidx (do not filter above)
    // - when a source is removed from bin_heap2
    */

    err = c0kvms_cursor_create(handle, &cur, skidx, 0, 0, 0, false);
    if (ev(err))
        return;

    while (bin_heap2_peek_debug(cur.c0mc_bh, &item, &es)) {
        struct bonsai_kv * kv;
        struct bonsai_val *v;
        int                len, idx;

        bin_heap2_pop(cur.c0mc_bh, &item);
        kv = item;
        len = key_imm_klen(&kv->bkv_key_imm);

        if (key_immediate_index(&kv->bkv_key_imm) != cur.c0mc_skidx)
            continue;

        for (idx = 0; idx < cur.c0mc_iterc; ++idx)
            if (cur.c0mc_esrcv[idx] == es)
                break;

        fmt_pe(disp, max, kv->bkv_key, len);
        printf("es %2d: %3d, %s = ", idx, len, disp);

        for (v = kv->bkv_values; v; v = v->bv_next) {
            len = v->bv_xlen;
            fmt_pe(disp, max, v->bv_value, len);
            printf(
                "%s, len %d seqref 0x%lx%s",
                disp,
                len,
                (ulong)v->bv_seqnoref,
                v->bv_next ? " / " : "");
        }
        printf("\n");
    }

    c0kvms_cursor_destroy(&cur);
}

HSE_USED HSE_COLD
void
c0kvms_cursor_kvs_debug(struct c0_kvmultiset *handle, void *key, int klen)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    int i;

    /* iterate each c0ms separately, looking for key */
    for (i = 0; i < self->c0ms_num_sets; ++i) {
        printf("kvms %p set[%d] ", self, i);
        c0kvs_debug(self->c0ms_sets[i], key, klen);
    }
}

BullseyeCoverageRestore

void
c0kvms_cursor_destroy(struct c0_kvmultiset_cursor *cur)
{
    bin_heap2_destroy(cur->c0mc_bh);
}

struct c0_ingest_work *
c0kvms_ingest_work_prepare(struct c0_kvmultiset *handle, void *c0)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    struct element_source **   source;
    struct c0_kvset_iterator * iter;
    struct c0_ingest_work *    work;
    int                        i;

    work = self->c0ms_ingest_work;
    assert(work);

    work->c0iw_c0kvms = handle;
    work->c0iw_c0 = c0;

    source = work->c0iw_sourcev + HSE_C0_KVSET_ITER_MAX;
    iter = work->c0iw_iterv + HSE_C0_KVSET_ITER_MAX;

    /* lay kvsets backwards so ptomb c0kvset is at the first position. */
    for (i = self->c0ms_num_sets - 1; i >= 0; --i) {
        uint flags = 0;

        if (i == 0)
            flags |= C0_KVSET_ITER_FLAG_PTOMB;

        c0kvs_iterator_init(self->c0ms_sets[i], iter - 1, flags, 0);

        if (c0_kvset_iterator_empty(iter - 1))
            continue;

        --source;
        --iter;

        /* The c0_kvset_iterator element sources have no lifetime
         * independent of the iterators themselves. They merely
         * serve as interfaces to the iterators.
         */
        *source = c0_kvset_iterator_get_es(iter);
    }

    work->c0iw_iterc = HSE_C0_KVSET_ITER_MAX - (iter - work->c0iw_iterv);

    return work;
}

void
c0kvms_seqno_set(struct c0_kvmultiset *handle, uint64_t kvdb_seq)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    atomic64_set(&self->c0ms_seqno, kvdb_seq);
}

merr_t
c0kvms_create(
    u32                    num_sets,
    size_t                 alloc_sz,
    u64                    ingest_delay,
    atomic64_t *           kvdb_seq,
    struct c0_kvmultiset **multiset)
{
    struct c0_kvmultiset_impl *kvms;
    merr_t                     err;
    size_t                     kvms_sz, sz;
    size_t                     c0snr_sz, iw_sz;
    int                        i;
    u32                        max_sets;

    *multiset = NULL;

    max_sets = (PAGE_SIZE - sizeof(*kvms)) / sizeof(void *);
    max_sets = min_t(s32, max_sets, HSE_C0_INGEST_WIDTH_MAX);

    /* Constrain the aggregate ingest buffer size to 4GB.
     */
    if (num_sets * alloc_sz > (4ul << 30))
        num_sets = (4ul << 30) / alloc_sz;
    num_sets = min_t(u32, num_sets, max_sets - 1);
    num_sets = max_t(u32, num_sets, 2);

    /* Ensure the total number of sets is even so that the modulus
     * used by c0kvms_get_hashed_c0kvset() is never a power of two.
     */
    num_sets = (num_sets + 1) & ~1u;
    assert(num_sets > 1 && num_sets <= max_sets);

    kvms = kmem_cache_alloc(c0kvms_cache);
    if (ev(!kvms))
        return merr(ENOMEM);

    memset(kvms, 0, sizeof(*kvms));

    atomic_set(&kvms->c0ms_refcnt, 1); /* birth reference */
    atomic_set(&kvms->c0ms_ingesting, 0);

    atomic_set(&kvms->c0ms_c0snr_cnt, 0);
    kvms->c0ms_c0snr_max = HSE_C0KVMS_C0SNR_MAX;

    kvms->c0ms_ingest_delay = ingest_delay;
    kvms->c0ms_rsvd_sn = HSE_SQNREF_INVALID;
    kvms->c0ms_ctime = get_time_ns();

    /* mark this seqno 'not in use'. */
    atomic64_set(&kvms->c0ms_seqno, HSE_SQNREF_INVALID);

    /* The first kvset is reserved for ptombs and needn't be as large
     * as the rest, so we leverage it for the c0snr buffer.  Note that
     * we needn't fail the create if we cannot allocate all c0kvsets,
     * but at a minimum we need at least two c0kvsets.
     */
    c0snr_sz = sizeof(*kvms->c0ms_c0snr_base) * HSE_C0KVMS_C0SNR_MAX;
    iw_sz = sizeof(*kvms->c0ms_ingest_work);

    sz = HSE_C0_CHEAP_SZ_MIN * 2 + c0snr_sz + iw_sz;
    if (sz < alloc_sz)
        sz = alloc_sz;

    for (i = 0; i < num_sets; ++i) {
        err = c0kvs_create(sz, kvdb_seq, &kvms->c0ms_seqno, &kvms->c0ms_sets[i]);
        if (ev(err)) {
            if (i > 1)
                break;
            goto errout;
        }

        c0kvs_ingesting_init(kvms->c0ms_sets[i], &kvms->c0ms_ingesting);

        ++kvms->c0ms_num_sets;
        sz = alloc_sz;
    }

    /* define thresholds for transactions to merge/flush */
    kvms_sz = (kvms->c0ms_num_sets - 1) * alloc_sz;
    kvms->c0ms_txn_thresh_lo = kvms_sz >> 4; /* 1/16th of kvms size */
    kvms->c0ms_txn_thresh_hi = kvms_sz >> 2; /* 1/4th  of kvms size */

    /* Allocate the c0snr buffer from the ptomb c0kvset,
     * this should never fail.
     */
    kvms->c0ms_c0snr_base = c0kvs_alloc(kvms->c0ms_sets[0], SMP_CACHE_BYTES, c0snr_sz);
    if (ev(!kvms->c0ms_c0snr_base)) {
        assert(kvms->c0ms_c0snr_base);
        err = merr(ENOMEM);
        goto errout;
    }

    /* Allocate the ingest work buffer from the ptomb c0kvset,
     * this should never fail.
     */
    kvms->c0ms_ingest_work = c0kvs_alloc(kvms->c0ms_sets[0], SMP_CACHE_BYTES, iw_sz);
    if (ev(!kvms->c0ms_ingest_work)) {
        assert(kvms->c0ms_ingest_work);
        err = merr(ENOMEM);
        goto errout;
    }

    /* Remember the size of the ptomb c0kvs for c0kvs_reset().
     */
    kvms->c0ms_resetsz = c0kvs_used(kvms->c0ms_sets[0]);

    err = c0_ingest_work_init(kvms->c0ms_ingest_work);

errout:
    if (ev(err)) {
        c0kvms_putref(&kvms->c0ms_handle);
        *multiset = NULL;
        return err;
    }

    perfc_inc(&c0_metrics_pc, PERFC_BA_C0METRICS_KVMS_CNT);

    *multiset = &kvms->c0ms_handle;

    return 0;
}

void
c0kvms_abort_active(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    uint c0snr_cnt = atomic_read(&self->c0ms_c0snr_cnt);
    int i;

    for (i = 0; i < c0snr_cnt; i++) {
        uintptr_t *ptr = (uintptr_t *)self->c0ms_c0snr_base[i];

        if (ptr)
            c0snr_abort(ptr);
    }
}

static void
c0kvms_destroy(struct c0_kvmultiset_impl *mset)
{
    int i;
    int c0snr_cnt = atomic_read(&mset->c0ms_c0snr_cnt);

    assert(atomic_read(&mset->c0ms_refcnt) == 0);

    /* Must destroy c0ms_ingest_work before c0ms_set[0].
     */
    if (mset->c0ms_ingest_work && mset->c0ms_ingest_work->t0 > 0)
        c0kvms_usage(&mset->c0ms_handle, &mset->c0ms_ingest_work->c0iw_usage);

    c0_ingest_work_fini(mset->c0ms_ingest_work);

    for (i = 0; i < c0snr_cnt; i++) {
        uintptr_t *ptr = (uintptr_t *)mset->c0ms_c0snr_base[i];

        if (ptr)
            c0snr_dropref(ptr);
    }
    atomic_sub(c0snr_cnt, &mset->c0ms_c0snr_cnt);

    assert(atomic_read(&mset->c0ms_c0snr_cnt) == 0);

    for (i = 0; i < mset->c0ms_num_sets; ++i)
        c0kvs_destroy(mset->c0ms_sets[i]);

    kmem_cache_free(c0kvms_cache, mset);

    perfc_dec(&c0_metrics_pc, PERFC_BA_C0METRICS_KVMS_CNT);
}

static void
c0kvms_destroy_cb(struct work_struct *w)
{
    struct c0_kvmultiset_impl *c0kvms;

    c0kvms = container_of(w, struct c0_kvmultiset_impl, c0ms_destroy_work);

    c0kvms_destroy(c0kvms);
}

void
c0kvms_reset(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    size_t                     resetsz;
    int                        i;

    assert(atomic_read(&self->c0ms_refcnt) == 1);
    atomic_set(&self->c0ms_refcnt, 1); /* birth reference */
    atomic_set(&self->c0ms_ingesting, 0);

    assert(atomic_read(&self->c0ms_c0snr_cnt) == 0);
    atomic_set(&self->c0ms_c0snr_cnt, 0);
    atomic_set(&self->c0ms_c0snr_cur, 0);

    self->c0ms_finalized = false;
    self->c0ms_ingested = false;

    resetsz = self->c0ms_resetsz;

    for (i = 0; i < self->c0ms_num_sets; ++i) {
        struct c0_kvset *c0kvs = self->c0ms_sets[i];

        c0kvs_reset(c0kvs, resetsz);
        c0kvs_ingesting_init(c0kvs, &self->c0ms_ingesting);
        resetsz = 0;
    }

    c0_ingest_work_reset(self->c0ms_ingest_work);
}

void
c0kvms_getref(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    int refcnt HSE_MAYBE_UNUSED;

    refcnt = atomic_inc_return(&self->c0ms_refcnt);

    assert(refcnt > 1);
}

void
c0kvms_putref(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    assert(handle);

    if (ev(!handle)) /* [HSE_REVISIT] fix cursor teardown bugs */
        return;

    if (atomic_dec_return(&self->c0ms_refcnt) > 0)
        return;

     assert(atomic_read(&self->c0ms_refcnt) == 0);

    if (self->c0ms_wq) {
        INIT_WORK(&self->c0ms_destroy_work, c0kvms_destroy_cb);
        queue_work(self->c0ms_wq, &self->c0ms_destroy_work);
        return;
    }

    c0kvms_destroy(self);
    ev(1);
}

u64
c0kvms_gen_update(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_gen = atomic64_inc_return(&c0kvms_gen);

    return self->c0ms_gen;
}

u64
c0kvms_gen_read(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_gen;
}

u64
c0kvms_gen_current(struct c0_kvmultiset *handle)
{
    return atomic64_read(&c0kvms_gen);
}

uintptr_t *
c0kvms_c0snr_alloc(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl  *self = c0_kvmultiset_h2r(handle);
    uint                        cur;
    uintptr_t                  *entry;

    assert(self->c0ms_c0snr_base);

    cur = atomic_fetch_add(1, &self->c0ms_c0snr_cur);

    if (ev(cur >= self->c0ms_c0snr_max))
        return NULL;

    atomic_inc(&self->c0ms_c0snr_cnt);
    entry = self->c0ms_c0snr_base + cur;

    return entry;
}

u64
c0kvms_ctime(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_ctime;
}

merr_t
c0kvms_init(void)
{
    struct c0_kvmultiset_impl *kvms HSE_MAYBE_UNUSED;

    if (atomic_inc_return(&c0kvms_init_ref) > 1)
        return 0;

    c0kvms_cache = kmem_cache_create("c0kvms", sizeof(*kvms), __alignof(*kvms), 0, NULL);
    if (ev(!c0kvms_cache)) {
        atomic_dec(&c0kvms_init_ref);
        return merr(ENOMEM);
    }

    return 0;
}

void
c0kvms_fini(void)
{
    if (atomic_dec_return(&c0kvms_init_ref) > 0)
        return;

    kmem_cache_destroy(c0kvms_cache);
    c0kvms_cache = NULL;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c0_kvmultiset_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
