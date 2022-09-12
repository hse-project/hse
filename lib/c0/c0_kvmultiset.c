/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c0kvms

#include <urcu-bp.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/condvar.h>
#include <hse_util/perfc.h>
#include <hse_util/fmt.h>
#include <hse_util/seqno.h>
#include <hse_util/xrand.h>
#include <hse_util/keycmp.h>
#include <hse/logging/logging.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/lc.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/kvdb_perfc.h>

#include "c0_cursor.h"
#include "c0_ingest_work.h"

#include <hse_util/bonsai_tree.h>

/* clang-format off */

#define c0_kvmultiset_cursor_es_h2r(handle) \
    container_of(handle, struct c0_kvmultiset_cursor, c0mc_es)

#define c0_kvmultiset_h2r(handle) \
    container_of(handle, struct c0_kvmultiset_impl, c0ms_handle)

/**
 * struct c0_kvmultiset_impl - managed collection of c0 kvsets
 * @c0ms_handle:
 * @c0ms_gen:           kvms unique generation count
 * @c0ms_seqno:
 * @c0ms_rsvd_sn:       reserved at kvms activation for txn flush and ingestid
 * @c0ms_used:          RAM footprint when queued for ingest (bytes)
 * @c0ms_stashp:        ptr to storage in which to cache a single freed kvms
 * @c0ms_ingesting:     kvms is being ingested (no longer active)
 * @c0ms_ingested:
 * @c0ms_finalized:     kvms guaranteed to be frozen (no more updates)
 * @c0ms_ingest_work:   data used to orchestrate c0+cn ingest
 * @c0ms_wq:            workqueue for c0kvms_destroy() offload
 * @c0ms_destroy_work:  work struct for c0kvms_destroy() offload
 * @c0ms_refcnt:        used to manage the lifetime of the kvms
 * @c0ms_c0snr_cur:     current offset into c0snr memory pool
 * @c0ms_c0snr_max:     max elements in c0snr memory pool
 * @c0ms_c0snr_base:    base of c0snr memory pool dedicated
 * @c0ms_num_sets:      size of c0ms_sets[]
 * @c0ms_ptreset_sz:    ptomb c0kvs reset size (bytes)
 * @c0ms_sets:          vector of c0 kvset pointers
 */
struct c0_kvmultiset_impl {
    struct c0_kvmultiset  c0ms_handle;
    u64                   c0ms_gen;
    atomic_ulong          c0ms_seqno;
    u64                   c0ms_rsvd_sn;
    atomic_ulong          c0ms_txhorizon;
    size_t                c0ms_used;
    atomic_ulong         *c0ms_kvdb_seq;
    void * _Atomic       *c0ms_stashp;
    struct kvdb_callback *c0ms_cb;

    atomic_int               c0ms_ingesting HSE_L1D_ALIGNED;
    bool                     c0ms_ingested;
    bool                     c0ms_finalized;
    struct c0_ingest_work   *c0ms_ingest_work;
    struct workqueue_struct *c0ms_wq;
    struct work_struct       c0ms_destroy_work;

    atomic_int   c0ms_refcnt HSE_L1D_ALIGNED;

    atomic_ulong c0ms_c0snr_cur HSE_ACP_ALIGNED;
    size_t       c0ms_c0snr_max HSE_L1D_ALIGNED;
    uintptr_t   *c0ms_c0snr_base;

    u32              c0ms_num_sets;
    u32              c0ms_ptreset_sz;
    struct c0_kvset *c0ms_sets[HSE_C0_INGEST_WIDTH_MAX * 2 + 1];
};

static struct kmem_cache *c0kvms_cache HSE_READ_MOSTLY;
static atomic_ulong       c0kvms_gen;

/* clang-format on */

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
    uint                       idx;

    idx = hash % HSE_C0_INGEST_WIDTH_MAX;

    return self->c0ms_sets[idx + 1]; /* skip ptomb c0kvset at index zero */
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

    n = self->c0ms_num_sets;

    for (i = 0; i < n; ++i) {
        c0kvs_usage(self->c0ms_sets[i], &u);

        usage->u_keys += u.u_keys;
        usage->u_tombs += u.u_tombs;
        usage->u_keyb += u.u_keyb;
        usage->u_valb += u.u_valb;
        usage->u_memsz += u.u_memsz;

        if (i == 0)
            continue;

        usage->u_alloc += u.u_alloc;
    }

    usage->u_count = n;
}

bool
c0kvms_should_ingest(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    const size_t               scaler = 1u << 30;
    size_t                     sum_kvbytes, r;
    uint                       sum_keyvals, sum_height;
    uint                       ndiv, n;

    r = xrand64_tls();

    if (HSE_LIKELY((r % scaler) < (93 * scaler) / 100))
        return false;

    if (atomic_read(&self->c0ms_ingesting) > 0)
        return true;

    /* Only 7% of callers reach this point to sample a random third
     * of the available c0 kvsets and return true if any of the
     * following are true:
     *
     * 1) The number of values for any key exceeds 4096
     * 2) The height of any bonsai tree is greater than 24
     * 3) The average number of values for all keys exceeds 2048
     * 4) The average height of all trees exceeds 22.
     * 5) The (interpolated) size of the keys+values exceeds HSE_C0_SPILL_MB_MAX (2048MB).
     */
    sum_kvbytes = sum_keyvals = sum_height = ndiv = 0;

    /* r may safely range from 0 to (WIDTH_MAX * 2) (see c0kvms_create()).
     */
    r = (r % HSE_C0_INGEST_WIDTH_MAX) + 1; /* skip ptomb c0kvset at index zero */
    n = self->c0ms_num_sets / 3;

    while (n-- > 0) {
        uint height, keyvals, cnt;
        size_t kvbytes;

        cnt = c0kvs_get_element_count2(self->c0ms_sets[r++], &height, &keyvals, &kvbytes);

        if (cnt > 0) {
            if (ev(keyvals > 4096 || height > 24))
                return true;

            sum_kvbytes += kvbytes;
            sum_keyvals += keyvals;
            sum_height += height;

            ndiv++;
        }
    }

    if (ndiv > 3 &&
        ev((sum_kvbytes >> 20) > (HSE_C0_SPILL_MB_MAX / HSE_C0_INGEST_WIDTH_MAX) * ndiv)) {
        return true; /* interpolated size is greater than 2048MB */
    }

    if (ev((sum_keyvals / 2048) > ndiv))
        return true;

    if (ev((sum_height / 22) > ndiv))
        return true;

    return false;
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

    while (bin_heap_pop(cur->c0mc_bh, element)) {
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
     * sources still in the bin_heap.  A subsequent prepare will then
     * reload the bin_heap with the same results for the existing
     * sources, and the new results for the new sources.
     */

    bin_heap_remove_all(cur->c0mc_bh);
    return true;
}

void
c0kvms_cursor_prepare(struct c0_kvmultiset_cursor *cur)
{
    bin_heap_prepare(cur->c0mc_bh, cur->c0mc_iterc, cur->c0mc_esrcv);
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
    u64                      view_seqno,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf,
    u64                      pt_seqno)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    merr_t err = 0;

    /* Skip over the ptomb c0_kvset by starting at index 1.
     */
    for (uint i = 1; i < self->c0ms_num_sets; i++) {
        err = c0kvs_pfx_probe_excl(self->c0ms_sets[i], skidx, kt, view_seqno, seqref, res,
                                   qctx, kbuf, vbuf, pt_seqno);
        if (err || qctx->seen > 1)
            break;
    }

    return err;
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
c0kvms_cursor_update(struct c0_kvmultiset_cursor *cur, u32 ct_pfx_len)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(cur->c0mc_kvms);
    struct c0_kvset_iterator * iter;
    struct element_source **   esrc;
    int                        num = self->c0ms_num_sets;
    bool                       rev = cur->c0mc_reverse;
    bool                       added = false;
    int                        i;

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

        bin_heap_insert_src(cur->c0mc_bh, *esrc);
        added = true;
    }

    if (!added)
        return false;

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

    err = bin_heap_create(
        HSE_C0_INGEST_WIDTH_MAX, reverse ? bn_kv_cmp_rev : bn_kv_cmp, &cur->c0mc_bh);
    if (ev(err)) {
        log_errx("bin_heap_create failed", err);
        return err;
    }

    return 0;
}

/* GCOV_EXCL_START */

HSE_USED HSE_COLD static void
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
    // - when a source is removed from bin_heap
    */

    err = c0kvms_cursor_create(handle, &cur, skidx, 0, 0, 0, false);
    if (ev(err))
        return;

    while (bin_heap_peek_debug(cur.c0mc_bh, &item, &es)) {
        struct bonsai_kv * kv;
        struct bonsai_val *v;
        int                len, idx;

        bin_heap_pop(cur.c0mc_bh, &item);
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

HSE_USED HSE_COLD void
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

/* GCOV_EXCL_STOP */

void
c0kvms_cursor_destroy(struct c0_kvmultiset_cursor *cur)
{
    bin_heap_destroy(cur->c0mc_bh);
    cur->c0mc_bh = NULL;
}

struct c0_ingest_work *
c0kvms_ingest_work_prepare(struct c0_kvmultiset *handle, struct c0sk *c0sk)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    struct element_source **   source;
    struct c0_kvset_iterator * iter;
    struct c0_ingest_work *    work;
    int                        i;
    uint                       flags;

    work = self->c0ms_ingest_work;
    assert(work);

    work->c0iw_c0kvms = handle;
    work->c0iw_c0sk = c0sk;
    work->c0iw_ingest_order = c0sk_ingest_order_register(c0sk);
    work->c0iw_ingest_max_seqno = c0kvms_seqno_get(handle);
    work->c0iw_ingest_min_seqno = c0sk_min_seqno_get(c0sk);
    c0sk_min_seqno_set(c0sk, work->c0iw_ingest_max_seqno); /* Update lower bound for next ingest */

    source = work->c0iw_kvms_sourcev;
    iter = work->c0iw_kvms_iterv;

    flags = C0_KVSET_ITER_FLAG_PTOMB;
    for (i = 0; i < self->c0ms_num_sets; i++) {
        c0kvs_iterator_init(self->c0ms_sets[i], iter, flags, 0);
        flags = 0;

        if (c0_kvset_iterator_empty(iter))
            continue;

        /* The c0_kvset_iterator element sources have no lifetime
         * independent of the iterators themselves. They merely
         * serve as interfaces to the iterators.
         */
        *source = c0_kvset_iterator_get_es(iter);

        source++;
        iter++;
    }

    work->c0iw_kvms_iterc = iter - work->c0iw_kvms_iterv;

    lc_ingest_iterv_init(
        c0sk_lc_get(c0sk),
        work->c0iw_lc_iterv,
        work->c0iw_lc_sourcev,
        work->c0iw_ingest_min_seqno,
        work->c0iw_ingest_max_seqno,
        &work->c0iw_lc_iterc);
    return work;
}

void
c0kvms_txhorizon_set(struct c0_kvmultiset *handle, uint64_t txhorizon)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    atomic_set(&self->c0ms_txhorizon, txhorizon);
}

uint64_t
c0kvms_txhorizon_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return atomic_read(&self->c0ms_txhorizon);
}

void
c0kvms_seqno_set(struct c0_kvmultiset *handle, uint64_t kvdb_seq)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    atomic_set(&self->c0ms_seqno, kvdb_seq);
}

u64
c0kvms_seqno_get(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return atomic_read(&self->c0ms_seqno);
}

merr_t
c0kvms_create(u32 num_sets, atomic_ulong *kvdb_seq, void * _Atomic *stashp, struct c0_kvmultiset **multiset)
{
    struct c0_kvmultiset_impl *kvms = stashp ? *stashp : NULL;
    merr_t                     err;
    size_t                     c0snr_sz, iw_sz;
    int                        i, j;

    *multiset = NULL;

    num_sets = clamp_t(u32, num_sets, HSE_C0_INGEST_WIDTH_MIN, HSE_C0_INGEST_WIDTH_MAX);

    /* Check the caller's stash for a recently freed kvms and use
     * it (if possible) rather than create a new one.
     */
    if (kvms && atomic_cas(stashp, (void *)kvms, NULL)) {
        if (kvms->c0ms_num_sets != num_sets ||
            kvms->c0ms_kvdb_seq != kvdb_seq) {

            for (i = 0; i < kvms->c0ms_num_sets; ++i)
                c0kvs_destroy(kvms->c0ms_sets[i]);
            kmem_cache_free(c0kvms_cache, kvms);

            kvms = NULL;
        } else {
            num_sets = 0;
        }
    }

    if (!kvms) {
        kvms = kmem_cache_alloc(c0kvms_cache);
        if (!kvms)
            return merr(ENOMEM);

        memset(kvms, 0, sizeof(*kvms));
    }

    kvms->c0ms_gen = 0;

    /* mark this seqno 'not in use'. */
    atomic_set(&kvms->c0ms_seqno, HSE_SQNREF_INVALID);
    kvms->c0ms_rsvd_sn = HSE_SQNREF_INVALID;
    atomic_set(&kvms->c0ms_txhorizon, U64_MAX);
    kvms->c0ms_used = 0;
    kvms->c0ms_kvdb_seq = kvdb_seq;
    kvms->c0ms_stashp = stashp;

    atomic_set(&kvms->c0ms_ingesting, 0);
    kvms->c0ms_ingested = false;
    kvms->c0ms_finalized = false;
    kvms->c0ms_wq = NULL;

    atomic_set(&kvms->c0ms_refcnt, 1); /* birth reference */

    atomic_set(&kvms->c0ms_c0snr_cur, 0);
    kvms->c0ms_c0snr_max = HSE_C0KVMS_C0SNR_MAX;

    /* The first kvset is reserved for ptombs and needn't be as large
     * as the rest, so we leverage it for the c0snr buffer.  Note that
     * we needn't fail the create if we cannot allocate all c0kvsets,
     * but at a minimum we need at least two c0kvsets.
     */
    c0snr_sz = sizeof(*kvms->c0ms_c0snr_base) * HSE_C0KVMS_C0SNR_MAX;
    iw_sz = sizeof(*kvms->c0ms_ingest_work);

    if (num_sets == 0)
        goto cached;

    for (i = 0; i < num_sets; ++i) {
        err = c0kvs_create(kvdb_seq, &kvms->c0ms_seqno, &kvms->c0ms_sets[i]);
        if (ev(err)) {
            if (i > num_sets / 2)
                break;

            c0kvms_putref(&kvms->c0ms_handle);
            return err;
        }

        ++kvms->c0ms_num_sets;
    }

    /* Copy c0kvs pointers (not including the ptomb c0kvs) to the remaining slots
     * such that we eliminate wrapping in c0kvms_should_ingest().
     */
    for (j = 1; i < NELEM(kvms->c0ms_sets); ++i, ++j) {
        kvms->c0ms_sets[i] = kvms->c0ms_sets[j];
    }

    /* Allocate the c0snr buffer from the ptomb c0kvset,
     * this should never fail.
     */
    kvms->c0ms_c0snr_base = c0kvs_alloc(kvms->c0ms_sets[0], HSE_ACP_LINESIZE, c0snr_sz);
    if (!kvms->c0ms_c0snr_base) {
        assert(kvms->c0ms_c0snr_base);
        c0kvms_putref(&kvms->c0ms_handle);
        return merr(ENOMEM);
    }

    /* Allocate the ingest work buffer from the ptomb c0kvset,
     * this should never fail.
     */
    kvms->c0ms_ingest_work = c0kvs_alloc(kvms->c0ms_sets[0], HSE_ACP_LINESIZE, iw_sz);
    if (!kvms->c0ms_ingest_work) {
        assert(kvms->c0ms_ingest_work);
        c0kvms_putref(&kvms->c0ms_handle);
        return merr(ENOMEM);
    }

    /* Remember the size of the ptomb c0kvs for c0kvs_reset().
     */
    kvms->c0ms_ptreset_sz = c0kvs_used(kvms->c0ms_sets[0]);

  cached:
    c0_ingest_work_init(kvms->c0ms_ingest_work);

    perfc_inc(&c0_metrics_pc, PERFC_BA_C0METRICS_KVMS_CNT);

    *multiset = &kvms->c0ms_handle;

    return 0;
}

void
c0kvms_destroy_cache(void * _Atomic *stashp)
{
    struct c0_kvmultiset_impl *kvms = stashp ? *stashp : NULL;
    int i;

    if (kvms && atomic_cas(kvms->c0ms_stashp, (void *)kvms, NULL)) {
        for (i = 0; i < kvms->c0ms_num_sets; ++i)
            c0kvs_destroy(kvms->c0ms_sets[i]);

        kmem_cache_free(c0kvms_cache, kvms);
    }
}

void
c0kvms_bufrel_walcb(struct c0_kvmultiset_impl *mset)
{
    struct ikvdb *ikvdb;

    if (!mset->c0ms_cb || !mset->c0ms_cb->kc_bufrel_cb)
        return;

    ikvdb = mset->c0ms_cb->kc_cbarg;
    mset->c0ms_cb->kc_bufrel_cb(ikvdb, mset->c0ms_gen);
}

static void
c0kvms_destroy(struct c0_kvmultiset_impl *mset)
{
    uint64_t c0snr_cnt;
    int      i;

    assert(atomic_read(&mset->c0ms_refcnt) == 0);

    /* Must destroy c0ms_ingest_work before c0ms_set[0].
     */
    if (mset->c0ms_ingest_work && mset->c0ms_ingest_work->t0 > 0)
        c0kvms_usage(&mset->c0ms_handle, &mset->c0ms_ingest_work->c0iw_usage);

    c0_ingest_work_fini(mset->c0ms_ingest_work);

    c0snr_cnt = atomic_read(&mset->c0ms_c0snr_cur);
    if (c0snr_cnt > mset->c0ms_c0snr_max)
        c0snr_cnt = mset->c0ms_c0snr_max;

    c0snr_droprefv(c0snr_cnt, (uintptr_t **)mset->c0ms_c0snr_base);

    /* Notify wal to free up buffer space */
    c0kvms_bufrel_walcb(mset);

    /* Try to save this kvms in the caller's stash for fast re-use...
     */
    if (mset->c0ms_finalized && mset->c0ms_stashp) {
        c0kvs_reset(mset->c0ms_sets[0], mset->c0ms_ptreset_sz);

        for (i = 1; i < mset->c0ms_num_sets; ++i)
            c0kvs_reset(mset->c0ms_sets[i], 0);

        if (atomic_cas(mset->c0ms_stashp, NULL, mset))
            mset = NULL;
    }

    if (mset) {
        for (i = 0; i < mset->c0ms_num_sets; ++i)
            c0kvs_destroy(mset->c0ms_sets[i]);

        kmem_cache_free(c0kvms_cache, mset);
    }

    perfc_dec(&c0_metrics_pc, PERFC_BA_C0METRICS_KVMS_CNT);
}

static void
c0kvms_destroy_cb(struct work_struct *w)
{
    struct c0_kvmultiset_impl *c0kvms;

    c0kvms = container_of(w, struct c0_kvmultiset_impl, c0ms_destroy_work);

    c0kvms_destroy(c0kvms);
}

int
c0kvms_refcnt(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return atomic_read(&self->c0ms_refcnt);
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

void
c0kvms_gen_init(uint64_t gen)
{
    atomic_set(&c0kvms_gen, gen);
}

u64
c0kvms_gen_update(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_gen = atomic_inc_return(&c0kvms_gen);

    return self->c0ms_gen;
}

void
c0kvms_gen_set(struct c0_kvmultiset *handle, uint64_t gen)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    c0kvms_gen_init(gen);

    self->c0ms_gen = gen;
}

u64
c0kvms_gen_read(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    return self->c0ms_gen;
}

uint64_t
c0kvms_gen_current(void)
{
    return atomic_read(&c0kvms_gen);
}

void
c0kvms_cb_setup(struct c0_kvmultiset *handle, struct kvdb_callback *cb)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);

    self->c0ms_cb = cb;
}

uintptr_t *
c0kvms_c0snr_alloc(struct c0_kvmultiset *handle)
{
    struct c0_kvmultiset_impl *self = c0_kvmultiset_h2r(handle);
    uint                       cur;
    uintptr_t *                entry;

    cur = atomic_fetch_add(&self->c0ms_c0snr_cur, 1);

    if (ev(cur >= self->c0ms_c0snr_max))
        return NULL;

    assert(self->c0ms_c0snr_base);
    entry = self->c0ms_c0snr_base + cur;

    return entry;
}

merr_t
c0kvms_init(void)
{
    struct c0_kvmultiset_impl *kvmsv[8];
    int i;

    assert(c0kvms_cache == NULL);

    c0kvms_cache = kmem_cache_create("c0kvms", sizeof(**kvmsv), __alignof__(**kvmsv),
                                     SLAB_PACKED, NULL);
    if (!c0kvms_cache)
        return merr(ENOMEM);

    /* Prime the cache...
     */
    for (i = 0; i < NELEM(kvmsv); ++i)
        kvmsv[i] = kmem_cache_alloc(c0kvms_cache);

    for (i = 0; i < NELEM(kvmsv); ++i)
        kmem_cache_free(c0kvms_cache, kvmsv[i]);

    return 0;
}

void
c0kvms_fini(void)
{
    kmem_cache_destroy(c0kvms_cache);
    c0kvms_cache = NULL;
}

#if HSE_MOCKING
#include "c0_kvmultiset_ut_impl.i"
#endif /* HSE_MOCKING */
