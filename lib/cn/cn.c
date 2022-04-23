/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn
#define MTF_MOCK_IMPL_cn_cursor
#define MTF_MOCK_IMPL_cn_mblocks
#define MTF_MOCK_IMPL_cn_comp
#define MTF_MOCK_IMPL_cn_internal

#include <bsd/string.h>

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/log2.h>
#include <hse_util/xrand.h>
#include <hse_util/vlb.h>
#include <hse_util/logging.h>

#include <hse_util/perfc.h>

#include <hse/limits.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/kvs_cparams.h>

#include <hse_ikvdb/csched.h>

#include <mpool/mpool.h>

#include "cn_internal.h"

#include "cn_work.h"
#include "cn_tree.h"
#include "cn_tree_cursor.h"
#include "cn_tree_create.h"
#include "cn_tree_compact.h"
#include "cn_tree_stats.h"
#include "cn_mblocks.h"
#include "cn_cursor.h"

#include "omf.h"
#include "kvset.h"
#include "spill.h"
#include "blk_list.h"
#include "kv_iterator.h"
#include "vblock_reader.h"
#include "wbt_reader.h"
#include "intern_builder.h"
#include "bloom_reader.h"
#include "cn_perfc.h"
#include "kvset_internal.h"

#define VMA_SIZE_MAX 30

struct tbkt;
struct mclass_policy;

static struct kmem_cache *cn_cursor_cache;

void
hse_log_reg_cn(void);

merr_t
cn_init(void)
{
    struct kmem_cache *cache;
    uint               sz;
    merr_t             err;

    err = wbti_init();
    if (err)
        return err;

    err = ib_init();
    if (err)
        goto wbti_cleanup;

    err = cn_tree_init();
    if (err)
        goto ib_cleanup;

    err = kvset_init();
    if (err)
        goto cn_tree_cleanup;

    hse_log_reg_cn();

    sz = sizeof(struct cn_cursor);
    cache = kmem_cache_create("cn_cursor", sz, alignof(struct cn_cursor), SLAB_PACKED, NULL);
    if (ev(!cache)) {
        err = merr(ENOMEM);
        goto kvset_cleanup;
    }

    cn_cursor_cache = cache;
    return 0;

kvset_cleanup:
    kvset_fini();

cn_tree_cleanup:
    cn_tree_fini();

ib_cleanup:
    ib_fini();

wbti_cleanup:
    wbti_fini();

    return err;
}

void
cn_fini(void)
{
    kmem_cache_destroy(cn_cursor_cache);
    cn_cursor_cache = NULL;

    kvset_fini();
    cn_tree_fini();
    ib_fini();
    wbti_fini();
}

u64
cn_get_ingest_dgen(struct cn *cn)
{
    return atomic_read(&cn->cn_ingest_dgen);
}

void
cn_inc_ingest_dgen(struct cn *cn)
{
    atomic_inc(&cn->cn_ingest_dgen);
}

struct kvs_rparams *
cn_get_rp(const struct cn *cn)
{
    return cn->rp;
}

struct mclass_policy *
cn_get_mclass_policy(const struct cn *cn)
{
    return cn->cn_mpolicy;
}

bool
cn_is_replay(const struct cn *cn)
{
    return cn->cn_replay;
}

struct mpool *
cn_get_dataset(const struct cn *cn)
{
    return cn->cn_dataset;
}

void *
cn_get_tree(const struct cn *handle)
{
    return handle->cn_tree;
}

u64
cn_get_seqno_horizon(struct cn *cn)
{
    return ikvdb_horizon(cn->ikvdb);
}

struct workqueue_struct *
cn_get_io_wq(struct cn *cn)
{
    return cn->cn_io_wq;
}

struct workqueue_struct *
cn_get_maint_wq(struct cn *cn)
{
    return cn ? cn->cn_maint_wq : NULL;
}

struct csched *
cn_get_sched(struct cn *cn)
{
    return cn->csched;
}

atomic_int *
cn_get_cancel(struct cn *cn)
{
    return &cn->cn_maint_cancel;
}

struct perfc_set *
cn_get_perfc(struct cn *cn, enum cn_action action)
{
    switch (action) {

        case CN_ACTION_COMPACT_K:
            return &cn->cn_pc_kcompact;

        case CN_ACTION_COMPACT_KV:
            return &cn->cn_pc_kvcompact;

        case CN_ACTION_SPILL:
            return &cn->cn_pc_spill;

        case CN_ACTION_NONE:
        case CN_ACTION_END:
            break;
    }

    return 0;
}

struct perfc_set *
cn_pc_capped_get(struct cn *cn)
{
    return &cn->cn_pc_capped;
}

/**
 * cn_ref_get() - acquire a reference on a cn object
 *
 * cn reference counts are used to ensure cn, along with it's tree and nodes,
 * are not deleted while in use by another object.  There is no explicit tree
 * reference count since cn and cn_tree objects have the same lifecycle.
 * Objects that need a tree ref should use a cn ref.
 *
 * See docs/cn-reference-counting.md for more information.
 */
void
cn_ref_get(struct cn *cn)
{
    atomic_inc_acq(&cn->cn_refcnt);
}

void
cn_ref_put(struct cn *cn)
{
    atomic_dec_rel(&cn->cn_refcnt);
}

/* Wait for all async jobs started by cn_work_submit() to complete.
 * Intended only for use by cn_close() and cn_tree_destroy().
 */
void
cn_ref_wait(struct cn *cn)
{
    useconds_t dly = 0;

    while (cn && atomic_read_acq(&cn->cn_refcnt) > 0) {
        if (dly < 10000)
            dly += timer_slack;
        usleep(dly);
    }
}

u64
cn_get_cnid(const struct cn *handle)
{
    return handle->cn_cnid;
}

struct cndb *
cn_get_cndb(const struct cn *handle)
{
    return handle ? handle->cn_cndb : 0;
}

struct cn_kvdb *
cn_get_cn_kvdb(const struct cn *handle)
{
    return handle ? handle->cn_kvdb : 0;
}

u32
cn_get_flags(const struct cn *handle)
{
    return handle->cn_cflags;
}

struct perfc_set *
cn_get_ingest_perfc(const struct cn *cn)
{
    return cn ? &((struct cn *)cn)->cn_pc_ingest : 0;
}

u32
cn_cp2cflags(const struct kvs_cparams *cp)
{
    u32 flags = 0;

    if (cp->kvs_ext01)
        flags |= CN_CFLAG_CAPPED;

    return flags;
}

bool
cn_is_capped(const struct cn *cn)
{
    return cn->cn_cflags & CN_CFLAG_CAPPED;
}

void
cn_disable_maint(struct cn *cn, bool onoff)
{
    if (cn->rp->cn_maint_disable != onoff) {
        cn->rp->cn_maint_disable = onoff;

        log_info("%s: background compaction %s", cn->cn_kvsname, onoff ? "disabled" : "enabled");
    }
}

struct kvs_cparams *
cn_get_cparams(const struct cn *handle)
{
    return handle->cp;
}

size_t
cn_get_sfx_len(struct cn *cn)
{
    return cn->cp->sfx_len;
}

/*----------------------------------------------------------------
 * CN GET
 */

merr_t
cn_get(
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf)
{
    struct query_ctx qctx;

    qctx.qtype = QUERY_GET;
    return cn_tree_lookup(cn->cn_tree, &cn->cn_pc_get, kt, seq, res, &qctx, 0, vbuf);
}

merr_t
cn_pfx_probe(
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    return cn_tree_lookup(cn->cn_tree, &cn->cn_pc_get, kt, seq, res, qctx, kbuf, vbuf);
}

/**
 * cn_commit_blks() - commit a set of mblocks
 * @ds:           dataset
 * @blks:         array of kvset_mblock structs
 * @n_committed:  (output) number of successfully committed mblocks by this
 *                function call.
 *
 * Given @N mblock IDs, attempt to commit all @N mblocks.  If all commits are
 * successful, then set @n_committed to @N and return with success status.  If
 * the @i-th commit fails, then: do not attempt to commit any more of the @N
 * mblocks, set @n_committed to @i-%1, and return with an error status
 * indicating the underlying cause of failure.
 */
static merr_t
cn_commit_blks(struct mpool *ds, struct blk_list *blks, u32 *n_committed)
{
    merr_t err;
    u32    bx;

    for (bx = 0; bx < blks->n_blks; ++bx) {
        err = commit_mblock(ds, &blks->blks[bx]);
        if (ev(err))
            return err;
        *n_committed += 1;
    }
    return 0;
}

merr_t
cn_mblocks_commit(
    struct mpool *        ds,
    struct cndb *         cndb,
    u64                   cnid,
    u64                   txid,
    u32                   num_lists,
    struct kvset_mblocks *list,
    enum cn_mutation      mutation,
    u32 *                 n_committed,
    u64 *                 context,
    u64 *                 tags)
{
    merr_t err = 0;
    u32    lx;

    *n_committed = 0;

    /* [HSE_REVISIT] it is possible to have no blocks here, but we must emit
     * a C record so that the metadata is complete.  In that case, there
     * will be no corresponding meta record, but the replay algorithm can
     * easily anticipate this case.
     */
    for (lx = 0; lx < num_lists; lx++) {

        /*
         * If key compaction, all the vblocks are already committed
         * and all of them need to be kept on rollback.
         * Else all vblocks need to be
         * committed and none will be kept on rollback.
         */
        err = cndb_txn_txc(
            cndb,
            txid,
            cnid,
            context,
            &list[lx],
            (mutation == CN_MUT_KCOMPACT) ? list[lx].vblks.n_blks : 0);
        if (ev(err))
            return err;
        tags[lx] = *context;
    }

    for (lx = 0; lx < num_lists; lx++) {
        err = cn_commit_blks(ds, &list[lx].kblks, n_committed);
        if (ev(err))
            return err;

        if (mutation == CN_MUT_KCOMPACT)
            continue;

        err = cn_commit_blks(ds, &list[lx].vblks, n_committed);
        if (ev(err))
            return err;
    }

    return 0;
}

/**
 * cn_delete_blks() - delete or abort multiple mblocks
 * @ds:           dataset
 * @blks:         blk_list of mblocks to delete
 * @n_committed:  number of mblocks in list already committed
 *
 * Given a blk_list of mblocks, delete the first @n_committed and
 * abort the remaining N-@n_committed.
 */
static void
cn_delete_blks(struct mpool *ds, struct blk_list *blks, u32 n_committed)
{
    u32 bx;

    for (bx = 0; bx < blks->n_blks; ++bx) {
        if (n_committed > 0) {
            delete_mblock(ds, &blks->blks[bx]);
            n_committed -= 1;
        } else {
            abort_mblock(ds, &blks->blks[bx]);
        }
    }
}

void
cn_mblocks_destroy(
    struct mpool *        ds,
    u32                   num_lists,
    struct kvset_mblocks *list,
    bool                  kcompact,
    u32                   n_committed)
{
    u32 lx;

    for (lx = 0; lx < num_lists; lx++) {
        cn_delete_blks(ds, &list[lx].kblks, n_committed);
        if (kcompact)
            continue;
        cn_delete_blks(ds, &list[lx].vblks, n_committed);
    }
}

static inline size_t
roundup_size(size_t val, size_t align)
{
    return align * ((val + align - 1) / align);
}

/**
 * cn_mb_est_alen() - estimate media space required to store data in mblocks
 * @full_captgt: value of mbc_captgt in mpool_mblock_alloc() for full size
 *               mblock
 * @alloc_unit: mblock unit of allocation (MPOOL_DEV_VEBLOCKBY_DEFAULT)
 * @wlen: total wlen needed by caller
 * @flags: see CN_MB_FLAGS_*
 *
 * This function is used to estimate the total media capacity used by
 * kblocks and vblocks after a compaction operation.  For example, if
 * a node contains 1.5 GiB of key data, 15 GiB of value data, and has
 * space amp of 1.5, then the expected key and value data after
 * compaction is 1.0 and 10.0 GiB respectively.  In that case, this
 * function would be called twice (once for kblocks and once for
 * vblocks) as follows:
 *
 * For kblocks (which are not preallocated):
 *    @full_captgt = KBLOCK_MAX_SIZE
 *    @alloc_unit = MPOOL_DEV_VEBLOCKBY_DEFAULT
 *    @wlen = 1.0 GiB
 *    @flags = CN_MB_EST_FLAGS_POW2;
 *
 * For vblocks (which are preallocated):
 *    @full_captgt = VBLOCK_MAX_SIZE
 *    @alloc_unit = MPOOL_DEV_VEBLOCKBY_DEFAULT
 *    @wlen  = 10.0 GiB
 *    @flags = CN_MB_EST_FLAGS_PREALLOC;
 */
/* MTF_MOCK */
size_t
cn_mb_est_alen(size_t full_captgt, size_t mb_alloc_unit, size_t wlen, uint flags)
{
    size_t full_alen; /* allocated len of one full mblock */
    size_t alen;      /* sum allocated len for all mblocks */
    size_t extra;
    bool   prealloc;
    bool   truncate;
    bool   pow2;

    if (!full_captgt || !mb_alloc_unit || !wlen)
        return 0;

    /* Storing wlen bytes in a set of mblocks requires a set of full
     * mblocks and at most one partial mblock.  The capacity of
     * each full mblock (full_alen) is determined by 'full_captgt'
     * rounded up to the nearest mblock allocation unit.  If
     * mblocks are preallocated and truncation is disabled, then
     * the partial mblock will be full size, otherwise it will be
     * rounded up to the mblock allocation unit.
     */

    prealloc = flags & CN_MB_EST_FLAGS_PREALLOC;
    truncate = flags & CN_MB_EST_FLAGS_TRUNCATE;
    pow2 = flags & CN_MB_EST_FLAGS_POW2;

    if (pow2)
        full_captgt = roundup_pow_of_two(full_captgt);

    full_alen = roundup_size(full_captgt, mb_alloc_unit);
    alen = full_alen * (wlen / full_alen);
    extra = wlen - alen;

    if (extra) {
        if (prealloc && !truncate)
            extra = full_alen;
        else if (pow2)
            extra = roundup_pow_of_two(extra);

        alen += roundup_size(extra, mb_alloc_unit);
    }

    return alen;
}

/**
 * cn_ingest_prep()
 * @cn:
 * @mblocks:
 * @txid:
 * @context:
 */
static merr_t
cn_ingest_prep(
    struct cn *           cn,
    struct kvset_mblocks *mblocks,
    u64                   txid,
    u64 *                 context,
    struct kvset **       kvsetp)
{
    struct kvset_meta km = {};
    u64               dgen, tag_throwaway = 0;
    u32               commitc = 0;
    merr_t            err = 0;

    if (ev(!mblocks))
        return merr(EINVAL);

    *kvsetp = NULL;

    dgen = atomic_read(&cn->cn_ingest_dgen) + 1;

    /* Note: cn_mblocks_commit() creates "C" records in CNDB */
    err = cn_mblocks_commit(
        cn->cn_dataset,
        cn->cn_cndb,
        cn->cn_cnid,
        txid,
        1,
        mblocks,
        CN_MUT_INGEST,
        &commitc,
        context,
        &tag_throwaway);
    if (ev(err))
        goto done;

    /* Lend kblk and vblk lists to kvset_create().
     * Yes, the struct copy is a bit gross, but it works and
     * avoids unnecessary allocations of temporary lists.
     */
    km.km_kblk_list = mblocks->kblks;
    km.km_vblk_list = mblocks->vblks;
    km.km_dgen = dgen;
    km.km_node_level = 0;
    km.km_node_offset = 0;

    km.km_vused = mblocks->bl_vused;
    km.km_compc = 0;
    km.km_capped = cn_is_capped(cn);
    km.km_restored = false;
    km.km_scatter = km.km_vused ? 1 : 0;

    /* It is conceivable that there are no kblocks on ingest.  All it takes
     * is the creation of builder in the c0 ingest code without any keys
     * ever making it to that builder.  We've already told CNDB how many
     * C-records to expect, so we had to get this far to create the
     * correct number of C and CMeta records.  But if there are in fact
     * no kblocks, there's nothing more to do.  CNDB recognizes this
     * and realizes that this is not a real kvset.
     */
    if (mblocks->kblks.n_blks == 0) {
        assert(mblocks->vblks.n_blks == 0);
        goto done;
    }

    err = cndb_txn_meta(cn->cn_cndb, txid, cn->cn_cnid, *context, &km);
    if (ev(err))
        goto done;

    err = kvset_create(cn->cn_tree, *context, &km, kvsetp);

done:
    if (err) {
        /* Delete committed mblocks, abort those not yet committed. */
        cn_mblocks_destroy(cn->cn_dataset, 1, mblocks, 0, commitc);
        *kvsetp = NULL;
    }

    return err;
}

merr_t
cn_ingestv(
    struct cn **           cn,
    struct kvset_mblocks **mbv,
    uint                   ingestc,
    u64                    ingestid,
    u64                    txhorizon,
    u64 *                  min_seqno_out,
    u64 *                  max_seqno_out)
{
    struct kvset **    kvsetv = NULL;
    struct cndb *      cndb = NULL;
    struct kvset_stats kst = {};

    merr_t err = 0;
    u64    txid = 0;
    uint   i, first, last, count, check;
    u64    context = 0; /* must be initialized to zero */
    u64    seqno_max = 0, seqno_min = UINT64_MAX;
    bool   log_ingest = false;
    u64    dgen = 0;

    /* Ingestc can be large (256), and is typically sparse.
     * Remember the first and last index so we don't have
     * to iterate the entire list each time.
     */
    first = last = count = 0;
    for (i = 0; i < ingestc; i++) {

        if (!cn[i] || !mbv[i])
            continue;

        seqno_max = max_t(u64, seqno_max, mbv[i]->bl_seqno_max);
        seqno_min = min_t(u64, seqno_min, mbv[i]->bl_seqno_min);

        if (ev(seqno_min > seqno_max)) {
            err = merr(EINVAL);
            goto done;
        }

        cndb = cn[i]->cn_cndb;

        if (!count)
            first = i;
        last = i;
        count++;
        perfc_inc(&cn[i]->cn_pc_ingest, PERFC_BA_CNCOMP_START);
    }

    if (!count) {
        err = 0;
        goto done;
    }

    if (min_seqno_out)
        *min_seqno_out = seqno_min;
    if (max_seqno_out)
        *max_seqno_out = seqno_max;

    kvsetv = calloc(ingestc, sizeof(*kvsetv));
    if (ev(!kvsetv)) {
        err = merr(EINVAL);
        goto done;
    }

    err = cndb_txn_start(cndb, &txid, count, 0, seqno_max, ingestid, txhorizon);
    if (ev(err))
        goto nak;

    check = 0;
    for (i = first; i <= last; i++) {

        if (!cn[i] || !mbv[i])
            continue;

        if (cn[i]->rp && !log_ingest)
            log_ingest = cn[i]->rp->cn_compaction_debug & 2;

        err = cn_ingest_prep(cn[i], mbv[i], txid, &context, &kvsetv[i]);
        if (ev(err))
            goto nak;

        if (kvsetv[i])
            check++;
    }

    if (check != count) {
        err = merr(EINVAL);
        goto nak;
    }

    /* There must not be any failure conditions after successful ACK_C
     * because the operation has been committed.
     */
    err = cndb_txn_ack_c(cndb, txid);
    if (ev(err))
        goto nak;

    for (i = first; i <= last; i++) {

        if (!cn[i] || !mbv[i] || !kvsetv[i])
            continue;

        if (log_ingest) {
            kvset_stats_add(kvset_statsp(kvsetv[i]), &kst);
            dgen = kvsetv[i]->ks_dgen;
        }

        cn_tree_ingest_update(
            cn[i]->cn_tree,
            kvsetv[i],
            mbv[i]->bl_last_ptomb,
            mbv[i]->bl_last_ptlen,
            mbv[i]->bl_last_ptseq);

        kvsetv[i] = NULL;

        check--;
    }
    assert(check == 0);

    if (log_ingest) {
        slog_info(
            HSE_SLOG_START("cn_ingest"),
            HSE_SLOG_FIELD("dgen", "%lu", (ulong)dgen),
            HSE_SLOG_FIELD("seqno", "%lu", (ulong)ingestid),
            HSE_SLOG_FIELD("kvsets", "%lu", (ulong)kst.kst_kvsets),
            HSE_SLOG_FIELD("keys", "%lu", (ulong)kst.kst_keys),
            HSE_SLOG_FIELD("kblks", "%lu", (ulong)kst.kst_kblks),
            HSE_SLOG_FIELD("vblks", "%lu", (ulong)kst.kst_vblks),
            HSE_SLOG_FIELD("kalen", "%lu", (ulong)kst.kst_kalen),
            HSE_SLOG_FIELD("kwlen", "%lu", (ulong)kst.kst_kwlen),
            HSE_SLOG_FIELD("valen", "%lu", (ulong)kst.kst_valen),
            HSE_SLOG_FIELD("vwlen", "%lu", (ulong)kst.kst_vwlen),
            HSE_SLOG_FIELD("vulen", "%lu", (ulong)kst.kst_vulen),
            HSE_SLOG_END);
    }

    txid = 0; /* Reset txid to prevent nak */

nak:
    if (txid) {
        merr_t err2 = cndb_txn_nak(cndb, txid);

        if (!err)
            err = err2;
    }

done:
    /* NOTE: we always free the callers kvset mblocks */
    for (i = first; i <= last; i++) {
        kvset_mblocks_destroy(mbv[i]);

        if (kvsetv && kvsetv[i])
            kvset_put_ref(kvsetv[i]);

        if (cn[i])
            perfc_inc(&cn[i]->cn_pc_ingest, PERFC_BA_CNCOMP_FINISH);
    }

    free(kvsetv);

    return err;
}

static void
cn_maint_task(struct work_struct *work)
{
    struct cn *cn = container_of(work, struct cn, cn_maint_dwork.work);

    if (kvdb_health_check(cn->cn_kvdb_health, KVDB_HEALTH_FLAG_ALL))
        cn->rp->cn_maint_disable = true;
    else if (cn_is_capped(cn))
        cn_tree_capped_compact(cn->cn_tree);

    queue_delayed_work(cn->cn_maint_wq, &cn->cn_maint_dwork,
                       msecs_to_jiffies(cn->rp->cn_maint_delay));
}

struct cn_kvsetmk_ctx {
    struct cn *ckmk_cn;
    u64 *      ckmk_dgen;
    uint       ckmk_node_level_max;//HSE_REVISIT: remove this in hse-3
    uint       ckmk_kvsets;
};

static merr_t
cn_kvset_mk(struct cn_kvsetmk_ctx *ctx, struct kvset_meta *km, u64 tag)
{
    struct kvset *kvset;
    struct cn *   cn = ctx->ckmk_cn;
    merr_t        err;

    err = kvset_create(cn->cn_tree, tag, km, &kvset);
    if (ev(err))
        return err;

    err = cn_tree_insert_kvset(cn->cn_tree, kvset, km->km_node_level, km->km_node_offset);
    if (ev(err)) {
        kvset_put_ref(kvset);
        return err;
    }

    ctx->ckmk_kvsets++;

    if (km->km_dgen > *(ctx->ckmk_dgen))
        *(ctx->ckmk_dgen) = km->km_dgen;

    if (km->km_node_level > ctx->ckmk_node_level_max)
        ctx->ckmk_node_level_max = km->km_node_level;

    return 0;
}

/*----------------------------------------------------------------
 * SECTION: perf counter initialization
 *
 * See kvs_perfc_fini() in kvs.c.
 */

/*----------------------------------------------------------------
 * SECTION: open/close
 */

merr_t
cn_open(
    struct cn_kvdb *    cn_kvdb,
    struct mpool *      mp,
    struct kvdb_kvs *   kvs,
    struct cndb *       cndb,
    u64                 cnid,
    struct kvs_rparams *rp,
    const char *        kvdb_alias,
    const char *        kvs_name,
    struct kvdb_health *health,
    uint                flags,
    struct cn **        cn_out)
{
    ulong       ksz, kcnt, kshift, vsz, vcnt, vshift;
    const char *kszsuf, *vszsuf;
    merr_t      err;
    struct cn * cn;
    size_t      sz;
    u64         dgen = 0;
    uint64_t    mperr;

    struct cn_kvsetmk_ctx ctx = { 0 };
    struct mpool_props    mpprops;
    struct merr_info      ei;

    assert(cn_kvdb);
    assert(mp);
    assert(kvs);
    assert(cndb);
    assert(kvdb_alias);
    assert(kvs_name);
    assert(health);
    assert(cn_out);

    mperr = mpool_props_get(mp, &mpprops);
    if (mperr) {
        log_err("mpool_props_get failed: %s\n", merr_info(mperr, &ei));
        return merr_errno(mperr);
    }

    /* stash rparams behind cn if caller did not provide them */
    sz = sizeof(*cn);
    if (!rp)
        sz += sizeof(*rp);

    cn = alloc_aligned(sz, __alignof__(*cn));
    if (ev(!cn))
        return merr(ENOMEM);

    memset(cn, 0, sz);

    if (!rp) {
        rp = (void *)(cn + 1);
        *rp = kvs_rparams_defaults();
    }

    cn->cn_kvdb_alias = kvdb_alias;
    strlcpy(cn->cn_kvsname, kvs_name, sizeof(cn->cn_kvsname));

    cn->cn_kvdb = cn_kvdb;
    cn->rp = rp;
    cn->cp = kvdb_kvs_cparams(kvs);
    cn->cn_cndb = cndb;
    cn->ikvdb = ikvdb_kvdb_handle(kvdb_kvs_parent(kvs));
    cn->cn_dataset = mp;
    cn->cn_cnid = cnid;
    cn->cn_cflags = kvdb_kvs_flags(kvs);
    cn->cn_kvdb_health = health;
    cn->cn_mpool_props = mpprops;

    if (cn_is_capped(cn))
        rp->kvs_cursor_ttl = rp->cn_capped_ttl;

    cn->cn_mpolicy = ikvdb_get_mclass_policy(cn->ikvdb, rp->mclass_policy);
    if (ev(!cn->cn_mpolicy)) {
        err = merr(EINVAL);
        log_err("%s: invalid media class policy %s", cn->cn_kvsname, rp->mclass_policy);
        goto err_exit;
    }

    cn->cn_replay = flags & IKVS_OFLAG_REPLAY;

    /* no perf counters in replay mode */
    if (!cn->cn_replay)
        cn_perfc_alloc(cn, rp->perfc_level);

    err = cn_tree_create(&cn->cn_tree, cn->cn_kvsname, cn->cn_cflags, cn->cp, health, rp);
    if (ev(err))
        goto err_exit;

    cn_tree_setup(cn->cn_tree, mp, cn, rp, cndb, cnid, cn->cn_kvdb);

    ctx.ckmk_cn = cn;
    ctx.ckmk_dgen = &dgen;

    ksz = kcnt = kshift = 0;
    vsz = vcnt = vshift = 0;
    kszsuf = vszsuf = "bkmgtp";

    if (cn_kvdb) {
        ksz = atomic_read(&cn_kvdb->cnd_kblk_size);
        kcnt = atomic_read(&cn_kvdb->cnd_kblk_cnt);
        vsz = atomic_read(&cn_kvdb->cnd_vblk_size);
        vcnt = atomic_read(&cn_kvdb->cnd_vblk_cnt);
    }

    err = cndb_cn_instantiate(cndb, cnid, &ctx, (void *)cn_kvset_mk);
    if (ev(err))
        goto err_exit;

    if (cn_kvdb) {
        /* [HSE_REVISIT]: This approach is not thread-safe */
        ksz = atomic_read(&cn_kvdb->cnd_kblk_size) - ksz;
        kcnt = atomic_read(&cn_kvdb->cnd_kblk_cnt) - kcnt;
        vsz = atomic_read(&cn_kvdb->cnd_vblk_size) - vsz;
        vcnt = atomic_read(&cn_kvdb->cnd_vblk_cnt) - vcnt;

        kshift = ilog2(ksz | 1) / 10;
        vshift = ilog2(vsz | 1) / 10;

        kszsuf += kshift;
        vszsuf += vshift;
    }

    cn_tree_set_initial_dgen(cn->cn_tree, dgen);

    cn_tree_samp_init(cn->cn_tree);

    atomic_set(&cn->cn_ingest_dgen, cn_tree_initial_dgen(cn->cn_tree));

    /* Enable tree maintenance unless it's deliberately disabled
     * or we're in replay, diag, or read-only mode.
     */
    rp->cn_maint_disable = rp->cn_maint_disable || cn->cn_replay ||
        rp->cn_diag_mode || rp->read_only;

    if (!rp->cn_maint_disable) {
        cn->cn_maint_wq = cn_kvdb->cn_maint_wq;
        cn->cn_io_wq = cn_kvdb->cn_io_wq;

        if (cn_is_capped(cn)) {
            cn->cn_maint_running = true;

            /* If capped bloom probability is zero then disable bloom creation.
             * Otherwise, cn_bloom_capped overrides cn_bloom_prob.
             */
            if (rp->cn_bloom_create) {
                rp->cn_bloom_create = (rp->cn_bloom_capped > 0);
                if (rp->cn_bloom_create)
                    rp->cn_bloom_prob = rp->cn_bloom_capped;
            }

            INIT_DELAYED_WORK(&cn->cn_maint_dwork, cn_maint_task);
            queue_delayed_work(cn->cn_maint_wq, &cn->cn_maint_dwork,
                               msecs_to_jiffies(rp->cn_maint_delay));
        } else {
            cn->csched = ikvdb_get_csched(cn->ikvdb);

            csched_tree_add(cn->csched, cn->cn_tree);
        }
    }

    log_info(
        "%s/%s cnid %lu fanout %u pfx_len %u"
        " kb %lu%c/%lu vb %lu%c/%lu %s%s%s%s%s%s",
        cn->cn_kvdb_alias, cn->cn_kvsname, (ulong)cnid,
        cn->cp->fanout, cn->cp->pfx_len,
        ksz >> (kshift * 10), *kszsuf, kcnt,
        vsz >> (vshift * 10), *vszsuf, vcnt,
        rp->mclass_policy,
        rp->cn_maint_disable ? " !maint" : "",
        rp->cn_diag_mode ? " diag" : "",
        rp->read_only ? " rdonly" : "",
        cn_is_capped(cn) ? " capped" : "",
        cn->cn_replay ? " replay" : "");

    /* successful exit */
    cndb_getref(cndb);
    *cn_out = cn;

    return 0;

err_exit:
    flush_workqueue(cn->cn_maint_wq);
    flush_workqueue(cn->cn_io_wq);
    cn_tree_destroy(cn->cn_tree);
    if (!cn->cn_replay)
        cn_perfc_free(cn);
    free_aligned(cn);

    return ev(err) ?: merr(EBUG);
}

merr_t
cn_close(struct cn *cn)
{
    bool cancel;

    cancel = !cn->rp->cn_close_wait;
    if (cancel)
        atomic_set(&cn->cn_maint_cancel, 1);

    /* Wait for the cn maint thread to exit.  Any async kvset destroys
     * that may have started will be waited on by the cn_refcnt loop.
     */
    if (cn->cn_maint_running) {
        while (!cancel_delayed_work(&cn->cn_maint_dwork))
            usleep(1000);
    }

    csched_tree_remove(cn->csched, cn->cn_tree, cancel);

    /* Wait for all compaction jobs and async kvset destroys to complete.
     * This wait holds up ikvdb_close(), so it's important not to dawdle.
     */
    cn_ref_wait(cn);

    cndb_cn_close(cn->cn_cndb, cn->cn_cnid);
    cndb_putref(cn->cn_cndb);

    cn_tree_destroy(cn->cn_tree);
    assert(atomic_read(&cn->cn_refcnt) == 0);

    cn_perfc_free(cn);
    free_aligned(cn);

    return 0;
}

void
cn_periodic(struct cn *cn, u64 now)
{
    if (kvdb_health_check(cn->cn_kvdb_health, KVDB_HEALTH_FLAG_ALL))
        cn->rp->cn_maint_disable = true;

    if (!PERFC_ISON(&cn->cn_pc_shape_rnode))
        return;

    now /= NSEC_PER_SEC;
    if (now >= cn->cn_pc_shape_next) {

        cn_tree_perfc_shape_report(
            cn->cn_tree, &cn->cn_pc_shape_rnode, &cn->cn_pc_shape_inode, &cn->cn_pc_shape_lnode);

        cn->cn_pc_shape_next = now + 60;
    }
}

void
cn_work_wrapper(struct work_struct *context)
{
    struct cn_work *work = container_of(context, struct cn_work, cnw_work);
    struct cn *     cn = work->cnw_cnref;

    work->cnw_handler(work);
    cn_ref_put(cn);
}

void
cn_work_submit(struct cn *cn, cn_work_fn *handler, struct cn_work *work)
{
    struct workqueue_struct *wq;

    work->cnw_cnref = cn;
    work->cnw_handler = handler;

    INIT_WORK(&work->cnw_work, cn_work_wrapper);

    if (!cn) {
        handler(work);
        return;
    }

    cn_ref_get(cn);

    wq = cn_get_maint_wq(cn);
    if (wq)
        queue_work(wq, &work->cnw_work);
    else
        cn_work_wrapper(&work->cnw_work);
}

/**
 * cn_cursor_alloc() - allocate and initialize a cn_cursor object
 */
static struct cn_cursor *
cn_cursor_alloc(void)
{
    struct cn_cursor *cur;

    cur = kmem_cache_zalloc(cn_cursor_cache);
    if (ev(!cur))
        return NULL;

    return cur;
}

static void
cn_cursor_free(struct cn_cursor *cur)
{
    kmem_cache_free(cn_cursor_cache, cur);
}

/*
 * This cursor supports both prefix scans and full tree scans.
 *
 * There is an important caveat for full scans: if the CN tree
 * is large, there will be many, many kvsets that must be merged.
 * This implies significant resource load, and reduced performance.
 * Care must be taken when initiating a full scan.
 *
 * Prefix scans have a limited number of nodes to visit, and
 * therefore a limited number of kvsets (compared to a full scan).
 *
 * Both scans should be limited in time; both hold on to resource
 * for the duration of the scan, which can lead to resource
 * exhaustion / contention.
 *
 * [HSE_REVISIT] There should be an enforced time limit to auto-release
 * all resources after expiration.
 */
merr_t
cn_cursor_create(
    struct cn *            cn,
    u64                    seqno,
    bool                   reverse,
    const void *           prefix,
    u32                    pfx_len,
    struct cursor_summary *summary,
    struct cn_cursor **    cursorp)
{
    int    ct_pfx_len = cn->cp->pfx_len;
    merr_t err;

    struct cn_cursor *cur;

    cur = cn_cursor_alloc();
    if (ev(!cur))
        return merr(ENOMEM);

    /*  Memory layout:
     *  cur     sizeof(cur)
     *  prefix  pfx_len
     *  keybuf  MAX_KEY_LEN
     *  valbuf  MAX_VAL_LEN
     */
    cur->cncur_pfxlen = pfx_len;
    cur->cncur_tree_pfxlen = ct_pfx_len;
    cur->cncur_pfx = prefix;

    /* for cursor update */
    cur->cncur_cn = cn;
    cur->cncur_seqno = seqno;

    cur->cncur_summary = summary;
    cur->cncur_reverse = reverse;

    err = cn_tree_cursor_create(cur);
    if (ev(err)) {
        cn_cursor_free(cur);
        return err;
    }

    *cursorp = cur;
    return 0;
}

merr_t
cn_cursor_update(struct cn_cursor *cur, u64 seqno, bool *updated)
{
    u64    dgen = atomic_read(&cur->cncur_cn->cn_ingest_dgen);
    merr_t err;

    if (updated)
        *updated = false;

    /* a cursor in error, stays in error: must destroy/recreate */
    if (ev(cur->cncur_merr))
        return cur->cncur_merr;

    cur->cncur_seqno = seqno;

    /* common case: nothing changed, nothing to do */
    if (cur->cncur_dgen == dgen)
        return 0;

    err = cn_tree_cursor_update(cur);
    if (updated)
        *updated = true;

    if (err) {
        log_errx("update failed (%p %lu): @@e", err, cur, seqno);
        cur->cncur_merr = err;
    }

    return err;
}

merr_t
cn_cursor_seek(struct cn_cursor *cursor, const void *key, u32 len, struct kc_filter *filter)
{
    return cn_tree_cursor_seek(cursor, key, len, filter);
}

merr_t
cn_cursor_read(struct cn_cursor *cursor, struct kvs_cursor_element *elem, bool *eof)
{
    return cn_tree_cursor_read(cursor, elem, eof);
}

static bool
cncur_next(struct element_source *es, void **element)
{
    struct cn_cursor *cncur = container_of(es, struct cn_cursor, cncur_es);
    bool              eof;
    merr_t            err;

    err = cn_cursor_read(cncur, &cncur->cncur_elem, &eof);
    if (ev(err) || eof)
        return false;

    cncur->cncur_elem.kce_source = KCE_SOURCE_CN;
    *element = &cncur->cncur_elem;
    return true;
}

struct element_source *
cn_cursor_es_make(struct cn_cursor *cncur)
{
    cncur->cncur_es = es_make(cncur_next, 0, 0);
    return &cncur->cncur_es;
}

struct element_source *
cn_cursor_es_get(struct cn_cursor *cncur)
{
    return &cncur->cncur_es;
}

void
cn_cursor_destroy(struct cn_cursor *cur)
{
    cn_tree_cursor_destroy(cur);
    cn_cursor_free(cur);
}

merr_t
cn_cursor_active_kvsets(struct cn_cursor *cursor, u32 *active, u32 *total)
{
    return cn_tree_cursor_active_kvsets(cursor, active, total);
}

merr_t
cn_make(struct mpool *ds, const struct kvs_cparams *cp, struct kvdb_health *health)
{
    merr_t             err;
    struct cn_tree *   tree;
    struct kvs_rparams rp;
    struct kvs_cparams icp;

    assert(ds);
    assert(cp);
    assert(health);

    if (cp->fanout < CN_FANOUT_MIN || cp->fanout > CN_FANOUT_MAX)
        return merr(EINVAL);

    if (cp->fanout != roundup_pow_of_two(cp->fanout))
        return merr(EINVAL);

    /* Create and destroy a tree as a means of validating
     * prefix len, etc.
     */
    rp = kvs_rparams_defaults();

    icp.fanout = cp->fanout;
    icp.pfx_len = cp->pfx_len;
    icp.sfx_len = cp->sfx_len;

    err = cn_tree_create(&tree, NULL, cn_cp2cflags(cp), &icp, health, &rp);
    if (!err)
        cn_tree_destroy(tree);

    return err;
}

u64
cn_mpool_dev_zone_alloc_unit_default(struct cn *cn, enum hse_mclass mclass)
{
    return cn->cn_mpool_props.mclass[mclass].mc_mblocksz;
}

/*
 * [HSE_REVISIT]: Fix the callers to pass a correct mclass rather than blindly
 * passing HSE_MCLASS_CAPACITY. For now, assume a default mblock size of 32MiB
 * for all the media classes. This needs to be fixed in future when we want
 * KVDB to operate on media classes with varying mblock sizes.
 */
u64
cn_vma_mblock_max(struct cn *cn)
{
    u64 vma_size_max;

    vma_size_max = 1ul << VMA_SIZE_MAX;

    return vma_size_max / MPOOL_MBLOCK_SIZE_DEFAULT;
}

#if HSE_MOCKING
#include "cn_ut_impl.i"
#include "cn_cursor_ut_impl.i"
#include "cn_mblocks_ut_impl.i"
#endif /* HSE_MOCKING */
