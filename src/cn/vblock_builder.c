/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_vblock_builder
#include "vblock_builder.h"
#include "vblock_builder_ext.h"

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse_util/logging.h>
#include <hse_util/perfc.h>
#include <hse_util/token_bucket.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/cn.h>

#include <hse/hse_limits.h>
#include <hse/kvdb_perfc.h>

#include "omf.h"
#include "blk_list.h"
#include "cn_mblocks.h"
#include "cn_metrics.h"

#include <mpool/mpool.h>

#include "vblock_builder_internal.h"

#define IS_INGEST(x) (!!((x)&KVSET_BUILDER_FLAGS_INGEST))

extern struct tbkt sp3_tbkt;

size_t
vbb_estimate_alen(struct cn *cn, size_t wlen, enum mp_media_classp mclass)
{
    u64 zonealloc_unit;

    zonealloc_unit = cn_mpool_dev_zone_alloc_unit_default(cn, mclass);
    return cn_mb_est_alen(
        VBLOCK_MAX_SIZE, zonealloc_unit, wlen, CN_MB_EST_FLAGS_TRUNCATE | CN_MB_EST_FLAGS_PREALLOC);
}

static merr_t
_vblock_start(struct vblock_builder *bld)
{
    merr_t                 err;
    struct mblock_props    mbprop;
    u64                    handle;
    u64                    tstart;
    bool                   spare;
    struct cn_merge_stats *stats = bld->mstats;
    struct kvs_rparams *   rp;

    spare = !!(bld->flags & KVSET_BUILDER_FLAGS_SPARE);

    if (stats)
        tstart = get_time_ns();
    err = mpool_mblock_alloc(bld->ds, bld->mclass, spare, &handle, &mbprop);
    if (ev(err))
        return err;
    if (stats)
        count_ops(&stats->ms_vblk_alloc, 1, mbprop.mpr_alloc_cap, get_time_ns() - tstart);

    rp = cn_get_rp(bld->cn);

    if (mbprop.mpr_mclassp == MP_MED_CAPACITY && bld->mclass != MP_MED_CAPACITY) {
        hse_log(HSE_WARNING "vblock alloc falling back to capacity.");
    }

    if (mbprop.mpr_alloc_cap != (rp->vblock_size_mb << 20)) {
        mpool_mblock_abort(bld->ds, handle);
        assert(0);
        return merr(ev(EBUG));
    }

    err = blk_list_append(&bld->vblk_list, handle, mbprop.mpr_objid);
    if (ev(err)) {
        mpool_mblock_abort(bld->ds, handle);
        return err;
    }

    assert(mbprop.mpr_stripe_len);

    /* set offsets to leave space for header */
    bld->vblk_off = VBLOCK_HDR_LEN;
    bld->wbuf_off = VBLOCK_HDR_LEN;
    bld->mbh = handle;
    bld->wbuf_len = WBUF_LEN_MAX - (WBUF_LEN_MAX % mbprop.mpr_stripe_len);
    bld->stripe_len = mbprop.mpr_stripe_len;

    /* add header to write buffer */
    memset(bld->wbuf, 0x0, VBLOCK_HDR_LEN);
    omf_set_vbh_magic(bld->wbuf, VBLOCK_HDR_MAGIC);
    omf_set_vbh_version(bld->wbuf, VBLOCK_HDR_VERSION2);
    omf_set_vbh_vgroup(bld->wbuf, bld->vgroup);

    return 0;
}

static merr_t
_vblock_flush_asynciolist(struct vblock_builder *bld, bool all)
{
    struct asyncio_list_entry *pelem;
    struct mp_asyncctx_ioc     asyncio;
    void *                     pPrevCtx = NULL;
    bool                       ingest;
    struct cn_merge_stats *    stats = bld->mstats;
    u64                        tstart;

    ingest = IS_INGEST(bld->flags);
    do {
        pelem = list_first_entry_or_null(&bld->asyncio_head, struct asyncio_list_entry, mp_link);
        if (!pelem || (!all && pPrevCtx && pPrevCtx != pelem->mp_ctx))
            break;

        if (NULL == pPrevCtx || pPrevCtx != pelem->mp_ctx) {
            memset(&asyncio, 0x0, sizeof(asyncio));
            asyncio.mp_ctx = pelem->mp_ctx;
            asyncio.mp_enabled = true;
            pPrevCtx = pelem->mp_ctx;

            if (stats)
                tstart = get_time_ns();
            mpool_mblock_asyncio_flush(bld->ds, &asyncio);
            if (asyncio.mp_err)
                return asyncio.mp_err;
            if (stats)
                count_ops(&stats->ms_vblk_flush, 1, 0, get_time_ns() - tstart);

            if (pelem->mp_ctx == bld->asyncio_ctx.mp_ctx)
                bld->asyncio_ctx.mp_ctx = NULL;
        }

        assert(NULL == pelem->mp_ctx || pelem->mp_ctx == pPrevCtx);

        list_del_init(&pelem->mp_link);
        cn_aio_free(bld->cn, pelem->mp_buf, WBUF_LEN_MAX, ingest);
        free(pelem);
        assert(bld->asyncio_lstcnt > 0);
        bld->asyncio_lstcnt--;

    } while (1);

    return 0;
}

static merr_t
_vblock_write(struct vblock_builder *bld)
{
    merr_t                     err, err1;
    struct iovec               iov;
    void *                     pbuf = NULL;
    struct asyncio_list_entry *pelem = NULL;
    struct mp_asyncctx_ioc *   pasyncio = &bld->asyncio_ctx;
    bool                       doasync = pasyncio->mp_enabled;
    bool                       ingest;
    struct cn_merge_stats *    stats = bld->mstats;
    u64                        tstart;

    assert(bld->mbh);
    assert(bld->asyncio_ctxswi);

    ingest = IS_INGEST(bld->flags);
    iov.iov_base = bld->wbuf;
    iov.iov_len = bld->wbuf_len;

    if (!ingest) {
        struct tbkt *tb = cn_get_tbkt_maint(bld->cn);

        if (tb)
            tbkt_delay(tbkt_request(tb, iov.iov_len));
    }

    while (doasync) {
        if (!pbuf)
            pbuf = cn_aio_alloc(bld->cn, WBUF_LEN_MAX, ingest, false);

        if (!pelem)
            pelem = malloc(sizeof(*pelem));

        if (!pbuf || !pelem) {
            if (bld->asyncio_lstcnt) {
                _vblock_flush_asynciolist(bld, false);
                continue;
            } else {
                cn_aio_free(bld->cn, pbuf, WBUF_LEN_MAX, ingest);
                free(pelem);
                doasync = false;
                break;
            }
        }

        INIT_LIST_HEAD(&pelem->mp_link);
        pelem->mp_buf = bld->wbuf;
        bld->asyncio_lstcnt++;
        list_add_tail(&pelem->mp_link, &bld->asyncio_head);
        bld->wbuf = pbuf;
        if (0 == (bld->asyncio_lstcnt % bld->asyncio_ctxswi))
            pasyncio->mp_ctx = NULL;
        break;
    }

    /* Function mblk_blow_chunks(), which is used in the kblock builder,
     * is not needed here because our write buffer is already
     * smallish (1MiB) and a multiple of the mblock stripe length.
     */
    if (stats)
        tstart = get_time_ns();
    err = mpool_mblock_write_data(bld->ds, !doasync, bld->mbh, &iov, 1, pasyncio);
    if (stats)
        count_ops(
            (doasync ? &stats->ms_vblk_write_async : &stats->ms_vblk_write),
            1,
            iov.iov_len,
            get_time_ns() - tstart);

    if (doasync) {
        if (!err)
            pelem->mp_ctx = pasyncio->mp_ctx;

        if (err || bld->asyncio_lstcnt >= bld->asyncio_max) {
            err1 = _vblock_flush_asynciolist(bld, false);

            if (!err)
                err = err1;
        }
    }

    if (ev(err)) {
        bld->destruct = true;
        return err;
    }

    bld->wbuf_off = 0;

    perfc_inc(bld->pc, PERFC_RA_CNCOMP_WREQS);
    perfc_add(bld->pc, PERFC_RA_CNCOMP_WBYTES, bld->wbuf_len);

    return 0;
}

static merr_t
_vblock_finish(struct vblock_builder *bld)
{
    merr_t err = 0;
    uint   buflen;
    uint   zfill_len;

    if (bld->mbh && bld->wbuf_off) {
        /*
         * c1 may issue media writes before the 1MB buffer
         * gets full. The final write should not exceed
         * the available space in the media.
         */
        zfill_len = bld->wbuf_len - bld->wbuf_off;
        if (zfill_len > _vblock_unused_media_space(bld))
            zfill_len = _vblock_unused_media_space(bld);

        buflen = bld->wbuf_len;
        bld->wbuf_len = bld->wbuf_off + zfill_len;

        memset(bld->wbuf + bld->wbuf_off, 0, zfill_len);

        err = _vblock_write(bld);
        bld->wbuf_len = buflen;
    }

    bld->mbh = 0;

    return err;
}

/* Disable asynchronous mode */
void
vbb_disable_async_mode(struct vblock_builder *bldr)
{
    assert(bldr);
    bldr->asyncio_ctx.mp_enabled = false;
}

/* Create a vblock builder */
merr_t
vbb_create(
    struct vblock_builder **builder_out,
    struct cn *             cn,
    struct perfc_set *      pc,
    u64                     vgroup,
    uint                    flags)
{
    struct vblock_builder *bld;
    struct kvs_rparams *   rp;
    merr_t                 err;
    bool                   ingest;

    assert(builder_out);

    bld = calloc(1, sizeof(*bld));
    if (ev(!bld))
        return merr(ENOMEM);

    ingest = IS_INGEST(flags);
    rp = cn_get_rp(cn);

    bld->cn = cn;
    bld->pc = pc;
    bld->ds = cn_get_dataset(cn);
    bld->flags = flags;
    bld->vgroup = vgroup;
    bld->max_size = rp->vblock_size_mb << 20;
    INIT_LIST_HEAD(&bld->asyncio_head);
    bld->asyncio_ctx.mp_enabled = !cn_get_mblk_sync_writes(cn);
    bld->asyncio_max = rp->vblock_asyncio;
    bld->asyncio_ctxswi = rp->vblock_asyncio_ctxswi;
    bld->asyncio_ingestpool = ingest;
    bld->mclass = MP_MED_CAPACITY;

    bld->wbuf = cn_aio_alloc(bld->cn, WBUF_LEN_MAX, ingest, true);
    if (ev(!bld->wbuf)) {
        free(bld);
        return merr(ENOMEM);
    }

    if (flags & KVSET_BUILDER_FLAGS_EXT) {
        err = vbb_create_ext(bld, rp);
        if (ev(err)) {
            cn_aio_free(bld->cn, bld->wbuf, WBUF_LEN_MAX, ingest);
            free(bld);
            return err;
        }
    }

    *builder_out = bld;

    return 0;
}

/* Destroy a vblock builder. Must also abort any mblocks left behind. */
void
vbb_destroy(struct vblock_builder *bld)
{
    if (ev(!bld))
        return;

    if (bld->asyncio_ctx.mp_enabled)
        _vblock_flush_asynciolist(bld, true);
    abort_mblocks(bld->ds, &bld->vblk_list);
    blk_list_free(&bld->vblk_list);
    cn_aio_free(bld->cn, bld->wbuf, WBUF_LEN_MAX, bld->asyncio_ingestpool);

    if (bld->vbb_ext)
        vbb_destroy_ext(bld);

    free(bld);
}

/* Add a value to vblock.  Create new vblock if needed. */
merr_t
vbb_add_entry(
    struct vblock_builder *bld,
    const void *           vdata,
    uint                   vlen,
    u64 *                  vbidout,
    uint *                 vbidxout,
    uint *                 vboffout)
{
    merr_t err;
    uint   voff, space, bytes;

    assert(!bld->destruct);

    assert(vdata);
    assert(vlen);
    assert(vlen <= HSE_KVS_VLEN_MAX);

    if (unlikely(!_vblock_has_room(bld, vlen))) {
        err = _vblock_finish(bld);
        if (ev(err))
            return err;
    }

    if (unlikely(!bld->mbh)) {
        err = _vblock_start(bld);
        if (ev(err))
            return err;
    }

    assert(bld->mbh);
    assert(_vblock_has_room(bld, vlen));

    voff = 0;

    while (voff < vlen) {

        assert(bld->wbuf_off < bld->wbuf_len);

        /* Copy whatever fits into the write buffer. */
        space = bld->wbuf_len - bld->wbuf_off;
        bytes = vlen - voff;
        if (bytes > space)
            bytes = space;
        memcpy(bld->wbuf + bld->wbuf_off, vdata + voff, bytes);

        bld->wbuf_off += bytes;
        voff += bytes;

        /* Issue write if buffer is full. */
        if (bld->wbuf_off == bld->wbuf_len) {
            err = _vblock_write(bld);
            if (ev(err))
                return err;
        }
    }

    assert(bld->wbuf_off < bld->wbuf_len);

    *vboffout = bld->vblk_off - VBLOCK_HDR_LEN;
    *vbidxout = bld->vblk_list.n_blks - 1;
    *vbidout = bld->vblk_list.blks[*vbidxout].bk_blkid;

    bld->vblk_off += vlen;
    bld->vsize += vlen;

    return 0;
}

/* Close out the current vblock, return IDs of all mblocks allocated so far,
 * and mark the builder as closed for business.
 */
merr_t
vbb_finish(struct vblock_builder *bld, struct blk_list *vblks)
{
    merr_t err;

    assert(!bld->destruct);

    bld->destruct = true;

    err = _vblock_finish(bld);
    if (ev(err))
        return err;

    err = _vblock_flush_asynciolist(bld, true);
    if (ev(err))
        return err;

    /* Transfer ownership of blk_list and the mblocks in
     * the blk_list to caller  */
    *vblks = bld->vblk_list;
    memset(&bld->vblk_list, 0, sizeof(bld->vblk_list));

    return 0;
}

void
vbb_set_mclass(struct vblock_builder *bld, enum mp_media_classp mclass)
{
    bld->mclass = mclass;
}

enum mp_media_classp
vbb_get_mclass(struct vblock_builder *bld)
{
    return bld->mclass;
}

void
vbb_set_merge_stats(struct vblock_builder *bld, struct cn_merge_stats *stats)
{
    bld->mstats = stats;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "vblock_builder_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
