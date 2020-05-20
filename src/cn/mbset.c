/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#define MTF_MOCK_IMPL_mbset

#include "mbset.h"

/*
 * An "mbset" is a reference counted set of mblocks with associated object
 * handles, mbcache maps and user data.  They enable multiple kvsets to share
 * a set of mblocks.  They are currently used by kvsets for vblocks since
 * vblocks can be shared by multiple kvsets as described below.  Kblocks are
 * never shared, so they don't need to be in mbsets, but they will likely be
 * moved into mbsets in the future to reduce the overall amount of code.
 *
 * Currently (early 2018), each kvset has an "mbset' containing:
 *   - vblocks
 *   - one handle for each vblock (for use with mpool_mblock_read)
 *   - one or more mcache maps (more than one if kvset has many vblocks)
 *   - a vblock descriptor for each vblock (this is the "user data")
 *
 * Mbsets can be shared by multiple kvsets after k-compaction operations as
 * follows:
 *   1. Consider two kvsets, S1 and S2.
 *   2. Suppose kvset S1 has one mbset M1, and kvset S2 has one mbset M2.
 *   3. Start k-compaction operation on kvsets S1 and S2.
 *   4. Cursor update operation takes a ref on kvset S1.
 *   5. k-compaction completes, creating kvset S3.
 *   6. Recall k-compaction passes vblocks from input to output.  Instead of
 *      re-creating mcache maps, it is more efficient to share the mbset.  As
 *      such, kvset S3 takes a ref on mbset M1 and M2, and then drops refs on
 *      S1 and S2.
 *   7. S2 is destroyed, but S1 lingers because the cursor is using it.
 *
 * At this point, M1 has two refs: one from S1 (which exists only to support
 * the cursor), and one from S3.  M2 has one ref from S3.
 *
 * Now suppose S3 is kv-compacted while the cursor is still active:
 *   8. When S3 kv-compaction completes:
 *      - S4 is created with all new mbsets,
 *      - the vblocks that were part of S3 are marked for deletion, and
 *      - the ref on S3 is dropped.
 *   9. Vblocks in M2 can now be unmapped and deleted because there are no
 *      more refs on M2.
 *   10. M1 must persist until the cursor is destroyed, at which time its
 *       vblocks can be unmapped and deleted.
 *
 * This is wny mbsets exist.
 *
 * Most of the code here is straight-forward.  The tricky part is the
 * interaction between the kvset and the mbset in the destructors to support
 * deleting mblocks that have been marked for deletion.  See
 * mbset_set_callback() adn mbset_put_ref() for details.
 */

/**
 * _mbset_mblk_getprops() - get mblock propertie3s for each mblock in the mbset
 *
 * Used by mbset constructor.
 */
static merr_t
_mbset_mblk_getprops(struct mbset *self, mbset_udata_init_fn *cb)
{
    merr_t err = 0;
    u64 *  argv;
    uint   argc;
    uint   i;

    /* Create some scratch space for the callback.  Currrently only used
     * by vblock_udata_init() to compute the number of vgroups.
     */
    argc = 0;
    argv = malloc(sizeof(*argv) * (self->mbs_idc + 1));
    if (ev(!argv))
        return merr(ENOMEM);

    self->mbs_alen = 0;
    self->mbs_wlen = 0;

    for (i = 0; i < self->mbs_idc; i++) {

        struct mblock_props props;

        err = mpool_mblock_props_get(self->mbs_ds, self->mbs_idv[i], &props);
        if (ev(err))
            break;

        if (cb) {
            err = cb(self, i, &argc, argv, &props, mbset_get_udata(self, i));
            if (ev(err))
                break;
        }

        self->mbs_alen += props.mpr_alloc_cap;
        self->mbs_wlen += props.mpr_write_len;
    }

    free(argv);

    return err;
}

void
mbset_apply(struct mbset *self, mbset_udata_init_fn *cb, uint *argcp, u64 *argv)
{
    uint i;

    if (!self || !cb)
        return;

    for (i = 0; i < self->mbs_idc; i++)
        cb(self, i, argcp, argv, NULL, mbset_get_udata(self, i));
}

/**
 * _mbset_mblk_del() - delete mblocks
 *
 * Used by mbset destructor if mblocks have been marked for deletion.
 *
 * Stop deleting mblocks on the fist sign of trouble and let CNDB finish
 * deleting them during recovery.  We could continue to delete remaining
 * mblocks here, but a delete failure might be indicative of a serious error,
 * and stopping immediately would do less harm.
 */
static merr_t
_mbset_mblk_del(struct mbset *self)
{
    merr_t err;
    uint   i;

    for (i = 0; i < self->mbs_idc; i++) {
        if (self->mbs_idv[i]) {
            err = mpool_mblock_delete(self->mbs_ds, self->mbs_idv[i]);
            if (ev(err))
                return err;
        }
    }
    return 0;
}

/**
 * _mbset_map() - create mcache maps
 *
 * Used by mbset constructor.
 */
static merr_t
_mbset_map(struct mbset *self, uint flags)
{
    enum mpc_vma_advice advice;

    merr_t err = 0;
    uint   mx = 0;
    uint   idc = self->mbs_idc;
    u64 *  idv = self->mbs_idv;

    /* Root spill uses mcache. Mcache pages belonging to the root node
     * vblocks are tagged as hot. This ensures that these pages are reaped
     * as a last resort by the mcache reaper, helping spill performance.
     */
    advice = (flags & MBSET_FLAGS_VBLK_ROOT) ? MPC_VMA_HOT : MPC_VMA_COLD;

    while (idc > 0) {
        uint cnt = min_t(uint, idc, self->mbs_mblock_max);

        assert(mx < self->mbs_mapc);
        err = mpool_mcache_mmap(self->mbs_ds, cnt, idv, advice, self->mbs_mapv + mx++);
        if (ev(err))
            break;
        idc -= cnt;
        idv += cnt;
    }

    return err;
}

/**
 * _mbset_unmap() - destroy mcache maps
 *
 * Used by mbset destructor.
 */
static void
_mbset_unmap(struct mbset *self)
{
    merr_t err;
    uint   i;

    for (i = 0; i < self->mbs_mapc; i++) {
        if (self->mbs_mapv[i]) {
            err = mpool_mcache_munmap(self->mbs_mapv[i]);
            ev(err);
        }
    }
}

/**
 * mbset_create() - mbset constructor
 */
merr_t
mbset_create(
    struct mpool *      ds,
    uint                idc,
    u64 *               idv,
    size_t              udata_sz,
    mbset_udata_init_fn udata_init_fn,
    uint                flags,
    u64                 mblock_max,
    struct mbset **     handle)
{
    struct mbset *self;
    size_t        alloc_len;
    merr_t        err;
    uint          mapc;

    if (!ds || !handle || !idv || !idc)
        return merr(ev(EINVAL));

    /* number of mcache maps needed */
    mapc = (idc + mblock_max - 1) / mblock_max;

    /* one allocation for:
     * - the mbset struct
     * - array of mblock ids
     * - array of mcache_map ptrs
     * - array of udata structs
     */
    alloc_len =
        (sizeof(*self) + sizeof(*self->mbs_idv) * idc +
         sizeof(*self->mbs_mapv) * mapc + udata_sz * idc);

    self = calloc(1, alloc_len);
    if (!self)
        return merr(ev(ENOMEM));

    self->mbs_idv = (void *)(self + 1);
    self->mbs_mapv = (void *)(self->mbs_idv + idc);
    self->mbs_udata = (void *)(self->mbs_mapv + mapc);

    assert(((void *)self) + alloc_len == (void *)(self->mbs_udata + idc * udata_sz));

    memcpy(self->mbs_idv, idv, sizeof(*idv) * idc);

    self->mbs_mapc = mapc;
    self->mbs_idc = idc;
    self->mbs_ds = ds;
    self->mbs_del = false;
    self->mbs_udata_sz = udata_sz;
    self->mbs_mblock_max = mblock_max;

    err = _mbset_map(self, flags);
    if (ev(err))
        goto fail;

    /* Must have mapped mblocks prior to this b/c the udata
     * callback uses the maps */
    err = _mbset_mblk_getprops(self, udata_init_fn);
    if (ev(err))
        goto fail;

    atomic_set(&self->mbs_ref, 1);
    *handle = self;
    return 0;

fail:
    _mbset_unmap(self);
    free(self);
    return err;
}

/**
 * _mbset_destroy() - mbset destructor
 */
static void
_mbset_destroy(struct mbset *self, bool *delete_errors)
{
    merr_t err = 0;

    if (ev(!self))
        return;

    _mbset_unmap(self);
    if (self->mbs_del) {
        err = _mbset_mblk_del(self);
        ev(err);
        *delete_errors = !!err;
    } else {
        *delete_errors = false;
    }

    free(self);
}

struct mbset *
mbset_get_ref(struct mbset *self)
{
    int v __maybe_unused;

    v = atomic_inc_return(&self->mbs_ref);
    assert(v > 1);

    return self;
}

void
mbset_put_ref(struct mbset *self)
{
    bool            delete_errors = false;
    mbset_callback *callback;
    void *          rock;
    int             v;

    v = atomic_dec_return(&self->mbs_ref);

    assert(v >= 0);

    if (v == 0) {
        callback = self->mbs_callback;
        rock = self->mbs_callback_rock;
        _mbset_destroy(self, &delete_errors);
        if (callback)
            callback(rock, delete_errors);
    }
}

/**
 * mbset_set_callback() - configure callback to be invoked by mbset destructor
 *
 * The callback is invoked with a boolean parameter indicating if there were
 * any errors deleting mblock that were marked for deletion.
 */
void
mbset_set_callback(struct mbset *self, mbset_callback *callback, void *rock)
{
    assert(!self->mbs_callback);
    self->mbs_callback = callback;
    self->mbs_callback_rock = rock;
}

void
mbset_set_delete_flag(struct mbset *self)
{
    self->mbs_del = true;
}

void
mbset_madvise(struct mbset *self, int advice)
{
    size_t len = SIZE_MAX;
    merr_t err;
    uint   i;

    for (i = 0; i < self->mbs_mapc; ++i) {
        err = mpool_mcache_madvise(self->mbs_mapv[i], 0, 0, len, advice);
        ev(err);
    }
}

void
mbset_purge(struct mbset *self, const struct mpool *ds)
{
    merr_t err;
    uint   i;

    for (i = 0; i < self->mbs_mapc; ++i) {
        err = mpool_mcache_purge(self->mbs_mapv[i], ds);
        ev(err);
    }
}

merr_t
mbset_mincore(struct mbset *self, size_t *rss_out, size_t *vss_out)
{
    uint i;

    if (ev(!self || (!rss_out && !vss_out)))
        return merr(EINVAL);

    if (rss_out)
        *rss_out = 0;

    if (vss_out)
        *vss_out = 0;

    for (i = 0; i < self->mbs_mapc; ++i) {
        merr_t err;
        size_t rss;
        size_t vss;

        rss = 0;
        vss = 0;

        err = mpool_mcache_mincore(self->mbs_mapv[i], self->mbs_ds, &rss, &vss);
        if (ev(err))
            return err;

        if (rss_out)
            *rss_out += rss;

        if (vss_out)
            *vss_out += vss;
    }

    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "mbset_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
