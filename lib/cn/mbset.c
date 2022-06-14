/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>

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
 *   - an mcache map handle
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
 * mbset_mblk_getprops() - get mblock properties for each mblock in the mbset
 *
 * Used by mbset constructor.
 */
static merr_t
mbset_mblk_getprops(struct mbset *self, mbset_udata_init_fn *cb)
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

        err = mpool_mblock_props_get(self->mbs_mp, self->mbs_idv[i], &props);
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
 * mbset_mblk_del() - delete mblocks
 *
 * Used by mbset destructor if mblocks have been marked for deletion.
 *
 * Stop deleting mblocks on the fist sign of trouble and let CNDB finish
 * deleting them during recovery.  We could continue to delete remaining
 * mblocks here, but a delete failure might be indicative of a serious error,
 * and stopping immediately would do less harm.
 */
static merr_t
mbset_mblk_del(struct mbset *self)
{
    merr_t err;
    uint   i;

    for (i = 0; i < self->mbs_idc; i++) {
        if (self->mbs_idv[i]) {
            err = mpool_mblock_delete(self->mbs_mp, self->mbs_idv[i]);
            if (ev(err))
                return err;
        }
    }
    return 0;
}

/**
 * mbset_map() - create mcache maps
 *
 * Used by mbset constructor.
 */
static merr_t
mbset_map(struct mbset *self, uint flags)
{
    return mpool_mcache_mmap(self->mbs_mp, self->mbs_idc, self->mbs_idv, &self->mbs_map);
}

/**
 * mbset_unmap() - destroy mcache maps
 *
 * Used by mbset destructor.
 */
static void
mbset_unmap(struct mbset *self)
{
    mpool_mcache_munmap(self->mbs_map);
}

/**
 * mbset_create() - mbset constructor
 */
merr_t
mbset_create(
    struct mpool *      mp,
    uint                idc,
    u64 *               idv,
    size_t              udata_sz,
    mbset_udata_init_fn udata_init_fn,
    uint                flags,
    struct mbset **     handle)
{
    struct mbset *self;
    size_t        alloc_len;
    merr_t        err;

    if (!mp || !handle || !idv || !idc)
        return merr(ev(EINVAL));

    /* one allocation for:
     * - the mbset struct
     * - array of mblock ids
     * - array of udata structs
     */
    alloc_len = sizeof(*self) + (sizeof(*self->mbs_idv) * idc) + (udata_sz * idc);

    self = calloc(1, alloc_len);
    if (!self)
        return merr(ev(ENOMEM));

    self->mbs_idv = (void *)(self + 1);
    self->mbs_udata = (void *)(self->mbs_idv + idc);

    assert(((void *)self) + alloc_len == (void *)(self->mbs_udata + idc * udata_sz));

    memcpy(self->mbs_idv, idv, sizeof(*idv) * idc);

    self->mbs_idc = idc;
    self->mbs_mp = mp;
    self->mbs_del = false;
    self->mbs_udata_sz = udata_sz;

    err = mbset_map(self, flags);
    if (ev(err))
        goto fail;

    /* Must have mapped mblocks prior to this b/c the udata
     * callback uses the maps */
    err = mbset_mblk_getprops(self, udata_init_fn);
    if (ev(err))
        goto fail;

    atomic_set(&self->mbs_ref, 1);
    *handle = self;

    return 0;

fail:
    mbset_unmap(self);
    free(self);

    return err;
}

/**
 * mbset_destroy() - mbset destructor
 */
static void
mbset_destroy(struct mbset *self, bool *delete_errors)
{
    merr_t err = 0;

    if (ev(!self))
        return;

    mbset_unmap(self);
    if (self->mbs_del) {
        err = mbset_mblk_del(self);
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
    int v HSE_MAYBE_UNUSED;

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
        mbset_destroy(self, &delete_errors);
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
    merr_t err;

    err = mpool_mcache_madvise(self->mbs_map, 0, 0, SIZE_MAX, advice);
    ev(err);
}

#if HSE_MOCKING
#include "mbset_ut_impl.i"
#endif /* HSE_MOCKING */
