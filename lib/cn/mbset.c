/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_mbset

#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/minmax.h>
#include <hse/util/event_counter.h>

#include <hse/logging/logging.h>

#include "mbset.h"
#include "kvs_mblk_desc.h"

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
 *      re-creating memory maps, it is more efficient to share the mbset.  As
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
    merr_t err_report = 0, err;
    uint64_t mbid_report = 0, mbid;
    uint count = 0;

    for (uint i = 0; i < self->mbs_mblkc; i++) {
        mbid = self->mbs_mblkv[i].mbid;
        if (mbid) {
            err = mpool_mblock_delete(self->mbs_mp, mbid);
            if (err) {
                count++;
                if (!err_report) {
                    err_report = err;
                    mbid_report = mbid;
                }
            }
        }
    }

    if (err_report)
        log_errx("%u of %u mblocks could not be deleted, mbid 0x%lx",
            err_report, count, self->mbs_mblkc, mbid_report);

    return err_report;
}

static merr_t
mbset_mmap(struct mbset *self, uint idc, uint64_t *idv)
{
    uint64_t alen_pages = 0;
    uint64_t wlen_pages = 0;
    merr_t err;

    self->mbs_mblkc = idc;

    for (uint i = 0; i < idc; i++) {
        err = mblk_mmap(self->mbs_mp, idv[i], &self->mbs_mblkv[i]);
        if (err)
            return err;
        alen_pages += self->mbs_mblkv[i].alen_pages;
        wlen_pages += self->mbs_mblkv[i].wlen_pages;
    }

    self->mbs_alen = alen_pages * PAGE_SIZE;
    self->mbs_wlen = wlen_pages * PAGE_SIZE;

    return 0;
}

static void
mbset_munmap(struct mbset *self)
{
    merr_t err_report = 0, err;
    uint64_t mbid_report = 0, mbid;
    uint count = 0;

    for (uint i = 0; i < self->mbs_mblkc; i++) {
        mbid = self->mbs_mblkv[i].mbid;
        if (mbid) {
            err = mblk_munmap(self->mbs_mp, &self->mbs_mblkv[i]);
            if (err) {
                count++;
                if (!err_report) {
                    err_report = err;
                    mbid_report = mbid;
                }
            }
        }
    }

    if (err_report)
        log_errx("%u of %u mblocks could not be unmapped, mbid 0x%lx",
            err_report, count, self->mbs_mblkc, mbid_report);
}

/**
 * mbset_create() - mbset constructor
 */
merr_t
mbset_create(
    struct mpool *      mp,
    uint                idc,
    uint64_t *          idv,
    size_t              udata_sz,
    mbset_udata_init_fn udata_init,
    struct mbset **     handle)
{
    struct mbset *self;
    size_t        alloc_len;
    merr_t        err;

    if (ev(!mp || !handle || !idv || !idc))
        return merr(EINVAL);

    /* one allocation for:
     * - the mbset struct
     * - array of kvs_mblk_desc
     * - array of udata elements
     */
    alloc_len  = sizeof(*self);
    alloc_len += idc * sizeof(*self->mbs_mblkv);
    alloc_len += idc * udata_sz;

    self = calloc(1, alloc_len);
    if (ev(!self))
        return merr(ENOMEM);

    self->mbs_mblkv = (void *)(self + 1);
    self->mbs_udata = (void *)(self->mbs_mblkv + idc);

    self->mbs_mblkc = idc;
    self->mbs_mp = mp;
    self->mbs_del = false;
    self->mbs_udata_sz = udata_sz;

    err = mbset_mmap(self, idc, idv);
    if (err)
        goto fail;

    for (uint i = 0; i < idc; i++) {
        err = udata_init(&self->mbs_mblkv[i], mbset_get_udata(self, i));
        if (ev(err))
            goto fail;
    }

    atomic_set(&self->mbs_ref, 1);
    *handle = self;

    return 0;

fail:

    mbset_munmap(self);
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

    if (!self)
        return;

    mbset_munmap(self);

    if (self->mbs_del) {
        err = mbset_mblk_del(self);
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

#if HSE_MOCKING
#include "mbset_ut_impl.i"
#endif /* HSE_MOCKING */
