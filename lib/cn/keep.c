/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>

#include "kvset.h"
#include "kcompact.h"

merr_t
kvset_keep_vblocks(
    struct kvset_vblk_map  *vbm,
    struct vgmap          **vgm_out,
    struct kv_iterator    **iv,
    int                     niv)
{
    struct vgmap *vgm = NULL;
    struct kvs_block *blks;
    uint32_t nv, nvg, vgidx;
    size_t sz;
    merr_t err = 0;

    INVARIANT(vbm && vgm_out && iv);

    *vgm_out = NULL;

    nv = 0;
    nvg = 0;
    for (int i = 0; i < niv; ++i) {
        struct kvset *kvset = kvset_from_iter(iv[i]);

        nv += kvset_get_num_vblocks(kvset);
        nvg += kvset_get_vgroups(kvset);
    }

    /* alloc both the vblks and the vbm; 1 free does both */
    sz = nv * sizeof(*vbm->vbm_blkv) + niv * sizeof(*vbm->vbm_map);
    blks = calloc(1, sz);
    if (!blks)
        return merr(ev(ENOMEM));

    if (nvg > 0) {
        vgm = vgmap_alloc(nvg);
        if (!vgm)
            err = merr(ENOMEM);
    } else {
        assert(nv == 0);
        if (nv > 0)
            err = merr(EBUG);
    }

    if (err) {
        free(blks);
        return err;
    }

    vbm->vbm_blkv = blks;
    vbm->vbm_blkc = 0;
    vbm->vbm_map = (u32 *)(blks + nv);
    vbm->vbm_mapc = niv;
    vbm->vbm_used = 0;
    vbm->vbm_waste = 0;
    vbm->vbm_tot = 0;

    /*
     * copy all the vblocks from the set of input iterators to
     * a single copy of vbmap, and create a map from the
     * input kvsets vbindex to their new location in vblks[]
     *
     * vbmap->used tracks the values referenced during compaction
     * vbmap->waste starts as cumulative of what we have before compact,
     * and is updated by drops values during compaction
     *
     * When a kvset is created by other than k-compact, both used
     * and waste start as zero: there is no waste in ingest, kv-compact
     * or spill.  If this node has been previously k-compacted, then
     * waste may be >= 0, and this cycle adds to the waste count.
     */

    nv = 0;
    vgidx = 0;
    for (int i = 0; i < niv; ++i) {
        struct kvset *kvset = kvset_from_iter(iv[i]);
        uint32_t cnt = kvset_get_num_vblocks(kvset);
        uint32_t kvg = 0;

        vbm->vbm_map[i] = nv;

        for (uint32_t j = 0; j < cnt; ++j) {
            blks[nv].bk_blkid = kvset_get_nth_vblock_id(kvset, j);
            vbm->vbm_tot += kvset_get_nth_vblock_len(kvset, j);

            if (j == vgmap_vbidx_out_end(kvset, kvg)) {
                merr_t err;

                assert(vgm);

                /* vgmap_src is passed as NULL as the kblocks are rewritten during k-compact */
                err = vgmap_vbidx_set(NULL, nv, vgm, nv, vgidx);
                if (err) {
                    free(vbm->vbm_blkv);
                    vbm->vbm_blkv = NULL;
                    free(vgm);

                    return err;
                }

                vgidx++;
                kvg++;
            }

            nv++;
        }
        assert(kvg == kvset_get_vgroups(kvset));

        vbm->vbm_blkc += cnt;
    }

    assert(vgidx == nvg);
    assert(vbm->vbm_blkc == nv);

    *vgm_out = vgm;

    return 0;
}
