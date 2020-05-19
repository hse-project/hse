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
kvset_keep_vblocks(struct kvset_vblk_map *vbm, struct kv_iterator **iv, int niv)
{
    int               i, j, nv;
    int               nbytes;
    struct kvs_block *blks;

    nv = 0;
    for (i = 0; i < niv; ++i)
        nv += kvset_get_num_vblocks(kvset_from_iter(iv[i]));

    /* alloc both the vblks and the vbm; 1 free does both */
    nbytes = nv * sizeof(*vbm->vbm_blkv) + niv * sizeof(*vbm->vbm_map);
    blks = calloc(1, nbytes);
    if (!blks)
        return merr(ev(ENOMEM));

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
    for (i = 0; i < niv; ++i) {
        struct kvset *kvset = kvset_from_iter(iv[i]);
        int           cnt = kvset_get_num_vblocks(kvset);

        vbm->vbm_map[i] = nv;
        for (j = 0; j < cnt; ++j) {
            blks[nv].bk_blkid = kvset_get_nth_vblock_id(kvset, j);
            vbm->vbm_tot += kvset_get_nth_vblock_len(kvset, j);
            nv++;
        }
        vbm->vbm_blkc += cnt;
    }

    assert(vbm->vbm_blkc == nv);

    return 0;
}
