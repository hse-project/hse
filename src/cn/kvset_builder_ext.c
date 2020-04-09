/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kvset_builder
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/limits.h>

#include <hse_ikvdb/c1.h>

#include <hse/hse_limits.h>

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/slab.h>
#include <hse_util/bonsai_tree.h>

#include "kcompact.h"
#include "spill.h"

#include "kblock_builder.h"
#include "vblock_builder.h"
#include "vblock_reader.h"
#include "blk_list.h"
#include "kvset_builder_internal.h"

merr_t
kvset_builder_add_val_ext(
    struct kvset_builder *self,
    u64                   seq,
    const void *          vdata,
    uint                  vlen,
    bool                  wait,
    u8                    index,
    u64 *                 vbidout,
    uint *                vbidxout,
    uint *                vboffout)
{
    merr_t err;
    uint   vbidx = 0, vboff = 0;
    u64    vbid = 0;

    assert(vdata);

    err = vbb_add_entry_ext(self->vbb, vdata, vlen, wait, index, &vbid, &vbidx, &vboff);
    if (err) {
        ev(merr_errno(err) != ENOSPC && merr_errno(err) != EAGAIN);
        return err;
    }

    *vbidout = vbid;
    *vbidxout = vbidx;
    *vboffout = vboff;

    assert(vbb_verify_entry(self->vbb, vbidx, vbid, 0, 0));

    return 0;
}

merr_t
kvset_builder_finish_vblock(struct kvset_builder *self, u8 index)
{
    return vbb_finish_entry(self->vbb, index);
}

merr_t
kvset_builder_flush_vblock(struct kvset_builder *self)
{
    return vbb_flush_entry(self->vbb);
}

void
kvset_builder_get_c0c1vstat(struct kvset_builder *self, u64 *c0_vlen, u64 *c1_vlen)
{
    *c0_vlen = self->key_stats.c0_vlen;
    *c1_vlen = self->key_stats.c1_vlen;
}

merr_t
kvset_builder_get_committed_vblock_count(struct kvset_builder *self, u32 *count)
{
    return vbb_get_committed_vblock_count(self->vbb, count);
}

merr_t
kvset_builder_remove_unused_vblocks(struct kvset_builder *self)
{
    return vbb_remove_unused_vblocks(self->vbb);
}

u32
kvset_builder_vblock_hdr_len(void)
{
    return vbb_vblock_hdr_len();
}

bool
kvset_vbuilder_vblock_exists(
    struct kvset_builder *  self,
    u64                     seq,
    const void *            vdata,
    uint                    vlen,
    struct c1_bonsai_vbldr *vbldr,
    uint *                  vbidx_out,
    uint *                  vboff_out,
    u64 *                   vbid_out)
{
    /*
     * c1's io threads update certain values which are read here.
     */
    smp_mb();
    if (vbldr && (vbldr->cbv_blkvlen == vlen) && (vbldr->cbv_blkval == (u64)vdata)) {
        struct kvset_builder *bldr;

        bldr = vbldr->cbv_bldr;
        assert(bldr);

        *vbid_out = vbldr->cbv_blkid;
        *vbidx_out = bldr->vblk_baseidx + vbldr->cbv_blkidx;
        *vboff_out = vbldr->cbv_blkoff;

        if (vbb_verify_entry(self->vbb, *vbidx_out, *vbid_out, vbldr->cbv_blkoff, vlen)) {
            self->key_stats.c1_vlen += vlen;
            return true;
        }

        hse_log(HSE_ERR "vbb_verify_entry failed");
    }

    return false;
}
