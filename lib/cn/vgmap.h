/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_CN_VGMAP_H
#define HSE_CN_VGMAP_H

#include <stdint.h>

/**
 * struct vgmap - vgroup map
 *
 * Vblock indexes are stored with keys in a kvset's kblocks and are used to identify
 * which vblock in the kvset's list of vblocks holds a key's value. A vgroup map is
 * associated with a kvset and is used to convert these indexes so they reference the
 * correct vblock. This conversion is only necessary with kvsets that have been
 * split because kvset split changes the vblock list but does not update the vblock
 * indexes stored in the kblocks.
 *
 * The last vblock index from each vgroup is stored in vbidx_out.
 *
 * In the case of a split kvset where the kblocks are not rewritten, a source vblock
 * index stored in its kblocks needs to be adjusted to obtain the correct output
 * vblock index. This index adjust value is stored in vbidx_adj.
 *
 * vbidx_src is memory-resident and it exists purely for efficient vbidx conversion.
 *
 * The nvgroups, vbidx_out and vbidx_adj for each kvset are persisted in its hblock.
 *
 * Each kvset must contain a vgroup map. A vgroup map is established during all the
 * different types of maintenance operations. However, queries and compaction
 * operations consult a kvset's vgmap only if that kvset is a result of a split
 * operation (flagged by setting a boolean in struct kvset).
 *
 * A vgroup map is also written for a kvset with zero vblocks with nvgroups as 0
 * and w/o any vblock index mappings.
 */
struct vgmap {
    uint32_t  nvgroups;  /* number of vgroups */
    uint16_t *vbidx_out; /* array of output indexes (indexes the vblock list in a kvset) */
    uint16_t *vbidx_adj; /* array of index adjust offsets */
    uint16_t *vbidx_src; /* array of source indexes (vblock index recorded in the kblocks) */
};

#endif
