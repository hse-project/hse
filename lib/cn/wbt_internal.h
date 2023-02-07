/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_CN_WBT_INTERNAL_H
#define HSE_KVS_CN_WBT_INTERNAL_H

#include <stdint.h>
#include <sys/types.h>

#include "kvs_mblk_desc.h"

#include <hse/util/compiler.h>
#include <hse/util/byteorder.h>

#include "omf.h"

static HSE_ALWAYS_INLINE const struct wbt_lfe_omf *
wbt_lfe(const struct wbt_node_hdr_omf *node, int nth)
{
    const struct wbt_lfe_omf *p = (void *)node + sizeof(*node) + omf_wbn_pfx_len(node);

    return p + nth;
}

static HSE_ALWAYS_INLINE void
wbt_node_pfx(const struct wbt_node_hdr_omf *node, const void **pfx, uint *pfx_len)
{
    *pfx_len = omf_wbn_pfx_len(node);
    *pfx = (void *)node + sizeof(*node);
}

static HSE_ALWAYS_INLINE void
wbt_lfe_key(
    const struct wbt_node_hdr_omf *node,
    const struct wbt_lfe_omf *lfe,
    const void **kdata,
    uint *klen)
{
    uint start, end;

    /* Add 4 if lfe_kmd == UINT16_MAX, else add 0. */
    start = omf_lfe_koff(lfe) + 4 * (omf_lfe_kmd(lfe) == UINT16_MAX);

    /* prefetch key data */
    __builtin_prefetch((void *)node + start);

    /* end == one byte past end of key. */
    end = (lfe == wbt_lfe(node, 0) ? WBT_NODE_SIZE : omf_lfe_koff(lfe - 1));

    *klen = end - start;
    *kdata = (void *)node + start;
}

static HSE_ALWAYS_INLINE uint32_t
wbt_lfe_kmd(const struct wbt_node_hdr_omf *node, const struct wbt_lfe_omf *lfe)
{
    uint32_t kmd_off = omf_lfe_kmd(lfe);

    /* Offset stored in front of key when its too large for 16-bits */
    if (kmd_off == UINT16_MAX) {
        const uint32_t *p = (void *)node + omf_lfe_koff(lfe);

        kmd_off = omf32_to_cpu(*p);
    }

    return omf_wbn_kmd(node) + kmd_off;
}

static HSE_ALWAYS_INLINE const struct wbt_ine_omf *
wbt_ine(const struct wbt_node_hdr_omf *node, int nth)
{
    const struct wbt_ine_omf *p = (void *)node + sizeof(*node) + omf_wbn_pfx_len(node);

    return p + nth;
}

static HSE_ALWAYS_INLINE void
wbt_ine_key(
    const struct wbt_node_hdr_omf *node,
    const struct wbt_ine_omf *ine,
    const void **kdata,
    uint *klen)
{
    uint start, end;

    /* start of key */
    start = omf_ine_koff(ine);

    /* end of key */
    end = (ine == wbt_ine(node, 0) ? WBT_NODE_SIZE : omf_ine_koff(ine - 1));

    *kdata = (void *)node + start;
    *klen = end - start;
}

#endif /* HSE_KVS_CN_WBT_INTERNAL_H */
