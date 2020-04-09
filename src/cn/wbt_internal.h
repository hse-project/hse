/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_WBT_INTERNAL_H
#define HSE_KVS_CN_WBT_INTERNAL_H

#include "kvs_mblk_desc.h"

#include <hse_util/inttypes.h>
#include <hse_util/byteorder.h>

#include "omf.h"

/*
 * Current version - Version 5
 */

static __always_inline struct wbt_lfe_omf *
wbt_lfe(void *node, int nth)
{
    uint                hdr_sz = sizeof(struct wbt_node_hdr_omf);
    struct wbt_lfe_omf *p = node + hdr_sz + omf_wbn_pfx_len(node);

    return p + nth;
}

static __always_inline void
wbt_node_pfx(void *node, const void **pfx, uint *pfx_len)
{
    *pfx_len = omf_wbn_pfx_len(node);
    *pfx = node + sizeof(struct wbt_node_hdr_omf);
}

static __always_inline void
wbt_lfe_key(void *node, struct wbt_lfe_omf *lfe, const void **kdata, uint *klen)
{
    uint start, end;

    /* Add 4 if lfe_kmd == U16_MAX, else add 0. */
    start = omf_lfe_koff(lfe) + 4 * (omf_lfe_kmd(lfe) == U16_MAX);

    /* prefetch key data */
    __builtin_prefetch(node + start);

    /* end == one byte past end of key. */
    end = (lfe == wbt_lfe(node, 0) ? WBT_NODE_SIZE : omf_lfe_koff(lfe - 1));

    *klen = end - start;
    *kdata = node + start;
}

static __always_inline uint
wbt_lfe_kmd(void *node, struct wbt_lfe_omf *lfe)
{
    u32 *p;
    uint kmd_off = omf_lfe_kmd(lfe);

    /* Offset stored in front of key when its too large for 16-bits */
    if (kmd_off == U16_MAX) {
        p = node + omf_lfe_koff(lfe);
        kmd_off = le32_to_cpu(*p);
    }

    return omf_wbn_kmd(node) + kmd_off;
}

static __always_inline struct wbt_ine_omf *
wbt_ine(void *node, int nth)
{
    uint                hdr_sz = sizeof(struct wbt_node_hdr_omf);
    struct wbt_ine_omf *p = node + hdr_sz + omf_wbn_pfx_len(node);

    return p + nth;
}

static __always_inline void
wbt_ine_key(void *node, struct wbt_ine_omf *ine, const void **kdata, uint *klen)
{
    uint start, end;

    /* start of key */
    start = omf_ine_koff(ine);

    /* end of key */
    end = (ine == wbt_ine(node, 0) ? WBT_NODE_SIZE : omf_ine_koff(ine - 1));

    *kdata = node + start;
    *klen = end - start;
}

/*
 * Version 4
 */
static __always_inline struct wbt_lfe_omf *
wbt4_lfe(void *node, int nth)
{
    uint                hdr_sz = sizeof(struct wbt4_node_hdr_omf);
    struct wbt_lfe_omf *p = node + hdr_sz;

    return p + nth;
}

static __always_inline void
wbt4_node_pfx(void *node, const void **pfx, uint *pfx_len)
{
    *pfx_len = 0;
    *pfx = NULL;
}

static __always_inline void
wbt4_lfe_key(void *node, struct wbt_lfe_omf *lfe, const void **kdata, uint *klen)
{
    uint start, end;

    /* Add 4 if lfe_kmd == U16_MAX, else add 0. */
    start = omf_lfe_koff(lfe) + 4 * (omf_lfe_kmd(lfe) == U16_MAX);

    /* prefetch key data */
    __builtin_prefetch(node + start);

    /* end == one byte past end of key. */
    end = (lfe == wbt4_lfe(node, 0) ? WBT_NODE_SIZE : omf_lfe_koff(lfe - 1));

    *klen = end - start;
    *kdata = node + start;
}

static __always_inline struct wbt_ine_omf *
wbt4_ine(void *node, int nth)
{
    uint                hdr_sz = sizeof(struct wbt4_node_hdr_omf);
    struct wbt_ine_omf *p = node + hdr_sz;

    return p + nth;
}

static __always_inline void
wbt4_ine_key(void *node, struct wbt_ine_omf *ine, const void **kdata, uint *klen)
{
    uint start, end;

    /* start of key */
    start = omf_ine_koff(ine);

    /* end of key */
    end = (ine == wbt4_ine(node, 0) ? WBT_NODE_SIZE : omf_ine_koff(ine - 1));

    *kdata = node + start;
    *klen = end - start;
}

#endif
