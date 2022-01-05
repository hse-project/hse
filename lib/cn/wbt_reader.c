/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/mman.h>
#include <hse_util/atomic.h>
#include <hse_util/event_counter.h>

#include <hse/limits.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/omf_kmd.h>

#include "wbt_internal.h"
#include "kvs_mblk_desc.h"
#include "kblock_reader.h"

/* omf version specific includes */
#include "wbt_reader_v6.h"

#define MTF_MOCK_IMPL_wbt_reader
#include "wbt_reader.h"

/*
 * This file should contain no wbt omf specific code.
 */

static struct kmem_cache *wbti_cache HSE_READ_MOSTLY;

void
wbt_read_kmd_vref(const void *kmd, size_t *off, u64 *seq, struct kvs_vtuple_ref *vref)
{
    enum kmd_vtype vtype;
    uint           vbidx = 0;
    uint           vboff = 0;
    uint           vlen = 0;
    uint           complen = 0;
    const void *   vdata = 0;

    kmd_type_seq(kmd, off, &vtype, seq);

    switch (vtype) {
        case vtype_val:
            kmd_val(kmd, off, &vbidx, &vboff, &vlen);
            /* assert no truncation */
            assert(vbidx <= U16_MAX);
            assert(vboff <= U32_MAX);
            assert(vlen <= U32_MAX);
            vref->vb.vr_index = vbidx;
            vref->vb.vr_off = vboff;
            vref->vb.vr_len = vlen;
            vref->vb.vr_complen = 0;
            break;
        case vtype_cval:
            kmd_cval(kmd, off, &vbidx, &vboff, &vlen, &complen);
            /* assert no truncation */
            assert(vbidx <= U16_MAX);
            assert(vboff <= U32_MAX);
            assert(vlen <= U32_MAX);
            assert(complen <= U32_MAX);
            vref->vb.vr_index = vbidx;
            vref->vb.vr_off = vboff;
            vref->vb.vr_len = vlen;
            vref->vb.vr_complen = complen;
            break;
        case vtype_ival:
            kmd_ival(kmd, off, &vdata, &vlen);
            /* assert no truncation */
            assert(vlen <= U32_MAX);
            vref->vi.vr_data = vdata;
            vref->vi.vr_len = vlen;
            break;
        case vtype_zval:
        case vtype_tomb:
        case vtype_ptomb:
            break;
    }

    vref->vr_type = vtype;
}

bool
wbti_seek(struct wbti *self, struct kvs_ktuple *seek)
{
    switch (self->wbd->wbd_version) {
        case WBT_TREE_VERSION:
            return wbti6_seek(self, seek);
    }

    assert(self->wbd->wbd_version == WBT_TREE_VERSION);
    return false;
}

bool
wbti_next(struct wbti *self, const void **kdata, uint *klen, const void **kmd)
{
    switch (self->wbd->wbd_version) {
        case WBT_TREE_VERSION:
            return wbti6_next(self, kdata, klen, kmd);
    }

    assert(self->wbd->wbd_version == WBT_TREE_VERSION);
    return false;
}

void
wbti_reset(
    struct wbti *         self,
    struct kvs_mblk_desc *kbd,
    struct wbt_desc *     desc,
    struct kvs_ktuple *   seek,
    bool                  reverse,
    bool                  cache)
{
    switch (desc->wbd_version) {
        case WBT_TREE_VERSION:
            wbti6_reset(self, kbd, desc, seek, reverse, cache);
            break;
        default:
            assert(desc->wbd_version == WBT_TREE_VERSION);
            break;
    }
}

merr_t
wbti_alloc(struct wbti **wbti_out)
{
    struct wbti *self;

    self = kmem_cache_alloc(wbti_cache);
    if (ev(!self))
        return merr(ENOMEM);

    *wbti_out = self;

    return 0;
}

merr_t
wbti_create(
    struct wbti **        wbti_out,
    struct kvs_mblk_desc *kbd,
    struct wbt_desc *     desc,
    struct kvs_ktuple *   seek,
    bool                  reverse,
    bool                  cache)
{
    struct wbti *self = NULL;
    merr_t       err;

    err = wbti_alloc(&self);
    if (ev(err))
        return err;

    wbti_reset(self, kbd, desc, seek, reverse, cache);

    *wbti_out = self;
    return 0;
}

void
wbti_destroy(struct wbti *self)
{
    kmem_cache_free(wbti_cache, self);
}

void
wbti_prefix(struct wbti *self, const void **pfx, uint *pfx_len)
{
    switch (self->wbd->wbd_version) {
        case WBT_TREE_VERSION:
            wbt_node_pfx(self->node, pfx, pfx_len);
            break;
        default:
            assert(self->wbd->wbd_version == WBT_TREE_VERSION);
            break;
    }
}

merr_t
wbtr_read_vref(
    const struct kvs_mblk_desc *kbd,
    const struct wbt_desc *     wbd,
    const struct kvs_ktuple *   kt,
    uint                        lcp,
    u64                         seq,
    enum key_lookup_res *       lookup_res,
    struct kvs_vtuple_ref *     vref)
{
    switch (wbd->wbd_version) {
        case WBT_TREE_VERSION:
            return wbtr6_read_vref(kbd, wbd, kt, lcp, seq, lookup_res, vref);
    }

    assert(wbd->wbd_version == WBT_TREE_VERSION);
    return merr(ev(EBUG));
}

merr_t
wbti_init(void)
{
    struct kmem_cache *zone;

    zone = kmem_cache_create("wbti", sizeof(struct wbti), 0, SLAB_HWCACHE_ALIGN, NULL);
    if (ev(!zone))
        return merr(ENOMEM);

    wbti_cache = zone;

    return 0;
}

void
wbti_fini(void)
{
    kmem_cache_destroy(wbti_cache);
    wbti_cache = NULL;
}

#if HSE_MOCKING
#include "wbt_reader_ut_impl.i"
#endif /* HSE_MOCKING */
