/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_WBT_READER_v5_H
#define HSE_KVS_CN_WBT_READER_v5_H

struct wbti;

bool
wbti6_seek(struct wbti *self, struct kvs_ktuple *seek);

bool
wbti6_next(struct wbti *self, const void **kdata, uint *klen, const void **kmd);

void
wbti6_reset(
    struct wbti *         self,
    struct kvs_mblk_desc *kbd,
    struct wbt_desc *     desc,
    struct kvs_ktuple *   seek,
    bool                  reverse,
    bool                  cache);

merr_t
wbtr6_read_vref(
    const struct kvs_mblk_desc *kbd,
    const struct wbt_desc *     wbd,
    const struct kvs_ktuple *   kt,
    uint                        lcp,
    u64                         seq,
    enum key_lookup_res *       lookup_res,
    struct kvs_vtuple_ref *     vref);

#endif /* HSE_KVS_CN_WBT_READER_v5_H */
