/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVB_BUILDER_INTERNAL_H
#define HSE_KVB_BUILDER_INTERNAL_H

merr_t
kvb_builder_get_next(struct kvb_builder_iter *iter, struct c1_kvbundle **ckvb);

merr_t
kvb_builder_kvtuple_add(
    struct kvb_builder_iter *iter,
    struct bonsai_kv *       bkv,
    struct c1_kvbundle *     kvb,
    u64 *                    kvlen,
    struct c1_kvtuple **     ckvt);

merr_t
kvb_builder_vtuple_add(
    struct kvb_builder_iter *iter,
    struct bonsai_kv *       bkv,
    struct c1_kvtuple *      ckvt,
    u64 *                    vlen,
    u64 *                    minseqno,
    u64 *                    maxseqno);

#endif /* HSE_KVB_BUILDER_INTERNAL_H */
