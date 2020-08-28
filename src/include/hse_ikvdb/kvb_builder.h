/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_KVB_BUILDER_H
#define HSE_CORE_KVB_BUILDER_H

#include <hse_ikvdb/kvs.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/slist.h>

/* MTF_MOCK_DECL(kvb_builder) */

struct c0_kvmultiset;
struct c0_kvset;
struct c1;
struct c1_kvcache;
struct c1_kvbundle;
struct c0kvsm_info;
struct c1_kvset_builder_elem;

/**
 * struct kvb_builder_iter - c0 key-value mutation iterator
 * @kvbi_c0skm:    c0sk mutation handle
 * @kvbi_c0kvms:   kvms handle
 * @kvbi_c1h:      c1 handle
 * @kvbi_kvcache:  c1 kv cache handle
 * @kvbi_info:     kvset mutation info.
 * @kvbi_ingestid: ingest id
 * @kvbi_vbldr:    ptr to vbuilder
 * @kvbi_bldrelm:
 * @kvbi_kvbc:     kv bundle count
 * @kvbi_ref:      reference count
 * @kvbi_ksize:    size of keys mutated
 * @kvbi_vsize:    size of values mutated
 * @get_next:      Returns the next key-value bundle
 * @put:           Releases an iterator
 */
struct kvb_builder_iter {
    struct c0sk_mutation *        kvbi_c0skm;
    struct c0_kvmultiset *        kvbi_c0kvms;
    struct c1 *                   kvbi_c1h;
    struct c1_kvcache *           kvbi_kvcache;
    struct c0kvsm_info *          kvbi_info;
    u64                           kvbi_ingestid;
    void *                        kvbi_vbldr;
    struct c1_kvset_builder_elem *kvbi_bldrelm;
    u64                           kvbi_kvbc;
    int *                         kvbi_ref;
    u64                           kvbi_ksize;
    u64                           kvbi_vsize;

    merr_t (*get_next)(struct kvb_builder_iter *iter, struct c1_kvbundle **kvb);
    void (*put)(struct kvb_builder_iter *iter);

} __aligned(SMP_CACHE_BYTES);

/*
 * kvb_builder_iter_alloc() -
 * @kvmsgen: kvms generation number
 * @gen:     mutation generation
 * @istxn:   tx or non-tx iter
 * @pc:      perfc handle
 * @iter:    iterator handle (output)
 */
merr_t
kvb_builder_iter_alloc(
    u64                       kvmsgen,
    u64                       gen,
    bool                      istxn,
    u16                       cpi,
    struct perfc_set *        pc,
    struct kvb_builder_iter **iter);

/*
 * kvb_builder_iter_init() -
 * @iter:   iterator handle
 * @c0skm:  c0sk mutation handle
 * @c0kvms: c0 kvmultiset handle
 * @c1h:    c1 handle
 * @ref:    number of c0_kvsets ingested into c1 mlogs
 * @istxn:  txn or non-tx iterator
 */
void
kvb_builder_iter_init(
    struct kvb_builder_iter *iter,
    struct c0sk_mutation *   c0skm,
    struct c0_kvmultiset *   c0kvms,
    struct c1 *              c1h,
    int *                    ref,
    u64                      ksize,
    u64                      vsize,
    bool                     istxn);

/*
 * kvb_builder_iter_put() -
 * @iter: iterator handle
 */
/* MTF_MOCK */
void
kvb_builder_iter_put(struct kvb_builder_iter *iter);

/*
 * kvb_builder_iter_destroy() -
 * @iter: iterator handle
 * @pc:   perfc handle
 */
void
kvb_builder_iter_destroy(struct kvb_builder_iter *iter, struct perfc_set *pc);

/*
 * kvb_builder_iter_istxn() -
 * @iter: iterator handle
 */
bool
kvb_builder_iter_istxn(struct kvb_builder_iter *iter);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "kvb_builder_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_CORE_KVB_BUILDER_H */
