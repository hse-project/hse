/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVMSM_INTERNAL_H
#define HSE_CORE_C0_KVMSM_INTERNAL_H

#include "c0_kvsetm.h"

struct c1_iterinfo;

merr_t
c0kvmsm_ingest_internal(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    u8                    itype,
    struct c0kvmsm_info * info_out,
    struct c0kvmsm_info * txinfo_out);

merr_t
c0kvmsm_ingest_common(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    int *                 ref,
    u64                   txnseq,
    enum c0kvsm_mut_type  type);

void
c0kvmsm_wait(struct c0_kvmultiset *c0kvms, int *ref);

merr_t
c0kvmsm_iterv_alloc(
    struct c0_kvmultiset *     c0kvms,
    u64                        gen,
    bool                       istxn,
    u32                        iterc,
    u16                        nkiter,
    struct perfc_set *         pc,
    struct kvb_builder_iter ***iterv);

void
c0kvmsm_iterv_stats(
    struct c0_kvmultiset *c0kvms,
    struct c1_iterinfo *  ci,
    enum c0kvsm_mut_type  type);

void
c0kvmsm_iter_params_get(struct c0_kvmultiset *c0kvms, u64 *maxkvsz, u16 *nkiter);

#endif /* HSE_CORE_C0_KVMSM_INTERNAL_H */
