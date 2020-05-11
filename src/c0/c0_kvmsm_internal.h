/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVMSM_INTERNAL_H
#define HSE_CORE_C0_KVMSM_INTERNAL_H

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
c0kvmsm_ingest_nontx(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    int *                 ref);

merr_t
c0kvmsm_ingest_tx(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    int *                 txnref,
    u64                   txnid);

merr_t
c0kvmsm_ingest_common(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    int *                 ref,
    u64                   txnseq,
    bool                  istxn);

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

#endif /* HSE_CORE_C0_KVMSM_INTERNAL_H */
