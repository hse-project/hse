/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVMSM_H
#define HSE_CORE_C0_KVMSM_H

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0_kvset.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/slist.h>
#include "c0_kvsetm.h"

struct c0sk_mutation;
struct c0_kvmultiset;
struct c1;

/**
 * struct c0kvmsm_info - c0_kvmultiset mutation info
 * @c0ms_kvbytes:  size of mutation
 * @c0ms_kvpbytes: size of tx pending bytes
 * @c0ms_kvscnt:   number of kvsets mutated
 */
struct c0kvmsm_info {
    u64 c0ms_kvbytes;
    u64 c0ms_kvpbytes;
    u32 c0ms_kvscnt;
};

/**
 * c0kvmsm_switch() - switch the mutation list in all c0kvsets in this kvms.
 * @handle:     kvms on which to operate
 */
void
c0kvmsm_switch(struct c0_kvmultiset *handle);

/**
 * c0kvmsm_ingest() - switch the mutation list in all c0kvsets in this kvms.
 * @handle: kvms on which to operate
 * @c0skm:  c0sk mutation handle
 * @c1h:    c1 handle
 * @gen:    mutation gen. to be persisted
 * @txnseq: max. seqno to be used for transaction mutations
 * @itype:  enum c1_ingest_type
 * final:   set to true if this kvms is cN ingesting
 */
merr_t
c0kvmsm_ingest(
    struct c0_kvmultiset *handle,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    u8                    itype,
    bool                  final,
    struct c0kvmsm_info * info_out,
    struct c0kvmsm_info * txinfo_out);

/**
 * c0kvmsm_reset_mlist() - Reset mutation list
 * @c0kvms: c0kvms handle
 * index:   starting c0kvset index
 */
void
c0kvmsm_reset_mlist(struct c0_kvmultiset *c0kvms, int index);

/**
 * c0kvmsm_has_txpend() - Check whether there are pending transaction mutations
 *                        in this kvms.
 * @c0kvms: kvms handle
 */
bool
c0kvmsm_has_txpend(struct c0_kvmultiset *c0kvms);

/**
 * c0kvmsm_get_info() - Retrive mutation info for the specified kvms.
 * @c0kvms: kvms handle
 * @info:   non-transactional mutation info.
 * @txinfo: transactional mutation info.
 * @active: active/inactive mutation list
 */
void
c0kvmsm_get_info(
    struct c0_kvmultiset *c0kvms,
    struct c0kvmsm_info * info,
    struct c0kvmsm_info * txinfo,
    bool                  active);

#endif /* HSE_CORE_C0_KVMSM_H */
