/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_TREE_UTILS_H
#define HSE_TREE_UTILS_H

/* MTF_MOCK_DECL(c1_tree_utils) */

struct c1_kvtuple_meta {
    u64   c1kvm_sign;
    u64   c1kvm_klen;
    u64   c1kvm_cnid;
    u64   c1kvm_xlen;
    u64   c1kvm_vcount;
    char *c1kvm_data;
};

struct c1_vtuple_meta {
    u64   c1vm_sign;
    u64   c1vm_seqno;
    u64   c1vm_xlen;
    u32   c1vm_tomb;
    u32   c1vm_logtype;
    char *c1vm_data;
};

struct c1_mblk_meta {
    u64 c1mblk_id;
    u32 c1mblk_off;
};

static __always_inline uint
c1_kvtuple_meta_vlen(const struct c1_kvtuple_meta *kvtm)
{
    uint clen = kvtm->c1kvm_xlen >> 32;
    uint vlen = kvtm->c1kvm_xlen & 0xfffffffful;

    return clen ?: vlen;
}

static __always_inline uint
c1_vtuple_meta_vlen(const struct c1_vtuple_meta *vtm)
{
    uint clen = vtm->c1vm_xlen >> 32;
    uint vlen = vtm->c1vm_xlen & 0xfffffffful;

    return clen ?: vlen;
}

merr_t
c1_tree_replay(struct c1 *c1, struct c1_tree *tree);

/* MTF_MOCK */
bool
c1_should_replay(u64 cningestid, u64 c1ingestid);

int
c1_tree_kvb_cmp(void *arg1, void *arg2);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_tree_utils_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_TREE_UTILS_H */
