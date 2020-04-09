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
    u64   c1kvm_vlen;
    u64   c1kvm_vcount;
    char *c1kvm_data;
};

struct c1_vtuple_meta {
    u64   c1vm_sign;
    u64   c1vm_seqno;
    u64   c1vm_vlen;
    u32   c1vm_tomb;
    u32   c1vm_logtype;
    char *c1vm_data;
};

struct c1_mblk_meta {
    u64 c1mblk_id;
    u32 c1mblk_off;
};

merr_t
c1_tree_replay(struct c1 *c1, struct c1_tree *tree);

/* MTF_MOCK */
bool
c1_ingest_kvbundle(u64 ingestid, u64 kvmsgen);

int
c1_tree_kvb_cmp(void *arg1, void *arg2);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_tree_utils_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_TREE_UTILS_H */
