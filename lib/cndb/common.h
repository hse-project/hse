/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CNDB_COMMON_H
#define HSE_KVS_CNDB_COMMON_H

struct cndb_kvset {
    uint64_t       ck_cnid;
    uint64_t       ck_kvsetid;
    uint64_t       ck_nodeid;
    uint64_t       ck_dgen_hi;
    uint64_t       ck_dgen_lo;
    uint64_t       ck_vused;
    uint64_t       ck_vgarb;
    uint32_t       ck_compc;
    uint16_t       ck_rule;
    uint64_t       ck_hblkid;
    unsigned int   ck_kblkc;
    unsigned int   ck_vblkc;
    uint64_t      *ck_kblkv;
    uint64_t      *ck_vblkv;
};

#endif
