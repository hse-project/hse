/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_TXN_H
#define HSE_C1_TXN_H

struct c1_ttxn {
    u64 c1t_ingestid;
    u64 c1t_segno;
    u64 c1t_gen;
    u64 c1t_txnid;
    u32 c1t_cmd;
    u32 c1t_flag;
};

struct c1_treetxn {
    struct list_head c1txn_list;
    u64              c1txn_seqno;
    u64              c1txn_gen;
    u64              c1txn_id;
    u64              c1txn_ingestid;
    u64              c1txn_mutation;
    u32              c1txn_cmd;
    u32              c1txn_flag;
};

#endif /* HSE_C1_TXN_H */
