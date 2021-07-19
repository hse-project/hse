/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_REPLAY_H
#define WAL_REPLAY_H

#include <hse_util/hse_err.h>
#include <hse_util/spinlock.h>

struct wal;
struct wal_replay_info;

struct wal_replay_gen_info {
    spinlock_t     txmlock HSE_ALIGNED(SMP_CACHE_BYTES);
    struct rb_root txmroot;

    struct wal_minmax_info info HSE_ALIGNED(SMP_CACHE_BYTES);
    char *buf;
    uint64_t gen;
    off_t soff;
    off_t eoff;
    off_t rgeoff;
    size_t size;
    uint fileid;
    bool info_valid;
};

struct wal_rechdr {
    u64 off;
    u32 cksum;
    u32 flags;
    u64 rid;
    u64 gen;
    u32 type;
    u32 len;
};

struct wal_rec {
    struct rb_node    node;
    struct wal_rechdr hdr;
    u64               cnid;
    u64               txid;
    u64               seqno;
    u32               op;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
};

struct wal_txmeta_rec {
    struct rb_node node;
    u64            rid;
    u64            txid;
    u64            cseqno;
    u64            gen;
};

merr_t
wal_replay(struct wal *wal, struct wal_replay_info *rinfo);

#endif /* WAL_REPLAY_H */
