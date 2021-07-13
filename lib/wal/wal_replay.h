/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_REPLAY_H
#define WAL_REPLAY_H

#include <hse_util/hse_err.h>

struct wal;
struct wal_replay_info;

struct wal_replay_gen_info {
    struct wal_minmax_info info;
    char *buf;
    uint64_t gen;
    off_t soff;
    off_t eoff;
    size_t size;
    uint fileid;
    bool info_valid;
};

struct wal_rec_hdr {
    u64 off;
    u32 cksum;
    u32 flags;
    u64 rid;
    u64 gen;
    u32 type;
    u32 len;
};

struct wal_rec {
    struct rb_node     node;
    struct wal_rec_hdr hdr;
    u64                cnid;
    u64                txid;
    u64                seqno;
    u32                op;
    struct kvs_ktuple  kt;
    struct kvs_vtuple  vt;
};


merr_t
wal_replay(struct wal *wal, struct wal_replay_info *rinfo);

#endif /* WAL_REPLAY_H */
