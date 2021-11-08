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
    spinlock_t     txm_lock HSE_ACP_ALIGNED;
    struct rb_root txm_root;
    struct rb_root txcid_root;

    struct wal_minmax_info info HSE_L1D_ALIGNED;
    char *buf;
    uint64_t gen;
    off_t soff;
    off_t eoff;
    size_t size;
    uint32_t fileid;
    bool info_valid;
};

struct wal_rechdr {
    uint64_t off;
    uint32_t cksum;
    uint32_t flags;
    uint64_t rid;
    uint64_t gen;
    uint32_t type;
    uint32_t len;
};

struct wal_rec {
    struct rb_node    node;
    struct wal_rechdr hdr;
    uint64_t          cnid;
    uint64_t          txid;
    uint64_t          seqno;
    uint32_t          op;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
};

struct wal_txmeta_rec {
    struct rb_node node;
    struct rb_node cid_node;
    uint64_t       rid;
    uint64_t       txid;
    uint64_t       cseqno;
    uint64_t       cid;
    uint64_t       gen;
    off_t          fileoff;
};

merr_t
wal_replay(struct wal *wal, struct wal_replay_info *rinfo);

#endif /* WAL_REPLAY_H */
