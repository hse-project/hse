/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CNDUMP_CNDB_RECORD_H
#define CNDUMP_CNDB_RECORD_H

#include <stdint.h>
#include <stdbool.h>

#include <hse/limits.h>

#include <hse/ikvdb/kvs_cparams.h>
#include <hse/util/compiler.h>

#include "cndb/omf.h"
#include "cn/kvset.h"

struct cndb_rec_version {
    uint16_t version;
    uint32_t magic;
    uint64_t size;
};

struct cndb_rec_meta {
    uint64_t seqno;
};

struct cndb_rec_kvs_add {
    struct kvs_cparams cp;
    uint64_t cnid;
    char name[HSE_KVS_NAME_LEN_MAX];
};

struct cndb_rec_kvs_del {
    uint64_t cnid;
};

struct cndb_rec_txstart {
    uint64_t txid;
    uint64_t seqno;
    uint64_t ingestid;
    uint64_t txhorizon;
    uint16_t add_cnt;
    uint16_t del_cnt;
};

struct cndb_rec_kvset_add {
    struct kvset_meta km;
    uint64_t txid;
    uint64_t cnid;
    uint64_t kvsetid;
    uint64_t nodeid;
    uint64_t hblkid;
    uint64_t *kblkv;
    uint64_t *vblkv;
    uint32_t kblkc;
    uint32_t vblkc;
};

struct cndb_rec_kvset_del {
    uint64_t txid;
    uint64_t cnid;
    uint64_t kvsetid;
};

struct cndb_rec_kvset_move {
    uint64_t cnid;
    uint64_t src_nodeid;
    uint64_t tgt_nodeid;
    uint32_t kvset_idc;
    uint64_t *kvset_idv;
};

struct cndb_rec_ack {
    uint64_t txid;
    uint64_t cnid;
    uint64_t kvsetid;
    uint ack_type;
};

struct cndb_rec_nak {
    uint64_t txid;
};

struct cndb_rec {
    size_t len;
    enum cndb_rec_type type;
    void *buf;
    size_t bufsz;
    union {
        struct cndb_rec_version version;
        struct cndb_rec_meta meta;
        struct cndb_rec_kvs_add kvs_add;
        struct cndb_rec_kvs_del kvs_del;
        struct cndb_rec_txstart txstart;
        struct cndb_rec_kvset_add kvset_add;
        struct cndb_rec_kvset_del kvset_del;
        struct cndb_rec_kvset_move kvset_move;
        struct cndb_rec_ack ack;
        struct cndb_rec_nak nak;
    } rec;
};

const char *
cndb_rec_type_name(enum cndb_rec_type rtype)
    HSE_RETURNS_NONNULL;

void
cndb_rec_init(struct cndb_rec *rec);

void
cndb_rec_clone(struct cndb_rec *rec, struct cndb_rec *clone);

void
cndb_rec_fini(struct cndb_rec *rec);

void
cndb_rec_resize(struct cndb_rec *rec, size_t reclen);

void
cndb_rec_parse(struct cndb_rec *rec);

void
cndb_rec_print(const struct cndb_rec *rec, bool oneline);

#endif
