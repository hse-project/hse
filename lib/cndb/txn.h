/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CNDB_TXN_H
#define HSE_KVS_CNDB_TXN_H

#include <stdbool.h>
#include <stdint.h>

#include <hse/error/merr.h>

#include "common.h"

struct cndb_txn;
struct kvset_meta;

merr_t
cndb_txn_create(
    uint64_t         txid,
    uint64_t         seqno,
    uint64_t         ingestid,
    uint64_t         txhorizon,
    uint16_t         add_cnt,
    uint16_t         del_cnt,
    struct cndb_txn **tx_out);

uint64_t
cndb_txn_txid_get(struct cndb_txn *tx);

void
cndb_txn_destroy(struct cndb_txn *tx);

merr_t
cndb_txn_kvset_add(
    struct cndb_txn    *tx,
    uint64_t           cnid,
    uint64_t           kvsetid,
    uint64_t           nodeid,
    struct kvset_meta *km,
    uint64_t           hblkid,
    size_t             kblkc,
    uint64_t          *kblkv,
    size_t             vblkc,
    uint64_t          *vblkv,
    void             **cookie);

merr_t
cndb_txn_kvset_del(
    struct cndb_txn    *tx,
    uint64_t           cnid,
    uint64_t           kvsetid,
    void             **cookie);

typedef merr_t
cndb_txn_cb(struct cndb_txn *, struct cndb_kvset *, bool, bool, void *);

merr_t
cndb_txn_apply(struct cndb_txn *tx, cndb_txn_cb *cb, void *cb_rock);

merr_t
cndb_txn_ack(struct cndb_txn *tx, void *cookie, struct cndb_kvset **kvset_out);

merr_t
cndb_txn_ack_by_kvsetid(struct cndb_txn *tx, uint64_t kvsetid, struct cndb_kvset **kvset_out);

bool
cndb_txn_needs_rollback(struct cndb_txn *tx);

bool
cndb_txn_can_rollforward(struct cndb_txn *tx);

bool
cndb_txn_is_complete(struct cndb_txn *tx);

void
cndb_txn_cnt_get(struct cndb_txn *tx, uint16_t *add_cnt, uint16_t *del_cnt);

#endif
