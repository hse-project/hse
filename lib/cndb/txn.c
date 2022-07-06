/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/list.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <cn/kvset.h>

#include "txn.h"

enum {
    KVSET_ADD,
    KVSET_DEL,
};

struct kvset_rec {
    struct list_head   link;
    int                type;
    bool               acked;
    struct cndb_kvset *kvset;
};

struct cndb_txn {
    struct list_head kvset_list;
    uint64_t         txid;
    uint64_t         seqno;
    uint64_t         ingestid;
    uint64_t         txhorizon;

    /* Expected */
    unsigned int     add_cnt;
    unsigned int     del_cnt;

    /* Seen */
    unsigned int     add_cnt_seen;
    unsigned int     del_cnt_seen;
    unsigned int     add_ack_cnt_seen;
    unsigned int     del_ack_cnt_seen;

};

merr_t
cndb_txn_create(
    uint64_t         txid,
    uint64_t         seqno,
    uint64_t         ingestid,
    uint64_t         txhorizon,
    uint16_t         add_cnt,
    uint16_t         del_cnt,
    struct cndb_txn **tx_out)
{
    struct cndb_txn *tx;

    tx = calloc(1, sizeof(*tx));
    if (ev(!tx))
        return merr(ENOMEM);

    tx->txid = txid;
    tx->seqno = seqno;
    tx->ingestid = ingestid;
    tx->txhorizon = txhorizon;
    tx->add_cnt = add_cnt;
    tx->del_cnt = del_cnt;

    INIT_LIST_HEAD(&tx->kvset_list);

    *tx_out = tx;
    return 0;
}

uint64_t
cndb_txn_txid_get(struct cndb_txn *tx)
{
    return tx->txid;
}

void
cndb_txn_destroy(struct cndb_txn *tx)
{
    struct kvset_rec *rec, *next;

    list_for_each_entry_safe(rec, next, &tx->kvset_list, link) {
        free(rec);
    }

    free(tx);
}

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
    void             **cookie)
{
    struct kvset_rec *rec;
    struct cndb_kvset *kvset;
    int i;

    assert(!tx->del_cnt_seen);
    assert(!tx->add_ack_cnt_seen);
    assert(!tx->del_ack_cnt_seen);

    rec = malloc(sizeof(*rec));
    kvset = malloc(sizeof(*kvset) + (kblkc + vblkc) * sizeof(uint64_t));
    if (ev(!rec || !kvset)) {
        free(rec);
        free(kvset);
        return merr(ENOMEM);
    }

    rec->type = KVSET_ADD;
    rec->acked = false;
    rec->kvset = kvset;

    kvset->ck_kblkv = (void *)(kvset + 1);
    kvset->ck_vblkv = kvset->ck_kblkv + kblkc;

    kvset->ck_cnid = cnid;
    kvset->ck_nodeid = nodeid;
    kvset->ck_kvsetid = kvsetid;
    kvset->ck_hblkid = hblkid;
    kvset->ck_dgen = km->km_dgen;
    kvset->ck_vused = km->km_vused;
    kvset->ck_compc = km->km_compc;
    kvset->ck_comp_rule = km->km_comp_rule;

    kvset->ck_kblkc = kblkc;
    for (i = 0; i < kblkc; i++)
        kvset->ck_kblkv[i] = kblkv[i];

    kvset->ck_vblkc = vblkc;
    for (i = 0; i < vblkc; i++)
        kvset->ck_vblkv[i] = vblkv[i];

    ++tx->add_cnt_seen;
    list_add_tail(&rec->link, &tx->kvset_list);

    if (cookie)
        *cookie = rec;

    return 0;
}

merr_t
cndb_txn_kvset_del(
    struct cndb_txn    *tx,
    uint64_t           cnid,
    uint64_t           kvsetid,
    void             **cookie)
{
    struct kvset_rec *rec;
    struct cndb_kvset *kvset;

    assert(!tx->add_ack_cnt_seen);
    assert(!tx->del_ack_cnt_seen);

    rec = malloc(sizeof(*rec));
    kvset = calloc(1, sizeof(*kvset));
    if (ev(!rec || !kvset)) {
        free(rec);
        free(kvset);
        return merr(ENOMEM);
    }

    rec->type = KVSET_DEL;
    rec->acked = false;
    rec->kvset = kvset;

    rec->kvset->ck_cnid = cnid;
    rec->kvset->ck_kvsetid = kvsetid;

    ++tx->del_cnt_seen;
    list_add_tail(&rec->link, &tx->kvset_list);

    if (cookie)
        *cookie = rec;

    return 0;
}

merr_t
cndb_txn_apply(struct cndb_txn *tx, cndb_txn_cb *cb, void *cb_rock)
{
    struct kvset_rec *rec;
    merr_t err = 0;

    list_for_each_entry(rec, &tx->kvset_list, link) {
        merr_t err1 = cb(tx, rec->kvset, rec->type == KVSET_ADD, rec->acked, cb_rock);
        if (ev(err1))
            err = err ? : err1;
    }

    return err;
}

merr_t
cndb_txn_ack(struct cndb_txn *tx, void *cookie, struct cndb_kvset **kvset_out)
{
    struct kvset_rec *rec = cookie;

    assert(rec);
    assert(!cndb_txn_is_complete(tx));

    rec->acked = true;

    if (rec->type == KVSET_ADD) {
        assert(tx->add_cnt_seen);
        assert (!tx->del_ack_cnt_seen);

        tx->add_ack_cnt_seen++;
    } else {
        assert(tx->del_cnt_seen);
        assert(tx->add_ack_cnt_seen == tx->add_cnt_seen);

        tx->del_ack_cnt_seen++;
    }

    if (kvset_out)
        *kvset_out = rec->kvset;

    return 0;
}

merr_t
cndb_txn_ack_by_kvsetid(struct cndb_txn *tx, uint64_t kvsetid, struct cndb_kvset **kvset_out)
{
    struct kvset_rec *rec;

    assert(!cndb_txn_is_complete(tx));

    list_for_each_entry(rec, &tx->kvset_list, link) {
        if (!rec->acked && rec->kvset->ck_kvsetid == kvsetid)
            break;
    }

    assert(rec);
    if (ev(!rec))
        return merr(ENOENT);

    return cndb_txn_ack(tx, rec, kvset_out);
}

bool
cndb_txn_needs_rollback(struct cndb_txn *tx)
{
    /* Check for empty transaction. */
    if (HSE_UNLIKELY(tx->add_cnt_seen + tx->del_cnt_seen == 0))
        return true;

    /* Check if all intent records are found. */
    if (tx->del_cnt_seen != tx->del_cnt)
        return true;

    return tx->add_ack_cnt_seen < tx->add_cnt_seen;
}

bool
cndb_txn_can_rollforward(struct cndb_txn *tx)
{
    return tx->add_cnt_seen == tx->add_ack_cnt_seen;
}

bool
cndb_txn_is_complete(struct cndb_txn *tx)
{
    return tx->add_cnt_seen + tx->del_cnt_seen == tx->add_ack_cnt_seen + tx->del_ack_cnt_seen;
}

void
cndb_txn_cnt_get(struct cndb_txn *tx, uint16_t *add_cnt, uint16_t *del_cnt)
{
    *add_cnt = tx->add_cnt;
    *del_cnt = tx->del_cnt;
}
