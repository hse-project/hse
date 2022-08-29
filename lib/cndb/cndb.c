/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cndb

#include <hse/logging/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse_util/platform.h>
#include <hse_util/map.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>

#include <bsd/string.h>

#include <cn/kvset.h>
#include <cn/kvset_internal.h>

#include "txn.h"
#include "omf.h"
#include "common.h"

struct cndb_cn {
    uint64_t            cnid;
    struct map         *kvset_map;
    struct kvs_cparams  cp;
    char                name[HSE_KVS_NAME_LEN_MAX];
};

struct cndb {
    struct mutex         mutex;
    uint16_t             cndb_version;

    uint64_t             seqno_max;
    uint64_t             ingestid_max;
    uint64_t             txhorizon_max;

    /* Tables */
    struct map          *tx_map;
    struct map          *cn_map;

    bool                 replaying;
    bool                 rdonly;

    /* Mpool and mdc. */
    struct mpool     *mp;
    struct mpool_mdc *mdc;
    uint64_t          cndb_captgt;
    uint64_t          oid1;
    uint64_t          oid2;

    /* Current id values */
    uint64_t         txid_curr;
    uint64_t         kvsetid_curr;
    uint64_t         nodeid_curr;
    uint64_t         cnid_curr;
};

merr_t
cndb_create(struct mpool *mp, size_t size, uint64_t *oid1_out, uint64_t *oid2_out)
{
    struct mpool_mdc *mdc;
    uint64_t oid1, oid2;
    merr_t err;
    int mc;

    /* Try staging followed by capacity */
    for (mc = HSE_MCLASS_STAGING; mc >= HSE_MCLASS_BASE; mc--) {
        if (mpool_mclass_is_configured(mp, mc))
            break;
    }

    if (mc < HSE_MCLASS_BASE) {
        /* Check for a pmem-only config before returning ENOENT */
        mc = HSE_MCLASS_PMEM;
        if (!mpool_mclass_is_configured(mp, mc))
            return merr(ENOENT);
    }

    err = mpool_mdc_alloc(mp, CNDB_MAGIC, size, mc, &oid1, &oid2);
    if (ev(err))
        return err;

    err = mpool_mdc_commit(mp, oid1, oid2);
    if (ev(err))
        goto errout;

    err = mpool_mdc_open(mp, oid1, oid2, false, &mdc);
    if (ev(err))
        goto errout;

    err = cndb_omf_ver_write(mdc, size);
    if (ev(err)) {
        mpool_mdc_close(mdc);
        goto errout;
    }

    err = cndb_omf_meta_write(mdc, 0);
    if (ev(err)) {
        mpool_mdc_close(mdc);
        goto errout;
    }

    err = mpool_mdc_close(mdc);
    if (ev(err))
        goto errout;

    *oid1_out = oid1;
    *oid2_out = oid2;

errout:
    if (err)
        mpool_mdc_delete(mp, oid1, oid2);

    return err;
}

merr_t
cndb_destroy(struct mpool *mp, uint64_t oid1, uint64_t oid2)
{
    return mpool_mdc_delete(mp, oid1, oid2);
}

merr_t
cndb_open(struct mpool *mp, uint64_t oid1, uint64_t oid2, bool rdonly, struct cndb **cndb_out)
{
    struct cndb *cndb;
    merr_t err;

    cndb = calloc(1, sizeof(*cndb));
    if (ev(!cndb))
        return merr(EINVAL);

    mutex_init(&cndb->mutex);
    cndb->mp = mp;

    cndb->seqno_max = 0;
    cndb->ingestid_max = 0;
    cndb->txhorizon_max = 0;
    cndb->replaying = false;
    cndb->rdonly = rdonly;

    cndb->tx_map = map_create(1024);
    cndb->cn_map = map_create(HSE_KVS_COUNT_MAX);
    if (ev(!cndb->tx_map || !cndb->cn_map)) {
        map_destroy(cndb->tx_map);
        map_destroy(cndb->cn_map);
        err = merr(ENOMEM);
        goto err_out;
    }

    err = mpool_mdc_open(mp, oid1, oid2, rdonly, &cndb->mdc);
    if (ev(err)) {
        map_destroy(cndb->tx_map);
        map_destroy(cndb->cn_map);
        goto err_out;
    }

    *cndb_out = cndb;

    return 0;

err_out:
    free(cndb);

    return err;
}

static void
cndb_cn_destroy(uint64_t key, uintptr_t val)
{
    struct cndb_cn *cn = (void *)val;
    struct cndb_kvset *kvset;
    struct map_iter kvset_iter;

    map_iter_init(&kvset_iter, cn->kvset_map);
    while (map_iter_next_val(&kvset_iter, &kvset))
        free(kvset);

    map_destroy(cn->kvset_map);
    free(cn);
}

static merr_t
cndb_txn_free_cb(struct cndb_txn *tx, struct cndb_kvset *kvset, bool isadd, bool isacked, void *ctx)
{
    /* For an add record, if the txn is rollforward-able then do not free `kvset' as its
     * ownership is with the kvset map.
     */
    if (!isadd || !cndb_txn_can_rollforward(tx))
        free(kvset);

    return 0;
}

merr_t
cndb_close(struct cndb *cndb)
{
    merr_t err;
    struct map_iter it;
    struct cndb_txn *tx;

    if (ev(!cndb))
        return 0;

    err = mpool_mdc_close(cndb->mdc);
    if (ev(err))
        return err;

    map_iter_init(&it, cndb->tx_map);
    while (map_iter_next_val(&it, &tx)) {
        cndb_txn_apply(tx, &cndb_txn_free_cb, NULL);
        cndb_txn_destroy(tx);
    }
    map_destroy(cndb->tx_map);

    map_apply(cndb->cn_map, cndb_cn_destroy);
    map_destroy(cndb->cn_map);

    free(cndb);

    return 0;
}

uint
cndb_kvs_count(struct cndb *cndb)
{
    uint cnt;

    mutex_lock(&cndb->mutex);
    cnt = map_count_get(cndb->cn_map);
    mutex_unlock(&cndb->mutex);

    return cnt;
}

merr_t
cndb_kvs_info(
    struct cndb         *cndb,
    void                *cb_ctx,
    cndb_kvs_callback   *cb)
{
    struct cndb_cn *cn;
    struct map_iter cniter;

    map_iter_init(&cniter, cndb->cn_map);
    while (map_iter_next_val(&cniter, &cn)) {
        merr_t err;

        err = cb(cn->cnid, &cn->cp, cn->name, cb_ctx);
        if (ev(err))
            return err;
    }

    return 0;
}

static bool
cndb_needs_compaction(struct cndb *cndb)
{
    merr_t err;
    uint64_t size, allocated, used, hwm;

    err = mpool_mdc_usage(cndb->mdc, &size, &allocated, &used);
    if (ev(err))
        return false;

    hwm = (4 * size) / 5;

    return used > hwm;
}

static merr_t
cndb_record_kvs_add_inner(
    struct cndb              *cndb,
    const struct kvs_cparams *cp,
    uint64_t                 *cnid,
    bool                      generate_cnid,
    const char               *name)
{
    struct cndb_cn *cn;
    struct map_iter cniter;
    merr_t err = 0;

    mutex_lock(&cndb->mutex);

    map_iter_init(&cniter, cndb->cn_map);

    while (map_iter_next_val(&cniter, &cn)) {
        if (strncmp(cn->name, name, sizeof(cn->name)) == 0) {
            mutex_unlock(&cndb->mutex);
            return merr(EEXIST);
        }
    }

    if (generate_cnid)
        *cnid = ++cndb->cnid_curr;

    mutex_unlock(&cndb->mutex);

    cn = calloc(1, sizeof(*cn));
    if (ev(!cn))
        return merr(ENOMEM);

    cn->cnid = *cnid;
    cn->cp = *cp;

    /* [HSE_REVISIT] Instead remove sfx_len altogether, also from mongo.
     */
    cn->cp.sfx_len = 0;

    strlcpy(cn->name, name, NELEM(cn->name));

    cn->kvset_map = map_create(HSE_KVS_COUNT_MAX);
    if (ev(!cn->kvset_map)) {
        free(cn);
        return merr(ENOMEM);
    }

    mutex_lock(&cndb->mutex);

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }
    }

    err = map_insert_ptr(cndb->cn_map, cn->cnid, cn);
    if (ev(err))
        goto out;

    if (!cndb->replaying) {
        err = cndb_omf_kvs_add_write(cndb->mdc, cn->cnid, &cn->cp, cn->name);
        if (ev(err))
            goto out;
    }

out:
    mutex_unlock(&cndb->mutex);

    if (err) {
        map_remove(cndb->cn_map, cn->cnid, NULL);
        free(cn);
    }

    return err;
}

merr_t
cndb_record_kvs_add(
    struct cndb              *cndb,
    const struct kvs_cparams *cp,
    uint64_t                 *cnid_out,
    const char               *name)
{
    return cndb_record_kvs_add_inner(cndb, cp, cnid_out, true, name);
}

merr_t
cndb_record_kvs_del(struct cndb *cndb, uint64_t cnid)
{
    struct cndb_cn *cn;
    merr_t err = 0;

    mutex_lock(&cndb->mutex);

    cn = map_remove_ptr(cndb->cn_map, cnid);
    if (ev(!cn)) {
        err = merr(ENOENT);
        goto out;
    }

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }

        err = cndb_omf_kvs_del_write(cndb->mdc, cn->cnid);
        if (ev(err))
            goto out;
    }

out:
    mutex_unlock(&cndb->mutex);

    if (cn)
        cndb_cn_destroy(cn->cnid, (uintptr_t)cn);

    return err;
}

static merr_t
cndb_record_txstart_inner(
    struct cndb       *cndb,
    uint64_t           seqno,
    uint64_t           ingestid,
    uint64_t           txhorizon,
    uint16_t           add_cnt,
    uint16_t           del_cnt,
    uint64_t           txid,
    struct cndb_txn  **tx_out)
{
    struct cndb_txn *tx = 0;
    merr_t err = 0;

    mutex_lock(&cndb->mutex);

    txid = txid ?: ++cndb->txid_curr;

    err = cndb_txn_create(txid, seqno, ingestid, txhorizon, add_cnt, del_cnt, &tx);
    if (ev(err)) {
        mutex_unlock(&cndb->mutex);
        return err;
    }

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }
    }

    err = map_insert_ptr(cndb->tx_map, txid, tx);
    if (ev(err))
        goto out;

    if (!cndb->replaying) {
        err = cndb_omf_txstart_write(cndb->mdc, txid, seqno, ingestid, txhorizon, add_cnt, del_cnt);
        if (ev(err))
            goto out;
    }

    cndb->seqno_max = seqno > cndb->seqno_max ? seqno : cndb->seqno_max;

    if (ingestid != CNDB_INVAL_INGESTID)
        cndb->ingestid_max = ingestid > cndb->ingestid_max ? ingestid : cndb->ingestid_max;

    if (txhorizon != CNDB_INVAL_HORIZON)
        cndb->txhorizon_max = txhorizon > cndb->txhorizon_max ? txhorizon : cndb->txhorizon_max;

out:
    mutex_unlock(&cndb->mutex);

    if (err) {
        map_remove(cndb->tx_map, cndb_txn_txid_get(tx), NULL);
        cndb_txn_destroy(tx);
    } else if (tx_out) {
        *tx_out = tx;
    }

    return err;
}

merr_t
cndb_record_txstart(
    struct cndb      *cndb,
    uint64_t          seqno,
    uint64_t          ingestid,
    uint64_t          txhorizon,
    uint32_t          add_cnt,
    uint32_t          del_cnt,
    struct cndb_txn **tx_out)
{
    if (add_cnt > UINT16_MAX || del_cnt > UINT16_MAX)
        return merr(EINVAL);

    return cndb_record_txstart_inner(cndb, seqno, ingestid, txhorizon,
                                     (uint16_t)add_cnt, (uint16_t)del_cnt, 0, tx_out);
}

/* [HSE_REVISIT] Do this inside cndb_record_kvset_add() and output the kvsetid to the caller.
 */
uint64_t
cndb_kvsetid_mint(struct cndb *cndb)
{
    uint64_t id;

    mutex_lock(&cndb->mutex);
    id = ++cndb->kvsetid_curr;
    mutex_unlock(&cndb->mutex);

    return id;
}

uint64_t
cndb_nodeid_mint(struct cndb *cndb)
{
    uint64_t id;

    mutex_lock(&cndb->mutex);
    id = ++cndb->nodeid_curr;
    mutex_unlock(&cndb->mutex);

    return id;
}

merr_t
cndb_record_kvset_add(
    struct cndb       *cndb,
    struct cndb_txn   *tx,
    uint64_t           cnid,
    uint64_t           nodeid,
    struct kvset_meta *km,
    uint64_t           kvsetid,
    uint64_t           hblkid,
    unsigned int       kblkc,
    uint64_t          *kblkv,
    unsigned int       vblkc,
    uint64_t          *vblkv,
    void             **cookie)
{
    merr_t err = 0;

    mutex_lock(&cndb->mutex);

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }
    }

    err = cndb_txn_kvset_add(tx, cnid, kvsetid, nodeid, km, hblkid, kblkc, kblkv,
                             vblkc, vblkv, cookie);
    if (ev(err))
        goto out;

    if (!cndb->replaying)
        err = cndb_omf_kvset_add_write(cndb->mdc, cndb_txn_txid_get(tx), cnid, kvsetid, nodeid,
                                       km->km_dgen, km->km_vused, km->km_compc, km->km_rule,
                                       hblkid, kblkc, kblkv, vblkc, vblkv);
out:
    mutex_unlock(&cndb->mutex);

    return err;
}

merr_t
cndb_record_kvset_del(
    struct cndb     *cndb,
    struct cndb_txn *tx,
    uint64_t         cnid,
    uint64_t         kvsetid,
    void           **cookie)
{
    merr_t err;

    mutex_lock(&cndb->mutex);

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }
    }

    err = cndb_txn_kvset_del(tx, cnid, kvsetid, cookie);
    if (ev(err))
        goto out;

    if (!cndb->replaying)
        err = cndb_omf_kvset_del_write(cndb->mdc, cndb_txn_txid_get(tx), cnid, kvsetid);

out:
    mutex_unlock(&cndb->mutex);

    return err;
}

static merr_t
process_finished_add_txn_cb(
    struct cndb_txn   *tx,
    struct cndb_kvset *kvset,
    bool               isadd,
    bool               isacked,
    void              *ctx)
{
    struct cndb *cndb = ctx;
    struct cndb_cn *cn;

    if (!isadd)
        return 0;

    cn = map_lookup_ptr(cndb->cn_map, kvset->ck_cnid);
    if (ev(!cn))
        return merr(EPROTO);

    /* These kvsets will be handed off to the cn's kvset table, do not free.
     */
    return map_insert_ptr(cn->kvset_map, kvset->ck_kvsetid, kvset);
}

static merr_t
process_finished_del_txn_cb(
    struct cndb_txn   *tx,
    struct cndb_kvset *kvset,
    bool               isadd,
    bool               isacked,
    void              *ctx)
{
    struct cndb *cndb = ctx;
    struct cndb_cn *cn;
    struct cndb_kvset *delme;
    merr_t err = 0;

    if (isadd)
        return 0;

    cn = map_lookup_ptr(cndb->cn_map, kvset->ck_cnid);
    if (ev(!cn)) {
        err = merr(EPROTO);
        goto errout;
    }

    /* Delete the old kvset from the cn's kvset tables and free it. Also free the kvset object
     * that was passed in.
     */
    delme = map_remove_ptr(cn->kvset_map, kvset->ck_kvsetid);
    if (ev(!delme)) {
        err = merr(EPROTO);
        goto errout;
    }

    free(delme);

errout:
    free(kvset);

    return err;
}

static merr_t
cndb_record_kvset_ack_cmn(struct cndb *cndb, struct cndb_txn *tx, uint ack_type, uintptr_t cookie)
{
    merr_t err = 0;
    struct cndb_kvset *kvset;
    uint64_t txid = cndb_txn_txid_get(tx);

    mutex_lock(&cndb->mutex);

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }
    }

    err = cndb->replaying ? cndb_txn_ack_by_kvsetid(tx, (uint64_t)cookie, &kvset) :
                            cndb_txn_ack(tx, (void *)cookie, &kvset);
    if (ev(err))
        goto out;

    if (!cndb->replaying) {
        err = cndb_omf_ack_write(cndb->mdc, txid, kvset->ck_cnid, ack_type, kvset->ck_kvsetid);
        if (ev(err))
            goto out;
    }

    if (ack_type == CNDB_ACK_TYPE_ADD && cndb_txn_can_rollforward(tx))
        err = cndb_txn_apply(tx, &process_finished_add_txn_cb, cndb);

    if (cndb_txn_is_complete(tx)) {
        if (ack_type == CNDB_ACK_TYPE_DEL)
            err = cndb_txn_apply(tx, &process_finished_del_txn_cb, cndb);

        map_remove(cndb->tx_map, txid, NULL);
        cndb_txn_destroy(tx);
    }

out:
    mutex_unlock(&cndb->mutex);

    return err;
}

merr_t
cndb_record_kvset_add_ack(struct cndb *cndb, struct cndb_txn *tx, void *cookie)
{
    return cndb_record_kvset_ack_cmn(cndb, tx, CNDB_ACK_TYPE_ADD, (uintptr_t)cookie);
}

merr_t
cndb_record_kvset_del_ack(struct cndb *cndb, struct cndb_txn *tx, void *cookie)
{
    return cndb_record_kvset_ack_cmn(cndb, tx, CNDB_ACK_TYPE_DEL, (uintptr_t)cookie);
}

merr_t
cndb_record_nak(struct cndb *cndb, struct cndb_txn *tx)
{
    merr_t err = 0;

    mutex_lock(&cndb->mutex);

    if (!cndb->replaying) {
        if (cndb_needs_compaction(cndb)) {
            err = cndb_compact(cndb);
            if (ev(err))
                goto out;
        }

        err = cndb_omf_nak_write(cndb->mdc, cndb_txn_txid_get(tx));
    }

out:
    mutex_unlock(&cndb->mutex);
    map_remove(cndb->tx_map, cndb_txn_txid_get(tx), NULL);
    cndb_txn_apply(tx, &cndb_txn_free_cb, NULL);
    cndb_txn_destroy(tx);

    return err;
}

static merr_t
compact_incomplete_intents(
    struct cndb_txn   *tx,
    struct cndb_kvset *kvset,
    bool               isadd,
    bool               isacked,
    void              *ctx)
{
    struct cndb *cndb = ctx;
    uint64_t txid = cndb_txn_txid_get(tx);
    merr_t err;

    if (!isadd)
        return cndb_omf_kvset_del_write(cndb->mdc, txid, kvset->ck_cnid, kvset->ck_kvsetid);

    err = cndb_omf_kvset_add_write(cndb->mdc, txid, kvset->ck_cnid, kvset->ck_kvsetid,
                                   kvset->ck_nodeid, kvset->ck_dgen, kvset->ck_vused,
                                   kvset->ck_compc, kvset->ck_rule, kvset->ck_hblkid,
                                   kvset->ck_kblkc, kvset->ck_kblkv,
                                   kvset->ck_vblkc, kvset->ck_vblkv);
    return err;
}

static merr_t
compact_incomplete_acks(
    struct cndb_txn   *tx,
    struct cndb_kvset *kvset,
    bool               isadd,
    bool               isacked,
    void              *ctx)
{
    struct cndb *cndb = ctx;
    uint64_t txid = cndb_txn_txid_get(tx);
    int type = isadd ? CNDB_ACK_TYPE_ADD : CNDB_ACK_TYPE_DEL;

    if (!isacked)
        return 0;

    return cndb_omf_ack_write(cndb->mdc, txid, kvset->ck_cnid, type, kvset->ck_kvsetid);
}

static merr_t
log_full_rec(
    struct cndb       *cndb,
    struct cndb_kvset *kvset)
{
    merr_t err;
    uint64_t txid = 1;

    /* [HSE_REVISIT] There could be a new type of record that describes a full kvset that is not
     * part of any transaction (i.e. doesn't need a doctored txid).
     *
     * The txid can be the same for all these transactions because these transactions will be
     * proceessed sequentially upon replay.
     */
    err = cndb_omf_txstart_write(cndb->mdc, txid, cndb->seqno_max, cndb->ingestid_max,
                                 cndb->txhorizon_max, 1, 0);
    if (ev(err))
        return err;

    err = cndb_omf_kvset_add_write(cndb->mdc, txid, kvset->ck_cnid, kvset->ck_kvsetid,
                                   kvset->ck_nodeid, kvset->ck_dgen, kvset->ck_vused,
                                   kvset->ck_compc, kvset->ck_rule, kvset->ck_hblkid,
                                   kvset->ck_kblkc, kvset->ck_kblkv,
                                   kvset->ck_vblkc, kvset->ck_vblkv);
    if (ev(err))
        return err;

    err = cndb_omf_ack_write(cndb->mdc, txid, kvset->ck_cnid, CNDB_ACK_TYPE_ADD, kvset->ck_kvsetid);
    if (ev(err))
        return err;

    return 0;
}

static merr_t
write_compacted_log(struct cndb *cndb)
{
    struct map_iter cniter;
    struct cndb_cn *cn;
    merr_t err = 0;

    map_iter_init(&cniter, cndb->cn_map);

    /* For each cn in cndb, write a kvs_add record followed by all the kvsets of that cn.
     */
    while (!err && map_iter_next_val(&cniter, &cn)) {
        struct map_iter kvset_iter;
        struct cndb_kvset *kvset;

        err = cndb_omf_kvs_add_write(cndb->mdc, cn->cnid, &cn->cp, cn->name);
        if (ev(err))
            return err;

        map_iter_init(&kvset_iter, cn->kvset_map);

        while (map_iter_next_val(&kvset_iter, &kvset)) {
            err = log_full_rec(cndb, kvset);
            if (ev(err))
                return err;
        }
    }

    return 0;
}

merr_t
cndb_compact(struct cndb *cndb)
{
    struct map_iter txiter;
    struct cndb_txn *tx;
    uint64_t txid;
    merr_t err;

    /* Start cndb compact with cstart and cndb meta records */
    err = mpool_mdc_cstart(cndb->mdc);
    if (ev(err))
        return err;

    err = cndb_omf_ver_write(cndb->mdc, cndb->cndb_captgt);
    if (ev(err))
        return err;

    err = cndb_omf_meta_write(cndb->mdc, cndb->seqno_max);
    if (ev(err))
        return err;

    /* Write completed transactions */
    err = write_compacted_log(cndb);
    if (ev(err))
        return err;

    /* Copy active transactions */
    map_iter_init(&txiter, cndb->tx_map);

    while (map_iter_next(&txiter, &txid, (uintptr_t *)&tx)) {
        uint16_t add_cnt, del_cnt;

        cndb_txn_cnt_get(tx, &add_cnt, &del_cnt);
        err = cndb_omf_txstart_write(cndb->mdc, txid, cndb->seqno_max, cndb->ingestid_max,
                                     cndb->txhorizon_max, add_cnt, del_cnt);
        if (ev(err))
            return err;

        err = cndb_txn_apply(tx, &compact_incomplete_intents, cndb);
        if (ev(err))
            return err;

        err = cndb_txn_apply(tx, &compact_incomplete_acks, cndb);
        if (ev(err))
            return err;
    }

    return mpool_mdc_cend(cndb->mdc);
}

/* Replay */

struct cndb_reader {
    struct mpool_mdc *mdc;
    bool              eof;
    size_t            recbufsz;
    void             *recbuf;
};

static merr_t
cndb_read_one(struct cndb_reader *reader, enum cndb_rec_type *rec_type, size_t *rec_len)
{
    merr_t err;
    size_t len;

    err = mpool_mdc_read(reader->mdc, reader->recbuf, reader->recbufsz, &len);
    if (merr_errno(err) == EOVERFLOW) {
        size_t newsz = ALIGN(len, 128);
        void *p = realloc(reader->recbuf, newsz);

        if (ev(!p))
            return merr(ENOMEM);

        reader->recbufsz = newsz;
        reader->recbuf = p;

        err = mpool_mdc_read(reader->mdc, reader->recbuf, reader->recbufsz, &len);
    }

    if (ev(err))
        return err;

    if (!len) {
        *rec_len = 0;
        return 0;
    }

    *rec_type = omf_cnhdr_type(reader->recbuf);
    *rec_len = omf_cnhdr_len(reader->recbuf);
    return 0;
}

static struct cndb_txn *
txid2tx(struct cndb *cndb, uint64_t txid)
{
    return map_lookup_ptr(cndb->tx_map, txid);
}

merr_t
cndb_read_record(struct cndb *cndb, struct cndb_reader *reader)
{
    merr_t err;
    enum cndb_rec_type rec_type;
    size_t reclen = 0;

    assert(cndb->replaying);

    err = cndb_read_one(reader, &rec_type, &reclen);
    if (ev(err))
        return err;

    if (!reclen) {
        reader->eof = true;
        return 0;
    }

    if (rec_type == CNDB_TYPE_VERSION) {
        uint32_t magic;

        cndb_omf_ver_read(reader->recbuf, &magic, &cndb->cndb_version, &cndb->cndb_captgt);
        if (magic != CNDB_MAGIC)
            err = merr(EPROTO);

    } else if (rec_type == CNDB_TYPE_META) {
        cndb_omf_meta_read(reader->recbuf, &cndb->seqno_max);

    } else if (rec_type == CNDB_TYPE_KVS_ADD) {
        struct kvs_cparams cp;
        char name[HSE_KVS_NAME_LEN_MAX];
        uint64_t cnid;

        cndb_omf_kvs_add_read(reader->recbuf, &cp, &cnid, name, sizeof(name));
        err = cndb_record_kvs_add_inner(cndb, &cp, &cnid, false, name);
        ev(err);

        if (cnid > cndb->cnid_curr)
            cndb->cnid_curr = cnid;

    } else if (rec_type == CNDB_TYPE_KVS_DEL) {
        uint64_t cnid;

        cndb_omf_kvs_del_read(reader->recbuf, &cnid);
        err = cndb_record_kvs_del(cndb, cnid);
        ev(err);

    } else if (rec_type == CNDB_TYPE_TXSTART) {
        uint64_t txid, seqno, ingestid, txhorizon;
        uint16_t add_cnt, del_cnt;

        cndb_omf_txstart_read(reader->recbuf, &txid, &seqno, &ingestid, &txhorizon,
                              &add_cnt, &del_cnt);

        err = cndb_record_txstart_inner(cndb, seqno, ingestid, txhorizon,
                                        add_cnt, del_cnt, txid, NULL);
        ev(err);

        if (txid > cndb->txid_curr)
            cndb->txid_curr = txid;

    } else if (rec_type == CNDB_TYPE_KVSET_ADD) {
        uint64_t txid, cnid, kvsetid, nodeid;
        uint64_t hblkid, *kblkv, *vblkv;
        uint32_t kblkc, vblkc;
        struct kvset_meta km;

        cndb_omf_kvset_add_read(reader->recbuf, &txid, &cnid, &kvsetid, &nodeid, &hblkid,
                                &kblkc, &kblkv, &vblkc, &vblkv, &km);

        err = cndb_record_kvset_add(cndb, txid2tx(cndb, txid), cnid, nodeid, &km, kvsetid,
                                    hblkid, kblkc, kblkv, vblkc, vblkv, NULL);
        ev(err);

        if (kvsetid > cndb->kvsetid_curr)
            cndb->kvsetid_curr = kvsetid;

        if (nodeid > cndb->nodeid_curr)
            cndb->nodeid_curr = nodeid;

    } else if (rec_type == CNDB_TYPE_KVSET_DEL) {
        uint64_t txid, cnid, kvsetid;

        cndb_omf_kvset_del_read(reader->recbuf, &txid, &cnid, &kvsetid);

        err = cndb_record_kvset_del(cndb, txid2tx(cndb, txid), cnid, kvsetid, NULL);
        ev(err);

    } else if (rec_type == CNDB_TYPE_ACK) {
        uint64_t txid, cnid, kvsetid;
        uint type;

        cndb_omf_ack_read(reader->recbuf, &txid, &cnid, &type, &kvsetid);

        err = cndb_record_kvset_ack_cmn(cndb, txid2tx(cndb, txid), type, kvsetid);
        ev(err);

    } else if (rec_type ==  CNDB_TYPE_NAK) {
        uint64_t txid;

        cndb_omf_nak_read(reader->recbuf, &txid);

        err = cndb_record_nak(cndb, txid2tx(cndb, txid));
        ev(err);
    } else {
        assert(0);
        return merr(EPROTO);
    }

    return err;
}

struct recovery_ctx {
    struct mpool     *mp;
    struct mpool_mdc *mdc;
    struct map       *cn_map;
    struct map       *mbid_map;
    bool              is_rollback;
};

static bool
mblock_get_ref(struct map *mbid_map, uint64_t mbid, uint64_t *refcnt)
{
    uintptr_t *val;
    bool found;

    found = map_lookup_ref(mbid_map, mbid, &val);
    if (found)
        *refcnt = ++(*val);

    return found;
}

static bool
mblock_put_ref(struct map *mbid_map, uint64_t mbid, uint64_t *refcnt)
{
    uintptr_t *val;
    bool found;

    found = map_lookup_ref(mbid_map, mbid, &val);
    if (found) {
        *refcnt = --(*val);
        if (*refcnt == 0)
            map_remove(mbid_map, mbid, NULL);
    }

    return found;
}

static merr_t
mbid_map_kvset_add(struct map *mbid_map, struct cndb_kvset *kvset)
{
    merr_t err;
    int i;
    uint64_t refcnt;

    for (i = 0; i < kvset->ck_kblkc; i++) {
        if (!mblock_get_ref(mbid_map, kvset->ck_kblkv[i], &refcnt)) {
            err = map_insert(mbid_map, kvset->ck_kblkv[i], 1);
            if (ev(err))
                return err;
        }
    }

    for (i = 0; i < kvset->ck_vblkc; i++) {
        if (!mblock_get_ref(mbid_map, kvset->ck_vblkv[i], &refcnt)) {
            err = map_insert(mbid_map, kvset->ck_vblkv[i], 1);
            if (ev(err))
                return err;
        }
    }

    return 0;
}

static struct map *
construct_mbid_map(struct cndb *cndb)
{
    struct map *mbid_map;
    struct map_iter cniter;
    struct cndb_cn *cn;
    merr_t err;

    mbid_map = map_create(0);
    if (ev(!mbid_map))
        return NULL;

    map_iter_init(&cniter, cndb->cn_map);

    while (map_iter_next_val(&cniter, &cn)) {
        struct map_iter kvset_iter;
        struct cndb_kvset *kvset;

        map_iter_init(&kvset_iter, cn->kvset_map);

        while (map_iter_next_val(&kvset_iter, &kvset)) {
            err = mbid_map_kvset_add(mbid_map, kvset);
            if (ev(err))
                goto err_out;
        }
    }

    return mbid_map;

err_out:
    map_destroy(mbid_map);

    return NULL;
}

static merr_t
kvset_mblock_delete(struct mpool *mp, struct map *mbid_map, struct cndb_kvset *kvset)
{
    int i;
    merr_t err;
    bool found;
    uint64_t refcnt;

    err = mpool_mblock_props_get(mp, kvset->ck_hblkid, NULL);
    if (!err)
        err = mpool_mblock_delete(mp, kvset->ck_hblkid);

    if (err && merr_errno(err) == ENOENT)
        err = 0;

    for (i = 0; !err && i < kvset->ck_kblkc; i++) {
        found = mblock_put_ref(mbid_map, kvset->ck_kblkv[i], &refcnt);
        if (!found || !refcnt) {
            err = mpool_mblock_props_get(mp, kvset->ck_kblkv[i], NULL);
            if (!err)
                err = mpool_mblock_delete(mp, kvset->ck_kblkv[i]);

            if (err && merr_errno(err) == ENOENT)
                err = 0;
        }
    }

    for (i = 0; !err && i < kvset->ck_vblkc; i++) {
        found = mblock_put_ref(mbid_map, kvset->ck_vblkv[i], &refcnt);
        if (!found || !refcnt) {
            err = mpool_mblock_props_get(mp, kvset->ck_vblkv[i], NULL);
            if (!err)
                err = mpool_mblock_delete(mp, kvset->ck_vblkv[i]);

            if (err && merr_errno(err) == ENOENT)
                err = 0;
        }
    }

    return err;
}

static merr_t
recover_incomplete_txn_cb(
    struct cndb_txn   *tx,
    struct cndb_kvset *kvset,
    bool               isadd,
    bool               isacked,
    void              *ctx)
{
    struct recovery_ctx *rctx = ctx;
    merr_t err = 0;
    struct cndb_cn *cn;

    cn = map_lookup_ptr(rctx->cn_map, kvset->ck_cnid);
    if (ev(!cn))
        return merr(EPROTO);

    if (isadd) {
        assert(rctx->is_rollback || isacked);

        err = mbid_map_kvset_add(rctx->mbid_map, kvset);
        if (ev(err)) {
            free(kvset);
            return err;
        }

        if (rctx->is_rollback) {
            err = kvset_mblock_delete(rctx->mp, rctx->mbid_map, kvset);
            free(kvset);
        } else {
            err = map_insert_ptr(cn->kvset_map, kvset->ck_kvsetid, kvset);
        }

        return ev(err);
    }

    /* If this txn needs to be rolled back, it's because it doesn't have enough acks for all kvset
     * add records. Until all kvset adds have been acked, no kvsets can be deleted.
     *
     * So, if this is a rollback, the kvset delete records must not be acked. And there's nothing
     * to do for these records.
     */
    if (!rctx->is_rollback) {
        struct cndb_kvset *delme;

        delme = map_remove_ptr(cn->kvset_map, kvset->ck_kvsetid);
        kvset_mblock_delete(rctx->mp, rctx->mbid_map, delme);

        err = cndb_omf_ack_write(rctx->mdc, cndb_txn_txid_get(tx), delme->ck_cnid,
                                 CNDB_ACK_TYPE_DEL, delme->ck_kvsetid);
        free(delme);
    }

    free(kvset);

    return err;
}

merr_t
cndb_replay(struct cndb *cndb, uint64_t *seqno, uint64_t *ingestid, uint64_t *txhorizon)
{
    struct cndb_reader reader;
    merr_t err;

    struct map_iter txiter;
    struct cndb_txn *tx;
    uint64_t txid;
    struct map *mbid_map = 0;

    reader.mdc = cndb->mdc;
    reader.recbufsz = sizeof(struct cndb_hdr_omf);
    reader.eof = false;
    reader.recbuf = malloc(reader.recbufsz);

    if (ev(!reader.recbuf))
        return merr(ENOMEM);

    err = mpool_mdc_rewind(cndb->mdc);
    if (ev(err))
        goto out;

    cndb->replaying = true;

    while (!reader.eof) {
        err = cndb_read_record(cndb, &reader);
        if (ev(err))
            goto out;
    }

    free(reader.recbuf);
    reader.recbuf = NULL;

    if (cndb->rdonly)
        goto out;

    mbid_map = construct_mbid_map(cndb);
    if (ev(!mbid_map)) {
        err = merr(ENOMEM);
        goto out;
    }

    map_iter_init(&txiter, cndb->tx_map);

    /* Active transactions */
    while (map_iter_next(&txiter, &txid, (uintptr_t *)&tx)) {
        struct recovery_ctx rctx = {
            .mp = cndb->mp,
            .mdc = cndb->mdc,
            .mbid_map = mbid_map,
            .cn_map = cndb->cn_map,
            .is_rollback = cndb_txn_needs_rollback(tx),
        };

        err = cndb_txn_apply(tx, &recover_incomplete_txn_cb, &rctx);
        if (!err && rctx.is_rollback)
            err = cndb_omf_nak_write(cndb->mdc, txid);

        map_remove(cndb->tx_map, cndb_txn_txid_get(tx), NULL);
        cndb_txn_destroy(tx);

        if (ev(err))
            goto out;
    }

    *seqno = cndb->seqno_max;
    *txhorizon = cndb->txhorizon_max;
    *ingestid = cndb->ingestid_max;

out:
    map_destroy(mbid_map);

    if (err)
        free(reader.recbuf);

    cndb->replaying = false;

    return err;
}

merr_t
cndb_cn_instantiate(struct cndb *cndb, uint64_t cnid, void *ctx, cn_init_callback *cb)
{
    struct cndb_cn *cn = map_lookup_ptr(cndb->cn_map, cnid);
    struct cndb_kvset *kvset;
    struct map_iter kvset_iter;
    merr_t err = 0;

    if (ev(!cn))
        return merr(EINVAL);

    map_iter_init(&kvset_iter, cn->kvset_map);

    while (map_iter_next_val(&kvset_iter, &kvset)) {
        struct kvset_meta km = {
            .km_dgen = kvset->ck_dgen,
            .km_compc = kvset->ck_compc,
            .km_rule = kvset->ck_rule,
            .km_vused = kvset->ck_vused,
            .km_capped = cn->cp.kvs_ext01,
            .km_nodeid = kvset->ck_nodeid,
            .km_hblk.bk_blkid = kvset->ck_hblkid,
            .km_restored = true,
        };

        int i;

        blk_list_init(&km.km_kblk_list);
        blk_list_init(&km.km_vblk_list);

        for (i = 0; i < kvset->ck_kblkc && !err; i++)
            err = blk_list_append(&km.km_kblk_list, kvset->ck_kblkv[i]);

        for (i = 0; i < kvset->ck_vblkc && !err; i++)
            err = blk_list_append(&km.km_vblk_list, kvset->ck_vblkv[i]);

        if (!err)
            err = cb(ctx, &km, kvset->ck_kvsetid);

        blk_list_free(&km.km_kblk_list);
        blk_list_free(&km.km_vblk_list);

        if (ev(err))
            return err;
    }

    return 0;
}

struct kvs_cparams *
cndb_kvs_cparams(struct cndb *cndb, uint64_t cnid)
{
    struct cndb_cn *cn = map_lookup_ptr(cndb->cn_map, cnid);

    return &cn->cp;
}

struct mpool_mdc *
cndb_mdc_get(struct cndb *cndb)
{
    return cndb->mdc;
}

#if HSE_MOCKING
#include "cndb_ut_impl.i"
#endif /* HSE_MOCKING */
