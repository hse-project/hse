/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c1
#define MTF_MOCK_IMPL_c1_ops

#include <hse_ikvdb/kvb_builder.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "c1_private.h"

#include <mpool/mpool.h>

static u64
c1_cur_txnid(struct c1 *c1);

merr_t
c1_alloc(struct mpool *ds, struct kvdb_cparams *cparams, u64 *oid1out, u64 *oid2out)
{
    struct c1_journal *jrnl;
    merr_t             err;
    u64                capacity;
    u64                ntrees;

    err = c1_parse_cparams(cparams, &capacity, &ntrees);
    if (ev(err))
        return err;

    err = c1_journal_alloc(ds, MP_MED_STAGING, capacity, &jrnl);
    if (ev(err))
        return err;

    *oid1out = jrnl->c1j_oid1;
    *oid2out = jrnl->c1j_oid2;

    c1_journal_close(jrnl);

    return 0;
}

merr_t
c1_make(struct mpool *ds, struct kvdb_cparams *cparams, u64 oid1, u64 oid2)
{
    struct c1_journal *jrnl;
    merr_t             err;
    merr_t             err2;
    u64                capacity;
    u64                ntrees;
    int                i;

    err = c1_parse_cparams(cparams, &capacity, &ntrees);
    if (ev(err))
        return err;

    err = c1_journal_make(ds, oid1, oid2, MP_MED_STAGING, capacity, &jrnl);
    if (ev(err))
        return err;

    for (i = 0; i < ntrees; ++i) {
        struct c1_tree *tree;

        err =
            c1_new_tree(jrnl, HSE_C1_DEFAULT_STRIP_SIZE, HSE_C1_DEFAULT_STRIPE_WIDTH, NULL, &tree);
        if (ev(err))
            goto err_exit;

        err = c1_journal_complete_tree(jrnl, tree->c1t_seqno, tree->c1t_gen, C1_INVALID_SEQNO);
        if (ev(err))
            goto err_exit;

        c1_tree_close(tree);
        c1_journal_inc_seqno(jrnl);
    }

    c1_journal_close(jrnl);

    return 0;

err_exit:
    /* [HSE_REVISIT]: Add error handling when ntrees > 1 */
    err2 = c1_journal_destroy(jrnl);
    if (ev(err2))
        hse_elog(HSE_ERR "%s: c1 jrnl destroy failed: @@e", err2, __func__);

    return err;
}

struct c1 *
c1_create(const char *mpname)
{
    struct c1 *c1;
    merr_t     err;

    c1 = malloc(sizeof(*c1));
    if (ev(!c1))
        return NULL;

    c1->c1_replay_hdl = NULL;
    c1->c1_jrnl = NULL;
    c1->c1_io = NULL;
    c1->c1_ikvdb = NULL;

    INIT_LIST_HEAD(&c1->c1_tree_inuse);
    INIT_LIST_HEAD(&c1->c1_tree_clean);
    INIT_LIST_HEAD(&c1->c1_tree_reset);
    INIT_LIST_HEAD(&c1->c1_tree_new);
    INIT_LIST_HEAD(&c1->c1_txn);

    mutex_init(&c1->c1_list_mtx);
    mutex_init(&c1->c1_active_mtx);
    mutex_init(&c1->c1_alloc_mtx);
    mutex_init(&c1->c1_txn_mtx);

    atomic_set(&c1->c1_active_cnt, 0);
    c1->c1_ingest_kvseqno = C1_INVALID_SEQNO;
    c1->c1_kvdb_seqno = C1_INVALID_SEQNO;

    c1->c1_rep.c1r_close = false;
    INIT_LIST_HEAD(&c1->c1_rep.c1r_info);
    INIT_LIST_HEAD(&c1->c1_rep.c1r_desc);
    INIT_LIST_HEAD(&c1->c1_rep.c1r_reset);
    INIT_LIST_HEAD(&c1->c1_rep.c1r_complete);
    INIT_LIST_HEAD(&c1->c1_rep.c1r_ingest);

    c1->c1_txnid = 0;
    memset(&c1->c1_pcset_op, 0, sizeof(c1->c1_pcset_op));
    memset(&c1->c1_pcset_kv, 0, sizeof(c1->c1_pcset_kv));
    memset(&c1->c1_pcset_tree, 0, sizeof(c1->c1_pcset_tree));

    err = c1_kvcache_create(c1);
    if (ev(err)) {
        free(c1);
        return NULL;
    }

    c1_perfc_alloc(c1, mpname);

    return c1;
}

void
c1_destroy(struct c1 *c1)
{
    if (!c1)
        return;

    c1_kvcache_destroy(c1);
    c1_perfc_free(c1);
    free(c1);
}

merr_t
c1_free(struct mpool *ds, u64 oid1, u64 oid2)
{
    struct c1_journal *jrnl;
    struct c1 *        c1;
    merr_t             err;

    err = c1_journal_open(false, ds, MP_MED_STAGING, NULL, oid1, oid2, &jrnl);
    if (ev(err))
        return err;

    c1 = c1_create(NULL);
    if (!c1)
        return merr(ev(ENOMEM));

    c1->c1_jrnl = jrnl;

    err = c1_journal_replay(c1, jrnl, c1_journal_replay_default_cb);
    if (ev(err))
        goto err_exit;

    err = c1_destroy_tree(ds, oid1, oid2, c1);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 tree destroy failed: @@e", err, __func__);
        goto err_exit;
    }

    err = c1_journal_destroy(jrnl);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 jrnl destroy failed: @@e", err, __func__);
        goto err_exit;
    }

err_exit:
    c1_destroy(c1);
    return err;
}

merr_t
c1_open(
    struct mpool *       ds,
    int                  rdonly,
    u64                  oid1,
    u64                  oid2,
    u64                  kvmsgen,
    const char *         mpname,
    struct kvdb_rparams *rparams,
    struct ikvdb *       ikvdb,
    struct c0sk *        c0sk,
    struct c1 **         out)
{
    struct c1_journal *jrnl;
    struct c1 *        c1;
    merr_t             err;
    u64                dtime;

    err = c1_journal_open(rdonly, ds, MP_MED_STAGING, mpname, oid1, oid2, &jrnl);
    if (ev(err))
        return err;

    c1 = c1_create(mpname);
    if (!c1) {
        err = merr(ev(ENOMEM));
        goto err_exit;
    }

    c1->c1_jrnl = jrnl;
    c1->c1_ikvdb = ikvdb;
    c1->c1_c0sk = c0sk;
    c1->c1_rdonly = rdonly;
    c1->c1_kvms_gen = kvmsgen;
    c1->c1_vbldr = (bool)rparams->dur_vbb;

    err = c1_replay(c1);
    if (ev(err))
        goto err_exit2;

    c1_journal_set_info(jrnl, rparams->dur_intvl_ms, rparams->dur_buf_sz);

    if (c1_rdonly(c1)) {
        *out = c1;
        return 0;
    }

    err = c1_compact(c1);
    if (ev(err))
        goto err_exit2;

    c1_journal_get_info(c1->c1_jrnl, &dtime, NULL, NULL);
    err = c1_io_create(c1, dtime, mpname, HSE_C1_DEFAULT_THREAD_CNT);
    if (ev(err))
        goto err_exit2;

    err = c1_next_tree(c1);
    if (ev(err))
        goto err_exit3;

    *out = c1;
    return 0;

err_exit3:
    c1_io_destroy(c1);

err_exit2:
    c1_close_trees(c1);

err_exit:
    *out = NULL;
    if (c1 && c1->c1_replay_hdl)
        (void)ikvdb_c1_replay_close(ikvdb, c1->c1_replay_hdl);

    if (c1) {
        c1_kvcache_destroy(c1);
        c1_perfc_free(c1);
        free(c1);
    }
    c1_journal_close(jrnl);

    return err;
}

merr_t
c1_close(struct c1 *c1)
{
    merr_t err;
    merr_t err2;

    /* error paths may call with uninitialized handles */
    if (!c1)
        return 0;

    assert(c1->c1_jrnl != NULL);

    if (!c1_rdonly(c1))
        c1_io_destroy(c1);

    err = c1_close_trees(c1);
    if (ev(err))
        hse_elog(HSE_ERR "%s: Cannot close one or more trees : @@e", err, __func__);

    err2 = c1_journal_close(c1->c1_jrnl);
    if (ev(err2))
        hse_elog(HSE_ERR "%s: Cannot close journal  : @@e", err2, __func__);

    c1_kvcache_destroy(c1);

    assert(list_empty(&c1->c1_rep.c1r_desc));
    assert(list_empty(&c1->c1_rep.c1r_complete));
    assert(list_empty(&c1->c1_rep.c1r_info));
    assert(list_empty(&c1->c1_rep.c1r_reset));
    assert(list_empty(&c1->c1_rep.c1r_ingest));

    c1_perfc_free(c1);
    free(c1);

    if (!err)
        err = err2;

    return err;
}

merr_t
c1_ingest(struct c1 *c1, struct kvb_builder_iter *iter, struct c1_kvinfo *cki, int ingestflag)
{
    merr_t err;
    u64    txnid;

    txnid = c1_cur_txnid(c1);

    if (!iter) {
        err = c1_issue_iter(c1, NULL, txnid, cki, ingestflag);
        return ev(err);
    }

    err = c1_issue_iter(c1, iter, txnid, cki, ingestflag);
    if (ev(err))
        return err;

    return 0;
}

BullseyeCoverageSaveOff
merr_t
c1_cningest_status(struct c1 *c1, u64 seqno, merr_t status, u64 cnid, const struct kvs_ktuple *kt)
{
    merr_t err;

    err = c1_invalidate_tree(c1, seqno, status, cnid, kt);
    if (ev(err))
        return err;

    return 0;
}
BullseyeCoverageRestore

bool
c1_ingest_seqno(struct c1 *c1, u64 seqno)
{
    /*
     * If ikvdb is NULL then it is a special case for unit tests
     */
    if (!c1->c1_ikvdb)
        return true;

    if (seqno < ikvdb_horizon(c1->c1_ikvdb))
        return false;

    if (c1->c1_ingest_kvseqno == C1_INVALID_SEQNO)
        return true;

    if (seqno < c1->c1_ingest_kvseqno)
        return false;

    return true;
}

u64
c1_ingest_stripsize(struct c1 *c1)
{
    return HSE_C1_DEFAULT_STRIP_SIZE;
}

u64
c1_ingest_space_threshold(struct c1 *c1)
{
    return c1_tree_space_threshold(c1_current_tree(c1));
}

merr_t
c1_sync(struct c1 *c1)
{
    struct c1_kvinfo cki = {};
    merr_t           err;
    u64              start;

    start = perfc_lat_start(&c1->c1_pcset_op);

    err = c1_ingest(c1, NULL, &cki, C1_INGEST_SYNC);
    if (ev(err))
        return err;

    assert(c1->c1_jrnl);

    err = c1_journal_flush(c1->c1_jrnl);
    if (err)
        return ev(err);

    if (PERFC_ISON(&c1->c1_pcset_op)) {
        perfc_rec_lat(&c1->c1_pcset_op, PERFC_LT_C1_SYNC, start);
        perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_SYNC);
    }

    return 0;
}

merr_t
c1_flush(struct c1 *c1)
{
    struct c1_kvinfo cki = {};
    merr_t           err;
    u64              start;

    start = perfc_lat_start(&c1->c1_pcset_op);

    err = c1_ingest(c1, NULL, &cki, C1_INGEST_FLUSH);
    if (ev(err))
        return err;

    if (PERFC_ISON(&c1->c1_pcset_op)) {
        perfc_rec_lat(&c1->c1_pcset_op, PERFC_LT_C1_FLUSH, start);
        perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_FLUSH);
    }

    return 0;
}

struct ikvdb *
c1_ikvdb(struct c1 *c1)
{
    return c1->c1_ikvdb;
}

merr_t
c1_config_info(struct c1 *c1, struct c1_config_info *info)
{
    u64 dtime = 0;
    u64 dsize = 0;
    u64 dcapacity = 0;

    assert(c1);
    assert(c1->c1_jrnl);

    c1_journal_get_info(c1->c1_jrnl, &dtime, &dsize, &dcapacity);

    if (dtime || dsize)
        info->c1_denabled = 1;
    else
        info->c1_denabled = 0;

    info->c1_dtime = dtime;
    info->c1_dsize = dsize;
    info->c1_dcapacity = dcapacity;

    return 0;
}

bool
c1_is_clean(struct c1 *c1)
{
    return c1->c1_rep.c1r_close;
}

u64
c1_get_size(u64 size)
{
    return size;
}

u64
c1_get_capacity(u64 capacity)
{
    if (capacity == 0)
        capacity = HSE_C1_DEFAULT_CAP;

    if (capacity < HSE_C1_MIN_CAP || capacity > HSE_C1_MAX_CAP) {
        u64 newcap;

        newcap = clamp_t(u64, capacity, HSE_C1_MIN_CAP, HSE_C1_MAX_CAP);

        hse_log(
            HSE_INFO "Invalid c1 tree capacity %lu MiB, "
                     "setting to %lu MiB",
            (ulong)(capacity >> 20),
            (ulong)(newcap >> 20));

        capacity = newcap;
    }

    return capacity;
}

bool
c1_jrnl_reaching_capacity(struct c1 *c1)
{
    return c1_journal_reaching_capacity(c1->c1_jrnl);
}

merr_t
c1_replay_on_ikvdb(
    struct c1 *        c1,
    struct ikvdb *     ikvdb,
    u64                cnid,
    u64                seqno,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    bool               tomb)
{
    if (tomb) {
        perfc_inc(&c1->c1_pcset_kv, PERFC_BA_C1_DELR);
        return ikvdb_c1_replay_del(ikvdb, c1->c1_replay_hdl, seqno, cnid, NULL, kt, vt);
    }

    perfc_inc(&c1->c1_pcset_kv, PERFC_BA_C1_PUTR);

    return ikvdb_c1_replay_put(ikvdb, c1->c1_replay_hdl, seqno, cnid, NULL, kt, vt);
}

merr_t
c1_txn_begin(struct c1 *c1, u64 txnid, struct c1_iterinfo *ci, int flag)
{
    return c1_io_txn_begin(c1, txnid, ci, flag);
}

merr_t
c1_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int flag)
{
    return c1_io_txn_commit(c1, txnid, seqno, flag);
}

BullseyeCoverageSaveOff
merr_t
c1_txn_abort(struct c1 *c1, u64 txnid)
{
    return c1_io_txn_abort(c1, txnid);
}
BullseyeCoverageRestore

u64
c1_get_txnid(struct c1 *c1)
{
    return ++c1->c1_txnid;
}

static u64
c1_cur_txnid(struct c1 *c1)
{
    return c1->c1_txnid;
}

u64
c1_kvmsgen(struct c1 *c1)
{
    return c1->c1_kvms_gen;
}

merr_t
c1_builder_get(struct c1 *c1, u64 gen, struct kvset_builder ***bldrout)
{
    return c1_io_kvset_builder_get(c1, gen, bldrout);
}

void
c1_builder_put(struct c1 *c1, u64 gen)
{
    c1_io_kvset_builder_put(c1, gen);
}

void
c1_kvset_builder_release(struct c1 *c1, struct c1_kvset_builder_elem *elem)
{
    c1_io_kvset_builder_release(c1, elem);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_ut_impl.i"
#include "c1_ops_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
