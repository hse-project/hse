/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/error/merr.h>
#include <hse_util/list.h>

#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include <mpool/mpool.h>

#include <cn/kvset.h>

#include <cndb/omf.h>

struct mock_mdc_record {
    struct mock_mdc_record *next;
    size_t len;
    unsigned char data[];
};

struct mock_mdc {
    struct mock_mdc_record *head;
    struct mock_mdc_record *read_curr;
    struct mock_mdc_record *append_curr;
} *_mock_mdc;

static merr_t
_mpool_mdc_alloc(
    struct mpool     *mp,
    uint32_t          magic,
    size_t            capacity,
    enum hse_mclass mclass,
    uint64_t         *logid1,
    uint64_t         *logid2)
{
    struct mock_mdc *m = calloc(1, sizeof(*m));

    if (!m)
        return merr(ENOMEM);

    _mock_mdc = m;
    return 0;
}

static merr_t
_mpool_mdc_delete(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    struct mock_mdc *m = _mock_mdc;

    m->read_curr = m->head;
    while (m->read_curr) {
        struct mock_mdc_record *n = m->read_curr->next;

        free(m->read_curr);
        m->read_curr = n;
    }

    free(m);
    _mock_mdc = 0;

    return 0;
}

static merr_t
_mpool_mdc_open(struct mpool *mp, uint64_t oid1, uint64_t oid2, bool rdonly, struct mpool_mdc **mdc)
{
    *mdc = (void *)_mock_mdc;
    return 0;
}

merr_t
_mpool_mdc_append(struct mpool_mdc *mdc, void *data, size_t len, bool sync)
{
    struct mock_mdc *m = (void *)mdc;
    struct mock_mdc_record *r = calloc(1, sizeof(*r) + len);

    if (!r)
        return merr(ENOMEM);

    memcpy(r->data, data, len);
    r->len = len;

    r->next = 0;
    if (m->append_curr) {
        m->append_curr->next = r;
    } else {
        m->head = r;
        m->read_curr = r;
    }

    m->append_curr = r;
    return 0;
}

merr_t
_mpool_mdc_rewind(struct mpool_mdc *mdc)
{
    struct mock_mdc *m = (void *)mdc;

    m->read_curr = m->head;
    return 0;
}

merr_t
_mpool_mdc_read(struct mpool_mdc *mdc, void *data, size_t max, size_t *dlen)
{
    struct mock_mdc *m = (void *)mdc;

    *dlen = 0;
    if (!m->read_curr)
        return 0; /* eof */

    *dlen = m->read_curr->len;
    if (max < m->read_curr->len)
        return merr(EOVERFLOW); /* buffer too small */

    memcpy(data, m->read_curr->data, m->read_curr->len);
    m->read_curr = m->read_curr->next;

    return 0;
}

merr_t
_mpool_mdc_cstart(struct mpool_mdc *mdc)
{
    struct mock_mdc *m = _mock_mdc;

    m->read_curr = m->head;
    while (m->read_curr) {
        struct mock_mdc_record *n = m->read_curr->next;

        free(m->read_curr);
        m->read_curr = n;
    }

    memset(m, 0x00, sizeof(*m));
    return 0;
}

merr_t
_mpool_mdc_close(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t
_mpool_mdc_usage(struct mpool_mdc *mdc, uint64_t *size, uint64_t *allocated, uint64_t *used)
{
    *size = 100;
    *used = 10;
    *allocated = 100;

    return 0;
}


static int
collection_pre(struct mtf_test_info *ti)
{
    MOCK_SET(mpool, _mpool_mdc_alloc);
    MOCK_SET(mpool, _mpool_mdc_delete);
    MOCK_SET(mpool, _mpool_mdc_open);
    MOCK_SET(mpool, _mpool_mdc_close);
    MOCK_SET(mpool, _mpool_mdc_append);
    MOCK_SET(mpool, _mpool_mdc_rewind);
    MOCK_SET(mpool, _mpool_mdc_read);
    MOCK_SET(mpool, _mpool_mdc_usage);
    MOCK_SET(mpool, _mpool_mdc_cstart);

    mapi_inject(mapi_idx_mpool_mdc_commit, 0);
    mapi_inject(mapi_idx_mpool_mdc_cend, 0);
    mapi_inject(mapi_idx_mpool_mdc_sync, 0);

    mapi_inject(mapi_idx_mpool_mclass_is_configured, 1);
    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);

    return 0;
}

static int
collection_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cndb_test, collection_pre, collection_post);

uint64_t cnid;
struct cndb *cndb;

static int
test_pre(struct mtf_test_info *lcl_ti)
{
    uint64_t oid1, oid2;
    struct mpool *mp = (void *)-1;
    merr_t err;
    struct kvdb_rparams rp = kvdb_rparams_defaults();

    err = cndb_create(mp, 0, &oid1, &oid2);
    ASSERT_EQ_RET(0, err, -1);

    err = cndb_open(mp, oid1, oid2, &rp, &cndb);
    ASSERT_EQ_RET(0, err, -1);

    struct kvs_cparams cp = kvs_cparams_defaults();

    err = cndb_record_kvs_add(cndb, &cp, &cnid, "cndb_kvs");
    ASSERT_EQ_RET(0, err, -1);

    return 0;
}

static int
test_post(struct mtf_test_info *lcl_ti)
{
    struct mpool *mp = (void *)-1;
    merr_t err;

    err = cndb_close(cndb);
    ASSERT_EQ_RET(0, err, -1);

    err = cndb_destroy(mp, 0, 0);
    ASSERT_EQ_RET(0, err, -1);

    cnid = 0;
    cndb = 0;

    return 0;
}

struct blks {
    unsigned int cnt;
    uint64_t idv[32];
};

struct t_kvset {
    uint64_t nid;   /* node id */
    struct blks kb; /* list of kblock ids */
    struct blks vb; /* list of vblock ids */
};

#define NUMARGS(...) (sizeof((int[]){__VA_ARGS__})/sizeof(int))
#define BLKS(...) { .cnt = NUMARGS(__VA_ARGS__), .idv = {__VA_ARGS__} }

uint64_t g_hbid = 0;
uint64_t g_seqno = 0;

static merr_t
txstart(struct cndb *cndb, uint nc, uint nd, struct cndb_txn **tx)
{
    return cndb_record_txstart(cndb, ++g_seqno, 0, 0, nc, nd, tx);
}

static void *
kvset_add(struct cndb *cndb, struct cndb_txn *tx, uint64_t dgen, struct t_kvset k, uint64_t *kid)
{
    merr_t err;
    struct kvset_meta km = {
        .km_dgen_hi = dgen,
        .km_dgen_lo = dgen,
    };

    void *cookie;

    *kid = cndb_kvsetid_mint(cndb);
    err = cndb_record_kvset_add(cndb, tx, 1, k.nid, &km, *kid, ++g_hbid,
                                k.kb.cnt, k.kb.idv, k.vb.cnt, k.vb.idv, &cookie);
    if (err)
        return 0;

    return cookie;
}

static void *
kvset_del(struct cndb *cndb, struct cndb_txn *tx, uint64_t kvsetid)
{
    void *cookie;
    merr_t err;

    err = cndb_record_kvset_del(cndb, tx, 1, kvsetid, &cookie);
    if (err)
        return 0;

    return cookie;
}

MTF_DEFINE_UTEST(cndb_test, mdc_mock_test)
{
    merr_t err = 0;
    struct mpool_mdc *mdc;
    uint64_t oid1, oid2;

    err = mpool_mdc_alloc((void *)-1, CNDB_MAGIC, 1234, HSE_MCLASS_CAPACITY, &oid1, &oid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_open((void *)-1, 0, 0, false, &mdc);
    ASSERT_EQ(0, err);

    char buf[128];

    snprintf(buf, sizeof(buf), "%s", "hello");
    err = mpool_mdc_append(mdc, buf, strlen(buf), true);
    ASSERT_EQ(0, err);

    snprintf(buf, sizeof(buf), "%s", "world");
    err = mpool_mdc_append(mdc, buf, strlen(buf), true);
    ASSERT_EQ(0, err);

    snprintf(buf, sizeof(buf), "%s", "again");
    err = mpool_mdc_append(mdc, buf, strlen(buf), true);
    ASSERT_EQ(0, err);

    memset(buf, 0x00, sizeof(buf));

    mpool_mdc_rewind(mdc);

    size_t buflen = 0;
    err = mpool_mdc_read(mdc, buf, sizeof(buf), &buflen);
    ASSERT_NE(0, buflen);
    ASSERT_EQ(0, strcmp(buf, "hello"));

    err = mpool_mdc_read(mdc, buf, sizeof(buf), &buflen);
    ASSERT_NE(0, buflen);
    ASSERT_EQ(0, strcmp(buf, "world"));

    err = mpool_mdc_read(mdc, buf, sizeof(buf), &buflen);
    ASSERT_NE(0, buflen);
    ASSERT_EQ(0, strcmp(buf, "again"));

    err = mpool_mdc_delete((void *)-1, oid1, oid2);
    ASSERT_EQ(0, err);
}

uint64_t g_mbid = 0;

static void
create_kvset(
    struct mtf_test_info *lcl_ti,
    struct cndb          *cndb,
    uint64_t              cnid,
    uint                  kblkc,
    uint64_t             *kblkv,
    uint                  vblkc,
    uint64_t             *vblkv,
    uint64_t             *kvsetid)
{
    struct cndb_txn *tx;
    merr_t err;

    uint64_t hblkid = ++g_mbid;
    struct kvset_meta km = {
        .km_dgen_hi = 2,
        .km_dgen_lo = 1,
        .km_vused = 10,
        .km_compc = 0,
    };

    *kvsetid = cndb_kvsetid_mint(cndb);

    err = cndb_record_txstart(cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON, 1, 0, &tx);
    ASSERT_EQ(0, err);

    void *cookie;
    err = cndb_record_kvset_add(cndb, tx, cnid, cndb_nodeid_mint(cndb), &km, *kvsetid, hblkid,
                                kblkc, kblkv, vblkc, vblkv, &cookie);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, cookie);
    ASSERT_EQ(0, err);
}

uint64_t tgt_nodeid = 20;
uint g_cb_ctr;

static merr_t
replay_full_move_cb(void *ctx, struct kvset_meta *km, uint64_t kvsetid)
{
    if (km->km_nodeid != tgt_nodeid)
        return merr(EBUG);

    ++g_cb_ctr;

    return 0;
}

static merr_t
replay_full_cb(void *ctx, struct kvset_meta *km, uint64_t kvsetid)
{
    ++g_cb_ctr;

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, replay_full, test_pre, test_post)
{
    struct mpool *mp = (void *)-1;
    merr_t err;

    g_mbid = 0;

    uint64_t kvsetid_ingest;
    uint64_t kblkv_ingest[2] = {1, 2};
    uint64_t vblkv_ingest[3] = {10, 20, 30};

    create_kvset(lcl_ti, cndb, cnid, NELEM(kblkv_ingest), kblkv_ingest,
                 NELEM(vblkv_ingest), vblkv_ingest, &kvsetid_ingest);

    /* Reuse some mblocks */
    const uint64_t hbid_left = 101;
    const uint64_t hbid_right = 102;
    const uint64_t kvsetid_left = cndb_kvsetid_mint(cndb);
    const uint64_t kvsetid_right = cndb_kvsetid_mint(cndb);
    const uint64_t src_nodeid = 10;
    const uint64_t kvsetidv[2] = { kvsetid_left, kvsetid_right };
    void *c1, *c2;

    struct kvset_meta km = {
        .km_dgen_hi = 1,
        .km_dgen_lo = 1,
        .km_vused = 10,
        .km_compc = 0,
    };

    struct cndb_txn *tx;

    err = cndb_record_txstart(cndb, 2, 0, 0, 2, 1, &tx);
    ASSERT_EQ(0, err);

    /* Reuse one kblk and all vblks */
    uint64_t kblkv_left[2] = {3, 4};
    uint64_t kblkv_right[2] = {2, 5};

    err = cndb_record_kvset_add(cndb, tx, cnid, src_nodeid, &km, kvsetid_left,
                                hbid_left, NELEM(kblkv_left), kblkv_left, NELEM(vblkv_ingest),
                                vblkv_ingest, &c1);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add(cndb, tx, cnid, src_nodeid, &km, kvsetid_right,
                                hbid_right, NELEM(kblkv_right), kblkv_right, NELEM(vblkv_ingest),
                                vblkv_ingest, &c2);
    ASSERT_EQ(0, err);

    void *delcookie;
    err = cndb_record_kvset_del(cndb, tx, cnid, kvsetid_ingest, &delcookie);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, c1);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, c2);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_del_ack(cndb, tx, delcookie);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_move(cndb, cnid, src_nodeid, tgt_nodeid, 2, kvsetidv);
    ASSERT_EQ(0, err);

    /* Reopen and replay */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    struct kvdb_rparams rp = kvdb_rparams_defaults();
    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    uint64_t seqno_out, ingestid_out, txhorizon_out;

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    g_cb_ctr = 0;
    err = cndb_cn_instantiate(cndb, cnid, NULL, (void *)replay_full_move_cb);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, g_cb_ctr);
}

static merr_t
assert_ingest_kvset(void *ctx, struct kvset_meta *km, u64 kvsetid)
{
    ++g_cb_ctr;

    if (kvsetid != (uint64_t)ctx)
        return merr(EBUG);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, rollback, test_pre, test_post)
{
    struct mpool *mp = (void *)-1;
    merr_t err;

    g_mbid = 0;

    uint64_t kvsetid_ingest;
    uint64_t kblkv_ingest[2] = {1, 2};
    uint64_t vblkv_ingest[3] = {10, 20, 30};

    create_kvset(lcl_ti, cndb, cnid, NELEM(kblkv_ingest), kblkv_ingest,
                 NELEM(vblkv_ingest), vblkv_ingest, &kvsetid_ingest);

    /* Reuse some mblocks */
    uint64_t hbid_left = 101;
    uint64_t hbid_right = 102;
    uint64_t kvsetid_left = cndb_kvsetid_mint(cndb);
    uint64_t kvsetid_right = cndb_kvsetid_mint(cndb);
    void *c1, *c2;

    struct kvset_meta km = {
        .km_dgen_hi = 1,
        .km_dgen_lo = 1,
        .km_vused = 10,
        .km_compc = 0,
    };

    struct cndb_txn *tx;

    err = cndb_record_txstart(cndb, 2, 0, 0, 2, 1, &tx);
    ASSERT_EQ(0, err);

    /* Reuse one kblk and all vblks */
    uint64_t kblkv_left[2] = {3, 4};
    uint64_t kblkv_right[2] = {2, 5};

    err = cndb_record_kvset_add(cndb, tx, cnid, cndb_nodeid_mint(cndb), &km, kvsetid_left, hbid_left,
                                NELEM(kblkv_left), kblkv_left, NELEM(vblkv_ingest), vblkv_ingest, &c1);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add(cndb, tx, cnid, cndb_nodeid_mint(cndb), &km, kvsetid_right, hbid_right,
                                NELEM(kblkv_right), kblkv_right, NELEM(vblkv_ingest), vblkv_ingest, &c2);
    ASSERT_EQ(0, err);

    void *delcookie;
    err = cndb_record_kvset_del(cndb, tx, cnid, kvsetid_ingest, &delcookie);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, c1);
    ASSERT_EQ(0, err);

    /* With only one kvset_add record acked, this txn should be rolled back when we come back up.
     */

    /* Reopen and replay */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    struct kvdb_rparams rp = kvdb_rparams_defaults();
    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    uint64_t seqno_out, ingestid_out, txhorizon_out;

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    /* Expect 5 mblock deletes during rollback: All kblocks from kblkv_left and kblkv_right, except
     * kblk 2, because that is not a new kblock, it is shared or handed over from kblkv_ingest. And
     * 2 hblkids - hblkid_left and hblkid_right
     */
    ASSERT_EQ(5, mapi_calls(mapi_idx_mpool_mblock_delete));

    g_cb_ctr = 0;
    err = cndb_cn_instantiate(cndb, cnid, (void *)kvsetid_ingest, (void *)assert_ingest_kvset);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, g_cb_ctr); /* Only one kvset needs to be instantiated */
}

static merr_t
assert_two_kvsets(void *ctx, struct kvset_meta *km, u64 kvsetid)
{
    uint64_t *remv = (uint64_t *)ctx;

    if (kvsetid != remv[g_cb_ctr++])
        return merr(EBUG);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, rollforward, test_pre, test_post)
{
    struct mpool *mp = (void *)-1;
    merr_t err;
    uint64_t seqno = 0;
    struct cndb_txn *tx;

    struct t_kvset k1 = { .nid = 0, .kb = BLKS(1, 2), .vb = BLKS(10, 20, 30) };

    /* Create */
    err = cndb_record_txstart(cndb, ++seqno, 0, 0, 1, 0, &tx);
    ASSERT_EQ(0, err);

    uint64_t dgen = 0;
    uint64_t kvsetid[3];
    void *cookie;

    cookie = kvset_add(cndb, tx, ++dgen, k1, &kvsetid[0]);
    ASSERT_NE(0, cookie);

    err = cndb_record_kvset_add_ack(cndb, tx, cookie);
    ASSERT_EQ(0, err);

    /* Test */
    void *c1, *c2;

    err = cndb_record_txstart(cndb, 2, 0, 0, 2, 1, &tx);
    ASSERT_EQ(0, err);

    /* Reuse one kblk and all vblks */
    struct t_kvset k[] = {
        { .nid = 0, .kb = BLKS(3, 4), .vb = BLKS(10, 20, 30) },
        { .nid = 0, .kb = BLKS(2, 5), .vb = BLKS(10, 20, 30) },
    };

    c1 = kvset_add(cndb, tx, ++dgen, k[0], &kvsetid[1]);
    ASSERT_NE(0, c1);
    c2 = kvset_add(cndb, tx, ++dgen, k[1], &kvsetid[2]);
    ASSERT_NE(0, c2);

    void *delcookie = kvset_del(cndb, tx, kvsetid[0]);
    ASSERT_NE(0, delcookie);

    err = cndb_record_kvset_add_ack(cndb, tx, c1);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, c2);
    ASSERT_EQ(0, err);

    /* Do not ack the delete record, and this transaction should be rolled forward.
     */

    /* Reopen and replay */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    struct kvdb_rparams rp = kvdb_rparams_defaults();
    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    uint64_t seqno_out, ingestid_out, txhorizon_out;

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    /* Expect 1 mblock delete during rollback: Kblock 2 from kblkv_ingest[] is reused and so are
     * all mblocks from vblk_ingest. So only kblk 1 will be deleted. Also, hblkid_ingest.
     */
    ASSERT_EQ(2, mapi_calls(mapi_idx_mpool_mblock_delete));

    uint64_t remaining[2] = {kvsetid[1], kvsetid[2]};

    g_cb_ctr = 0;
    err = cndb_cn_instantiate(cndb, cnid, (void *)&remaining, (void *)assert_two_kvsets);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, g_cb_ctr); /* Only one kvset needs to be instantiated */

    /* Reopen the recovered kvdb.
     */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mapi_calls(mapi_idx_mpool_mblock_delete));
}

MTF_DEFINE_UTEST(cndb_test, multiple_kvs)
{
    struct mpool *mp = (void *)-1;
    merr_t err;
    struct cndb *cndb;
    uint64_t oid1, oid2;

    /* Setup */
    err = cndb_create(mp, 0, &oid1, &oid2);
    ASSERT_EQ(0, err);

    struct kvdb_rparams rp = kvdb_rparams_defaults();
    err = cndb_open(mp, oid1, oid2, &rp, &cndb);
    ASSERT_EQ(0, err);

    uint64_t cnid;
    struct kvs_cparams cp = kvs_cparams_defaults();

    /* Test */
    ASSERT_EQ(0, cndb_kvs_count(cndb));

    err = cndb_record_kvs_add(cndb, &cp, &cnid, "kvs-01");
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, cnid);
    ASSERT_EQ(1, cndb_kvs_count(cndb));

    err = cndb_record_kvs_add(cndb, &cp, &cnid, "kvs-02");
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, cnid);
    ASSERT_EQ(2, cndb_kvs_count(cndb));

    err = cndb_record_kvs_add(cndb, &cp, &cnid, "kvs-03");
    ASSERT_EQ(0, err);
    ASSERT_EQ(3, cnid);
    ASSERT_EQ(3, cndb_kvs_count(cndb));

    err = cndb_record_kvs_del(cndb, 2);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, cndb_kvs_count(cndb));

    err = cndb_record_kvs_add(cndb, &cp, &cnid, "kvs-02");
    ASSERT_EQ(0, err);
    ASSERT_EQ(4, cnid);
    ASSERT_EQ(3, cndb_kvs_count(cndb));

    /* Verify */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    err = cndb_open(mp, oid1, oid2, &rp, &cndb);
    ASSERT_EQ(0, err);

    uint64_t seqno_out, ingestid_out, txhorizon_out;

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    ASSERT_EQ(3, cndb_kvs_count(cndb));

    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    err = cndb_destroy(mp, oid1, oid2);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, compact_no_recovery, test_pre, test_post)
{
    merr_t err;
    struct mpool *mp = (void *)-1;

    g_mbid = 0;

    uint64_t kvsetid_ingest, kvsetid_left, kvsetid_right;
    struct t_kvset k[] = {
        {.nid = 0, .kb = BLKS(1, 2), .vb = BLKS(10, 20, 30)},
        {.nid = 2, .kb = BLKS(3, 4), .vb = BLKS(10, 20, 30)},
        {.nid = 3, .kb = BLKS(2, 5), .vb = BLKS(10, 20, 30)},
    };
    void *c1, *c2;
    uint64_t dgen = 0;

    /* Create */
    struct cndb_txn *tx;
    err = txstart(cndb, 1, 0, &tx);
    ASSERT_EQ(0, err);

    c1 = kvset_add(cndb, tx, ++dgen, k[0], &kvsetid_ingest);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, c1);
    ASSERT_EQ(0, err);

    /* Begin Test */
    err = txstart(cndb, 2, 1, &tx);
    ASSERT_EQ(0, err);

    /* Reuse one kblk and all vblks */
    c1 = kvset_add(cndb, tx, ++dgen, k[1], &kvsetid_left);
    ASSERT_NE(0, c1);

    c2 = kvset_add(cndb, tx, ++dgen, k[2], &kvsetid_right);
    ASSERT_NE(0, c2);

    void *delcookie = kvset_del(cndb, tx, kvsetid_ingest);
    ASSERT_NE(0, delcookie);

    err = cndb_record_kvset_add_ack(cndb, tx, c1);
    ASSERT_EQ(0, err);

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    /* Compact with one complete and one incomplete transaction.
     */
    err = cndb_compact(cndb);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mapi_calls(mapi_idx_mpool_mblock_delete));

    err = cndb_record_kvset_add_ack(cndb, tx, c2);
    ASSERT_EQ(0, err);

    /* Compact with one complete and one incomplete transaction.
     */
    err = cndb_compact(cndb);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mapi_calls(mapi_idx_mpool_mblock_delete));

    err = cndb_record_kvset_del_ack(cndb, tx, delcookie);
    ASSERT_EQ(0, err);

    /* Compact with two complete transactions.
     */
    err = cndb_compact(cndb);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mapi_calls(mapi_idx_mpool_mblock_delete));

    /* Reopen and replay.
     */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    struct kvdb_rparams rp = kvdb_rparams_defaults();
    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    /* All txns must be complete, no recovery necessary.
     */
    uint64_t seqno_out, ingestid_out, txhorizon_out;

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mapi_calls(mapi_idx_mpool_mblock_delete));

    g_cb_ctr = 0;
    err = cndb_cn_instantiate(cndb, cnid, NULL, (void *)replay_full_cb);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, g_cb_ctr); /* kvsetid_left and kvsetid_right */
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, only_deletes_rollforward, test_pre, test_post)
{
    struct cndb_txn *tx;
    merr_t err;

    /* Create */
    struct t_kvset k[] = {
        { .nid = 0, .kb = BLKS(1, 2), .vb = BLKS(10, 20, 30) },
        { .nid = 0, .kb = BLKS(3, 4), .vb = BLKS(11, 21, 31) },
        { .nid = 0, .kb = BLKS(5, 6), .vb = BLKS(12, 22, 32) },
    };

    err = txstart(cndb, NELEM(k), 0, &tx);
    ASSERT_EQ(0, err);

    uint64_t dgen = 0;
    uint64_t kvsetid[5];
    void *add_cookiev[3];

    add_cookiev[0] = kvset_add(cndb, tx, ++dgen, k[0], &kvsetid[0]);
    ASSERT_NE(0, add_cookiev[0]);
    add_cookiev[1] = kvset_add(cndb, tx, ++dgen, k[1], &kvsetid[1]);
    ASSERT_NE(0, add_cookiev[1]);
    add_cookiev[2] = kvset_add(cndb, tx, ++dgen, k[2], &kvsetid[2]);
    ASSERT_NE(0, add_cookiev[2]);

    err = cndb_record_kvset_add_ack(cndb, tx, add_cookiev[0]);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, add_cookiev[1]);
    ASSERT_EQ(0, err);

    err = cndb_record_kvset_add_ack(cndb, tx, add_cookiev[2]);
    ASSERT_EQ(0, err);

    /* Delete-only */
    err = txstart(cndb, 0, 2, &tx);
    ASSERT_EQ(0, err);

    void *del_cookiev[2];

    del_cookiev[0] = kvset_del(cndb, tx, kvsetid[1]);
    ASSERT_NE(0, del_cookiev[0]);

    del_cookiev[1] = kvset_del(cndb, tx, kvsetid[2]);
    ASSERT_NE(0, del_cookiev[1]);

    /* Reopen and replay. */
    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    struct mpool *mp = (void *)-1;
    struct kvdb_rparams rp = kvdb_rparams_defaults();

    err = cndb_open(mp, 0, 0, &rp, &cndb);
    ASSERT_EQ(0, err);

    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    /* Rollforward.  */
    uint64_t seqno_out, ingestid_out, txhorizon_out;

    err = cndb_replay(cndb, &seqno_out, &ingestid_out, &txhorizon_out);
    ASSERT_EQ(0, err);

    /* 2 hblocks, 4 kblocks and 6 vblocks = 12 blocks.
     */
    ASSERT_EQ(12, mapi_calls(mapi_idx_mpool_mblock_delete));

    g_cb_ctr = 0;
    err = cndb_cn_instantiate(cndb, cnid, NULL, (void *)replay_full_cb);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, g_cb_ctr); /* Only kvsetid1 */
}

MTF_END_UTEST_COLLECTION(cndb_test)
