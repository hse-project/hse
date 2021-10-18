/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>
#include <hse_util/log2.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/cn.h>
#include <mpool/mpool.h>

#include <cn/cndb_omf.h>
#include <cn/cn_internal.h>
#include <cn/cndb_internal.h>
#include <cn/kvset.h>

#include <mocks/mock_mpool.h>

MTF_BEGIN_UTEST_COLLECTION(cndb_test);

static struct kvdb_health mock_health;
static struct cndb        mock_cndb;

merr_t
test_unpack_v1(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    return 0;
}

merr_t
test_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    return 0;
}

struct cndb_upg_history cndb_upgh_test[2] = {
    {
        test_unpack_v1,
        4,
    },
    {
        test_unpack,
        5,
    },
};

static int
test_pre(struct mtf_test_info *ti)
{
    mapi_inject_clear();

    mock_mpool_set();

    mapi_inject(mapi_idx_mpool_mdc_alloc, 0);
    mapi_inject(mapi_idx_mpool_mdc_commit, 0);
    mapi_inject(mapi_idx_mpool_mdc_delete, 0);
    mapi_inject(mapi_idx_mpool_mdc_open, 0);
    mapi_inject(mapi_idx_mpool_mdc_close, 0);
    mapi_inject(mapi_idx_mpool_mdc_append, 0);
    mock_cndb.cndb_kvdb_health = &mock_health;

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    mapi_inject_unset(mapi_idx_mpool_mdc_open);
    mapi_inject_unset(mapi_idx_mpool_mdc_close);
    mapi_inject_unset(mapi_idx_mpool_mdc_alloc);
    mapi_inject_unset(mapi_idx_mpool_mdc_commit);
    mapi_inject_unset(mapi_idx_mpool_mdc_delete);
    mapi_inject_unset(mapi_idx_mpool_mdc_open);
    mapi_inject_unset(mapi_idx_mpool_mdc_close);
    mapi_inject_unset(mapi_idx_mpool_mdc_append);

    return 0;
}

MTF_DEFINE_UTEST(cndb_test, cndb_validate_vector_test)
{
    union cndb_mtu mtuv[2] = {};
    void *         pv[2] = { &mtuv[0], &mtuv[1] };

    mtuv[0].h.mth_type = CNDB_TYPE_TX;
    mtuv[1].h.mth_type = CNDB_TYPE_TXD;

    cndb_validate_vector(pv, sizeof(pv) / sizeof(*pv));
}

MTF_DEFINE_UTEST(cndb_test, omf2len_test)
{
    struct cndb_tx_omf  tx = {};
    struct cndb_txc_omf txc = {};
    struct cndb_txm_omf txm = {};
    struct cndb_txd_omf txd = {};
    struct cndb_ack_omf ack = {};
    struct cndb_nak_omf nak = {};
    struct cndb_ver_omf ver = {};
    u32                 sz;

    cndb_set_hdr(&tx.hdr, CNDB_TYPE_TX, sizeof(tx));
    cndb_set_hdr(&txc.hdr, CNDB_TYPE_TXC, sizeof(txc));
    cndb_set_hdr(&txm.hdr, CNDB_TYPE_TXM, sizeof(txm));
    cndb_set_hdr(&txd.hdr, CNDB_TYPE_TXD, sizeof(txd));
    cndb_set_hdr(&ack.hdr, CNDB_TYPE_ACK, sizeof(ack));
    cndb_set_hdr(&nak.hdr, CNDB_TYPE_NAK, sizeof(nak));
    cndb_set_hdr(&ver.hdr, CNDB_TYPE_VERSION, sizeof(ver));

    omf2len(&tx, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_tx));

    omf2len(&txc, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_txc));

    omf2len(&txm, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_txm));

    omf2len(&txd, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_txd));

    omf2len(&ack, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_ack));

    omf2len(&nak, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_nak));

    omf2len(&ver, CNDB_VERSION, &sz);
    ASSERT_EQ(sz, sizeof(struct cndb_ver));
}

MTF_DEFINE_UTEST(cndb_test, mtx2omf_test)
{
    struct cndb_tx_omf  tx = {};
    struct cndb_txc_omf txc = {};
    struct cndb_txm_omf txm = {};
    struct cndb_txd_omf txd = {};
    struct cndb_ack_omf ack = {};
    struct cndb_nak_omf nak = {};

    struct cndb_tx  mtx = { { CNDB_TYPE_TX }, 1, 2, 3, 4, 5, 6 };
    struct cndb_txc mtc = { { CNDB_TYPE_TXC }, 1, 2, 3, 0, 0, 0 };
    struct cndb_txm mtm = { { CNDB_TYPE_TXM }, 1, 2, 3, 4, 5, 6, 7, 8, 1 };
    struct cndb_txd mtd = { { CNDB_TYPE_TXD }, 1, 2, 3, 0 };
    struct cndb_ack mta = { { CNDB_TYPE_ACK }, 1, CNDB_ACK_TYPE_D, 3, 0 };
    struct cndb_nak mtn = { { CNDB_TYPE_NAK }, 1 };
    struct cndb_ver mtv = { { CNDB_TYPE_VERSION }, 1, 2, 0 };
    char            buf[CNDB_CBUFSZ_DEFAULT];

    mock_cndb.cndb_cbuf = buf;
    mock_cndb.cndb_cbufsz = sizeof(buf);

    mtx2omf(&mock_cndb, &tx, (void *)&mtx);
    ASSERT_EQ(CNDB_TYPE_TX, omf_cnhdr_type((void *)&tx));
    ASSERT_EQ(sizeof(tx) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&tx));
    ASSERT_EQ(1, omf_tx_id(&tx));
    ASSERT_EQ(2, omf_tx_nc(&tx));
    ASSERT_EQ(3, omf_tx_nd(&tx));
    ASSERT_EQ(4, omf_tx_seqno(&tx));
    ASSERT_EQ(5, omf_tx_ingestid(&tx));
    ASSERT_EQ(6, omf_tx_txhorizon(&tx));

    mtx2omf(&mock_cndb, &txc, (void *)&mtc);
    ASSERT_EQ(CNDB_TYPE_TXC, omf_cnhdr_type((void *)&txc));
    ASSERT_EQ(sizeof(txc) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&txc));
    ASSERT_EQ(1, omf_txc_cnid(&txc));
    ASSERT_EQ(2, omf_txc_id(&txc));
    ASSERT_EQ(3, omf_txc_tag(&txc));
    ASSERT_EQ(0, omf_txc_keepvbc(&txc));
    ASSERT_EQ(0, omf_txc_kcnt(&txc));
    ASSERT_EQ(0, omf_txc_vcnt(&txc));

    mtx2omf(&mock_cndb, &txm, (void *)&mtm);
    ASSERT_EQ(CNDB_TYPE_TXM, omf_cnhdr_type((void *)&txm));
    ASSERT_EQ(sizeof(txm) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&txm));
    ASSERT_EQ(1, omf_txm_cnid(&txm));
    ASSERT_EQ(2, omf_txm_id(&txm));
    ASSERT_EQ(3, omf_txm_tag(&txm));
    ASSERT_EQ(4, omf_txm_level(&txm));
    ASSERT_EQ(5, omf_txm_offset(&txm));
    ASSERT_EQ(6, omf_txm_dgen(&txm));
    ASSERT_EQ(7, omf_txm_vused(&txm));
    ASSERT_EQ(8, omf_txm_compc(&txm));
    ASSERT_EQ(1, omf_txm_scatter(&txm));

    mtx2omf(&mock_cndb, &txd, (void *)&mtd);
    ASSERT_EQ(CNDB_TYPE_TXD, omf_cnhdr_type((void *)&txd));
    ASSERT_EQ(sizeof(txd) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&txd));
    ASSERT_EQ(1, omf_txd_cnid(&txd));
    ASSERT_EQ(2, omf_txd_id(&txd));
    ASSERT_EQ(3, omf_txd_tag(&txd));
    ASSERT_EQ(0, omf_txd_n_oids(&txd));

    mtx2omf(&mock_cndb, &ack, (void *)&mta);
    ASSERT_EQ(CNDB_TYPE_ACK, omf_cnhdr_type((void *)&ack));
    ASSERT_EQ(sizeof(ack) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&ack));
    ASSERT_EQ(1, omf_ack_txid(&ack));
    ASSERT_EQ(CNDB_ACK_TYPE_D, omf_ack_type(&ack));
    ASSERT_EQ(3, omf_ack_tag(&ack));

    mtx2omf(&mock_cndb, &nak, (void *)&mtn);
    ASSERT_EQ(CNDB_TYPE_NAK, omf_cnhdr_type((void *)&nak));
    ASSERT_EQ(sizeof(nak) - sizeof(struct cndb_hdr_omf), omf_cnhdr_len((void *)&nak));
    ASSERT_EQ(1, omf_nak_txid(&nak));

    mtx2omf(&mock_cndb, NULL, (void *)&mtv); /* non-default case cores */
}

MTF_DEFINE_UTEST(cndb_test, omf2mtx_test)
{
    struct cndb_tx_omf  tx = {};
    struct cndb_txc_omf txc = {};
    struct cndb_txm_omf txm = {};
    struct cndb_txd_omf txd = {};
    struct cndb_ack_omf ack = {};
    struct cndb_nak_omf nak = {};
    struct cndb_ver_omf ver = {};

    struct cndb_tx  mcx = {};
    struct cndb_txc mcc = {};
    struct cndb_txm mcm = {};
    struct cndb_txd mcd = {};
    struct cndb_ack mca = {};
    struct cndb_nak mcn = {};

    struct cndb_tx  mtx = {};
    struct cndb_txc mtc = {};
    struct cndb_txm mtm = {};
    struct cndb_txd mtd = {};
    struct cndb_ack mta = {};
    struct cndb_nak mtn = {};
    struct cndb_ver mtv = {};

    int rc;

    mcx.hdr.mth_type = CNDB_TYPE_TX;
    mcx.mtx_id = 1;
    mcx.mtx_nc = 2;
    mcx.mtx_nd = 3;
    mcx.mtx_seqno = 4;
    mcx.mtx_ingestid = 5;

    mcc.hdr.mth_type = CNDB_TYPE_TXC;
    mcc.mtc_cnid = 1;
    mcc.mtc_id = 2;
    mcc.mtc_tag = 3;
    mcc.mtc_keepvbc = 4;
    mcc.mtc_kcnt = 0;
    mcc.mtc_vcnt = 0;

    mcm.hdr.mth_type = CNDB_TYPE_TXM;
    mcm.mtm_cnid = 1;
    mcm.mtm_id = 2;
    mcm.mtm_tag = 3;
    mcm.mtm_level = 4;
    mcm.mtm_offset = 5;
    mcm.mtm_dgen = 6;
    mcm.mtm_vused = 7;
    mcm.mtm_compc = 8;
    mcm.mtm_scatter = 1;

    mcd.hdr.mth_type = CNDB_TYPE_TXD;
    mcd.mtd_cnid = 1;
    mcd.mtd_id = 2;
    mcd.mtd_tag = 3;
    mcd.mtd_n_oids = 0;

    mca.hdr.mth_type = CNDB_TYPE_ACK;
    mca.mta_txid = 1;
    mca.mta_type = CNDB_ACK_TYPE_D;
    mca.mta_tag = 3;

    mcn.hdr.mth_type = CNDB_TYPE_NAK;
    mcn.mtn_txid = 1;

    omf_set_cnhdr_type((void *)&tx, CNDB_TYPE_TX);
    omf_set_cnhdr_len((void *)&tx, sizeof(tx) - sizeof(struct cndb_hdr_omf));
    omf_set_tx_id(&tx, 1);
    omf_set_tx_nc(&tx, 2);
    omf_set_tx_nd(&tx, 3);
    omf_set_tx_seqno(&tx, 4);
    omf_set_tx_ingestid(&tx, 5);
    omf2mtx((void *)&mtx, NULL, &tx, CNDB_VERSION);
    rc = memcmp(&mtx, &mcx, sizeof(mcx));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&txc, CNDB_TYPE_TXC);
    omf_set_cnhdr_len((void *)&txc, sizeof(txc) - sizeof(struct cndb_hdr_omf));
    omf_set_txc_cnid(&txc, 1);
    omf_set_txc_id(&txc, 2);
    omf_set_txc_tag(&txc, 3);
    omf_set_txc_keepvbc(&txc, 4);
    omf_set_txc_kcnt(&txc, 0);
    omf_set_txc_vcnt(&txc, 0);
    omf2mtx((void *)&mtc, NULL, &txc, CNDB_VERSION);
    rc = memcmp(&mtc, &mcc, sizeof(mcc));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&txm, CNDB_TYPE_TXM);
    omf_set_cnhdr_len((void *)&txm, sizeof(txm) - sizeof(struct cndb_hdr_omf));
    omf_set_txm_cnid(&txm, 1);
    omf_set_txm_id(&txm, 2);
    omf_set_txm_tag(&txm, 3);
    omf_set_txm_level(&txm, 4);
    omf_set_txm_offset(&txm, 5);
    omf_set_txm_dgen(&txm, 6);
    omf_set_txm_vused(&txm, 7);
    omf_set_txm_compc(&txm, 8);
    omf_set_txm_scatter(&txm, 1);
    omf2mtx((void *)&mtm, NULL, &txm, CNDB_VERSION);
    rc = memcmp(&mtm, &mcm, sizeof(mcm));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&txd, CNDB_TYPE_TXD);
    omf_set_cnhdr_len((void *)&txd, sizeof(txd) - sizeof(struct cndb_hdr_omf));
    omf_set_txd_cnid(&txd, 1);
    omf_set_txd_id(&txd, 2);
    omf_set_txd_tag(&txd, 3);
    omf_set_txd_n_oids(&txd, 0);
    omf2mtx((void *)&mtd, NULL, &txd, CNDB_VERSION);
    rc = memcmp(&mtd, &mcd, sizeof(mcd));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&ack, CNDB_TYPE_ACK);
    omf_set_cnhdr_len((void *)&ack, sizeof(ack) - sizeof(struct cndb_hdr_omf));
    omf_set_ack_txid(&ack, 1);
    omf_set_ack_type(&ack, CNDB_ACK_TYPE_D);
    omf_set_ack_tag(&ack, 3);
    omf2mtx((void *)&mta, NULL, &ack, CNDB_VERSION);
    rc = memcmp(&mta, &mca, sizeof(mca));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&nak, CNDB_TYPE_NAK);
    omf_set_cnhdr_len((void *)&nak, sizeof(nak) - sizeof(struct cndb_hdr_omf));
    omf_set_nak_txid(&nak, 1);
    omf2mtx((void *)&mtn, NULL, &nak, CNDB_VERSION);
    rc = memcmp(&mtn, &mcn, sizeof(mcn));
    ASSERT_EQ(0, rc);

    omf_set_cnhdr_type((void *)&ver, CNDB_TYPE_VERSION);
    omf_set_cnhdr_len((void *)&ver, sizeof(ver) - sizeof(struct cndb_hdr_omf));
    omf_set_cnver_magic(&ver, CNDB_MAGIC);
    omf_set_cnver_version(&ver, CNDB_VERSION);
    omf2mtx((void *)&mtv, NULL, &ver, CNDB_VERSION);
    ASSERT_EQ(CNDB_TYPE_VERSION, mtv.hdr.mth_type);
    ASSERT_EQ(CNDB_MAGIC, mtv.mtv_magic);
    ASSERT_EQ(CNDB_VERSION, mtv.mtv_version);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_txc_bitmap, test_pre, test_post)
{
    struct kvset_mblocks mb = {};
    struct cndb          cndb = {};
    struct kvdb_health   health;
    struct cndb_txc *    mtc;
    u64                  txid = 0;
    u64                  tag;
    merr_t               err;
    int                  i;

    mapi_inject(mapi_idx_mpool_mdc_usage, 0);

    cndb_init(&cndb, NULL, false, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    cndb.cndb_captgt = CNDB_CAPTGT_DEFAULT;
    cndb.cndb_high_water = CNDB_HIGH_WATER(&cndb);

    err = cndb_txn_txc(&cndb, txid, 0, &tag, NULL, 0);
    ASSERT_EQ(0, err);

    err = cndb_txn_txc(&cndb, txid, 0, &tag, &mb, 0);
    ASSERT_EQ(0, err);

    err = cndb_txn_txc(&cndb, txid, 0, &tag, &mb, 10);
    ASSERT_EQ(0, err);

    mb.kblks.n_blks = 10;
    mb.kblks.blks = calloc(mb.kblks.n_blks, sizeof(struct kvs_block));
    mb.vblks.n_blks = 100;
    mb.vblks.blks = calloc(mb.vblks.n_blks, sizeof(struct kvs_block));

    err = cndb_txn_txc(&cndb, txid, 0, &tag, &mb, 10);
    ASSERT_EQ(0, err);
    mtc = (struct cndb_txc *)cndb.cndb_workv[3];
    ASSERT_EQ(mtc->mtc_keepvbc, 10);
    ASSERT_EQ(mtc->mtc_kcnt, mb.kblks.n_blks);
    ASSERT_EQ(mtc->mtc_vcnt, mb.vblks.n_blks);

    free(mb.vblks.blks);
    free(mb.kblks.blks);

    for (i = 0; i < cndb.cndb_workc; ++i)
        free(cndb.cndb_workv[i]);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
}

MTF_DEFINE_UTEST(cndb_test, nfault_probes_test)
{
    struct nfault_probe probes[4] = { {},
                                      { 0, { NFAULT_TRIG_ONESHOT, 3 } },
                                      { 0, { NFAULT_TRIG_PERIOD, 3 } },
                                      { 0, { NFAULT_TRIG_LEVEL, 3 } } };
    int                 i;
    int                 trig;

    for (i = 1; i <= 4; i++) {
        trig = nfault_probe(probes, 0);
        ASSERT_EQ(trig, NFAULT_TRIG_NONE);
    }

    for (i = 1; i <= 4; i++) {
        trig = nfault_probe(probes, 1);
        if (i != 3)
            ASSERT_EQ(trig, NFAULT_TRIG_NONE);
        else
            ASSERT_EQ(trig, NFAULT_TRIG_ONESHOT);
    }

    for (i = 1; i <= 10; i++) {
        trig = nfault_probe(probes, 2);
        if (i % 3)
            ASSERT_EQ(trig, NFAULT_TRIG_NONE);
        else
            ASSERT_EQ(trig, NFAULT_TRIG_PERIOD);
    }

    for (i = 1; i <= 10; i++) {
        trig = nfault_probe(probes, 3);
        if (i < 3)
            ASSERT_EQ(trig, NFAULT_TRIG_NONE);
        else
            ASSERT_EQ(trig, NFAULT_TRIG_LEVEL);
    }
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_cnv_add_test, test_pre, test_post)
{
    struct cndb cndb = {};
    int         i;
    merr_t      err;

    struct kvs_cparams cp = {
        .fanout = 1 << 1,
        .pfx_len = 2,
        .pfx_pivot = 0,
    };

    cndb.cndb_kvdb_health = &mock_health;

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = cndb_cnv_add(&cndb, 0, &cp, 3, "", 0, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    ASSERT_EQ(0, cndb.cndb_cnc);

    ASSERT_EQ(256, HSE_KVS_COUNT_MAX);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        u32 meta = (((ulong)i << 24) + i) ^ 0xaa55aa55;

        err = cndb_cnv_add(&cndb, 0, &cp, i, "", sizeof(meta), &meta);
        if (err)
            break;
    }
    ASSERT_EQ(0, err);
    ASSERT_EQ(HSE_KVS_COUNT_MAX, cndb.cndb_cnc);

    err = cndb_cnv_add(&cndb, 0, &cp, i, "", 0, NULL);
    ASSERT_EQ(ENFILE, merr_errno(err));
    ASSERT_EQ(HSE_KVS_COUNT_MAX, cndb.cndb_cnc);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        u32    expect = (((ulong)i << 24) + i) ^ 0xaa55aa55;
        u64    expect8 = (u64)expect << 32 | (u64)expect;
        u32 *  meta;
        size_t metasz;
        u64 *  meta8;

        err = cndb_cn_blob_get(&cndb, i, &metasz, (void **)&meta);

        ASSERT_EQ(0, err);
        ASSERT_EQ(sizeof(*meta), metasz);
        ASSERT_EQ(*meta, expect);

        cndb.cndb_read_only = true;
        err = cndb_cn_blob_set(&cndb, i, sizeof(expect8), &expect8);
        cndb.cndb_read_only = false;

        ASSERT_EQ(EROFS, merr_errno(err));

        err = cndb_cn_blob_get(&cndb, i, &metasz, (void **)&meta8);

        ASSERT_EQ(0, err);
        ASSERT_EQ(sizeof(*meta8), metasz);
        ASSERT_EQ(*meta8, expect8);

        free(meta);
        free(meta8);
    }

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        err = cndb_cnv_del(&cndb, 0);
        ASSERT_EQ(0, err);
    }

    ASSERT_EQ(0, cndb.cndb_cnc);
}

MTF_DEFINE_UTEST(cndb_test, mtxutil_test)
{
    enum {
        INVAL_0 = 0,
        CNID_1 = 1,
        TXID_2 = 2,
        TAG_3 = 3,
    };

    struct cndb_tx  tx = { { CNDB_TYPE_TX }, TXID_2, 5, 3, 4 };
    struct cndb_txc txc = { { CNDB_TYPE_TXC }, CNID_1, TXID_2, TAG_3, 5, 0, 0 };
    struct cndb_txm txm = { { CNDB_TYPE_TXM }, CNID_1, TXID_2, TAG_3, 4, 5, 6, 7, 8, 1 };
    struct cndb_txd txd = { { CNDB_TYPE_TXD }, CNID_1, TXID_2, TAG_3, 0 };
    struct cndb_ack ack = { { CNDB_TYPE_ACK }, TXID_2, CNDB_ACK_TYPE_D, TAG_3, 0 };
    struct cndb_nak nak = { { CNDB_TYPE_NAK }, TXID_2 };
    struct cndb_ver ver = { { CNDB_TYPE_VERSION }, CNDB_MAGIC, CNDB_VERSION, 0 };
    u64             value;

    value = mtxcnid((void *)&tx);
    ASSERT_EQ(INVAL_0, value);

    value = mtxcnid((void *)&txc);
    ASSERT_EQ(CNID_1, value);

    value = mtxcnid((void *)&txm);
    ASSERT_EQ(CNID_1, value);

    value = mtxcnid((void *)&txd);
    ASSERT_EQ(CNID_1, value);

    value = mtxtag((void *)&tx);
    ASSERT_EQ(INVAL_0, value);

    value = mtxtag((void *)&txc);
    ASSERT_EQ(TAG_3, value);

    value = mtxtag((void *)&txm);
    ASSERT_EQ(TAG_3, value);

    value = mtxtag((void *)&txd);
    ASSERT_EQ(TAG_3, value);

    value = mtxtag((void *)&ack);
    ASSERT_EQ(TAG_3, value);

    value = mtxid((void *)&ver);
    ASSERT_EQ(INVAL_0, value);

    value = mtxid((void *)&tx);
    ASSERT_EQ(TXID_2, value);

    value = mtxid((void *)&txc);
    ASSERT_EQ(TXID_2, value);

    value = mtxid((void *)&txm);
    ASSERT_EQ(TXID_2, value);

    value = mtxid((void *)&txd);
    ASSERT_EQ(TXID_2, value);

    value = mtxid((void *)&ack);
    ASSERT_EQ(TXID_2, value);

    value = mtxid((void *)&nak);
    ASSERT_EQ(TXID_2, value);
}

MTF_DEFINE_UTEST(cndb_test, cmp_test)
{
    int            rc;
    union cndb_mtu u = {};
    union cndb_mtu v = {};
    void *         up = &u;
    void *         vp = &v;

    u.h.mth_type = CNDB_TYPE_ACK;
    u.a.mta_txid = 1;

    v.h.mth_type = CNDB_TYPE_TXD;
    v.d.mtd_id = 2;

    rc = cndb_cmp(&up, &vp);
    ASSERT_GT(0, rc);

    u.a.mta_txid = 3;
    rc = cndb_cmp(&up, &vp);
    ASSERT_LT(0, rc);

    u.a.mta_txid = 2;
    rc = cndb_cmp(&up, &vp);
    ASSERT_GT(0, rc);

    rc = cndb_cmp(&vp, &up);
    ASSERT_LT(0, rc);

    v.d.mtd_id = 0;
    v.h.mth_type = u.h.mth_type;
    v.a.mta_txid = u.a.mta_txid;
    u.a.mta_tag = 1;
    v.a.mta_tag = 2;

    rc = cndb_cmp(&up, &vp);
    ASSERT_GT(0, rc);

    rc = cndb_cmp(&vp, &up);
    ASSERT_LT(0, rc);

    v.a.mta_tag = u.a.mta_tag;
    rc = cndb_cmp(&up, &vp);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_tagalloc_test, test_pre, test_post)
{
    struct cndb      cndb = {};
    struct cndb_tx   tx = {};
    struct cndb_txc  txc = {};
    struct cndb_txm  txm = {};
    struct cndb_ack  ack = {};
    struct cndb_idx *tagv[CNDB_ENTRIES] = { 0 };
    merr_t           err;
    int              i;

    cndb.cndb_tagv = &tagv[0];
    cndb.cndb_tagc = CNDB_ENTRIES;
    cndb.cndb_entries = CNDB_ENTRIES;

    err = cndb_tagalloc(&cndb, &txc, &tx, true);
    ASSERT_EQ(EMLINK, merr_errno(err));

    cndb.cndb_tagc = 0;
    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = cndb_tagalloc(&cndb, &txc, &tx, true);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    txc.mtc_tag = 2;
    txm.mtm_tag = txc.mtc_tag;

    err = cndb_tagalloc(&cndb, &txc, &tx, true);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, tagv[0]);
    ASSERT_EQ(1, cndb.cndb_tagc);

    err = cndb_tagmeta(&cndb, &txm);
    ASSERT_EQ(0, err);

    err = cndb_tagack(&cndb, txc.mtc_tag, &ack);
    ASSERT_EQ(0, err);

    err = cndb_tagdel(&cndb, 1);
    ASSERT_EQ(EL2NSYNC, merr_errno(err));

    err = cndb_tagdel(&cndb, 2);
    ASSERT_EQ(0, err);

    /* and tagdel doesn't actually remove the tag, so */
    for (i = 0; i < CNDB_ENTRIES; ++i)
        free(tagv[i]);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, import_md_test, test_pre, test_post)
{
    struct cndb     cndb = {};
    merr_t          err;
    union cndb_mtu *mtu;
    int             i;

    struct cndb_ver_omf  ver = {};
    struct cndb_info_omf inf = {};
    struct cndb_tx_omf   tx = {};

    cndb.cndb_version = CNDB_VERSION;
    cndb.cndb_entries = CNDB_ENTRIES;
    cndb.cndb_workv = calloc(CNDB_ENTRIES, sizeof(void **));
    ASSERT_NE(NULL, cndb.cndb_workv);

    cndb_set_hdr(&ver.hdr, CNDB_TYPE_VERSION, sizeof(ver));
    err = cndb_import_md(&cndb, &ver.hdr, &mtu);
    ASSERT_EQ(EPROTO, merr_errno(err));
    ASSERT_EQ(0, cndb.cndb_workc);
    ASSERT_EQ(0, cndb.cndb_keepc);
    ASSERT_EQ(0, cndb.cndb_cnc);
    free(cndb.cndb_tagv);
    free(cndb.cndb_keepv);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    cndb_set_hdr(&inf.hdr, CNDB_TYPE_INFO, sizeof(inf));
    err = cndb_import_md(&cndb, &inf.hdr, &mtu);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    ASSERT_EQ(0, cndb.cndb_workc);
    ASSERT_EQ(0, cndb.cndb_keepc);
    ASSERT_EQ(0, cndb.cndb_cnc);
    free(cndb.cndb_tagv);
    free(cndb.cndb_keepv);

    cndb.cndb_workc = CNDB_ENTRIES;
    cndb_set_hdr(&tx.hdr, CNDB_TYPE_TX, sizeof(tx));
    err = cndb_import_md(&cndb, &tx.hdr, &mtu);
    ASSERT_EQ(0, err);
    ASSERT_LT(CNDB_ENTRIES, cndb.cndb_workc);
    ASSERT_EQ(0, cndb.cndb_keepc);
    ASSERT_EQ(0, cndb.cndb_cnc);
    free(cndb.cndb_tagv);
    free(cndb.cndb_keepv);
    free(mtu);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    cndb.cndb_workc = 0;
    cndb_set_hdr(&tx.hdr, CNDB_TYPE_TX, sizeof(tx));
    err = cndb_import_md(&cndb, &tx.hdr, &mtu);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    ASSERT_EQ(0, cndb.cndb_workc);
    ASSERT_EQ(0, cndb.cndb_keepc);
    ASSERT_EQ(0, cndb.cndb_cnc);

    cndb.cndb_workc = 0;
    cndb_set_hdr(&tx.hdr, CNDB_TYPE_TX, sizeof(tx));
    err = cndb_import_md(&cndb, &tx.hdr, &mtu);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, cndb.cndb_workc);
    ASSERT_EQ(0, cndb.cndb_keepc);
    ASSERT_EQ(0, cndb.cndb_cnc);

    for (i = 0; i < cndb.cndb_workc; ++i)
        free(cndb.cndb_workv[i]);
    free(cndb.cndb_workv);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_blkdel_test, test_pre, test_post)
{
    struct cndb cndb = {};
    merr_t      err;

    enum {
        INVAL_0 = 0,
        CNID_1 = 1,
        TXID_2 = 2,
        TAG_3 = 3,
    };

    struct cndb_txc  txc = { { CNDB_TYPE_TXC }, CNID_1, TXID_2, TAG_3, 0, 0, 0 };
    struct cndb_txd  txd = { { CNDB_TYPE_TXD }, CNID_1, TXID_2, TAG_3, 0 };
    char             buf[CNDB_CBUFSZ_DEFAULT];
    struct cndb_txd *db = (void *)&buf;
    u64 *            oidp;

    err = cndb_blkdel(&cndb, (void *)&txc, TXID_2);
    ASSERT_EQ(0, err);

    err = cndb_blkdel(&cndb, (void *)&txd, TXID_2);
    ASSERT_EQ(0, err);

    db->hdr.mth_type = txd.hdr.mth_type;
    db->mtd_cnid = txd.mtd_cnid;
    db->mtd_id = txd.mtd_id;
    db->mtd_tag = txd.mtd_tag;
    db->mtd_n_oids = 1;
    oidp = (void *)&db[1];
    *oidp = 0x21122112;

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    err = cndb_blkdel(&cndb, (void *)db, TXID_2);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, ENOENT);
    err = cndb_blkdel(&cndb, (void *)db, TXID_2);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, EINVAL);
    err = cndb_blkdel(&cndb, (void *)db, TXID_2);
    ASSERT_EQ(EINVAL, merr_errno(err));
    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = cndb_blkdel(&cndb, (void *)db, TXID_2);
    ASSERT_EQ(ENOMEM, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_create_test, test_pre, test_post)
{
    merr_t        err;
    struct mpool *ds = (struct mpool *)-1;
    u64           oid1, oid2;

    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(err, 0);
    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(err, 0);

    mapi_inject(mapi_idx_mpool_mdc_close, 1);
    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(err, 0);
    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(err, 1);
    mapi_inject(mapi_idx_mpool_mdc_close, 0);

    mapi_inject(mapi_idx_mpool_mdc_alloc, merr(EBUG));
    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(merr_errno(err), EBUG);
    mapi_inject(mapi_idx_mpool_mdc_alloc, 0);

    mapi_inject(mapi_idx_mpool_mdc_commit, merr(EBUG));
    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(err, 0);
    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(merr_errno(err), EBUG);
    mapi_inject(mapi_idx_mpool_mdc_commit, 0);

    mapi_inject(mapi_idx_mpool_mdc_open, merr(EBUG));
    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(err, 0);
    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(merr_errno(err), EBUG);
    mapi_inject(mapi_idx_mpool_mdc_open, 0);

    mapi_inject(mapi_idx_mpool_mdc_append, merr(EBUG));
    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(err, 0);
    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(merr_errno(err), EBUG);
    mapi_inject(mapi_idx_mpool_mdc_append, 0);
}

/* Test to verify that a cndb_cn_create updates in memory structures (cndb_cnv[])
 */
MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_cn_create_updates_cnv, test_pre, test_post)
{
    merr_t             err;
    struct mpool *     ds = (struct mpool *)-1;
    u64                oid1, oid2;
    struct cndb *      c;
    u64                cnid = 1;
    struct kvs_cparams cp = kvs_cparams_defaults();

    struct cndb_cn *    cn;
    struct kvs_cparams *icp;

    u64  getcnid;
    u32  getflags;
    char getname[CNDB_CN_NAME_MAX];

    cp.fanout = 4;
    cp.pfx_len = 6;

    err = cndb_alloc(ds, 0, &oid1, &oid2);
    ASSERT_EQ(0, err);

    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(0, err);

    err = cndb_open(ds, false, 0, 0, 0, 0, &mock_health, NULL, &c);
    ASSERT_EQ(0, err);

    c->cndb_high_water = 16384;
    c->cndb_captgt = 32768;

    mapi_inject(mapi_idx_cn_make, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    err = cndb_cn_create(c, &cp, &cnid, "sabotage");
    ASSERT_EQ(0, err);
    mapi_inject_unset(mapi_idx_cn_make);
    mapi_inject_unset(mapi_idx_mpool_mdc_usage);

    err = cndb_cnv_get(c, cnid, &cn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, ilog2(cn->cn_cp.fanout));
    ASSERT_EQ(6, cn->cn_cp.pfx_len);

    err = cndb_cn_info_idx(c, 42, NULL, NULL, NULL, NULL, 0);
    ASSERT_EQ(ESTALE, merr_errno(err));

    err = cndb_cn_info_idx(c, 0, NULL, NULL, NULL, NULL, 0);
    ASSERT_EQ(0, err);

    getcnid = 42;
    getflags = CN_CFLAG_CAPPED;

    memset(getname, 0, sizeof(getname));
    err = cndb_cn_info_idx(c, 0, &getcnid, &getflags, &icp, getname, sizeof(getname));
    ASSERT_EQ(0, err);
    ASSERT_EQ(cnid, getcnid);
    ASSERT_EQ(0, getflags);
    ASSERT_EQ(2, ilog2(icp->fanout));
    ASSERT_EQ(6, icp->pfx_len);
    ASSERT_EQ(0, strcmp(getname, "sabotage"));

    cndb_close(c);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_open_test, test_pre, test_post)
{
    merr_t        err;
    struct mpool *ds = (struct mpool *)-1;
    u64           oid1 = 0, oid2 = 0;
    struct cndb * c;

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = cndb_open(ds, false, 0, 0, 0, 0, &mock_health, NULL, &c);
    ASSERT_EQ(merr_errno(err), ENOMEM);

    err = cndb_open(ds, false, 0, 0, 0, 0, &mock_health, NULL, &c);
    ASSERT_EQ(err, 0);

    err = cndb_close(c);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mdc_open, merr(EBUG));

    err = cndb_create(ds, 0, oid1, oid2);
    ASSERT_EQ(merr_errno(err), EBUG);

    err = cndb_open(ds, false, 0, 0, 0, 0, &mock_health, NULL, &c);
    ASSERT_EQ(merr_errno(err), EBUG);
    mapi_inject(mapi_idx_mpool_mdc_open, 0);

    err = cndb_close(0);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(cndb_test, cndb_misc_test)
{
    merr_t                err;
    struct cn             cn = {};
    struct kvset_mblocks  mb = {};
    struct cn *           cnv[1] = { &cn };
    struct kvset_mblocks *mbv[1] = { &mb };
    struct cndb           cndb = {};
    struct kvs_rparams    rp = {};
    u64                   tag;
    u64                   txid;
    u64                   seqno;
    struct kvset_meta     km = {};
    struct kvdb_health    health;
    u64                   ingestid, txhorizon;

    cn.cn_cndb = &cndb;
    cn.rp = &rp;
    cndb.cndb_kvdb_health = &health;

    mutex_init(&cndb.cndb_lock);
    err = cndb_cn_drop(&cndb, 0);
    ASSERT_EQ(ENOENT, merr_errno(err));

    mapi_inject(mapi_idx_mpool_mdc_read, 1);
    mapi_inject(mapi_idx_mpool_mdc_append, 0);
    mapi_inject(mapi_idx_cndb_journal, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 1);
    err = cn_ingestv(cnv, mbv, 1, U64_MAX, U64_MAX, NULL, NULL);
    ASSERT_EQ(1, err);

    err = cn_ingestv(cnv, mbv, 1, U64_MAX, U64_MAX, NULL, NULL);
    ASSERT_EQ(1, err);

    err = cndb_replay(&cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(1, err);

    mapi_inject(mapi_idx_mpool_mdc_read, 0);
    err = cndb_replay(&cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(ENODATA, merr_errno(err));

    err = cndb_txn_start(&cndb, &txid, 0, 0, 0, 0, 0);
    ASSERT_EQ(1, err);

    tag = 0;
    err = cndb_txn_txc(&cndb, txid, 0, &tag, &mb, 0);
    ASSERT_EQ(1, err);

    err = cndb_txn_txc(&cndb, txid, 0, &tag, NULL, 0);
    ASSERT_EQ(1, err);

    /* Shenanigans: using txid as an oid */
    /* cndb_txn_txd() will assert that txid > tag */
    txid = tag + 1;
    err = cndb_txn_txd(&cndb, txid, 0, tag, 1, &txid);
    ASSERT_EQ(1, err);

    err = cndb_txn_meta(&cndb, txid, 0, tag, &km);
    ASSERT_EQ(1, err);

    err = cndb_txn_ack_c(&cndb, txid);
    ASSERT_EQ(1, err);

    err = cndb_txn_ack_d(&cndb, txid, tag, 0);
    ASSERT_EQ(1, err);

    err = cndb_txn_nak(&cndb, txid);
    ASSERT_EQ(1, err);

    free(cndb.cndb_cbuf);

    mapi_inject_unset(mapi_idx_cndb_journal);
    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mdc_read);
    mapi_inject_unset(mapi_idx_mpool_mdc_append);
}

MTF_DEFINE_UTEST(cndb_test, cndb_compaction_test)
{
    merr_t               err;
    struct cndb *        cndb;
    u64                  tag, deltag;
    u64                  txid;
    struct kvset_meta    km = {};
    struct kvdb_health   health;
    struct kvset_mblocks mb = {};
    struct kvs_block     vb = {}, kb = {};
    struct mpool *       ds = (void *)-1;

    mapi_inject(mapi_idx_mpool_mdc_read, 1);
    mapi_inject(mapi_idx_mpool_mdc_open, 0);
    mapi_inject(mapi_idx_mpool_mdc_append, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);

    err = cndb_open(ds, false, 0, 100, 11, 101, &health, NULL, &cndb);
    ASSERT_EQ(0, err);

    cndb->cndb_high_water = 1000;
    atomic64_set(&cndb->cndb_txid, 10);

    kb.bk_blkid = 11;
    vb.bk_blkid = 11;

    mb.kblks.blks = &kb;
    mb.kblks.n_blks = 1;
    mb.vblks.blks = &vb;
    mb.vblks.n_blks = 1;

    /* txn1: Finishes its creates, but is waiting on an ack-D
     */
    err = cndb_txn_start(cndb, &txid, 2, 1, 0, 0, 0);
    ASSERT_EQ(0, err);

    tag = 0;
    err = cndb_txn_txc(cndb, txid, 0, &tag, &mb, 0);
    ASSERT_EQ(0, err);

    deltag = tag; /* a subsequent txn will delete this kvset */

    err = cndb_txn_meta(cndb, txid, 0, 10, &km);
    ASSERT_EQ(0, err);

    err = cndb_txn_txc(cndb, txid, 0, &tag, NULL, 0);
    ASSERT_EQ(0, err);

    tag = 8; /* tag < txid */
    err = cndb_txn_txd(cndb, txid, 0, tag, 1, &txid);
    ASSERT_EQ(0, err);

    err = cndb_txn_ack_c(cndb, txid);
    ASSERT_EQ(0, err);

    /* txn2: Deletes a kvset from the previous incomplete txn
     */
    atomic64_set(&cndb->cndb_txid, 20);
    err = cndb_txn_start(cndb, &txid, 2, 1, 0, 0, 0);
    ASSERT_EQ(0, err);

    tag = 0;
    err = cndb_txn_txc(cndb, txid, 0, &tag, &mb, 0);
    ASSERT_EQ(0, err);

    err = cndb_txn_txc(cndb, txid, 0, &tag, NULL, 0);
    ASSERT_EQ(0, err);

    err = cndb_txn_meta(cndb, txid, 0, 20, &km);
    ASSERT_EQ(0, err);

    /* delete kvset from previous txn. When we are compacting, this record
     * should be able to find the kvset it is deleting even though the
     * transaction that created the kvset is incomplete.
     */
    err = cndb_txn_txd(cndb, txid, 0, deltag, 1, &txid);
    ASSERT_EQ(0, err);

    err = cndb_txn_ack_c(cndb, txid);
    ASSERT_EQ(0, err);

    err = cndb_txn_ack_d(cndb, txid, deltag, 0);
    ASSERT_EQ(0, err);

    cndb->cndb_refcnt = 1; /* compact only. No recovery */
    err = cndb_compact(cndb);
    ASSERT_EQ(0, err);

    err = cndb_close(cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mdc_read);
    mapi_inject_unset(mapi_idx_mpool_mdc_append);
}

MTF_DEFINE_UTEST(cndb_test, cndb_get_ingestid_test)
{
    struct cndb                cndb;
    struct cndb_tx             tx;
    struct cndb_ingest_replay *ing_rep;

    ing_rep = &cndb.cndb_ing_rep;
    memset(&cndb, 0, sizeof(cndb));
    memset(&tx, 0, sizeof(tx));

    tx.mtx_ingestid = CNDB_INVAL_INGESTID;
    tx.mtx_id = 5;
    cndb_get_ingestid(&cndb, &tx);
    ASSERT_EQ(ing_rep->cir_ingestid, 0);
    ASSERT_EQ(ing_rep->cir_txid, 0);

    ing_rep->cir_ingestid = CNDB_INVAL_INGESTID;
    tx.mtx_ingestid = 10;
    cndb_get_ingestid(&cndb, &tx);
    ASSERT_EQ(ing_rep->cir_ingestid, 10);
    ASSERT_EQ(ing_rep->cir_txid, 5);

    tx.mtx_ingestid = 11;
    tx.mtx_id = 4;
    cndb_get_ingestid(&cndb, &tx);
    ASSERT_EQ(ing_rep->cir_ingestid, 10);
    ASSERT_EQ(ing_rep->cir_txid, 5);

    tx.mtx_ingestid = 8;
    tx.mtx_id = 6;
    cndb_get_ingestid(&cndb, &tx);
    ASSERT_EQ(ing_rep->cir_ingestid, 8);
    ASSERT_EQ(ing_rep->cir_txid, 6);
}

MTF_DEFINE_UTEST(cndb_test, cndb_upgrade_test1)
{
    struct cndb_upg_histlen uhl;
    cndb_unpack_fn *        fn;
    cndb_unpack_fn *        fnt[CNDB_TYPE_TXD];
    struct cndb_ver_omf     ver = {};
    struct cndb_info_omf    info = {};
    struct cndb_tx_omf      tx = {};
    struct cndb_ack_omf     ack = {};
    struct cndb_nak_omf     nak = {};
    struct cndb_txc_omf     txc = {};
    struct cndb_txm_omf     txm = {};
    struct cndb_txd_omf     txd = {};
    union cndb_mtu *        mtu;
    int                     i;
    u32                     len;
    char *                  omf_rec[CNDB_TYPE_TXD];
    merr_t                  err;
    u32                     zero_len = 0;

    omf_rec[0] = (char *)&ver;
    omf_rec[1] = (char *)&info;
    omf_rec[2] = (char *)&info;
    omf_rec[3] = (char *)&tx;
    omf_rec[4] = (char *)&ack;
    omf_rec[5] = (char *)&nak;
    omf_rec[6] = (char *)&txc;
    omf_rec[7] = (char *)&txm;
    omf_rec[8] = (char *)&txd;
    fnt[0] = omf_cndb_ver_unpack;
    fnt[1] = omf_cndb_info_unpack;
    fnt[2] = omf_cndb_info_unpack;
    fnt[3] = omf_cndb_tx_unpack;
    fnt[4] = omf_cndb_ack_unpack;
    fnt[5] = omf_cndb_nak_unpack;
    fnt[6] = omf_cndb_txc_unpack;
    fnt[7] = omf_cndb_txm_unpack;
    fnt[8] = omf_cndb_txd_unpack;
    uhl.uhl_his = cndb_upgh_test;
    uhl.uhl_len = NELEM(cndb_upgh_test);

    for (i = 0; i < 4; i++) {
        fn = cndb_unpack_get_fn(&uhl, i);
        ASSERT_EQ(fn, NULL);
    }
    fn = cndb_unpack_get_fn(&uhl, 4);
    ASSERT_EQ(fn, (cndb_unpack_fn *)test_unpack_v1);
    fn = cndb_unpack_get_fn(&uhl, 5);
    ASSERT_EQ(fn, (cndb_unpack_fn *)test_unpack);
    fn = cndb_unpack_get_fn(&uhl, 10);
    ASSERT_EQ(fn, (cndb_unpack_fn *)test_unpack);

    for (i = 0; i < CNDB_TYPE_TXD; i++) {
        err = fnt[i](omf_rec[i], 0, NULL, NULL);
        ASSERT_EQ(merr_errno(err), EINVAL);

        cndb_set_hdr((struct cndb_hdr_omf *)omf_rec[i], i + 1, sizeof(struct cndb_hdr_omf));
        err = fnt[i](omf_rec[i], 0, NULL, NULL);
        ASSERT_EQ(merr_errno(err), EINVAL);

        err = fnt[i](omf_rec[i], 0, NULL, &len);
        ASSERT_EQ(merr_errno(err), 0);
        ASSERT_NE(len, 0);

        mtu = calloc(1, len);
        err = fnt[i](omf_rec[i], 0, mtu, &zero_len);
        ASSERT_EQ(merr_errno(err), EINVAL);

        err = fnt[i](omf_rec[i], 0, mtu, &len);
        ASSERT_EQ(merr_errno(err), 0);

        free(mtu);
    }

    err = omf2mtx(NULL, NULL, omf_rec[0], 0);
    ASSERT_EQ(merr_errno(err), EPROTO);

    err = omf2len(omf_rec[0], 0, &len);
    ASSERT_EQ(merr_errno(err), EPROTO);

    cndb_set_hdr((struct cndb_hdr_omf *)omf_rec[0], 1000, sizeof(struct cndb_hdr_omf));
    err = omf2mtx(NULL, NULL, omf_rec[0], 0);
    ASSERT_EQ(merr_errno(err), EPROTO);

    err = omf2len(omf_rec[0], 0, &len);
    ASSERT_EQ(merr_errno(err), EPROTO);
}

MTF_DEFINE_UTEST(cndb_test, cndb_upgrade_test2)
{
    struct cndb_tx_omf_v4   tx_v4 = {};
    union cndb_mtu *        mtu;
    struct cndb_txc_omf_v4 *txc_v4;
    u32                     len;
    merr_t                  err;
    u32                     zero_len = 0;
    size_t                  sz;
    int                     vcnt;

    /*
     * Test unpacking tx v4
     */
    cndb_set_hdr(&tx_v4.hdr, CNDB_TYPE_TX, sizeof(tx_v4));
    err = omf_cndb_tx_unpack_v4(&tx_v4, 0, NULL, NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = omf_cndb_tx_unpack_v4(&tx_v4, 0, NULL, NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);
    err = omf_cndb_tx_unpack_v4(&tx_v4, 0, NULL, &len);
    ASSERT_EQ(err, 0);
    ASSERT_NE(len, 0);

    mtu = calloc(1, len);
    ASSERT_NE(NULL, mtu);

    err = omf_cndb_tx_unpack_v4(&tx_v4, 0, mtu, &zero_len);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = omf_cndb_tx_unpack_v4(&tx_v4, 0, mtu, &len);
    ASSERT_EQ(err, 0);
    free(mtu);

    /*
     * Test unpacking TXC cndb version 4.
     */
    vcnt = 9;
    sz = sizeof(struct cndb_txc) + sizeof(struct cndb_oid) * vcnt;
    txc_v4 = calloc(1, sz);
    ASSERT_NE(NULL, txc_v4);

    cndb_set_hdr(&txc_v4->hdr, CNDB_TYPE_TXC, sizeof(*txc_v4));
    txc_v4->txc_vcnt = cpu_to_omf32(vcnt);
    err = omf_cndb_txc_unpack_v4(txc_v4, CNDB_VERSION4, NULL, &len);
    ASSERT_EQ(err, 0);
    ASSERT_NE(len, 0);
    ASSERT_EQ(len, sz);

    mtu = calloc(1, len);
    ASSERT_NE(NULL, mtu);
    err = omf_cndb_txc_unpack_v4(txc_v4, CNDB_VERSION4, mtu, &len);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(mtu->c.mtc_keepvbc, 0);

    txc_v4->txc_flags = cpu_to_omf32(1);
    err = omf_cndb_txc_unpack_v4(txc_v4, CNDB_VERSION4, mtu, &len);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(mtu->c.mtc_keepvbc, 9);

    free(mtu);
    free(txc_v4);
}

MTF_DEFINE_UTEST_PREPOST(cndb_test, cndb_record_unpack_test, test_pre, test_post)
{
    struct cndb_ver_omf ver = {};
    union cndb_mtu *    mtu;
    merr_t              err;

    err = cndb_record_unpack(1000, &(ver.hdr), &mtu);
    ASSERT_EQ(merr_errno(err), EPROTO);
    free(mtu);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    cndb_set_hdr(&ver.hdr, CNDB_TYPE_VERSION, sizeof(ver.hdr));
    err = cndb_record_unpack(CNDB_VERSION5, &(ver.hdr), &mtu);
    ASSERT_EQ(merr_errno(err), ENOMEM);
    ASSERT_EQ(mtu, NULL);
}

MTF_END_UTEST_COLLECTION(cndb_test)
