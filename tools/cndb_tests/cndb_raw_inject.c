/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Write to cndb log
 */

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/diag_kvdb.h>

#include <mpool/mpool.h>

#include <cn/cn/cndb_omf.h>
#include <cn/cn/cndb_internal.h>

#include <sysexits.h>
#include <libgen.h>

const char *progname;

#define BUF_SZ ((25 * 1024)) /* fo=8: 24K for C and D + extra (for omf structs) */

struct kvs_info {
    const char *     mp;
    const char *     kvs;
    char             buf[BUF_SZ];
    u64              ref_cnid;
    int              verbosity;
    struct hse_kvdb *kvdbh;
    struct cndb *    cndb;
};

void
fatal(char *who, merr_t err)
{
    struct merr_info info;

    hse_log(HSE_ERR "%s: %s", who, merr_info(err, &info));
    exit(1);
}

void
syntax(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

void
usage(void)
{
    static const char msg[] = "usage: %s [options] kvdb kvs\n"
                              "-h     this help list\n"
                              "kvdb   name of the kvdb\n"
                              "kvs    name of the kvs\n"
                              "\n";

    printf(msg, progname);
}

void
open_kvdb_and_cndb(struct kvs_info *ki)
{
    uint64_t rc;

    rc = diag_kvdb_open(ki->mp, 0, NULL, &ki->kvdbh);
    if (rc)
        fatal("diag_kvdb_open", rc);

    rc = diag_kvdb_get_cndb(ki->kvdbh, &ki->cndb);
    if (rc)
        fatal("diag_kvdb_cndb", rc);
}

int nk = 1; /* kblks in each crec */
int nv = 1; /* vblks in each crec */

u64 txid = 1111;
u64 kb = 1000;
u64 vb = 10000;
int dgen = 0;
u64 tag = 0;
u64 ingestid = 0;

void
write_ingest(struct kvs_info *ki)
{
    char                buf[25 * 1024] = { 0 };
    int                 cur;
    struct cndb_txc_omf txc = {};
    struct cndb_tx_omf  tx;
    struct cndb_txm_omf txm;
    int                 i;
    int                 nc = 3; /* number of cn - number of create records */
    u64                 otag = tag;

    omf_set_cnhdr_type(&tx.hdr, CNDB_TYPE_TX);
    omf_set_cnhdr_len(&tx.hdr, sizeof(tx) - sizeof(struct cndb_hdr_omf));
    omf_set_tx_id(&tx, ++txid);
    omf_set_tx_nc(&tx, nc);
    omf_set_tx_nd(&tx, 0);
    omf_set_tx_ingestid(&tx, ingestid++);
    omf_set_tx_txhorizon(&tx, 0);

    mpool_mdc_append(ki->cndb->cndb_mdc, &tx, sizeof(tx), true);

    for (i = 0; i < nc; i++) {
        __le64 mblkid[2]; /* 1 kb, 1 vb */

        omf_set_cnhdr_type(&txc.hdr, CNDB_TYPE_TXC);
        omf_set_cnhdr_len(&txc.hdr, sizeof(mblkid) + sizeof(txc) - sizeof(struct cndb_hdr_omf));
        omf_set_txc_cnid(&txc, i + 1);
        omf_set_txc_id(&txc, txid);
        omf_set_txc_tag(&txc, otag++);
        omf_set_txc_keepvbc(&txc, 0);
        omf_set_txc_kcnt(&txc, 1);
        omf_set_txc_vcnt(&txc, 1);

        memcpy(&buf[0], &txc, sizeof(txc));
        cur = sizeof(txc);

        mblkid[0] = cpu_to_le64(kb++);
        mblkid[1] = cpu_to_le64(vb++);

        memcpy(&buf[cur], mblkid, sizeof(mblkid));
        cur += sizeof(mblkid);

        mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);
    }

    otag = tag;

    for (i = 0; i < nc; i++) {
        omf_set_cnhdr_type(&txm.hdr, CNDB_TYPE_TXM);
        omf_set_cnhdr_len(&txm.hdr, sizeof(txm) - sizeof(struct cndb_hdr_omf));
        omf_set_txm_tag(&txm, otag++);
        omf_set_txm_id(&txm, ++txid);
        omf_set_txm_level(&txm, 0);
        omf_set_txm_offset(&txm, 0);
        omf_set_txm_dgen(&txm, dgen++ / 3);
        omf_set_txm_vused(&txm, 0);
        omf_set_txm_compc(&txm, 0);
        omf_set_txm_scatter(&txm, 0);
        mpool_mdc_append(ki->cndb->cndb_mdc, &txm, sizeof(txm), true);
    }

    tag += nc;
}

void
write_spill(struct kvs_info *ki)
{
    char                buf[25 * 1024] = { 0 };
    int                 cur = 0;
    struct cndb_txc_omf txc = {};
    struct cndb_txd_omf txd = {};
    struct cndb_txm_omf txm;
    struct cndb_tx_omf  tx;
    int                 c = 8; /* number of crecs = fanout*/
    int                 d = 4; /* number of drecs */
    int                 i;
    u64                 otag = tag;
    __le64              mblkid[5];

    omf_set_cnhdr_type(&tx.hdr, CNDB_TYPE_TX);
    omf_set_cnhdr_len(&tx.hdr, sizeof(tx) - sizeof(struct cndb_hdr_omf));
    omf_set_tx_id(&tx, ++txid);
    omf_set_tx_nc(&tx, c);
    omf_set_tx_nd(&tx, d);

    mpool_mdc_append(ki->cndb->cndb_mdc, &tx, sizeof(tx), true);

    for (i = 0; i < c; i++) {
        __le64 mblkid[2];

        omf_set_cnhdr_type(&txc.hdr, CNDB_TYPE_TXC);
        omf_set_cnhdr_len(&txc.hdr, sizeof(mblkid) + sizeof(txc) - sizeof(struct cndb_hdr_omf));
        omf_set_txc_cnid(&txc, 1);
        omf_set_txc_id(&txc, txid);
        omf_set_txc_tag(&txc, otag++);
        omf_set_txc_kcnt(&txc, 1);
        omf_set_txc_vcnt(&txc, 1);
        omf_set_txc_keepvbc(&txc, 0);
        memcpy(&buf[0], &txc, sizeof(txc));

        cur = sizeof(txc);

        mblkid[0] = cpu_to_le64(kb++);
        mblkid[1] = cpu_to_le64(vb++);

        memcpy(&buf[cur], mblkid, sizeof(mblkid));
        cur += sizeof(mblkid);

        mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);
    }

    otag = tag;

    for (i = 0; i < c; i++) {
        omf_set_cnhdr_type(&txm.hdr, CNDB_TYPE_TXM);
        omf_set_cnhdr_len(&txm.hdr, sizeof(txm) - sizeof(struct cndb_hdr_omf));
        omf_set_txm_cnid(&txm, 1);
        omf_set_txm_id(&txm, txid);
        omf_set_txm_tag(&txm, otag++);
        omf_set_txm_level(&txm, 1);
        omf_set_txm_offset(&txm, i);
        omf_set_txm_dgen(&txm, 6);
        omf_set_txm_vused(&txm, 0);
        omf_set_txm_compc(&txm, 0);

        mpool_mdc_append(ki->cndb->cndb_mdc, &txm, sizeof(txm), true);
    }

    omf_set_cnhdr_type(&txd.hdr, CNDB_TYPE_TXD);
    omf_set_cnhdr_len(&txd.hdr, sizeof(mblkid) + sizeof(txd) - sizeof(struct cndb_hdr_omf));
    omf_set_txd_cnid(&txd, 1);
    omf_set_txd_id(&txd, txid);
    omf_set_txd_n_oids(&txd, NELEM(mblkid));
    omf_set_txd_tag(&txd, otag++);
    memcpy(&buf[0], &txd, sizeof(txd));
    cur = sizeof(txd);

    mblkid[0] = cpu_to_le64(1024);

    mblkid[1] = cpu_to_le64(10000);
    mblkid[2] = cpu_to_le64(10003);
    mblkid[3] = cpu_to_le64(10006);
    mblkid[4] = cpu_to_le64(10009);

    memcpy(&buf[cur], mblkid, sizeof(mblkid));
    cur += sizeof(mblkid);
    mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);

    for (i = 0; i < d - 1; i++) {
        __le64 m[2];

        omf_set_cnhdr_type(&txd.hdr, CNDB_TYPE_TXD);
        omf_set_cnhdr_len(&txd.hdr, sizeof(m) + sizeof(txd) - sizeof(struct cndb_hdr_omf));
        omf_set_txd_cnid(&txd, 1);
        omf_set_txd_id(&txd, txid);
        omf_set_txd_n_oids(&txd, NELEM(m));
        omf_set_txd_tag(&txd, otag++);
        memcpy(&buf[0], &txd, sizeof(txd));
        cur = sizeof(txd);

        m[0] = cpu_to_le64(1012 + (3 * i));
        m[1] = cpu_to_le64(10012 + (3 * i));

        memcpy(&buf[cur], m, sizeof(m));
        cur += sizeof(m);
        mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);
    }

    tag = otag;
}

void
write_kc(struct kvs_info *ki)
{
    char                buf[25 * 1024] = { 0 };
    int                 cur = 0;
    struct cndb_txc_omf txc = {};
    struct cndb_txm_omf txm;
    struct cndb_txd_omf txd = {};
    struct cndb_tx_omf  tx;
    int                 c = 1;
    int                 d = 4; /* number of drecs */
    int                 i;
    u64                 otag = tag;

    omf_set_cnhdr_type(&tx.hdr, CNDB_TYPE_TX);
    omf_set_cnhdr_len(&tx.hdr, sizeof(tx) - sizeof(struct cndb_hdr_omf));
    omf_set_tx_id(&tx, ++txid);
    omf_set_tx_nc(&tx, c);
    omf_set_tx_nd(&tx, d);

    mpool_mdc_append(ki->cndb->cndb_mdc, &tx, sizeof(tx), true);

    for (i = 0; i < c; i++) {
        __le64 mblkid[5];

        omf_set_cnhdr_type(&txc.hdr, CNDB_TYPE_TXC);
        omf_set_cnhdr_len(&txc.hdr, sizeof(txc) + sizeof(mblkid) - sizeof(struct cndb_hdr_omf));
        omf_set_txc_cnid(&txc, 1);
        omf_set_txc_id(&txc, txid);
        omf_set_txc_tag(&txc, otag++);
        omf_set_txc_kcnt(&txc, 1);
        omf_set_txc_vcnt(&txc, 4);
        omf_set_txc_keepvbc(&txc, 2);
        memcpy(&buf[0], &txc, sizeof(txc));
        cur = sizeof(txc);

        mblkid[0] = cpu_to_le64(kb++);

        mblkid[1] = cpu_to_le64(10000);
        mblkid[2] = cpu_to_le64(10003);
        mblkid[3] = cpu_to_le64(10006);
        mblkid[4] = cpu_to_le64(10009);

        memcpy(&buf[cur], mblkid, sizeof(mblkid));
        cur += sizeof(mblkid);

        mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);
    }

    otag = tag;

    for (i = 0; i < c; i++) {
        omf_set_cnhdr_type(&txm.hdr, CNDB_TYPE_TXM);
        omf_set_cnhdr_len(&txm.hdr, sizeof(txm) - sizeof(struct cndb_hdr_omf));
        omf_set_txm_cnid(&txm, 1);
        omf_set_txm_id(&txm, txid);
        omf_set_txm_tag(&txm, otag++);
        omf_set_txm_level(&txm, 0);
        omf_set_txm_offset(&txm, 0);
        omf_set_txm_dgen(&txm, 3);
        omf_set_txm_vused(&txm, 50);
        omf_set_txm_compc(&txm, 0);
        mpool_mdc_append(ki->cndb->cndb_mdc, &txm, sizeof(txm), true);
    }

    for (i = 0; i < d; i++) {
        __le64 mblkid;

        omf_set_cnhdr_type(&txd.hdr, CNDB_TYPE_TXD);
        omf_set_cnhdr_len(&txd.hdr, sizeof(txd) + sizeof(mblkid) - sizeof(struct cndb_hdr_omf));
        omf_set_txd_cnid(&txd, 1);
        omf_set_txd_n_oids(&txd, 1);
        omf_set_txd_id(&txd, txid);
        /* [HSE_REVISIT] should construct tag from level/offset/dgen */
        omf_set_txd_tag(&txd, otag++);
        memcpy(&buf[0], &txd, sizeof(txd));
        cur = sizeof(txd);

        mblkid = cpu_to_le64(1000 + (3 * i)); /* delete old kblks */

        memcpy(&buf[cur], &mblkid, sizeof(mblkid));
        cur += sizeof(mblkid);
        mpool_mdc_append(ki->cndb->cndb_mdc, buf, cur, true);
    }

    tag = otag;
}

int subid = 0;
int an_type;

void
ackc(struct kvs_info *ki)
{
    struct cndb_ack_omf ack;

    omf_set_cnhdr_type(&ack.hdr, CNDB_TYPE_ACK);
    omf_set_cnhdr_len(&ack.hdr, sizeof(ack) - sizeof(struct cndb_hdr_omf));
    omf_set_ack_txid(&ack, txid);
    omf_set_ack_tag(&ack, tag);
    omf_set_ack_type(&ack, CNDB_ACK_TYPE_C);
    mpool_mdc_append(ki->cndb->cndb_mdc, &ack, sizeof(ack), true);
}

void
ackd(struct kvs_info *ki)
{
    struct cndb_ack_omf ack;

    omf_set_cnhdr_type(&ack.hdr, CNDB_TYPE_ACK);
    omf_set_cnhdr_len(&ack.hdr, sizeof(ack) - sizeof(struct cndb_hdr_omf));
    omf_set_ack_txid(&ack, txid);
    omf_set_ack_tag(&ack, tag);
    omf_set_ack_type(&ack, CNDB_ACK_TYPE_D);
    mpool_mdc_append(ki->cndb->cndb_mdc, &ack, sizeof(ack), true);
}

void
write_nak(struct kvs_info *ki)
{
    struct cndb_nak_omf nak;

    omf_set_cnhdr_type(&nak.hdr, CNDB_TYPE_NAK);
    omf_set_cnhdr_len(&nak.hdr, sizeof(nak) - sizeof(struct cndb_hdr_omf));
    omf_set_nak_txid(&nak, txid);
    mpool_mdc_append(ki->cndb->cndb_mdc, &nak, sizeof(nak), true);
}

int
main(int argc, char **argv)
{
    struct kvs_info ki = { 0 };
    int             c, i;

    progname = basename(argv[0]);

    while ((c = getopt(argc, argv, ":h")) != -1) {
        switch (c) {
            case 'h': /* fallthru */
                usage();
                exit(0);

            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                syntax("option -%c ignored\n", c);
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    } else if (argc > 2) {
        syntax("extraneous arguments ignored");
    }

    ki.mp = argv[0];
    ki.kvs = argc == 2 ? argv[1] : 0;

    open_kvdb_and_cndb(&ki);

    mpool_mdc_cstart(ki.cndb->cndb_mdc);

    /* 8 ingests */
    for (i = 0; i < 8; i++) {
        write_ingest(&ki);
        ackc(&ki);
    }

    /* 1 kcompact */
    write_kc(&ki);
    subid = 0;
    ackc(&ki);

    subid = 0;
    ackd(&ki);
    subid = 1;
    ackd(&ki);
    subid = 2;
    ackd(&ki);
    subid = 3;
    ackd(&ki);

    struct junk {
        struct cndb_hdr_omf hdr;
        char                buf[16];
    } j;

    omf_set_cnhdr_type(&j.hdr, 42);
    omf_set_cnhdr_len(&j.hdr, sizeof(j) - sizeof(struct cndb_hdr_omf));
    strcpy(j.buf, "hello, world");
    mpool_mdc_append(ki.cndb->cndb_mdc, &j, sizeof(j), true);

    /* 1 spill */
    write_spill(&ki);
    subid = 0;
    ackc(&ki);
    subid = 3;
    ackd(&ki);
    subid = 4;
    ackd(&ki);
    subid = 5;
    ackd(&ki);
    subid = 6;
    ackd(&ki);

    mpool_mdc_cend(ki.cndb->cndb_mdc);

    diag_kvdb_close(ki.kvdbh);

    return 0;
}
