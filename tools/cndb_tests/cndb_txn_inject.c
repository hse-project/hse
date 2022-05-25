/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Write to cndb log
 */

#include <hse/hse.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/omf_version.h>
#include <hse_ikvdb/cndb.h>

#include <mpool/mpool.h>

#include <cn/kvset.h>
#include <cn/cndb_omf.h>
#include <cn/cndb_internal.h>

#include <libgen.h>

struct nfault_probe *cndb_probes;

#define BUF_SZ ((25 * 1024)) /* fo=8: 24K for C and D + extra (for omf structs) */

struct kvs_info {
    const char *     kvdb_home;
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

    log_err("%s: %s", who, merr_info(err, &info));
    exit(1);
}

void
usage(char *prog)
{
    static const char msg[] = "usage: %s [options] <kvdb_home>\n"
                              "-b         inject txns that require rollback\n"
                              "-f         inject txns that require rollforward\n"
                              "-i         inject wrong ingest ids\n"
                              "-c         attempt to bracket with cstart/cend\n"
                              "-Z config  path to global config file\n"
                              "kvdb home dir\n";

    fprintf(stderr, msg, prog);
    exit(1);
}

void
open_kvdb_and_cndb(struct kvs_info *ki)
{
    uint64_t rc;

    rc = diag_kvdb_open(ki->kvdb_home, 0, NULL, &ki->kvdbh);
    if (rc)
        fatal("diag_kvdb_open", rc);

    rc = diag_kvdb_get_cndb(ki->kvdbh, &ki->cndb);
    if (rc)
        fatal("diag_kvdb_cndb", rc);

    /* [HSE_REVISIT] - this tool is intended to be used with newly
     * created kvdbs using default MDC sizes.
     */
    ki->cndb->cndb_captgt = CNDB_CAPTGT_DEFAULT;
    ki->cndb->cndb_high_water = CNDB_HIGH_WATER(ki->cndb);

    fprintf(stderr, "CNDB oids(0x%lx, 0x%lx)\n", ki->cndb->cndb_oid1, ki->cndb->cndb_oid2);
}

int nh = 1; /* hblks in each crec */
int nk = 1; /* kblks in each crec */
int nv = 1; /* vblks in each crec */

u64 txid = 1111;
u64 hb = 100;
u64 kb = 1000;
u64 vb = 10000;
int dgen = 0;
u64 ingestid = 0;

/* [HSE_REVISIT] oversized, use table_make during the next refactor */
static u64  tags[64]; /* all tags used with txc */
static int  tagc;     /* count of all tags with txc) */
static int  dtagc;    /* count of all tags used with txd (dtagc <= tagc) */
static int  atagc;    /* count of all tags used with ackd (atagc <= dtagc) */
static bool backward;
static bool forward;
static bool compact;
static bool wrongingestid;

merr_t
ver(struct kvs_info *ki)
{
    struct cndb_ver_omf ver;

    merr_t err;

    omf_set_cnhdr_type(&ver.hdr, CNDB_TYPE_VERSION);
    omf_set_cnhdr_len(&ver.hdr, sizeof(ver) - sizeof(ver.hdr));
    omf_set_cnver_magic(&ver, CNDB_MAGIC);
    omf_set_cnver_version(&ver, CNDB_VERSION);
    omf_set_cnver_captgt(&ver, ki->cndb->cndb_captgt);

    err = mpool_mdc_append(ki->cndb->cndb_mdc, &ver, sizeof(ver), true);
    assert(err == 0);
    return err;
}

void
write_ingest(struct kvs_info *ki, bool wrongingestid)
{
    struct kvset_mblocks mblocks;
    struct kvset_meta    km = {};
    int                  i;
    int                  nc = 3; /* number of cn - number of create records */
    int                  otagc = tagc;
    u64                  tag;

    /*
     * If wrong ingest id is requested, keep passing the same ingest id
     * at each successive ingest.
     */
    cndb_txn_start(ki->cndb, &txid, nc, 0, 0, wrongingestid ? 33 : ingestid++, 0);

    for (i = 0, tag = 0; i < nc; i++) {
        u64 mblkid[3]; /* 1 hb, 1 kb, 1 vb */

        mblkid[0] = hb++;
        mblkid[1] = kb++;
        mblkid[2] = vb++;

        mblocks.kblks.n_blks = 1;
        mblocks.vblks.n_blks = 1;

        mblocks.hblk.bk_blkid = mblkid[0];

        mblocks.kblks.blks = (void *)&mblkid[1];
        mblocks.vblks.blks = (void *)&mblkid[2];

        cndb_txn_txc(ki->cndb, txid, i + 1, &tag, &mblocks, 0);
        tags[tagc++] = tag;
    }

    for (i = 0; i < nc; i++) {
        km.km_dgen = dgen++ / 3;
        cndb_txn_meta(ki->cndb, txid, i + 1, tags[otagc++], &km);
    }
}

void
write_spill(struct kvs_info *ki)
{
    struct kvset_mblocks mblocks;
    struct kvset_meta    km = {};
    int                  c = 8; /* number of crecs = fanout*/
    int                  d = 4; /* number of drecs */
    int                  i;
    u64                  tag;
    int                  otagc = tagc;
    u64                  mblkid[5];

    cndb_txn_start(ki->cndb, &txid, c, d, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON);

    for (i = 0, tag = 0; i < c; i++) {
        u64 mblkid[3];

        mblkid[0] = hb++;
        mblkid[1] = kb++;
        mblkid[2] = vb++;

        mblocks.kblks.n_blks = 1;
        mblocks.vblks.n_blks = 1;

        mblocks.hblk.bk_blkid = mblkid[0];
        mblocks.kblks.blks = (void *)&mblkid[1];
        mblocks.vblks.blks = (void *)&mblkid[2];

        cndb_txn_txc(ki->cndb, txid, 1, &tag, &mblocks, 0);
        tags[tagc++] = tag;
    }

    for (i = 0; i < c; i++) {
        km.km_dgen = 6;
        km.km_node_level = 1;
        km.km_node_offset = 1;

        cndb_txn_meta(ki->cndb, txid, 1, tags[otagc++], &km);
    }

    mblkid[0] = 1024;
    mblkid[1] = 10000;
    mblkid[2] = 10003;
    mblkid[3] = 10006;
    mblkid[4] = 10009;

    cndb_txn_txd(ki->cndb, txid, 1, tags[dtagc++], NELEM(mblkid), (void *)mblkid);

    for (i = 0; i < d - 1; i++) {
        u64 m[3];

        m[0] = 112 + (3 * i);
        m[1] = 1012 + (3 * i);
        m[2] = 10012 + (3 * i);

        assert(dtagc < tagc);
        cndb_txn_txd(ki->cndb, txid, 1, tags[dtagc++], NELEM(m), (void *)m);
    }
}

void
write_kc(struct kvs_info *ki)
{
    struct kvset_mblocks mblocks;
    struct kvset_meta    km = {};
    int                  c = 1;
    int                  d = 4; /* number of drecs */
    int                  i;
    u64                  tag;
    int                  otagc = tagc;

    cndb_txn_start(ki->cndb, &txid, c, d, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON);

    for (i = 0, tag = 0; i < c; i++) {
        u64 mblkid[6];

        mblkid[0] = hb++;
        mblkid[1] = kb++;
        mblkid[2] = 10000;
        mblkid[3] = 10003;
        mblkid[4] = 10006;
        mblkid[5] = 10009;

        mblocks.kblks.n_blks = 1;
        mblocks.vblks.n_blks = 4;

        mblocks.hblk.bk_blkid = mblkid[0];
        mblocks.kblks.blks = (void *)&mblkid[0];
        mblocks.vblks.blks = (void *)&mblkid[1];

        cndb_txn_txc(ki->cndb, txid, 1, &tag, &mblocks, mblocks.vblks.n_blks);
        tags[tagc++] = tag;
    }

    for (i = 0; i < c; i++) {
        km.km_dgen = 3;
        km.km_vused = 50;

        cndb_txn_meta(ki->cndb, txid, 1, tags[otagc++], &km);
    }

    for (i = 0; i < d; i++) {
        u64 mblkid;

        mblkid = 1000 + (3 * i); /* delete old kblks */

        assert(dtagc < tagc);
        cndb_txn_txd(ki->cndb, txid, 1, tags[dtagc++], 1, (void *)&mblkid);
    }
}

void
ackc(struct kvs_info *ki)
{
    ki->cndb->cndb_mdc = ki->cndb->cndb_mdc;

    cndb_txn_ack_c(ki->cndb, txid);
}

void
ackd(struct kvs_info *ki)
{
    ki->cndb->cndb_mdc = ki->cndb->cndb_mdc;

    cndb_txn_ack_d(ki->cndb, txid, tags[atagc++], 0);
}

void
write_nak(struct kvs_info *ki)
{
    ki->cndb->cndb_mdc = ki->cndb->cndb_mdc;

    cndb_txn_nak(ki->cndb, txid);
}

int
main(int argc, char **argv)
{
    const char *    config = NULL;
    char *          prog;
    int             opt;
    struct kvs_info ki = { 0 };
    int             i;
    hse_err_t       herr;

    prog = basename(argv[0]);

    while ((opt = getopt(argc, argv, "?hbfciZ:")) != -1) {
        switch (opt) {
            case 'b':
                backward = true;
                break;
            case 'f':
                forward = true;
                break;
            case 'c':
                compact = true;
                break;
            case 'Z':
                config = optarg;
                break;
            case 'i':
                wrongingestid = true;
                break;
            case 'h': /* fallthru */
            case '?': /* fallthru */
            default:
                usage(prog);
        }
    }
    argc -= optind;
    argv += optind;

    if ((argc != 1) || (backward && forward))
        usage(prog);

    ki.kvdb_home = argv[0];

    herr = hse_init(config, 0, NULL);
    if (herr)
        fatal("hse_init failure", herr);

    open_kvdb_and_cndb(&ki);

    if (compact) {
        mpool_mdc_cstart(ki.cndb->cndb_mdc);
        ver(&ki);
    }

    /* 8 ingests */
    for (i = 0; i < 8; i++) {
        write_ingest(&ki, wrongingestid);
        ackc(&ki);
    }

    /* 1 kcompact */
    write_kc(&ki);
    ackc(&ki);

    if (forward)
        atagc++;
    else
        ackd(&ki);
    ackd(&ki);
    ackd(&ki);
    ackd(&ki);

    /* 1 spill */
    write_spill(&ki);
    if (backward) {
        atagc += 4;
    } else {
        /* Don't write ackd if you dropped ackc */
        ackc(&ki);
        ackd(&ki);
        if (forward)
            atagc++;
        else
            ackd(&ki);
        ackd(&ki);
        ackd(&ki);
    }

    if (compact)
        mpool_mdc_cend(ki.cndb->cndb_mdc);
    (void)mpool_mdc_close(ki.cndb->cndb_mdc);

    hse_fini();

    return 0;
}
