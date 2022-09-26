/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

/*
 * cndb_log - read and interpret a cndb log
 */

#include <stdio.h>
#include <libgen.h>

#include <hse/hse.h>

#include <hse_util/page.h>

#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/diag_kvdb.h>

#include <mpool/mpool.h>

#include <cndb/omf.h>
#include <cn/kvset.h>

struct test_options {
};

static void
fatal(char *who, hse_err_t err)
{
    char buf[256];
    hse_strerror(err, buf, sizeof(buf));

    fprintf(stderr, "cndb_log: %s: %s\n", who, buf);
    exit(1);
}

struct cndb_reader {
    struct mpool_mdc *mdc;
    void             *buf;
    size_t            bufsz;
    bool              eof;
};

static merr_t
cndb_read_one(struct cndb_reader *reader, enum cndb_rec_type *rec_type, size_t *reclen_out)
{
    merr_t err;
    size_t reclen;

    err = mpool_mdc_read(reader->mdc, reader->buf, reader->bufsz, &reclen);
    if (merr_errno(err) == EOVERFLOW) {
        size_t newsz = ALIGN(reclen, 16);
        void *p = realloc(reader->buf, newsz);

        if (!p)
            return merr(ENOMEM);

        reader->bufsz = newsz;
        reader->buf = p;

        err = mpool_mdc_read(reader->mdc, reader->buf, reader->bufsz, &reclen);
        if (err)
            return err;
    }

    if (!reclen) {
        *reclen_out = 0;
        return 0;
    }

    *rec_type = omf_cnhdr_type(reader->buf);
    *reclen_out = omf_cnhdr_len(reader->buf);
    return 0;
}

static void
cndb_print_record(struct cndb_reader *reader)
{
    merr_t err;
    enum cndb_rec_type rec_type;
    size_t reclen = 0;

    err = cndb_read_one(reader, &rec_type, &reclen);
    if (err)
        fatal("Failed to read an mdc record", err);

    if (!reclen) {
        reader->eof = true;
        return;
    }

    if (rec_type == CNDB_TYPE_VERSION) {
        uint16_t version;
        uint32_t magic;
        uint64_t size;

        cndb_omf_ver_read(reader->buf, &magic, &version, &size);
        printf("%-8s %u magic %u size %lu\n", "ver", version, magic, size);

    } else if (rec_type == CNDB_TYPE_META) {
        uint64_t seqno;

        cndb_omf_meta_read(reader->buf, &seqno);
        printf("%-8s seqno %lu\n", "meta", seqno);

    } else if (rec_type == CNDB_TYPE_KVS_ADD) {
        struct kvs_cparams cp;
        char name[HSE_KVS_NAME_LEN_MAX];
        uint64_t cnid;

        cndb_omf_kvs_add_read(reader->buf, &cp, &cnid, name, sizeof(name));
        printf("%-8s name %s cnid %lu pfxlen %u capped %c\n",
               "kvs_add", name, cnid, cp.pfx_len, cp.kvs_ext01 ? 'y' : 'n');

    } else if (rec_type == CNDB_TYPE_KVS_DEL) {
        uint64_t cnid;

        cndb_omf_kvs_del_read(reader->buf, &cnid);
        printf("%-8s cnid %lu\n", "kvs_del", cnid);

    } else if (rec_type == CNDB_TYPE_TXSTART) {
        uint64_t txid, seqno, ingestid, txhorizon;
        uint16_t add_cnt, del_cnt;

        cndb_omf_txstart_read(reader->buf, &txid, &seqno, &ingestid, &txhorizon,
                              &add_cnt, &del_cnt);

        printf("%-8s txid %lu seqno %lu ingestid %lu txhorizon %lu add %u del %u\n",
               "txstart", txid, seqno, ingestid, txhorizon, add_cnt, del_cnt);

    } else if (rec_type == CNDB_TYPE_KVSET_ADD) {
        uint64_t txid, cnid, kvsetid, nodeid;
        uint64_t hblkid, *kblkv, *vblkv;
        uint32_t kblkc, vblkc;
        struct kvset_meta km;

        cndb_omf_kvset_add_read(reader->buf, &txid, &cnid, &kvsetid, &nodeid, &hblkid,
                                &kblkc, &kblkv, &vblkc, &vblkv, &km);
        printf("%-8s txid %lu cnid %lu kvsetid %lu nodeid %lu dgen_hi %lu dgen_lo %lu vused %lu "
               "compc %u hblkid %lu nkblk %u nvblk %u",
               "txadd", txid, cnid, kvsetid, nodeid, km.km_dgen_hi, km.km_dgen_lo, km.km_vused,
               km.km_compc, hblkid, kblkc, vblkc);

        for (int i = 0; i < kblkc; i++)
            printf(" 0x%lx", kblkv[i]);

        printf(" /");

        for (int i = 0; i < vblkc; i++)
            printf(" 0x%lx", vblkv[i]);

        printf("\n");

    } else if (rec_type == CNDB_TYPE_KVSET_DEL) {
        uint64_t txid, cnid, kvsetid;

        cndb_omf_kvset_del_read(reader->buf, &txid, &cnid, &kvsetid);
        printf("%-8s txid %lu cnid %lu kvsetid %lu\n", "txdel", txid, cnid, kvsetid);

    } else if (rec_type == CNDB_TYPE_KVSET_MOVE) {
        uint64_t cnid, src_nodeid, tgt_nodeid;
        uint32_t kvset_idc;
        uint64_t *kvset_idv;

        cndb_omf_kvset_move_read(reader->buf, &cnid, &src_nodeid, &tgt_nodeid,
                                 &kvset_idc, &kvset_idv);
        printf("%-8s cnid %lu src_nodeid %lu tgt_nodeid %lu nkvsets %u kvsetids",
               "move", cnid, src_nodeid, tgt_nodeid, kvset_idc);

        for (uint32_t i = 0; i < kvset_idc; i++)
            printf(" %lu", kvset_idv[i]);

        printf("\n");

    } else if (rec_type == CNDB_TYPE_ACK) {
        uint64_t txid, cnid, kvsetid;
        uint type;

        cndb_omf_ack_read(reader->buf, &txid, &cnid, &type, &kvsetid);
        printf("%-8s txid %lu cnid %lu kvsetid %lu\n",
               type == CNDB_ACK_TYPE_ADD ? "ackA" : "ackD", txid, cnid, kvsetid);

    } else if (rec_type ==  CNDB_TYPE_NAK) {
        uint64_t txid;

        cndb_omf_nak_read(reader->buf, &txid);
        printf("%-8s txid %lu\n", "nak", txid);
    }
}

static void
cndb_read(struct cndb *cndb)
{
    struct cndb_reader r = {
        .mdc = cndb_mdc_get(cndb),
        .eof = false,
        .bufsz = 1024,
    };

    merr_t err;

    r.buf = malloc(r.bufsz);
    if (!r.buf)
        fatal("Failed to allocate a buffer", merr(ENOMEM));

    err = mpool_mdc_rewind(r.mdc);
    if (err)
        fatal("Could not rewind mdc", err);

    while (!r.eof)
        cndb_print_record(&r);

    free(r.buf);
}

char *progname;

void
usage(void)
{
    printf("usage: %s <kvdb_home>\n", progname);
}

int
main(int argc, char **argv)
{
    char *kvdb_home;
    struct cndb *cndb;
    int rc;
    struct hse_kvdb *kvdb;
    int c;

    progname = basename(argv[0]);

    while ((c = getopt(argc, argv, ":h")) != -1) {
        switch (c) {
        case 'h':
            usage();
            return 0;
        default:
            fprintf(stderr, "Invalid option -%c\n", c);
            exit(1);
        }
    }

    if (argc != 2) {
        usage();
        exit(1);
    }

    kvdb_home = argv[1];

    hse_init(0, 0, 0);

    rc = diag_kvdb_open(kvdb_home, 0, 0, &kvdb);
    if (rc)
        fatal("Failed to open kvdb", rc);

    rc = diag_kvdb_get_cndb(kvdb, &cndb);
    if (rc)
        fatal("Failed to open cndb", rc);

    cndb_read(cndb);

    diag_kvdb_close(kvdb);
    hse_fini();

    return 0;
}
