/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/omf_kmd.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/diag_kvdb.h>

#include "../kvdb/kvdb_omf.h"
#include "../kvdb/kvdb_omf.h"
#include "../cn/omf.h"
#include "../cn/cndb_omf.h"
#include "../cn/cndb_internal.h"
#include "../cn/kvset.h"
#include "../c1/c1_private.h"
#include "../c1/c1_diag.h"
#include "../c1/c1_omf_internal.h"

BullseyeCoverageSaveOff static char *prog;
static bool                          verbose;
static bool                          ascii_fmt;
static bool                          dump_key;
static bool                          dump_value;

static void
fatal(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "Error: %s: %s\n", prog, msg);
    exit(1);
}

struct c1log_mblk {
    struct mpool *           ds;
    u64                      blkid;
    struct mpool_mcache_map *map;
};

static struct c1log_mblk last_mblk;

static int
usage(char *prog, bool verbose)
{
    printf(
        "usage: %s [options] kvdb\n"
        "-A  dump key/value in binary format\n"
        "-h  print this help message\n"
        "-K  dump key\n"
        "-V  dump value(s)\n"
        "-v  verbose output\n",
        prog);

    return 1;
}

static void
print_line(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    printf("\n");
}

static merr_t
c1log_journal_version(struct c1 *c1, char *omf)
{
    struct c1_version vers;

    merr_t err;

    err = omf_c1_ver_unpack(omf, &vers);
    if (ev(err))
        return err;

    printf(
        "c1 log magic 0x%x version 0x%x\n",
        (unsigned int)vers.c1v_magic,
        (unsigned int)vers.c1v_version);

    return 0;
}

static merr_t
c1log_journal_info(struct c1 *c1, char *omf)
{
    struct c1_info info;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&info);
    if (ev(err))
        return err;

    printf(
        "c1 info tree_ver 0x%lx gen 0x%lx dur. time %ld ms "
        "dur. size %ld dur. capacity %ld\n",
        (unsigned long)info.c1i_seqno,
        (unsigned long)info.c1i_gen,
        (unsigned long)info.c1i_dtime,
        (unsigned long)info.c1i_dsize,
        (unsigned long)info.c1i_capacity);

    return 0;
}

static merr_t
c1log_journal_desc(struct c1 *c1, char *omf)
{
    struct c1_desc desc;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&desc);
    if (ev(err))
        return err;

    printf(
        "c1 log desc oid 0x%lx tree_ver 0x%lx gen 0x%lx state 0x%lx\n",
        (unsigned long)desc.c1d_oid,
        (unsigned long)desc.c1d_seqno,
        (unsigned long)desc.c1d_gen,
        (unsigned long)desc.c1d_state);

    return 0;
}

static merr_t
c1log_journal_ingest(struct c1 *c1, char *omf)
{
    struct c1_ingest ingest;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&ingest);
    if (ev(err))
        return err;

    printf(
        "c1 log ingest seqno 0x%lx cnid 0x%lx tgen 0x%lx status 0x%lx\n",
        (unsigned long)ingest.c1ing_seqno,
        (unsigned long)ingest.c1ing_cnid,
        (unsigned long)ingest.c1ing_cntgen,
        (unsigned long)ingest.c1ing_status);

    return 0;
}

static merr_t
c1log_journal_reset(struct c1 *c1, char *omf)
{
    struct c1_reset reset;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&reset);
    if (ev(err))
        return err;

    printf(
        "c1 log reset ver 0x%lx new_ver 0x%lx "
        "gen 0x%lx new_gen 0x%lx\n",
        (unsigned long)reset.c1reset_seqno,
        (unsigned long)reset.c1reset_newseqno,
        (unsigned long)reset.c1reset_gen,
        (unsigned long)reset.c1reset_newgen);

    return 0;
}

static void
c1log_journal_close(struct c1 *c1, char *omf)
{
    printf("c1 log is gracefully closed\n");
}

static merr_t
c1log_journal_complete(struct c1 *c1, char *omf)
{
    struct c1_complete cmp;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&cmp);
    if (ev(err))
        return err;

    printf(
        "c1 log complete seqno 0x%lx gen 0x%lx "
        "kvseqno 0x%lx\n",
        (unsigned long)cmp.c1c_seqno,
        (unsigned long)cmp.c1c_gen,
        (unsigned long)cmp.c1c_kvseqno);

    return 0;
}

static merr_t
c1log_journal_replay_cb(struct c1 *c1, u32 cmd, void *rec, void *rec2)
{
    merr_t err;

    err = 0;

    switch (cmd) {
        case C1_TYPE_VERSION:
            err = c1log_journal_version(c1, rec);
            break;

        case C1_TYPE_INFO:
            err = c1log_journal_info(c1, rec);
            break;

        case C1_TYPE_DESC:
            err = c1log_journal_desc(c1, rec);
            break;

        case C1_TYPE_INGEST:
            err = c1log_journal_ingest(c1, rec);
            break;

        case C1_TYPE_RESET:
            err = c1log_journal_reset(c1, rec);
            break;

        case C1_TYPE_CLOSE:
            c1log_journal_close(c1, rec);
            break;

        case C1_TYPE_COMPLETE:
            err = c1log_journal_complete(c1, rec);
            break;

        default:
            break;
    }

    return err;
}

static merr_t
c1log_log_replay_kvlog(struct c1 *c1, char *kvlomf, u64 oid)
{
    struct c1_log log;

    merr_t err;

    err = c1_record_unpack(kvlomf, c1->c1_version, (union c1_record *)&log);
    if (ev(err))
        return err;

    printf(
        "c1 log kvlog oid 0x%lx MDC oid 0x%lx-0x%lx "
        "tree_ver 0x%lx gen 0x%lx size %ld\n",
        (unsigned long)oid,
        (unsigned long)log.c1l_mdcoid1,
        (unsigned long)log.c1l_mdcoid2,
        (unsigned long)log.c1l_seqno,
        (unsigned long)log.c1l_gen,
        (unsigned long)log.c1l_space);

    return 0;
}

static merr_t
c1log_log_replay_txn(struct c1 *c1, char *omf)
{
    struct c1_treetxn ttxn;

    merr_t err;

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)&ttxn);
    if (ev(err))
        return err;

    printf(
        "c1 log txn seqno 0x%lx gen 0x%lx txnid 0x%lx "
        "kvseqno 0x%lx mutno 0x%lx cmd 0x%lx flag 0x%lx\n",
        (unsigned long)ttxn.c1txn_seqno,
        (unsigned long)ttxn.c1txn_gen,
        (unsigned long)ttxn.c1txn_id,
        (unsigned long)ttxn.c1txn_kvseqno,
        (unsigned long)ttxn.c1txn_mutation,
        (unsigned long)ttxn.c1txn_cmd,
        (unsigned long)ttxn.c1txn_flag);

    return 0;
}

static void
c1_log_print_kvtuple(char *data, u64 len, bool ascii)
{
    char *fmt;
    u64   i;
    char  c;

    if (ascii)
        fmt = "%c";
    else
        fmt = "%02x";

    for (i = 0; i < len; i++) {
        c = *(data + i) & 0xFF;
        printf(fmt, (unsigned int)c);
    }
}

static merr_t
c1_log_print_ktuple(char *kvtomf, struct c1_kvtuple_meta *kvtm, u16 ver)
{
    char * key;
    merr_t err;

    err = c1_record_unpack_bytype(kvtomf, C1_TYPE_KVT, ver, (union c1_record *)kvtm);
    if (ev(err))
        return err;

    if (!verbose)
        return 0;

    printf(
        "  key sign 0x%lx klen %ld cnid 0x%lx vlen %ld vcount %ld\n",
        (unsigned long)kvtm->c1kvm_sign,
        (unsigned long)kvtm->c1kvm_klen,
        (unsigned long)kvtm->c1kvm_cnid,
        (unsigned long)c1_kvtuple_meta_vlen(kvtm),
        (unsigned long)kvtm->c1kvm_vcount);

    if (!dump_key)
        return 0;

    key = (char *)kvtm->c1kvm_data;

    if (ascii_fmt) {
        printf("\tkey contents (ascii) ");
        c1_log_print_kvtuple(key, kvtm->c1kvm_klen, true);
    } else {
        printf("\tkey contents (hex)   ");
        c1_log_print_kvtuple(key, kvtm->c1kvm_klen, false);
    }
    printf("\n");

    return 0;
}

static void
c1_log_put_mblk_value(struct c1 *c1, struct c1log_mblk *mblk)
{
    if (mblk->blkid) {
        mpool_mcache_munmap(mblk->map);
        mblk->blkid = 0;
    }
}

static merr_t
c1_log_print_vtuple(struct c1 *c1, u64 n, char *vtomf, struct c1_vtuple_meta *vtm)
{
    char * value = NULL;
    merr_t err;

    err = c1_record_unpack_bytype(vtomf, C1_TYPE_VT, c1->c1_version, (union c1_record *)vtm);
    if (ev(err))
        return err;

    if (!verbose)
        return 0;

    printf(
        "   value[%ld] sign 0x%lx seqno 0x%lx vlen %ld "
        "tomb 0x%x type 0x%x\n",
        (unsigned long)n,
        (unsigned long)vtm->c1vm_sign,
        (unsigned long)vtm->c1vm_seqno,
        (unsigned long)c1_vtuple_meta_vlen(vtm),
        (unsigned int)vtm->c1vm_tomb,
        (unsigned int)vtm->c1vm_logtype);

    if (!dump_value)
        return 0;

    value = vtm->c1vm_data;

    if (ascii_fmt) {
        printf("\tvalue contents (ascii) ");
        c1_log_print_kvtuple(value, c1_vtuple_meta_vlen(vtm), true);
    } else {
        printf("\tvalue contents (hex)   ");
        c1_log_print_kvtuple(value, c1_vtuple_meta_vlen(vtm), false);
    }

    printf("\n");

    return 0;
}

static merr_t
c1_log_replay_kvtuple(struct c1 *c1, void **nextkey)
{
    struct c1_kvtuple_meta kvtm;
    struct c1_vtuple_meta  vtm;

    char * kvtomf;
    char * vtomf;
    u64    i;
    void * value;
    merr_t err;

    kvtomf = *nextkey;
    if (!kvtomf) {
        printf("c1 log error c1_kvtuple_omf missing\n");
        return merr(EINVAL);
    }

    c1_log_print_ktuple(kvtomf, &kvtm, c1->c1_version);

    if (kvtm.c1kvm_sign != C1_KEY_MAGIC) {
        printf("Invalid ktuple signature\n");
        return merr(EINVAL);
    }

    value = kvtm.c1kvm_data + kvtm.c1kvm_klen;

    for (i = 0; i < kvtm.c1kvm_vcount; i++) {
        u32 len;

        vtomf = value;

        c1_log_print_vtuple(c1, i, vtomf, &vtm);

        if (c1_vtuple_meta_vlen(&vtm) && (vtm.c1vm_sign != C1_VAL_MAGIC)) {
            printf("Invalid vtuple signature\n");
            return merr(EINVAL);
        }

        err = c1_record_type2len(C1_TYPE_VT, c1->c1_version, &len);
        if (ev(err))
            return err;

        value += len;
        value += c1_vtuple_meta_vlen(&vtm);
    }

    *nextkey = value;

    return 0;
}

static merr_t
c1log_log_replay_kvb(struct c1 *c1, char *kvbomf, void *data)
{
    struct c1_kvb kvb;

    u64    i;
    merr_t err;
    void * next;

    err = c1_record_unpack(kvbomf, c1->c1_version, (union c1_record *)&kvb);
    if (ev(err))
        return err;

    if (verbose) {
        printf(
            " c1 log tree_ver 0x%lx gen 0x%x txnid 0x%lx "
            "keycount %ld mutno 0x%lx size %ld "
            "minseqno 0x%lx maxseqno 0x%lx\n",
            (unsigned long)kvb.c1kvb_seqno,
            (unsigned int)kvb.c1kvb_gen,
            (unsigned long)kvb.c1kvb_txnid,
            (unsigned long)kvb.c1kvb_keycount,
            (unsigned long)kvb.c1kvb_mutation,
            (unsigned long)kvb.c1kvb_size,
            (unsigned long)kvb.c1kvb_minseqno,
            (unsigned long)kvb.c1kvb_maxseqno);
    }

    next = data;
    if (!next) {
        printf("c1 log error kvtuple missing\n");
        return merr(EINVAL);
    }

    for (i = 0; i < kvb.c1kvb_keycount; i++) {
        err = c1_log_replay_kvtuple(c1, &next);
        if (err)
            return err;
    }

    if (verbose)
        printf("\n");

    return 0;
}

static merr_t
c1log_log_replay_cb(struct c1 *c1, u32 cmd, void *rec, void *rec2)
{
    merr_t err;

    err = 0;

    switch (cmd) {
        case C1_TYPE_KVLOG:
            c1log_log_replay_kvlog(c1, rec, (u64)rec2);
            break;
        case C1_TYPE_KVB:
            err = c1log_log_replay_kvb(c1, rec, rec2);
            break;
        case C1_TYPE_TXN:
            c1log_log_replay_txn(c1, rec);
            break;
        default:
            return merr(EINVAL);
    }

    return err;
}

int
main(int argc, char **argv)
{
    char *              mpool;
    struct cndb *       cndb;
    struct kvdb_rparams rp; /* for cndb_entries */
    struct hse_kvdb *   kvdbh;
    struct c1 *         c1;

    bool   help = false;
    char   errbuf[300];
    char   c;
    u64    rc = 0;
    u64    seqno;
    u64    ingestid;
    merr_t err;

    prog = (prog = strrchr(argv[0], '/')) ? prog + 1 : argv[0];

    while ((c = getopt(argc, argv, "?hvKVA")) != -1) {
        switch (c) {
            case 'v':
                verbose = true;
                break;
            case 'K':
                dump_key = true;
                break;
            case 'V':
                dump_value = true;
                break;
            case 'A':
                ascii_fmt = true;
                break;
            case 'h':
            case '?':
                help = true;
        }
    }

    if (help)
        return usage(prog, verbose);

    err = hse_kvdb_init();
    if (err)
        fatal("failed to initialize kvdb: %s", hse_err_to_string(err, errbuf, sizeof(errbuf), 0));

    /* [HSE_REVISIT]
     * The rparams are needed only to provide the user an option to use
     * larger cndb in-memory tables. Once cndb can grow its tables and mdc
     * by itself, this can and should be removed.
     * Since this is a workaround until cndb can grow itself, it isn't
     * listed in the help message either.
     */
    rp = kvdb_rparams_defaults();

    err = kvdb_rparams_parse(argc - optind, argv + optind, &rp, &optind);
    if (err)
        return usage(prog, false);

    if (optind + 2 > argc)
        return usage(prog, false);

    mpool = argv[optind++];

    rp.read_only = 1;

    kc_print_reg(verbose, (void *)print_line);

    rc = diag_kvdb_open(mpool, &rp, &kvdbh);
    if (rc)
        fatal("cannot open kvdb %s: %s", mpool, hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));

    rc = diag_kvdb_get_cndb(kvdbh, &cndb);
    if (rc || !cndb)
        fatal("cannot open cndb");

    err = cndb_replay(cndb, &seqno, &ingestid);
    if (err)
        fatal("cannot replay cndb: %s", merr_strinfo(err, errbuf, sizeof(errbuf), 0));

    err = diag_kvdb_get_c1(kvdbh, ingestid, &c1);
    if (err)
        fatal("cannot open c1 : %s", merr_strinfo(err, errbuf, sizeof(errbuf), 0));

    printf(
        "c1 cndb ingestid 0x%lx kvdb_seqno 0x%lx\n",
        (unsigned long)ingestid,
        (unsigned long)c1_get_kvdb_seqno(c1));

    err = c1_diag_replay_journal(c1, c1log_journal_replay_cb);
    if (err)
        fatal("cannot replay c1 journal: %s", merr_strinfo(err, errbuf, sizeof(errbuf), 0));

    err = c1_diag_replay_trees(c1, c1log_log_replay_cb);
    if (err)
        fatal("cannot replay c1 tree : %s", merr_strinfo(err, errbuf, sizeof(errbuf), 0));

    c1_log_put_mblk_value(c1, &last_mblk);

    c1_close(c1);

    diag_kvdb_close(kvdbh);

    hse_kvdb_fini();

    return rc;
}
BullseyeCoverageRestore
