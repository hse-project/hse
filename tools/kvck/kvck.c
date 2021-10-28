/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/inttypes.h>
#include <hse_util/string.h>
#include <hse_util/log2.h>
#include <hse_util/logging.h>

#include <mpool/mpool.h>

#include <hse/hse.h>

#include <hse_ikvdb/omf_kmd.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/diag_kvdb.h>

#include <tools/parm_groups.h>

#include "cn/omf.h"
#include "cn/cndb_omf.h"
#include "cn/cndb_internal.h"
#include "cn/kvset.h"

const char *progname;

struct parm_groups *pg;
struct svec         hse_gparm = { 0 };
struct svec         db_oparm = { 0 };

struct diag_kvdb_kvs_list kvs_tab[HSE_KVS_COUNT_MAX] = {};

struct entity {
    u32 level;
    u32 offset;
    u32 dgen;
};

struct callback_info {
    struct mpool *       ds;
    struct kvs_cparams * cp;
    struct entity *      ent;
    struct cn_tstate_omf omf;
    bool                 errors;
};

static void
fatal(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s\n", progname, msg);
    exit(1);
}

static hse_err_t
verify_kvset(void *ctx, struct kvset_meta *km, u64 tag)
{
    struct callback_info *info = ctx;
    struct entity *       ent = info->ent;
    u8                    khmapv[CN_TSTATE_KHM_SZ];
    hse_err_t             err;

    omf_ts_khm_mapv(&info->omf, khmapv, CN_TSTATE_KHM_SZ);

    if (ent) {
        if (ent->level != km->km_node_level || ent->offset != km->km_node_offset)
            return 0; /* skip node */

        /* correct node. now verify if dgen matches, if specified */
        if (ent->dgen && ent->dgen != km->km_dgen)
            return 0; /* skip kvset */
    }

    err = merr_to_hse_err(kc_kvset_check(info->ds, info->cp, km, khmapv));
    if (err)
        info->errors = true;

    return err;
}

static hse_err_t
_verify_kvs(struct cndb *cndb, int cndb_idx, struct entity *ent)
{
    int                  i;
    size_t               cnt;
    struct cndb_cn **    cnv = cndb->cndb_cnv;
    struct cndb_cn *     cn = cnv[cndb_idx];
    struct callback_info info = {
        .ds = cndb->cndb_ds,
        .cp = &cn->cn_cp,
        .errors = false,
        .ent = ent,
    };
    void *    ptr = NULL;
    size_t    sz = 0;
    hse_err_t err;

    err = merr_to_hse_err(cndb_cn_blob_get(cndb, cn->cn_cnid, &sz, &ptr));
    if (ev(err)) {
        log_err("Failed to retrieve key hashmap blob from cndb");
        return EBUG;
    }

    if (ptr && sz != 0)
        memcpy(&info.omf, ptr, sz);

    cnt = NELEM(kvs_tab);
    for (i = 0; i < cnt; i++)
        if (kvs_tab[i].kdl_cnid == cnv[cndb_idx]->cn_cnid)
            break;

    if (i >= cnt) {
        free(ptr);
        return ENOENT;
    }

    printf(
        "Checking kvs %s cnid %lu fanout %u pfx_len %u sfx_len %u\n",
        kvs_tab[i].kdl_name,
        kvs_tab[i].kdl_cnid,
        info.cp->fanout,
        info.cp->pfx_len,
        info.cp->sfx_len);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
    cndb_cn_instantiate(
        cndb,
        cnv[cndb_idx]->cn_cnid,
        &info,
        (hse_err_t(*)(void *, struct kvset_meta *, u64))verify_kvset);
#pragma GCC diagnostic pop

    free(ptr);

    return info.errors ? EILSEQ : 0;
}

static hse_err_t
verify_kvs(struct cndb *cndb, const char *kvs, struct entity *ent)
{
    int              i, cndb_idx;
    int              cnc = cndb->cndb_cnc;
    struct cndb_cn **cnv = cndb->cndb_cnv;

    for (i = 0; i < cnc; i++)
        if (strcmp(kvs_tab[i].kdl_name, kvs) == 0)
            break;

    if (i >= cnc)
        return ENOENT;

    for (cndb_idx = 0; cndb_idx < cnc; cndb_idx++)
        if (cnv[cndb_idx]->cn_cnid == kvs_tab[i].kdl_cnid)
            break;

    if (cndb_idx >= cnc)
        return EPROTO;

    return _verify_kvs(cndb, cndb_idx, ent);
}

static hse_err_t
verify_kvdb(struct cndb *cndb)
{
    int  i, cnc = cndb->cndb_cnc;
    bool errors = false;

    for (i = 0; i < cnc; i++) {
        hse_err_t err;

        err = _verify_kvs(cndb, i, 0);
        errors = err ? true : errors;
    }

    return errors ? EILSEQ : 0;
}

static void
usage(bool verbose)
{
    printf(
        "usage: %s [options] kvdb [kbid ...[/ vbid ...]]\n"
        "-h                 print this help message\n"
        "-n lvl,off[,dgen]  check only this node or kvset\n"
        "-v                 verbose output\n"
        "-Z config          path to global config file\n",
        progname);

    if (!verbose)
        return;

    printf(
        "\n"
        "Examples:\n"
        "   %s kvdb1\n"
        "   %s kvdb1 0x0383d102 0x0383d103\n"
        "   %s kvdb1 0x0383d102 0x0383d103 / 0x0383d10e\n"
        "   %s kvdb1 kvs1\n"
        "   %s kvdb1 kvs1 -n1,7\n"
        "   %s kvdb1 kvs1 -n1,7,16\n"
        "\n"
        "Note:\n"
        "   Using '-n lvl,off,dgen' to check a kvset enables more\n"
        "   robust verification than listing mblock ids directly on\n"
        "   the command line. In the latter form, there's no way\n"
        "   to check that the vblocks even belong to the correct\n"
        "   kvset.\n",
        progname,
        progname,
        progname,
        progname,
        progname,
        progname);
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

static int
check_blklist(struct mpool *ds, int argc, char **argv)
{
    int              rc = 0;
    int              i, j = -1;
    char *           p = argv[0];
    struct blk_list  kblk_list, vblk_list;
    struct blk_list *list;
    struct vb_meta * vb_meta = 0;

    blk_list_init(&kblk_list);
    blk_list_init(&vblk_list);

    list = &kblk_list;

    for (i = 0; i < argc; i++) {
        u64 blkid;

        p = argv[i];
        if (*p == '/') {
            if (argc > i)
                j = 0;

            list = &vblk_list;
            continue;
        }

        if (p[0] != '0' || p[1] != 'x') {
            fprintf(
                stderr,
                "Invalid block id: '%s' (must use hex "
                "notation)\n",
                p);
            rc = EINVAL;
            goto out;
        }

        blkid = strtoull(p, 0, 0);

        rc = blk_list_append(list, blkid);
        if (ev(rc))
            goto out;

        if (list == &vblk_list)
            j++;
    }

    /* if there's atleast one vblock, get vb_meta */
    if (j > 0)
        vb_meta = kc_vblock_meta(ds, &vblk_list);

    for (i = 0; i < kblk_list.n_blks; i++)
        kc_kblock_check(ds, kblk_list.blks[i].bk_blkid, vb_meta);
out:
    blk_list_free(&vblk_list);
    blk_list_free(&kblk_list);
    free(vb_meta);

    return rc;
}

int
main(int argc, char **argv)
{
    const char *        config = NULL;
    char *              mpool, *kvs = 0;
    char *              loc_buf, *loc;
    struct mpool *      ds;
    struct cndb *       cndb;
    struct entity       ent;
    struct hse_kvdb *   kvdbh;
    struct parm_groups *pg = NULL;
    bool                verbose = false;
    bool                help = false;
    hse_err_t           err;
    char                errbuf[300];
    int                 c;
    uint64_t            rc = 0;
    int                 kvscnt = 0;
    u64                 seqno;
    u64                 ingestid, txhorizon;

    loc = loc_buf = 0;

    progname = (progname = strrchr(argv[0], '/')) ? progname + 1 : argv[0];

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, NULL);
    if (rc)
        fatal("pg_create");

    while ((c = getopt(argc, argv, "?hvn:Z:")) != -1) {
        switch (c) {
            case 'Z':
                config = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'n':
                loc = loc_buf = strdup(optarg);
                if (!loc)
                    fatal("cannot allocate memory");
                break;
            case 'h':
            case '?':
                help = true;
        }
    }

    if (help) {
        usage(verbose);
        exit(0);
    }

    if (argc - optind < 1)
        fatal("missing required parameters");

    mpool = argv[optind++];

    /* get hse parms from command line */
    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
        case 0:
            if (optind < argc)
                fatal(0, "unknown parameter: %s", argv[optind]);
            break;
        case EINVAL:
            fatal(0, "missing group name (e.g. %s) before parameter %s\n",
                PG_KVDB_OPEN, argv[optind]);
            break;
        default:
            fatal("error processing parameter %s\n", argv[optind]);
            break;
    }

    rc = svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    if (rc)
        fatal("svec_apppend_pg failed: %d", rc);
    rc = svec_append_pg(&db_oparm, pg, PG_KVDB_OPEN, NULL);
    if (rc)
        fatal("svec_apppend_pg failed: %d", rc);

    kc_print_reg(verbose, (void *)print_line);

    err = hse_init(config, hse_gparm.strc, hse_gparm.strv);
    if (err) {
        hse_strerror(err, errbuf, sizeof(errbuf));
        fatal(
            "failed to initialize kvdb: %s", errbuf);
    }

    rc = merr_to_hse_err(diag_kvdb_open(mpool, db_oparm.strc, db_oparm.strv, &kvdbh));
    if (rc) {
        hse_strerror(rc, errbuf, sizeof(errbuf));
        fatal("cannot open kvdb %s: %s", mpool, errbuf);
    }

    if (optind < argc && !(argv[optind][0] == '0' && argv[optind][1] == 'x'))
        kvs = argv[optind++];

    rc = merr_to_hse_err(diag_kvdb_get_cndb(kvdbh, &cndb));
    if (rc || !cndb)
        fatal("cannot open cndb");

    ds = cndb->cndb_ds;

    if (optind < argc) {
        rc = check_blklist(ds, argc - optind, &argv[optind]);
        goto out;
    }

    err = merr_to_hse_err(cndb_replay(cndb, &seqno, &ingestid, &txhorizon));
    if (err) {
        hse_strerror(err, errbuf, sizeof(errbuf));
        fatal("cannot replay cndb: %s", errbuf);
    }

    err = merr_to_hse_err(diag_kvdb_kvslist(kvdbh, kvs_tab, NELEM(kvs_tab), &kvscnt));
    if (err)
        fatal("cannot list kvses");

    if (loc && !kvs)
        fatal("please specify kvs for the '-n' option to take effect");

    if (kvs && loc) {
        char *p = loc;
        int   cnt = 0;

        memset(&ent, 0, sizeof(ent));
        do {
            p = strsep(&loc, ":,;");
            if (cnt == 0)
                ent.level = strtoul(p, 0, 0);
            else if (cnt == 1)
                ent.offset = strtoul(p, 0, 0);
            else
                ent.dgen = strtoul(p, 0, 0);
            cnt++;
        } while (loc);

        if (cnt == 1 || cnt > 3)
            fatal("The tuple passed to '-n' should be either "
                  "level,offset or level,offset,dgen");
    }

    if (kvs)
        err = verify_kvs(cndb, kvs, loc_buf ? &ent : 0);
    else
        err = verify_kvdb(cndb);

    if (err) {
        hse_strerror(err, errbuf, sizeof(errbuf));
        fatal("Verification failed: %s", errbuf);
    }

out:
    free(loc_buf);

    diag_kvdb_close(kvdbh);

    pg_destroy(pg);

    svec_reset(&hse_gparm);
    svec_reset(&db_oparm);

    hse_fini();

    return rc;
}
