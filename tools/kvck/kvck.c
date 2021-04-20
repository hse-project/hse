/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/inttypes.h>
#include <hse_util/platform.h>
#include <hse_util/string.h>
#include <hse_util/log2.h>

#include <mpool/mpool.h>

#include <hse/hse.h>

#include <hse_ikvdb/omf_kmd.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/diag_kvdb.h>

#include "kvdb/kvdb_omf.h"
#include "kvdb/kvdb_omf.h"
#include "cn/omf.h"
#include "cn/cndb_omf.h"
#include "cn/cndb_internal.h"
#include "cn/kvset.h"

const char *progname;

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
        hse_log(HSE_ERR "Failed to retrieve key hashmap "
                        "blob from cndb");
        return EBUG;
    }

    if (ptr && sz != 0)
        memcpy(&info.omf, ptr, sz);

    cnt = NELEM(kvs_tab);
    for (i = 0; i < cnt; i++)
        if (kvs_tab[i].kdl_cnid == cnv[cndb_idx]->cn_cnid)
            break;

    if (i >= cnt)
        return ENOENT;

    printf(
        "Checking kvs %s cnid %lu fanout %u pfx_len %u sfx_len %u\n",
        kvs_tab[i].kdl_name,
        kvs_tab[i].kdl_cnid,
        info.cp->cp_fanout,
        info.cp->cp_pfx_len,
        info.cp->cp_sfx_len);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
    cndb_cn_instantiate(
        cndb,
        cnv[cndb_idx]->cn_cnid,
        &info,
        (hse_err_t(*)(void *, struct kvset_meta *, u64))verify_kvset);
#pragma GCC diagnostic pop

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

static int
usage(bool verbose)
{
    printf(
        "usage: %s [options] kvdb [kbid ...[/ vbid ...]]\n"
        "-h                 print this help message\n"
        "-n lvl,off[,dgen]  check only this node or kvset\n"
        "-v                 verbose output\n",
        progname);

    if (!verbose)
        return 1;

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
    char *              mpool, *kvs = 0;
    char *              loc_buf, *loc;
    struct mpool *      ds;
    struct cndb *       cndb;
    struct entity       ent;
    struct kvdb_rparams rp; /* for cndb_entries */
    struct hse_kvdb *   kvdbh;
    bool                verbose = false;
    bool                help = false;
    hse_err_t           err;
    char                errbuf[300];
    char                c;
    uint64_t            rc = 0;
    int                 kvscnt = 0;
    u64                 seqno;
    u64                 ingestv;

    loc = loc_buf = 0;

    progname = (progname = strrchr(argv[0], '/')) ? progname + 1 : argv[0];

    while ((c = getopt(argc, argv, "?hvn:")) != -1) {
        switch (c) {
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

    if (help)
        return usage(verbose);

    err = hse_init();
    if (err)
        fatal(
            "failed to initialize kvdb: %s", hse_err_to_string(err, errbuf, sizeof(errbuf), NULL));

    /* [HSE_REVISIT]
     * The rparams are needed only to provide the user an option to use
     * larger cndb in-memory tables. Once cndb can grow its tables and mdc
     * by itself, this can and should be removed.
     * Since this is a workaround until cndb can grow itself, it isn't
     * listed in the help message either.
     */
    rp = kvdb_rparams_defaults();

    err = merr_to_hse_err(kvdb_rparams_parse(argc - optind, argv + optind, &rp, &optind));
    if (err)
        return usage(false);

    if (optind + 1 > argc)
        return usage(false);

    mpool = argv[optind++];

    kc_print_reg(verbose, (void *)print_line);

    rc = merr_to_hse_err(diag_kvdb_open(mpool, &rp, &kvdbh));
    if (rc)
        fatal("cannot open kvdb %s: %s", mpool, hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));

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

    err = merr_to_hse_err(cndb_replay(cndb, &seqno, &ingestv));
    if (err)
        fatal("cannot replay cndb: %s", hse_err_to_string(err, errbuf, sizeof(errbuf), 0));

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

    if (err)
        fatal("Verification failed: %s", hse_err_to_string(err, errbuf, sizeof(errbuf), 0));

out:
    free(loc_buf);

    diag_kvdb_close(kvdbh);

    hse_fini();

    return rc;
}
