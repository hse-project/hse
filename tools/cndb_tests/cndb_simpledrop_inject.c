/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Write to cndb log
 */

#include <hse/hse.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/blk_list.h>
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
    static const char msg[] = "usage: %s <kvdb_home>\n"
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

#include "simpledrop.c"

int
main(int argc, char **argv)
{
    const char *    config = NULL;
    char *          prog;
    int             opt;
    struct kvs_info ki = { 0 };
    hse_err_t       herr;

    prog = basename(argv[0]);

    while ((opt = getopt(argc, argv, "Z:?h")) != -1) {
        switch (opt) {
            case 'Z':
                config = optarg;
                break;
            case 'h': /* fallthru */
            case '?': /* fallthru */
            default:
                usage(prog);
        }
    }
    argc -= optind;
    argv += optind;

    if ((argc != 1))
        usage(prog);

    ki.kvdb_home = argv[0];

    herr = hse_init(config, 0, NULL);
    if (herr)
        fatal("hse_init failure", herr);

    open_kvdb_and_cndb(&ki);

    mpool_mdc_cstart(ki.cndb->cndb_mdc);

    inject_raw(ki.cndb->cndb_mdc);

    mpool_mdc_cend(ki.cndb->cndb_mdc);
    (void)mpool_mdc_close(ki.cndb->cndb_mdc);

    hse_fini();

    return 0;
}
