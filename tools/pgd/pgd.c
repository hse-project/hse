/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc. All rights reserved.
 */

/*
 * pgd - a simple client to put/get/del keys/values from stdin
 *
 * this is useful for:
 * - creating bulk, controlled ingest loads of new keys
 * - querying for a set of keys
 * - deleting a set of keys
 * - verifying keys have certain values
 *
 * TODO:
 * - consider transactions, either by new verb or by count (w/random)
 *   . perhaps: tx label; txcommit label
 *   . if so, then need verb put to allow keys named "tx", "txcommit"
 *   . if this could be a dot (.) as well
 */

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tools/common.h>
#include <tools/parm_groups.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/util/fmt.h>

enum Actions { PUT = 0, GET = 1, DEL = 2, VFY = 3 };

struct parm_groups *pg;

int
do_open(const char *mpname, const char *kvname, struct hse_kvdb **kvdb, struct hse_kvs **kvs)
{
    int rc;
    uint64_t err;
    struct svec sv = { 0 };

    rc = svec_append_pg(&sv, pg, PG_KVDB_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_append_pg");

    err = hse_kvdb_open(mpname, sv.strc, sv.strv, kvdb);
    if (err)
        fatal(err, "cannot open kvdb %s", mpname);

    svec_reset(&sv);

    rc = svec_append_pg(&sv, pg, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_append_pg");

    err = hse_kvdb_kvs_open(*kvdb, kvname, sv.strc, sv.strv, kvs);
    if (err)
        fatal(err, "cannot open kvs %s/%s", mpname, kvname);

    svec_reset(&sv);

    return 0;
}

void
usage(void)
{
    fprintf(
        stderr,
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-P         put keys values\n"
        "-G         get keys\n"
        "-D         delete keys\n"
        "-V         verify puts, fails on first miss\n"
        "-C         show tunable parameters\n"
        "-Z config  path to global config file\n",
        progname);

    exit(1);
}

int
main(int argc, char **argv)
{
    static char buf[(HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX) * 3];
    struct parm_groups *pg = NULL;
    char *mpname;
    const char *kvsname;
    struct hse_kvdb *kvdb;
    struct hse_kvs *kvs;
    hse_err_t err;
    int c, rc, help;
    bool fnd;
    enum Actions action;
    struct svec hse_gparm = { 0 };
    const char *config = NULL;

    progname_set(argv[0]);

    help = 0;
    action = PUT;

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "pg_create");

    while ((c = getopt(argc, argv, "?PGDVCzZ:")) != -1) {
        switch (c) {
        case 'P':
            action = PUT;
            break;
        case 'G':
            action = GET;
            break;
        case 'D':
            action = DEL;
            break;
        case 'V':
            action = VFY;
            break;
        case 'z':
            Opts.zero++;
            break;
        case 'Z':
            config = optarg;
            break;
        case '?': /* fallthru */
        default:
            help = 1;
            break;
        }
    }

    if (help == 1)
        usage();

    if (argc - optind < 2)
        fatal(0, "missing required params: kvdb and kvs");

    mpname = argv[optind++];
    kvsname = argv[optind++];

    /* get hse parms from command line */
    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
    case 0:
        if (optind < argc)
            fatal(0, "unknown parameter: %s", argv[optind]);
        break;
    case EINVAL:
        fatal(0, "missing group name (e.g. %s) before parameter %s\n", PG_KVDB_OPEN, argv[optind]);
        break;
    default:
        fatal(rc, "error processing parameter %s\n", argv[optind]);
        break;
    }

    rc = svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    if (rc)
        fatal(rc, "failed to parse hse-gparams\n");

    err = hse_init(config, hse_gparm.strc, hse_gparm.strv);
    if (err)
        fatal(err, "failed to initialize kvdb");

    do_open(mpname, kvsname, &kvdb, &kvs);

    err = 0;
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        static char kbuf[HSE_KVS_KEY_LEN_MAX];
        static char vbuf[HSE_KVS_VALUE_LEN_MAX];
        static char gbuf[HSE_KVS_VALUE_LEN_MAX];
        static char obuf[HSE_KVS_VALUE_LEN_MAX];
        char *key = buf;
        char *val = 0;
        char *cp = strchr(buf, ' ');
        int klen, vlen;
        size_t glen;

        buf[strlen(buf) - 1] = 0; /* lose trailing newline */

        /* allow and suppress comments and blank lines */
        ++Opts.lineno;
        if (buf[0] == '#' || buf[0] == '\n')
            continue;

        if (cp) {
            *cp++ = 0;
            val = cp;

            /* allow "a = 1" */
            if (*val == '=') {
                while (*++val == ' ')
                    ;
            }
        }

        /* MU_REVISIT: allow grouping into txns? */

        klen = fmt_data(kbuf, key);
        vlen = fmt_data(vbuf, val);

        switch (action) {
        case PUT:
            err = hse_kvs_put(kvs, 0, NULL, kbuf, klen, vbuf, vlen);
            break;
        case DEL:
            err = hse_kvs_delete(kvs, 0, NULL, kbuf, klen);
            break;
        case GET:
        case VFY:
            glen = sizeof(gbuf);
            err = hse_kvs_get(kvs, 0, NULL, kbuf, klen, &fnd, gbuf, glen, &glen);
            if (err)
                break;
            if (!fnd)
                warn(ENOENT, "cannot find key %s", key);
            else if (action == GET)
                show(kbuf, klen, gbuf, glen, 0);
            else if (glen != vlen || memcmp(vbuf, gbuf, vlen)) {
                fmt_pe(obuf, sizeof(gbuf), gbuf, glen);
                warn(EIO, "wanted %d/%s, got %ld/%s", vlen, val, glen, obuf);
            }
            break;
        }
    }

    hse_kvdb_close(kvdb);
    pg_destroy(pg);
    svec_reset(&hse_gparm);
    hse_fini();

    return err ? 1 : 0;
}
