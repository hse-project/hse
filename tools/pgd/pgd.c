/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
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
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hse/hse.h>

#include <hse_util/fmt.h>
#include <hse_util/hse_params_helper.h>

#include <tools/common.h>

enum Actions { PUT = 0, GET = 1, DEL = 2, VFY = 3 };

int
do_open(
    const char *       mpname,
    const char *       kvname,
    struct hse_kvdb ** kvdb,
    struct hse_kvs **  kvs,
    struct hse_params *params)
{
    uint64_t err;

    err = hse_kvdb_open(mpname, params, kvdb);
    if (err)
        fatal(err, "cannot open kvdb %s", mpname);

    err = hse_kvdb_kvs_open(*kvdb, kvname, params, kvs);
    if (err)
        fatal(err, "cannot open kvs %s/%s", mpname, kvname);

    return 0;
}

void
do_params(int *argc, char ***argv, struct hse_params *params)
{
    int idx = optind;

    hse_params_set(params, "kvdb.perfc_enable", "0");

    hse_params_set(params, "kvs.kv_print_config", "0");
    hse_params_set(params, "kvs.cn_bloom_create", "0");
    hse_params_set(params, "kvs.cn_bloom_lookup", "0");

    if (hse_parse_cli(*argc - idx, *argv + idx, &idx, 0, params))
        rp_usage();

    *argc -= idx;
    *argv += idx;
    optind = 0;
}

void
usage(char *prog)
{
    fprintf(
        stderr,
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-P      put keys values\n"
        "-G      get keys\n"
        "-D      delete keys\n"
        "-V      verify puts, fails on first miss\n"
        "-C      show tunable parameters\n",
        prog);

    exit(1);
}

int
main(int argc, char **argv)
{
    static char        buf[(HSE_KVS_KLEN_MAX + HSE_KVS_VLEN_MAX) * 3];
    struct hse_params *params;
    char *             mpname, *prog;
    const char *       kvsname;
    struct hse_kvdb *  kvdb;
    struct hse_kvs *   h;
    int                rc, c, help;
    bool               fnd;
    enum Actions       action;

    prog = basename(argv[0]);
    help = 0;
    action = PUT;

    while ((c = getopt(argc, argv, "?PGDVCz")) != -1) {
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
            case 'C':
                help = 2;
                break;
            case 'z':
                Opts.zero++;
                break;
            case '?': /* fallthru */
            default:
                help = 1;
                break;
        }
    }

    if (help == 1)
        usage(prog);
    if (help == 2)
        rp_usage();

    rc = hse_init();
    if (rc)
        fatal(rc, "failed to initialize kvdb");

    hse_params_create(&params);

    do_params(&argc, &argv, params);

    if (argc != 3)
        usage(prog);

    mpname = argv[0];
    kvsname = argv[1];

    do_open(mpname, kvsname, &kvdb, &h, params);

    rc = 0;
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        static char kbuf[HSE_KVS_KLEN_MAX];
        static char vbuf[HSE_KVS_VLEN_MAX];
        static char gbuf[HSE_KVS_VLEN_MAX];
        static char obuf[HSE_KVS_VLEN_MAX];
        char *      key = buf;
        char *      val = 0;
        char *      cp = strchr(buf, ' ');
        int         klen, vlen;
        size_t      glen;

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
                rc = hse_kvs_put(h, 0, kbuf, klen, vbuf, vlen);
                break;
            case DEL:
                rc = hse_kvs_delete(h, 0, kbuf, klen);
                break;
            case GET:
            case VFY:
                glen = sizeof(gbuf);
                rc = hse_kvs_get(h, 0, kbuf, klen, &fnd, gbuf, glen, &glen);
                if (rc)
                    break;
                if (!fnd)
                    warn(ENOENT, "cannot find key %s", key);
                else if (action == GET)
                    show(kbuf, klen, gbuf, glen, 0);
                else if (glen != vlen || memcmp(vbuf, gbuf, vlen)) {
                    fmt_pe(obuf, sizeof(gbuf), gbuf, glen);
                    warn(EIO, "wanted %d/%s, got %d/%s", vlen, val, glen, obuf);
                }
                break;
        }
    }

    hse_kvdb_close(kvdb);

    hse_params_destroy(params);

    hse_fini();

    return rc;
}
