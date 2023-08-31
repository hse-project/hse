/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse/flags.h>
#include <hse/hse.h>

#include <hse/cli/output.h>
#include <hse/cli/param.h>
#include <hse/cli/program.h>
#include <hse/util/arch.h>
#include <hse/util/compiler.h>

#include "kvs_helper.h"

int errcnt = 0;

struct opts {
    ulong nthread;
    ulong count;
    bool reverse;
} opts = {
    .nthread = 64,
    .count = 3000000,
    .reverse = false,
};

struct thread_info {
    uint64_t start HSE_ACP_ALIGNED;
    uint64_t end;
} *g_ti;

#define VLEN 1024

void
do_work(void *arg)
{
    hse_err_t rc;
    struct kh_thread_arg *targ = arg;
    struct thread_info *ti = targ->arg;
    struct hse_kvdb_txn *txn;
    unsigned int flags = 0;
    char val[VLEN];
    char key[sizeof(uint64_t)];
    uint64_t *k = (void *)key;
    struct hse_kvs_cursor *c;
    int cnt;
    const void *kdata, *vdata;
    size_t klen, vlen;
    bool eof = false;
    int attempts = 5;

    txn = hse_kvdb_txn_alloc(targ->kvdb);

    memset(val, 0xfe, sizeof(val));

    hse_kvdb_txn_begin(targ->kvdb, txn);
    for (uint64_t i = ti->start; i < ti->end; i++) {
        *k = htobe64(i);

        rc = hse_kvs_put(targ->kvs, 0, txn, key, sizeof(key), val, sizeof(val));
        if (rc)
            fatal(rc, "Failed to put key");
    }

    if (opts.reverse) {
        *k = htobe64(ti->end - 1);
        flags = HSE_CURSOR_CREATE_REV;
    } else {
        *k = htobe64(ti->start);
        flags = 0;
    }

    do {
        rc = hse_kvs_cursor_create(targ->kvs, flags, txn, 0, 0, &c);
    } while (rc == EAGAIN);

    if (rc)
        fatal(rc, "Failed to create cursor");

    hse_kvdb_txn_commit(targ->kvdb, txn);
    hse_kvdb_txn_free(targ->kvdb, txn);

    cnt = 0;

    sleep(1); /* allow KVMSes to be ingested */

    /* seek to beginning */
    do {
        rc = hse_kvs_cursor_seek(c, 0, key, sizeof(key), &kdata, &klen);
        if (rc == EAGAIN)
            usleep(1000 * 1000);

    } while (rc == EAGAIN && attempts-- > 0);

    if (rc || klen != sizeof(key) || memcmp(key, kdata, sizeof(key)))
        fatal(
            rc ? rc : ENOKEY,
            "Seek: found unexpected key. "
            "Expected %lu got %lu\n",
            be64toh(*k), be64toh(*(uint64_t *)kdata));

    for (uint64_t i = ti->start; i < ti->end; i++) {
        rc = hse_kvs_cursor_read(c, 0, &kdata, &klen, &vdata, &vlen, &eof);
        if (rc || eof)
            break;

        ++cnt;
    }

    if (cnt < ti->end - ti->start) {
        fatal(
            ENOANO,
            "Found incorrect number of records: "
            "Expected %lu Got %d",
            ti->end - ti->start, cnt);

        ++errcnt;
    }

    rc = hse_kvs_cursor_destroy(c);
}

void
usage(void)
{
    printf(
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-c keys    Number of keys\n"
        "-j jobs    Number of threads\n"
        "-r         Use reverse cursors\n"
        "-Z config  Path to global config file\n",
        progname);

    printf("\nDescription:\n");
    printf("Number of kv-pairs per prefix = "
           "chunk_size * number_of_put_threads\n");
    printf("Each cursor thread will read a max of 'batch size' "
           "(set using the '-b' option) kv-pairs before it updates the "
           "cursor and continues reading. The default value (0) will let "
           "it read to EOF\n");
    printf("\n");
    exit(0);
}

int
main(int argc, char **argv)
{
    struct parm_groups *pg = NULL;
    struct svec hse_gparms = { 0 };
    struct svec db_oparms = { 0 };
    struct svec kv_cparms = { 0 };
    struct svec kv_oparms = { 0 };

    const char *mpool, *kvs, *config = NULL;
    int c;
    merr_t rc;

    progname_set(argv[0]);

    while ((c = getopt(argc, argv, "c:hj:rZ:")) != -1) {
        char *errmsg, *end;

        errmsg = end = 0;
        errno = 0;
        switch (c) {
        case 'c':
            opts.count = strtoul(optarg, &end, 0);
            errmsg = "invalid key count";
            break;
        case 'h':
            usage();
            exit(0);
        case 'j':
            opts.nthread = strtoul(optarg, &end, 0);
            errmsg = "invalid thread count";
            break;
        case 'r':
            opts.reverse = true;
            break;
        case 'Z':
            config = optarg;
            break;
        default:
            fprintf(stderr, "option -%c ignored\n", c);
            break;
        }

        if (errno && errmsg) {
            syntax("%s", errmsg);
            exit(EX_USAGE);
        } else if (end && *end) {
            syntax("%s '%s'", errmsg, optarg);
            exit(EX_USAGE);
        }
    }

    if (argc - optind < 2) {
        syntax("missing required parameters");
        exit(EX_USAGE);
    }

    mpool = argv[optind++];
    kvs = argv[optind++];

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
    case 0:
        if (optind < argc)
            fatalx("unknown parameter: %s", argv[optind]);
        break;
    case EINVAL:
        fatalx("missing group name (e.g. %s) before parameter %s\n", PG_KVDB_OPEN, argv[optind]);
        break;
    default:
        fatal(rc, "error processing parameter %s\n", argv[optind]);
        break;
    }

    rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ?: svec_append_pg(&db_oparms, pg, PG_KVDB_OPEN, NULL);
    rc = rc ?: svec_append_pg(&kv_cparms, pg, PG_KVS_CREATE, NULL);
    rc = rc ?: svec_append_pg(&kv_oparms, pg, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_append_pg failed");

    kh_init(config, mpool, &hse_gparms, &db_oparms);

    g_ti = malloc(sizeof(*g_ti) * opts.nthread);
    if (!g_ti)
        fatal(ENOMEM, "Failed to allocate resources for threads");

    for (ulong i = 0; i < opts.nthread; i++) {
        uint64_t stride = opts.count / opts.nthread;
        bool last = i == (opts.nthread - 1);

        g_ti[i].start = i * stride;
        g_ti[i].end = g_ti[i].start + stride;
        g_ti[i].end += last ? (opts.count % opts.nthread) : 0;
        kh_register_kvs(kvs, 0, &kv_cparms, &kv_oparms, &do_work, &g_ti[i]);
    }

    kh_wait();
    kh_fini();

    svec_reset(&hse_gparms);
    svec_reset(&db_oparms);
    svec_reset(&kv_cparms);
    svec_reset(&kv_oparms);
    pg_destroy(pg);

    free(g_ti);

    if (errcnt) {
        fprintf(stderr, "errcnt %d", errcnt);
        assert(0);
    }

    printf("Finished successfully\n");

    return errcnt;
}
