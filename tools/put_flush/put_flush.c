/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/* This test creates several threads that call non-transactional PUTs on a loop.
 * One  thread that calls flush periodically on the KVDB.
 * And another thread that creates dummy transactions to bump up the kvdb seqno.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse/hse.h>
#include <hse/limits.h>

#include <hse/cli/param.h>

#include "kvs_helper.h"

static int err;
static bool killthreads;

void
flush_kvs(void *arg)
{
    struct kh_thread_arg *targ = arg;

    while (!killthreads) {
        hse_kvdb_sync(targ->kvdb, HSE_KVDB_SYNC_ASYNC);
        usleep(10 * 1000);
    }
}

void
put(void *arg)
{
    struct kh_thread_arg *targ = arg;
    uint64_t p = 0;
    int rc;

    char key[HSE_KVS_KEY_LEN_MAX];

    memset(key, 0xaf, sizeof(key));
    while (!killthreads) {
        p++;
        rc = hse_kvs_put(targ->kvs, 0, NULL, key, sizeof(key), &p, sizeof(p));
        if (rc) {
            err = 1;
            killthreads = true;
        }
    }
}

void
seq_inc(void *arg)
{
    struct kh_thread_arg *targ = arg;
    struct hse_kvdb_txn *txn = hse_kvdb_txn_alloc(targ->kvdb);

    while (!killthreads) {

        hse_kvdb_txn_begin(targ->kvdb, txn);
        hse_kvdb_txn_abort(targ->kvdb, txn);
    }

    hse_kvdb_txn_free(targ->kvdb, txn);
}

int
main(int argc, char **argv)
{
    struct parm_groups *pg = NULL;
    struct svec hse_gparms = { 0 };
    struct svec kvdb_oparms = { 0 };
    struct svec kvs_cparms = { 0 };
    struct svec kvs_oparms = { 0 };
    const char *mpool;
    int i;
    int rc;
    int optindex = 0;

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    if (!argc) {
        fprintf(stderr, "missing required parameters");
        exit(EX_USAGE);
    }

    mpool = argv[optindex++];

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

    rc = pg_set_parms(pg, PG_KVS_OPEN, "transactions.enabled=true", NULL);
    if (rc)
        fatal(rc, "pg_set_parms");

    rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
    rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
    rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "failed to parse params\n");

    kh_init(NULL, mpool, &hse_gparms, &kvdb_oparms);

    /* frequent flushes */
    kh_register_kvs("kvs1", 0, &kvs_cparms, &kvs_oparms, &flush_kvs, 0);

    /* bump up seqno */
    kh_register_kvs("kvs1", 0, &kvs_cparms, &kvs_oparms, &seq_inc, 0);

    for (i = 0; i < 64; i++)
        kh_register_kvs("kvs1", 0, &kvs_cparms, &kvs_oparms, &put, 0);

    sleep(10);
    killthreads = true;
    kh_wait();

    kh_fini();

    pg_destroy(pg);
    svec_reset(&hse_gparms);
    svec_reset(&kvdb_oparms);
    svec_reset(&kvs_cparms);
    svec_reset(&kvs_oparms);

    return err;
}
