/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

/*
 * Note: Make sure the KVS instances are freshly created. No keys in them.
 *
 * This example shows a simple use of transactions in KVDB.
 * This program has two phases. In the first phase, it
 *   1. allocates a transaction handle
 *   2. begins a transaction
 *   3. puts a key in two KVSes
 *   4. commits the transaction.
 *
 * Since the transaction was committed at this stage, the second phase reuses
 * this handle for transaction number 2. The second phase
 *   1. puts a key in the three KVSes
 *   2. aborts the transaction.
 *
 * After the two phases have finished, we check to see that the keys from the
 * transaction that was committed can be accessed, but the keys from the aborted
 * transaction cannot.
 *
 */

int
usage(char *prog)
{
    printf("usage: %s <mpool> <kvs1> <kvs2>\n", prog);
    return 1;
}

int
main(int argc, char **argv)
{
    char *mpool_name;
    char *kvs_name1, *kvs_name2;

    struct hse_kvdb *      kvdb;
    struct hse_kvs *       kvs1, *kvs2;
    struct hse_kvdb_opspec os;

    char      vbuf[64];
    size_t    vlen;
    bool      found;
    hse_err_t rc;
    char      errbuf[200];

    if (argc != 4)
        return usage(argv[0]);

    mpool_name = argv[1];
    kvs_name1 = argv[2];
    kvs_name2 = argv[3];

    rc = hse_kvdb_init();
    if (rc) {
        printf("Failed to initialize kvdb");
        exit(1);
    }

    HSE_KVDB_OPSPEC_INIT(&os);

    /* Open the KVDB and the KVS instances in it */
    rc = hse_kvdb_open(mpool_name, NULL, &kvdb);
    if (rc) {
        printf("Cannot open kvdb: %s\n", hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));
        exit(1);
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name1, NULL, &kvs1);
    if (rc) {
        printf(
            "Cannot open kvs %s: %s\n",
            kvs_name1,
            hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));
        exit(1);
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name2, NULL, &kvs2);
    if (rc) {
        printf(
            "Cannot open kvs %s: %s\n",
            kvs_name2,
            hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));
        exit(1);
    }

    os.kop_txn = hse_kvdb_txn_alloc(kvdb);

    /* txn 1 */
    hse_kvdb_txn_begin(kvdb, os.kop_txn);

    /* Error handling is elided for clarity */

    rc = hse_kvs_put(kvs1, &os, "k1", 2, "val1", 4);
    rc = hse_kvs_put(kvs2, &os, "k2", 2, "val2", 4);

    /* This txn hasn't been committed or aborted yet. So we should be able
     * to see the keys from inside the txn, but not from outside.
     */
    rc = hse_kvs_get(kvs1, &os, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k1 from inside txn: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs1, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k1 from outside txn: found = %s\n", found ? "true" : "false");

    hse_kvdb_txn_commit(kvdb, os.kop_txn);

    /* txn 2. Reuse txn object from the first allocation */
    hse_kvdb_txn_begin(kvdb, os.kop_txn);

    rc = hse_kvs_put(kvs1, &os, "k3", 2, "val3", 4);
    rc = hse_kvs_put(kvs2, &os, "k4", 2, "val4", 4);

    hse_kvdb_txn_abort(kvdb, os.kop_txn);

    /* 3.1 Verify keys that are part of txn number 1 can be found */
    rc = hse_kvs_get(kvs1, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("txn1(committed), k1: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs2, NULL, "k2", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("txn1(committed), k2: found = %s\n", found ? "true" : "false");

    /* 3.2 Verify keys that are part of txn number 2 cannot be found */
    rc = hse_kvs_get(kvs1, NULL, "k3", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("txn2(aborted), k3: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs2, NULL, "k4", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("txn2(aborted), k4: found = %s\n", found ? "true" : "false");

    hse_kvdb_txn_free(kvdb, os.kop_txn);

    hse_kvdb_close(kvdb);
    hse_kvdb_fini();

    return 0;
}
