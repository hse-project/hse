/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

#include "helper.h"

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
    printf("usage: %s <kvdb_home> <kvs1> <kvs2>\n", prog);
    return 1;
}

int
main(int argc, char **argv)
{
    char *kvdb_home;
    char *kvs_name1, *kvs_name2;

	const char *paramv[] = { "transactions_enable=1" };

    struct hse_kvdb *    kvdb;
    struct hse_kvs *     kvs1 = NULL, *kvs2 = NULL;
    struct hse_kvdb_txn *txn;

    char      vbuf[64];
    size_t    vlen;
    bool      found;
    hse_err_t rc, rc2;

    if (argc != 4)
        return usage(argv[0]);

    kvdb_home = argv[1];
    kvs_name1 = argv[2];
    kvs_name2 = argv[3];

    rc = hse_init(kvdb_home, 0, NULL);
    if (rc) {
		error(rc, "Failed to initialize HSE");
		goto out;
    }

    /* Open the KVDB and the KVS instances in it */
    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
		error(rc, "Failed to open KVDB (%s)", kvdb_home);
		goto hse_cleanup;
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name1, sizeof(paramv) / sizeof(paramv[0]), paramv, &kvs1);
    if (rc) {
		error(rc, "Failed to open KVS (%s)", kvs_name1);
		goto kvdb_cleanup;
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name2, sizeof(paramv) / sizeof(paramv[0]), paramv, &kvs2);
    if (rc) {
		error(rc, "Failed to open KVS (%s)", kvs_name2);
		goto kvs_cleanup;
    }

    txn = hse_kvdb_txn_alloc(kvdb);

	/* txn 1 */
    rc = hse_kvdb_txn_begin(kvdb, txn);
	if (rc) {
		error(rc, "Failed to being transaction");
		goto txn_cleanup;
	}

    rc = hse_kvs_put(kvs1, 0, txn, "k1", 2, "val1", 4);
	if (rc) {
		error(rc, "Failed to put data (k1, val1) into KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    rc = hse_kvs_put(kvs2, 0, txn, "k2", 2, "val2", 4);
	if (rc) {
		error(rc, "Failed to put data (k2, val2) into KVS (%s)", kvs_name2);
		goto txn_cleanup;
	}

    /* This txn hasn't been committed or aborted yet. So we should be able
     * to see the keys from inside the txn, but not from outside.
     */
    rc = hse_kvs_get(kvs1, 0, txn, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k1 data from KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    printf("k1 from inside txn: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs1, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k1 data from KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    printf("k1 from outside txn: found = %s\n", found ? "true" : "false");

    rc = hse_kvdb_txn_commit(kvdb, txn);
	if (rc) {
		error(rc, "Failed to commit the transaction");
		goto txn_cleanup;
	}

    /* txn 2. Reuse txn object from the first allocation */
    rc = hse_kvdb_txn_begin(kvdb, txn);
	if (rc) {
		error(rc, "Failed to begin the transaction");
		goto txn_cleanup;
	}

    rc = hse_kvs_put(kvs1, 0, txn, "k3", 2, "val3", 4);
	if (rc) {
		error(rc, "Failed to put data (k3, val3) into KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    rc = hse_kvs_put(kvs2, 0, txn, "k4", 2, "val4", 4);
	if (rc) {
		error(rc, "Failed to put data (k4, val4) into KVS (%s)", kvs_name2);
		goto txn_cleanup;
	}

    rc = hse_kvdb_txn_abort(kvdb, txn);
	if (rc) {
		error(rc, "Failed to abort the transaction");
		goto txn_cleanup;
	}

    /* 3.1 Verify keys that are part of txn number 1 can be found */
    rc = hse_kvs_get(kvs1, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k1 data from KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    printf("txn1(committed), k1: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs2, 0, NULL, "k2", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k2 data from KVS (%s)", kvs_name2);
		goto txn_cleanup;
	}
    printf("txn1(committed), k2: found = %s\n", found ? "true" : "false");

    /* 3.2 Verify keys that are part of txn number 2 cannot be found */
    rc = hse_kvs_get(kvs1, 0, NULL, "k3", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k3 data from KVS (%s)", kvs_name1);
		goto txn_cleanup;
	}
    printf("txn2(aborted), k3: found = %s\n", found ? "true" : "false");
    rc = hse_kvs_get(kvs2, 0, NULL, "k4", 2, &found, vbuf, sizeof(vbuf), &vlen);
	if (rc) {
		error(rc, "Failed to get k4 data from KVS (%s)", kvs_name2);
		goto txn_cleanup;
	}
    printf("txn2(aborted), k4: found = %s\n", found ? "true" : "false");

txn_cleanup:
    hse_kvdb_txn_free(kvdb, txn);
kvs_cleanup:
	if (kvs1) {
		rc2 = hse_kvdb_kvs_close(kvs1);
		if (rc2)
			error(rc, "Failed to close KVS (%s)", kvs_name1);
		rc = rc ?: rc2;
	}
	if (kvs2) {
		rc2 = hse_kvdb_kvs_close(kvs2);
		if (rc2)
			error(rc2, "Failed to close KVS (%s)", kvs_name2);
		rc = rc ?: rc2;
	}
kvdb_cleanup:
    rc2 = hse_kvdb_close(kvdb);
	if (rc2)
		error(rc2, "Failed to close KVDB (%s)", kvdb_home);
	rc = rc ?: rc2;
hse_cleanup:
	hse_fini();
out:
    return hse_err_to_errno(rc);
}
