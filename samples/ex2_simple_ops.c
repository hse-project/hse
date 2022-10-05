/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

#include "helper.h"

/*
 * This is a simple example application that performs basic key-value operations
 * on a KVS.
 *
 * This program
 *   1. puts few keys into a KVS
 *   2. verifies that hse_kvs_get() can find them.
 *   3. delete one of the keys
 *   4. verify that the deleted key cannot be found.
 */

int
usage(char *prog)
{
    printf("usage: %s <kvdb_home> <kvs>\n", prog);

    return 1;
}

int
main(int argc, char **argv)
{
    char *kvdb_home, *kvs_name;

    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;

    const char * paramv[] = { "logging.destination=stdout",
                             "logging.level=3",
                             "rest.enabled=false" };
    const size_t paramc = sizeof(paramv) / sizeof(paramv[0]);

    size_t    vlen;
    char      vbuf[32];
    bool      found;
    hse_err_t rc, rc2;

    if (argc != 3)
        return usage(argv[0]);

    kvdb_home = argv[1];
    kvs_name = argv[2];

    rc = hse_init(NULL, paramc, paramv);
    if (rc) {
        error(rc, "Failed to initialize KVDB (%s)", kvdb_home);
        goto out;
    }

    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
        error(rc, "Cannot open KVDB (%s)", kvdb_home);
        goto hse_cleanup;
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, 0, NULL, &kvs);
    if (rc) {
        error(rc, "Cannot open KVS (%s)", kvs_name);
        goto kvdb_cleanup;
    }

    /* Error handling is elided for clarity */

    /* 1. Put a few keys and verify that hse_kvs_get() can find them */
    rc = hse_kvs_put(kvs, 0, NULL, "k1", 2, "val1", 4);
    rc = rc ?: hse_kvs_put(kvs, 0, NULL, "k2", 2, "val2", 4);
    rc = rc ?: hse_kvs_put(kvs, 0, NULL, "k3", 2, "val3", 4);
    rc = rc ?: hse_kvs_put(kvs, 0, NULL, "k4", 2, NULL, 0);
    if (rc) {
        error(rc, "Failed to put data into KVS (%s)", kvs_name);
        goto kvs_cleanup;
    }

    rc = hse_kvs_get(kvs, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    if (rc) {
        error(rc, "Failed to get k1 data");
        goto kvs_cleanup;
    }
    printf("k1 found = %s\n", found ? "true" : "false");

    rc = hse_kvs_get(kvs, 0, NULL, "k2", 2, &found, vbuf, sizeof(vbuf), &vlen);
    if (rc) {
        error(rc, "Failed to get k2 data");
        goto kvs_cleanup;
    }
    printf("k2 found = %s\n", found ? "true" : "false");

    rc = hse_kvs_get(kvs, 0, NULL, "k3", 2, &found, vbuf, sizeof(vbuf), &vlen);
    if (rc) {
        error(rc, "Failed to get k3 data");
        goto kvs_cleanup;
    }
    printf("k3 found = %s\n", found ? "true" : "false");

    rc = hse_kvs_get(kvs, 0, NULL, "k4", 2, &found, vbuf, sizeof(vbuf), &vlen);
    if (rc) {
        error(rc, "Failed to get k4 data");
        goto kvs_cleanup;
    }
    printf("k4 found = %s, length was %lu bytes\n", found ? "true" : "false", vlen);

    /* 2. Delete a key and ensure that it cannot be found by hse_kvs_get() */
    rc = hse_kvs_delete(kvs, 0, NULL, "k1", 2);
    if (rc) {
        error(rc, "Failed to delete k1 data");
        goto kvs_cleanup;
    }
    printf("k1 deleted\n");

    rc = hse_kvs_get(kvs, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    if (rc) {
        error(rc, "Failed to get k1 data");
        goto kvs_cleanup;
    }
    printf("k1 found = %s\n", found ? "true" : "false");

kvs_cleanup:
    rc2 = hse_kvdb_kvs_close(kvs);
    if (rc2)
        error(rc2, "Failed to close KVS (%s)", kvs_name);
    rc = rc ?: rc2;
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
