/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

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
    printf("usage: %s <kvdb> <kvs>\n", prog);

    return 1;
}

int
main(int argc, char **argv)
{
    char *kvdb_home, *kvs_name;

    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;

    size_t    vlen;
    char      vbuf[32];
    bool      found;
    hse_err_t rc;

    if (argc != 3)
        return usage(argv[0]);

    kvdb_home = argv[1];
    kvs_name = argv[2];

    rc = hse_init(0, NULL);
    if (rc) {
        printf("failed to initialize kvdb");
        exit(1);
    }

    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
        printf("Cannot open kvdb: %s\n", strerror(rc));
        exit(1);
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, 0, NULL, &kvs);
    if (rc)
        exit(1);

    /* Error handling is elided for clarity */

    /* 1. Put a few keys and verify that hse_kvs_get() can find them */
    rc = hse_kvs_put(kvs, 0, NULL, "k1", 2, "val1", 4);
    rc = hse_kvs_put(kvs, 0, NULL, "k2", 2, "val2", 4);
    rc = hse_kvs_put(kvs, 0, NULL, "k3", 2, "val3", 4);
    rc = hse_kvs_put(kvs, 0, NULL, "k4", 2, NULL, 0);

    hse_kvs_get(kvs, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k1 found = %s\n", found ? "true" : "false");

    hse_kvs_get(kvs, 0, NULL, "k2", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k2 found = %s\n", found ? "true" : "false");

    hse_kvs_get(kvs, 0, NULL, "k3", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k3 found = %s\n", found ? "true" : "false");

    hse_kvs_get(kvs, 0, NULL, "k4", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k4 found = %s, length was %lu bytes\n", found ? "true" : "false", vlen);

    /* 2. Delete a key and ensure that it cannot be found by hse_kvs_get() */
    rc = hse_kvs_delete(kvs, 0, NULL, "k1", 2);
    printf("k1 deleted\n");

    rc = hse_kvs_get(kvs, 0, NULL, "k1", 2, &found, vbuf, sizeof(vbuf), &vlen);
    printf("k1 found = %s\n", found ? "true" : "false");

    hse_kvdb_close(kvdb);

    hse_fini();

    return 0;
}
