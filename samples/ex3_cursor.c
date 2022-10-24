/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

#include "helper.h"

/*
 * This is an example program that illustrates the use of cursors in a KVS.
 * In this example, we
 *   1. put few keys into the KVS.
 *   2. iterate over the keys using a cursor and verify that all the keys exist
 *   3. seek to a key and read the value there. Print the expected value and
 *      the value read by the cursor.
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

    struct hse_kvdb *      kvdb;
    struct hse_kvs *       kvs;
    struct hse_kvs_cursor *cursor = NULL;

    const char * paramv[] = { "logging.destination=stdout",
                              "logging.level=3",
                              "rest.enabled=false" };
    const size_t paramc = sizeof(paramv) / sizeof(paramv[0]);

    char key[64], val[64];

    int       i, cnt = 15;
    bool      eof = false;
    hse_err_t rc, rc2;
    size_t    key_len, val_len;

    if (argc != 3)
        return usage(argv[0]);

    kvdb_home = argv[1];
    kvs_name = argv[2];

    rc = hse_init(NULL, paramc, paramv);
    if (rc) {
        error(rc, "Failed to initialize HSE");
        goto out;
    }

    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
        error(rc, "Failed to open KVDB (%s)", kvdb_home);
        goto hse_cleanup;
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, 0, NULL, &kvs);
    if (rc) {
        error(rc, "Failed to open KVS (%s)", kvs_name);
        goto kvdb_cleanup;
    }

    /* put 'cnt' keys */
    for (i = 0; i < cnt; i++) {
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(val, sizeof(val), "val%03d", i);

        rc = hse_kvs_put(kvs, 0, NULL, key, strlen(key), val, strlen(val));
        if (rc) {
            error(rc, "Failed to put data (%s, %s) into KVS (%s)", key, val, kvs_name);
            goto kvs_cleanup;
        }
    }

    rc = hse_kvs_cursor_create(kvs, 0, NULL, NULL, 0, &cursor);
    if (rc) {
        error(rc, "Failed to create cursor");
        goto kvs_cleanup;
    }

    while (!eof) {
        rc = hse_kvs_cursor_read(cursor, 0, key, sizeof(key), &key_len, val, sizeof(val), &val_len,
            &eof);
        if (rc) {
            error(rc, "Failed to read from cursor");
            goto cursor_cleanup;
        }

        if (!eof)
            printf(
                "key:%.*s\tval:%.*s\n",
                (int)key_len,
                (char *)key,
                (int)val_len,
                (char *)val);
    }

    rc = hse_kvs_cursor_seek(cursor, 0, "key010", 6, NULL, 0, NULL);
    if (rc) {
        error(rc, "Failed to seek cursor to key010");
        goto cursor_cleanup;
    }
    rc = hse_kvs_cursor_read(cursor, 0, key, sizeof(key), &key_len, val, sizeof(val), &val_len,
        &eof);
    if (rc) {
        error(rc, "Failed to read from cursor");
        goto cursor_cleanup;
    }

    printf("After seek to key010:\n");
    printf("expected: key:%s\tval:%s\n", "key010", "val010");
    printf("found:    key:%.*s\tval:%.*s\n", (int)key_len, (char *)key,
           (int)val_len, (char *)val);

cursor_cleanup:
    rc2 = hse_kvs_cursor_destroy(cursor);
    if (rc2)
        error(rc2, "Failed to destroy cursor");
    rc = rc ?: rc2;
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
