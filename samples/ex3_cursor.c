/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <hse/hse.h>

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
    printf("usage: %s <kvdb> <kvs>\n", prog);

    return 1;
}

int
main(int argc, char **argv)
{
    char *mp_name, *kvs_name;

    struct hse_kvdb *      kvdb;
    struct hse_kvs *       kvs;
    struct hse_kvs_cursor *cursor = NULL;

    char key[64], val[64];

    int       i, cnt = 15;
    bool      eof = false;
    hse_err_t rc;
    char      errbuf[200];

    const void *cur_key, *cur_val;
    size_t      cur_klen, cur_vlen;

    if (argc != 3)
        return usage(argv[0]);

    mp_name = argv[1];
    kvs_name = argv[2];

    rc = hse_kvdb_init();
    if (rc) {
        printf("failed to initialize kvdb");
        exit(1);
    }

    rc = hse_kvdb_open(mp_name, NULL, &kvdb);
    if (rc) {
        printf("Cannot open kvdb: %s\n", hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));
        exit(1);
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, NULL, &kvs);
    if (rc)
        exit(1);

    /* Error handling is elided for clarity */

    /* put 'cnt' keys */
    for (i = 0; i < cnt; i++) {
        snprintf(key, sizeof(key), "key%03d", i);
        snprintf(val, sizeof(val), "val%03d", i);

        rc = hse_kvs_put(kvs, NULL, key, strlen(key), val, strlen(val));
    }

    rc = hse_kvs_cursor_create(kvs, NULL, NULL, 0, &cursor);
    if (rc)
        exit(1);

    while (!eof) {
        rc = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

        if (!eof)
            printf(
                "key:%.*s\tval:%.*s\n",
                (int)cur_klen,
                (char *)cur_key,
                (int)cur_vlen,
                (char *)cur_val);
    }

    rc = hse_kvs_cursor_seek(cursor, NULL, "key010", 6, NULL, NULL);
    rc = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

    printf("After seek to key010:\n");
    printf("expected: key:%s\tval:%s\n", "key010", "val010");
    printf("found:    key:%.*s\tval:%.*s\n", (int)cur_klen, (char *)cur_key,
           (int)cur_vlen, (char *)cur_val);

    hse_kvs_cursor_destroy(cursor);

    hse_kvdb_close(kvdb);
    hse_kvdb_fini();

    return 0;
}
