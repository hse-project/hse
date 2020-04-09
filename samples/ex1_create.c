/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This is a basic example that shows how to create a KVDB in an mpool and add
 * KVSes to it.
 */

#include <stdio.h>

#include <hse/hse.h>

int
main(int argc, char **argv)
{
    char *           mpool_name, **kvslist;
    int              kvscnt, i;
    hse_err_t        rc;
    struct hse_kvdb *kvdb;

    if (argc < 3) {
        printf(
            "Usage: %s <mpool> <kvs1> "
            "[<kvs2> ... <kvsN>]\n",
            argv[0]);
        exit(1);
    }

    mpool_name = argv[1];
    kvslist = &argv[2];
    kvscnt = argc - 2;

    rc = hse_kvdb_init();
    if (rc) {
        printf("Failed to initialize hse kvdb");
        exit(1);
    }

    rc = hse_kvdb_make(mpool_name, NULL);
    if (rc)
        exit(1);

    rc = hse_kvdb_open(mpool_name, NULL, &kvdb);
    if (rc)
        exit(1);

    for (i = 0; i < kvscnt; i++) {
        rc = hse_kvdb_kvs_make(kvdb, kvslist[i], NULL);
        if (rc)
            break;
    }

    printf("KVDB and KVSes created\n");

    hse_kvdb_close(kvdb);

    hse_kvdb_fini();

    return rc;
}
