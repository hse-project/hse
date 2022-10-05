/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This is a basic example that shows how to create a KVDB in an mpool and add
 * KVSes to it.
 */

#include <stdio.h>
#include <errno.h>

#include <hse/hse.h>

#include "helper.h"

int
main(int argc, char **argv)
{
    struct hse_kvdb *kvdb;

    char       *kvdb_home;
    char      **kvs_list;
    int         kvs_cnt;
    hse_err_t   rc, rc2;

    const char * paramv[] = { "logging.destination=stdout",
                             "logging.level=3",
                             "rest.enabled=false" };
    const size_t paramc = sizeof(paramv) / sizeof(paramv[0]);

    if (argc < 3) {
        printf("Usage: %s <kvdb_home> <kvs1> [<kvs2> ... <kvsN>]\n", argv[0]);
        exit(1);
    }

    kvdb_home = argv[1];
    kvs_list = &argv[2];
    kvs_cnt = argc - 2;

    rc = hse_init(NULL, paramc, paramv);
    if (rc) {
        error(rc, "Failed to initialize HSE");
        goto out;
    }

    rc = hse_kvdb_create(kvdb_home, 0, NULL);
    switch (hse_err_to_errno(rc)) {
    case 0:
        printf("KVDB (%s) created\n", kvdb_home);
        break;

    case EEXIST:
        printf("Using existing KVDB (%s)\n", kvdb_home);
        break;

    default:
        error(rc, "Failed to create KVDB (%s)", kvdb_home);
        goto hse_cleanup;
    }

    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
        error(rc, "Failed to open KVDB (%s)", kvdb_home);
        goto hse_cleanup;
    }

    for (int i = 0; i < kvs_cnt; i++) {
        rc = hse_kvdb_kvs_create(kvdb, kvs_list[i], 0, NULL);
        if (rc) {
            error(rc, "Failed to create KVS (%s)", kvs_list[i]);
            goto kvdb_cleanup;
        }
    }

    printf("KVSes created\n");

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
