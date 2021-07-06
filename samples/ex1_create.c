/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This is a basic example that shows how to create a KVDB in an mpool and add
 * KVSes to it.
 */

#include <stdio.h>
#include <errno.h>

#include <hse/hse.h>

void
report_error(const char *api, hse_err_t err)
{
    char message[256];

    hse_strerror(err, message, sizeof(message));
    printf("%s: %s\n", api, message);
}


int
main(int argc, char **argv)
{
    struct hse_kvdb *kvdb;

    char       *kvdb_home;
    char      **kvs_list;
    int         kvs_cnt;
    hse_err_t   err, err2;
    bool        init, open;
    int errno;

    if (argc < 3) {
        printf("Usage: %s <mpool> <kvs1> [<kvs2> ... <kvsN>]\n", argv[0]);
        exit(1);
    }

    kvdb_home = argv[1];
    kvs_list = &argv[2];
    kvs_cnt = argc - 2;

    init = false;
    open = false;

    err = hse_init(0, NULL);
    if (err) {
        report_error("hse_init", err);
        goto error;
    }

    init = true;

    err = hse_kvdb_create(kvdb_home, 0, NULL);
    switch (hse_err_to_errno(err)) {

        case 0:
            printf("KVDB created\n");
            break;

        case EEXIST:
            printf("Use existing KVDB\n");
            err = 0;
            break;

        case ENODATA:
            printf("No such mpool: %s\n", kvdb_home);
            goto error;

        default:
            report_error("hse_kvdb_create", err);
            goto error;
    }

    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (err) {
        report_error("hse_kvdb_open", err);
        goto error;
    }

    open = true;

    for (int i = 0; i < kvs_cnt; i++) {
        err = hse_kvdb_kvs_create(kvdb, kvs_list[i], 0, NULL);
        if (err) {
            report_error("hse_kvdb_kvs_create", err);
            goto error;
        }
    }

    printf("KVSes created\n");

  error:

    err2 = 0;

    if (open) {
        err2 = hse_kvdb_close(kvdb);
        if (err2)
            report_error("hse_kvdb_close", err2);
    }

    if (init)
        hse_fini();

    return (err || err2) ? 1 : 0;
}
