/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stddef.h>
#include <stdio.h>

#include <hse/hse.h>

#include "helper.h"

/*
 * This example demonstrates how to pass configuration parameters to HSE.
 * Various APIs support paramc/paramv parameters where paramv is an array of
 * key=value strings, and paramc is the length of the array. These APIs include:
 *
 *  - hse_init()
 *  - hse_kvdb_create()
 *  - hse_kvdb_open()
 *  - hse_kvdb_kvs_create()
 *  - hse_kvdb_kvs_open()
 *
 * hse_init() reads from an hse.conf. The conf file will override paramc/paramv
 * passed through the API.
 *
 * hse_kvdb_open() and hse_kvdb_kvs_open() also read from a kvdb.conf file. The
 * conf file will override paramc/paramv passed through the API.
 *
 * Refer to documentation for what each parameter is and how to set them.
 */

int
main(int argc, const char **argv)
{
    hse_err_t        err = 0;
    const char *     home;
    const char *     hi_paramv[] = { "logging.destination=stdout",
                                "logging.level=3",
                                "rest.enabled=false", };
    const size_t     hi_paramc = sizeof(hi_paramv) / sizeof(hi_paramv[0]);
    const char *     kvdb_paramv[] = { "mode=rdonly" };
    const size_t     kvdb_paramc = sizeof(kvdb_paramv) / sizeof(kvdb_paramv[0]);
    struct hse_kvdb *kvdb;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <kvdb_home>", argv[0]);
        return 1;
    }

    home = argv[1];

    err = hse_init(NULL, hi_paramc, hi_paramv);
    if (err) {
        error(err, "Failed to initialize HSE");
        goto out;
    }

    err = hse_kvdb_open(home, kvdb_paramc, kvdb_paramv, &kvdb);
    if (err) {
        error(err, "Failed to open KVDB (%s)", home);
        goto out;
    }

    err = hse_kvdb_close(kvdb);
    if (err) {
        error(err, "Failed to close the KVDB (%s)", home);
        goto out;
    }

out:
    hse_fini();

    return hse_err_to_errno(err);
}
