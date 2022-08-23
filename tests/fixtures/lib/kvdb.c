/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.
 */

#include <hse/hse.h>
#include <hse/test/fixtures/kvdb.h>

hse_err_t
fxt_kvdb_setup(
    const char *const        kvdb_home,
    const size_t             rparamc,
    const char *const *const rparamv,
    const size_t             cparamc,
    const char *const *const cparamv,
    struct hse_kvdb **       kvdb)
{
    hse_err_t err;

    err = hse_kvdb_create(kvdb_home, cparamc, cparamv);
    if (err)
        return err;

    err = hse_kvdb_open(kvdb_home, rparamc, rparamv, kvdb);
    if (err)
        hse_kvdb_drop(kvdb_home);

    return err;
}

hse_err_t
fxt_kvdb_teardown(const char *const kvdb_home, struct hse_kvdb *const kvdb)
{
    hse_err_t err, rc = 0;
    size_t    kvs_namec;
    char **   kvs_namev = NULL;

    err = hse_kvdb_kvs_names_get(kvdb, &kvs_namec, &kvs_namev);
    if (err) {
        rc = err;
    } else {
        for (size_t i = 0; i < kvs_namec; i++) {
            err = hse_kvdb_kvs_drop(kvdb, kvs_namev[i]);
            if (err && !rc)
                rc = err;
        }
    }

    hse_kvdb_kvs_names_free(kvdb, kvs_namev);

    err = hse_kvdb_close(kvdb);
    if (err && !rc)
        rc = err;

    err = hse_kvdb_drop(kvdb_home);
    if (err && !rc)
        rc = err;

    return rc;
}
