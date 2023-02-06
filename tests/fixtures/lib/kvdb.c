/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
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
    hse_err_t err;

    if (kvdb) {
        err = hse_kvdb_close(kvdb);
        if (err)
            return err;
    }

    err = hse_kvdb_drop(kvdb_home);

    return err;
}
