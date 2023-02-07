/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <errno.h>

#include <hse/hse.h>
#include <hse/test/fixtures/kvs.h>

hse_err_t
fxt_kvs_setup(
    struct hse_kvdb *        kvdb,
    const char *const        kvs_name,
    const size_t             rparamc,
    const char *const *const rparamv,
    const size_t             cparamc,
    const char *const *const cparamv,
    struct hse_kvs **        kvs)
{
    hse_err_t err;

    err = hse_kvdb_kvs_create(kvdb, kvs_name, cparamc, cparamv);
    if (err)
        return err;

    err = hse_kvdb_kvs_open(kvdb, kvs_name, rparamc, rparamv, kvs);
    if (err)
        hse_kvdb_kvs_drop(kvdb, kvs_name);

    return err;
}

hse_err_t
fxt_kvs_teardown(struct hse_kvdb *const kvdb, const char *const kvs_name, struct hse_kvs *const kvs)
{
    hse_err_t err, rc = 0;

    err = hse_kvdb_kvs_close(kvs);
    if (err)
        rc = err;

    err = hse_kvdb_kvs_drop(kvdb, kvs_name);
    if (err && !rc)
        rc = err;

    return rc;
}
