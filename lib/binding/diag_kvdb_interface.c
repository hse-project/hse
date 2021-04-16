/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include <mpool/mpool.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/wp.h>
#include <hse_ikvdb/hse_params_internal.h>

#include <hse/hse_version.h>

#include <hse_util/platform.h>
#include <hse_util/rest_api.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>

merr_t
diag_kvdb_open(
    const char               *mpool_name,
    const struct hse_params  *params,
    struct hse_kvdb         **handle)
{
    merr_t              err;
    struct ikvdb *      ikvdb;
    struct mpool *      mp;
    struct kvdb_rparams rparams;

    if (ev(!mpool_name || !handle))
        return merr(EINVAL);

    /* [HSE_REVISIT] snapshot_id and certain rparams are ignored */
    if (!params) {
        /* Open the kvdb using default parameters */
        rparams = kvdb_rparams_defaults();
    } else  {
        err = hse_params_to_kvdb_rparams(params, NULL, &rparams);
        if (err)
            return err;
    }

    err = kvdb_rparams_validate(&rparams);
    if (ev(err))
        return err;

    perfc_verbosity = rparams.perfc_enable;

    if (rparams.log_lvl <= 7)
        hse_log_set_pri((int)rparams.log_lvl);

    hse_log_set_squelch_ns(rparams.log_squelch_ns);

    kvdb_rparams_print(&rparams);

    /* Need write access in case recovery data needs to be replayed into cN.
     * Need exclusive access to prevent multiple applications from
     * working on the same KVDB, which would cause corruption.
     */
    err = mpool_open(mpool_name, params, O_RDWR, &mp);
    if (ev(err))
        return err;

    err = ikvdb_diag_open(mpool_name, mp, &rparams, &ikvdb);
    if (ev(err))
        goto close_ds;

    *handle = (struct hse_kvdb *)ikvdb;

    return 0UL;

close_ds:
    mpool_close(mp);

    return err;
}

merr_t
diag_kvdb_close(struct hse_kvdb *handle)
{
    merr_t        err = 0, err2 = 0;
    struct mpool *ds;

    if (ev(!handle))
        return merr(EINVAL);

    /* Retrieve mpool descriptor before ikvdb_impl is free'd */
    ds = ikvdb_mpool_get((struct ikvdb *)handle);

    err = ikvdb_diag_close((struct ikvdb *)handle);
    ev(err);

    err2 = mpool_close(ds);
    ev(err2);

    return err ? err : err2;
}

merr_t
diag_kvdb_kvslist(struct hse_kvdb *handle, struct diag_kvdb_kvs_list *list, int len, int *kvscnt)
{
    merr_t err;

    err = ikvdb_diag_kvslist((struct ikvdb *)handle, list, len, kvscnt);
    if (ev(err))
        return err;

    return 0UL;
}

merr_t
diag_kvdb_get_cndb(struct hse_kvdb *handle, struct cndb **cndb)
{
    merr_t err;

    err = ikvdb_diag_cndb((struct ikvdb *)handle, cndb);
    if (ev(err))
        return err;

    return 0UL;
}
