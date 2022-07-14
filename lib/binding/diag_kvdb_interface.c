/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include <mpool/mpool.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/kvdb_home.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include <hse/version.h>

#include <hse_util/platform.h>
#include <hse_util/rest_api.h>
#include <hse_util/logging.h>

#include <pidfile/pidfile.h>

#include <bsd/string.h>

merr_t
diag_kvdb_open(
    const char *       kvdb_home,
    size_t             paramc,
    const char *const *paramv,
    struct hse_kvdb ** handle)
{
    merr_t              err;
    struct ikvdb *      ikvdb;
    struct mpool *      mp = NULL;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct pidfh *      pfh = NULL;
    struct pidfile      content;
    char                pidfile_path[PATH_MAX];
    size_t              n;
    struct config *     conf;

    if (ev(!kvdb_home || !handle))
        return merr(EINVAL);

    err = argv_deserialize_to_kvdb_rparams(paramc, paramv, &params);
    if (err)
        goto close_mp;

    err = config_from_kvdb_conf(kvdb_home, &conf);
    if (err)
        goto close_mp;

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    if (err)
        goto close_mp;

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err)
        goto close_mp;

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh)
        goto close_mp;

    content.pid = getpid();
    n = strlcpy(content.socket.path, hse_gparams.gp_socket.path, sizeof(content.socket.path));
    if (n >= sizeof(content.socket.path)) {
        err = merr(ENAMETOOLONG);
        goto close_mp;
    }

    err = pidfile_serialize(pfh, &content);
    if (err)
        goto close_mp;

    err = ikvdb_diag_open(kvdb_home, &params, &ikvdb);
    if (ev(err))
        goto close_mp;

    ikvdb_pidfh_attach(ikvdb, pfh);
    ikvdb_config_attach(ikvdb, conf);

    *handle = (struct hse_kvdb *)ikvdb;

    return 0UL;

close_mp:
    if (mp)
        mpool_close(mp);
    if (pfh)
        pidfile_remove(pfh);

    return err;
}

merr_t
diag_kvdb_close(struct hse_kvdb *handle)
{
    merr_t        err = 0, err2 = 0;
    struct pidfh *pfh;
    char          home[PATH_MAX];
    struct mpool *ds;

    if (ev(!handle))
        return merr(EINVAL);

    pfh = ikvdb_pidfh((struct ikvdb *)handle);
    strlcpy(home, ikvdb_home((struct ikvdb *)handle), sizeof(home));

    /* Retrieve mpool descriptor before ikvdb_impl is free'd */
    ds = ikvdb_mpool_get((struct ikvdb *)handle);

    err = ikvdb_diag_close((struct ikvdb *)handle);
    ev(err);

    err2 = mpool_close(ds);
    ev(err2);

    if (err || err2) {
        pidfile_remove(pfh);
    } else {
        if (pidfile_remove(pfh) == -1)
            err = merr(errno);
    }

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
