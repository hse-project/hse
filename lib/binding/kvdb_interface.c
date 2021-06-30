/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include "_config.h"

#include <mpool/mpool.h>

#include <hse/hse.h>
#include <hse/hse_experimental.h>
#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_dparams.h>
#include <hse_ikvdb/home.h>

#include <hse/hse_version.h>

#include <hse_util/platform.h>
#include <hse_util/rest_api.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>

#include <bsd/libutil.h>
#include <pidfile/pidfile.h>

#define HSE_FLAG_SYNC_ALL HSE_FLAG_SYNC_ASYNC
#define HSE_FLAG_PUT_ALL HSE_FLAG_PUT_PRIORITY
#define HSE_FLAG_CURSOR_ALL \
    (HSE_FLAG_CURSOR_REVERSE | HSE_FLAG_CURSOR_BIND_TXN | HSE_FLAG_CURSOR_STATIC_VIEW)

static HSE_ALWAYS_INLINE u64
kvdb_lat_startu(const u32 cidx)
{
    return perfc_lat_startu(&kvdb_pkvdbl_pc, cidx);
}

static HSE_ALWAYS_INLINE void
kvdb_lat_record(const u32 cidx, const u64 start)
{
    perfc_lat_record(&kvdb_pkvdbl_pc, cidx, start);
}

/* Accessing hse_initialized is not thread safe, but it is only used
 * in hse_init() and hse_fini(), which must be serialized
 * with all other HSE APIs.
 */
static bool hse_initialized = false;

hse_err_t
hse_init(const size_t paramc, const char *const *const paramv)
{
    merr_t err;

    if (hse_initialized)
        return 0;

    err = hse_platform_init();
    if (err)
        return merr_to_hse_err(err);

    err = ikvdb_init();
    if (err) {
        hse_platform_fini();

        return merr_to_hse_err(err);
    }

    hse_log(HSE_INFO "%s, version %s", HSE_KVDB_DESC, HSE_VERSION_STRING);

    hse_initialized = true;

    return 0;
}

void
hse_fini(void)
{
    if (!hse_initialized)
        return;

    ikvdb_fini();
    hse_platform_fini();
    hse_initialized = false;
}

hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *const paramv)
{
    struct kvdb_cparams  dbparams = kvdb_cparams_defaults();
    struct mpool *       mp;
    merr_t               err;
    u64                  tstart;
    char                 real_home[PATH_MAX];
    char                 pidfile_path[PATH_MAX];
    size_t               n;
    struct pidfh *       pfh = NULL;
    struct pidfile       content;
    struct mpool_rparams mp_rparams = { 0 };
    bool                 mpool_created = false;
#ifdef HSE_CONF_EXTENDED
    struct config *conf = NULL;
#endif

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CREATE);

    err = kvdb_home_translate(kvdb_home, real_home, sizeof(real_home));
    if (ev(err))
        return merr_to_hse_err(err);

    err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &dbparams);
    if (ev(err))
        return merr_to_hse_err(err);

#ifdef HSE_CONF_EXTENDED
    err = config_from_hse_conf(real_home, &conf);
    if (ev(err))
        return merr_to_hse_err(err);

    err = config_deserialize_to_kvdb_cparams(conf, &dbparams);
    if (ev(err))
        goto out;
#endif

    err = kvdb_cparams_resolve(&dbparams, real_home);
    if (ev(err))
        goto out;

    n = kvdb_home_pidfile_path_get(real_home, pidfile_path, sizeof(pidfile_path));
    if (n >= sizeof(pidfile_path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = merr(errno);
        goto out;
    }

    content.pid = getpid();
    memset(content.socket.path, '\0', sizeof(content.socket.path));

    err = merr(pidfile_serialize(pfh, &content));
    if (err)
        goto out;

    err = mpool_create(real_home, &dbparams.storage);
    if (ev(err))
        goto out;
    mpool_created = true;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        if (dbparams.storage.mclass[i].path[0] != '\0') {
            strlcpy(
                mp_rparams.mclass[i].path,
                dbparams.storage.mclass[i].path,
                sizeof(mp_rparams.mclass[i].path));
        }
    }

    err = mpool_open(real_home, &mp_rparams, O_RDWR, &mp);
    if (ev(err))
        goto out;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_props_get(mp, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto out;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto out;
    }

    err = ikvdb_create(real_home, mp, &dbparams, MPOOL_ROOT_LOG_CAP);
    if (ev(err))
        goto out;

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_MAKE, tstart);

out:
    if (err) {
        if (mpool_created) {
            struct mpool_dparams mp_dparams;

            for (int i = 0; i < MP_MED_COUNT; i++) {
                if (dbparams.storage.mclass[i].path[0] != '\0') {
                    strlcpy(
                        mp_dparams.mclass[i].path,
                        dbparams.storage.mclass[i].path,
                        sizeof(mp_dparams.mclass[i].path));
                }
            }
            mpool_destroy(real_home, &mp_dparams);
        }
        pidfile_remove(pfh);
    } else {
        mpool_close(mp);
        if (pidfile_remove(pfh) == -1)
            err = merr(errno);
    }
    pfh = NULL;

#ifdef HSE_CONF_EXTENDED
    config_destroy(conf);
#endif

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_drop(const char *kvdb_home, const size_t paramc, const char *const *const paramv)
{
    char                real_home[PATH_MAX];
    struct kvdb_dparams params = kvdb_dparams_defaults();
    char                pidfile_path[PATH_MAX];
    struct pidfh       *pfh = NULL;
    merr_t              err, err1;
    size_t              n;
    u64                 logid1, logid2;
#ifdef HSE_CONF_EXTENDED
    struct config *conf = NULL;
#endif

    err = kvdb_home_translate(kvdb_home, real_home, sizeof(real_home));
    if (err)
        goto out;

    err1 = ikvdb_log_deserialize_to_kvdb_dparams(real_home, &params);
    ev(err1);

    err = argv_deserialize_to_kvdb_dparams(paramc, paramv, &params);
    if (err)
        goto out;

#ifdef HSE_CONF_EXTENDED
    err = config_from_hse_conf(real_home, &conf);
    if (ev(err))
        goto out;

    err = config_deserialize_to_kvdb_dparams(conf, &params);
    if (ev(err))
        goto out;
#endif

    err = kvdb_dparams_resolve(&params, real_home);
    if (ev(err))
        goto out;

    n = kvdb_home_pidfile_path_get(real_home, pidfile_path, sizeof(pidfile_path));
    if (n >= sizeof(pidfile_path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        goto out;
    }

    err = mpool_destroy(real_home, &params.storage);
    ev(err);

    if (!err1) {
        err = mpool_mdc_rootid_get(&logid1, &logid2);
        if (err)
            goto out;

        err = mpool_mdc_root_destroy(real_home, logid1, logid2);
    }

out:
#ifdef HSE_CONF_EXTENDED
    config_destroy(conf);
#endif
    pidfile_remove(pfh);

    return merr_to_hse_err(err);
}

static merr_t
handle_params(struct kvdb_rparams *params)
{
    perfc_verbosity = params->perfc_enable;

    if (params->log_lvl <= 7)
        hse_log_set_pri((int)params->log_lvl);

    hse_log_set_squelch_ns(params->log_squelch_ns);

    return 0;
}

hse_err_t
hse_kvdb_open(
    const char *             kvdb_home,
    size_t                   paramc,
    const char *const *const paramv,
    struct hse_kvdb **       handle)
{
    merr_t              err;
    struct ikvdb *      ikvdb;
    struct mpool *      mp = NULL;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    u64                 tstart;
    int                 flags;
    size_t              n;
    char                real_home[PATH_MAX];
    char                pidfile_path[PATH_MAX];
    struct config *     conf = NULL;
    struct pidfh *      pfh = NULL;
    struct pidfile      content;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_OPEN);

    err = kvdb_home_translate(kvdb_home, real_home, sizeof(real_home));
    if (ev(err))
        goto out;

    err = ikvdb_log_deserialize_to_kvdb_rparams(real_home, &params);
    if (err)
        goto out;

    err = argv_deserialize_to_kvdb_rparams(paramc, paramv, &params);
    if (ev(err))
        goto out;

    err = config_from_hse_conf(real_home, &conf);
    if (ev(err))
        goto out;

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    if (ev(err))
        goto out;

    err = kvdb_rparams_resolve(&params, real_home);
    if (ev(err))
        goto out;

    n = kvdb_home_pidfile_path_get(real_home, pidfile_path, sizeof(pidfile_path));
    if (n >= sizeof(pidfile_path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        goto out;
    }

    content.pid = getpid();
    n = kvdb_home_socket_path_get(
        real_home, params.socket.path, content.socket.path, sizeof(content.socket.path));
    if (n >= sizeof(content.socket.path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }

    err = merr(pidfile_serialize(pfh, &content));
    if (err)
        goto out;

    handle_params(&params);

    /* Need write access in case recovery data needs to be replayed into cN.
     * Need exclusive access to prevent multiple applications from
     * working on the same KVDB, which would cause corruption.
     */

    flags = params.read_only == 0 ? O_RDWR : O_RDONLY;
    err = mpool_open(real_home, &params.storage, flags, &mp);
    if (ev(err))
        goto out;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_props_get(mp, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto out;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto out;
    }

    err = ikvdb_open(real_home, &params, pfh, mp, conf, &ikvdb);
    if (ev(err))
        goto out;

    *handle = (struct hse_kvdb *)ikvdb;

    if (params.read_only == 0) {
        err = rest_server_start(content.socket.path);
        if (ev(err)) {
            hse_log(HSE_WARNING "Could not start rest server on %s", content.socket.path);
            err = 0;
        } else {
            hse_log(HSE_INFO "Rest server started: %s", content.socket.path);
        }
    }

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_OPEN, tstart);

out:
    if (err) {
        if (mp)
            mpool_close(mp);
        if (pfh)
            pidfile_remove(pfh);
        if (conf)
            config_destroy(conf);
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_close(struct hse_kvdb *handle)
{
    merr_t         err = 0, err2 = 0;
    struct pidfh * pfh;
    struct mpool * mp;
    struct config *conf = NULL;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CLOSE);

    conf = ikvdb_config((struct ikvdb *)handle);
    pfh = ikvdb_pidfh((struct ikvdb *)handle);

    /* Retrieve mpool descriptor before ikvdb_impl is free'd */
    mp = ikvdb_mpool_get((struct ikvdb *)handle);

    err = ikvdb_close((struct ikvdb *)handle);
    ev(err);

    err2 = mpool_close(mp);
    ev(err2);

    rest_server_stop();

    if (err || err2) {
        pidfile_remove(pfh);
    } else {
        if (pidfile_remove(pfh) == -1)
            err = merr(errno);
    }

    config_destroy(conf);

    return err ? merr_to_hse_err(err) : merr_to_hse_err(err2);
}

hse_err_t
hse_kvdb_get_names(struct hse_kvdb *handle, unsigned int *count, char ***kvs_list)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !kvs_list))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_GET_NAMES);

    err = ikvdb_get_names((struct ikvdb *)handle, count, kvs_list);
    ev(err);

    return merr_to_hse_err(err);
}

void
hse_kvdb_free_names(struct hse_kvdb *handle, char **kvsv)
{
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_FREE_NAMES);

    ikvdb_free_names((struct ikvdb *)handle, kvsv);
}

hse_err_t
hse_kvdb_kvs_create(
    struct hse_kvdb *        handle,
    const char *             kvs_name,
    size_t                   paramc,
    const char *const *const paramv)
{
    struct kvs_cparams params = kvs_cparams_defaults();
    merr_t             err;
#ifdef HSE_CONF_EXTENDED
    const struct config *conf = ikvdb_config((struct ikvdb *)handle);
#endif

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CREATE);

    err = validate_kvs_name(kvs_name);
    if (ev(err))
        return merr_to_hse_err(err);

    err = argv_deserialize_to_kvs_cparams(paramc, paramv, &params);
    if (ev(err))
        return merr_to_hse_err(err);

#ifdef HSE_CONF_EXTENDED
    err = config_deserialize_to_kvs_cparams(conf, kvs_name, &params);
    if (ev(err))
        return merr_to_hse_err(err);
#endif

    err = ikvdb_kvs_create((struct ikvdb *)handle, kvs_name, &params);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *handle, const char *const kvs_name)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !kvs_name))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_DROP);

    err = ikvdb_kvs_drop((struct ikvdb *)handle, kvs_name);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *        handle,
    const char *             kvs_name,
    size_t                   paramc,
    const char *const *const paramv,
    struct hse_kvs **        kvs_out)
{
    struct kvs_rparams params = kvs_rparams_defaults();
    merr_t             err;
    u64                tstart;
#ifdef HSE_CONF_EXTENDED
    const struct config *conf = ikvdb_config((struct ikvdb *)handle);
#endif

    if (HSE_UNLIKELY(!handle || !kvs_name || !kvs_out))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_OPEN);

    err = argv_deserialize_to_kvs_rparams(paramc, paramv, &params);
    if (ev(err))
        return merr_to_hse_err(err);

#ifdef HSE_CONF_EXTENDED
    err = config_deserialize_to_kvs_rparams(conf, kvs_name, &params);
    if (ev(err))
        return merr_to_hse_err(err);
#endif

    err = ikvdb_kvs_open((struct ikvdb *)handle, kvs_name, &params, IKVS_OFLAG_NONE, kvs_out);
    ev(err);

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVS_OPEN, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *handle)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CLOSE);

    err = ikvdb_kvs_close((struct hse_kvs *)handle);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_storage_info_get(struct hse_kvdb *kvdb, struct hse_kvdb_storage_info *info)
{
    if (HSE_UNLIKELY(!kvdb || !info))
        return merr_to_hse_err(merr(EINVAL));

    return merr_to_hse_err(ikvdb_storage_info_get((struct ikvdb *)kvdb, info, NULL, NULL, 0));
}

hse_err_t
hse_kvs_put(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               key,
    size_t                     key_len,
    const void *               val,
    size_t                     val_len)
{
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    merr_t            err;

    if (HSE_UNLIKELY(!handle || !key || (val_len > 0 && !val) || flags & ~HSE_FLAG_PUT_ALL))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    if (HSE_UNLIKELY(val_len > HSE_KVS_VALUE_LEN_MAX))
        return merr_to_hse_err(merr(EMSGSIZE));

    kvs_ktuple_init_nohash(&kt, key, key_len);
    kvs_vtuple_init(&vt, (void *)val, val_len);

    err = ikvdb_kvs_put(handle, flags, txn, &kt, &vt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_PUT, PERFC_RA_KVDBOP_KVS_PUTB, key_len + val_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_get(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               key,
    size_t                     key_len,
    bool *                     found,
    void *                     valbuf,
    size_t                     valbuf_sz,
    size_t *                   val_len)
{
    struct kvs_ktuple   kt;
    struct kvs_buf      vbuf;
    enum key_lookup_res res;
    merr_t              err;

    if (HSE_UNLIKELY(!handle || !key || !found || !val_len || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(!valbuf && valbuf_sz > 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    /* If valbuf is NULL and valbuf_sz is zero, this call is meant as a
     * probe for the existence of the key and length of its value. To
     * prevent c0/cn from allocating a new buffer for the value, set valbuf
     * to non-zero and proceed.
     */
    if (!valbuf && valbuf_sz == 0)
        valbuf = (void *)-1;

    kvs_ktuple_init_nohash(&kt, key, key_len);
    kvs_buf_init(&vbuf, valbuf, valbuf_sz);

    err = ikvdb_kvs_get(handle, flags, txn, &kt, &res, &vbuf);
    if (ev(err))
        return merr_to_hse_err(err);

    /* If the key is found then vbuf.b_len contains the length of the value
     * stored in the kvs.  We expect it to fit into output buffer.
     */
    *found = (res == FOUND_VAL);
    *val_len = vbuf.b_len;

    if (ev(res == FOUND_MULTIPLE))
        return merr_to_hse_err(merr(EPROTO));

    PERFC_INCADD_RU(
        &kvdb_pc, PERFC_RA_KVDBOP_KVS_GET, PERFC_RA_KVDBOP_KVS_GETB, *found ? *val_len : 0);

    return 0;
}

/**
 * hse_kvs_delete() - remove the supplied key and associated value from the KVS
 */
hse_err_t
hse_kvs_delete(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               key,
    size_t                     key_len)
{
    merr_t            err = 0;
    struct kvs_ktuple kt;

    if (HSE_UNLIKELY(!handle || !key || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    kvs_ktuple_init_nohash(&kt, key, key_len);
    err = ikvdb_kvs_del(handle, flags, txn, &kt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_DEL, PERFC_RA_KVDBOP_KVS_DELB, key_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               prefix_key,
    size_t                     key_len,
    size_t *                   kvs_pfx_len)
{
    merr_t            err;
    struct kvs_ktuple kt;

    if (HSE_UNLIKELY(!handle || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_PFX_LEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    kvs_ktuple_init(&kt, prefix_key, key_len);

    err = ikvdb_kvs_prefix_delete(handle, flags, txn, &kt, kvs_pfx_len);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_PFX_DEL, PERFC_RA_KVDBOP_KVS_PFX_DELB, key_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_sync(struct hse_kvdb *handle, const unsigned int flags)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || flags & ~HSE_FLAG_SYNC_ALL))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_startl(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_SYNC);

    err = ikvdb_sync((struct ikvdb *)handle, flags);
    ev(err);

    perfc_sl_record(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC, tstart);

    return merr_to_hse_err(err);
}

struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *handle)
{
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ALLOC);

    return ikvdb_txn_alloc((struct ikvdb *)handle);
}

void
hse_kvdb_txn_free(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_FREE);

    ikvdb_txn_free((struct ikvdb *)handle, txn);
}

hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || !txn))
        return merr_to_hse_err(merr(EINVAL));

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_BEGIN);

    err = ikvdb_txn_begin((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_COMMIT);

    err = ikvdb_txn_commit((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_ABORT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ABORT);

    err = ikvdb_txn_abort((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_ABORT, tstart);

    return merr_to_hse_err(err);
}

enum hse_kvdb_txn_state
hse_kvdb_txn_get_state(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    enum hse_kvdb_txn_state state = 0;
    enum kvdb_ctxn_state    istate;
    struct kvdb_ctxn *      ctxn = kvdb_ctxn_h2h(txn);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_GET_STATE);

    istate = kvdb_ctxn_get_state(ctxn);

    switch (istate) {
        case KVDB_CTXN_ACTIVE:
            state = HSE_KVDB_TXN_ACTIVE;
            break;

        case KVDB_CTXN_COMMITTED:
            state = HSE_KVDB_TXN_COMMITTED;
            break;

        case KVDB_CTXN_ABORTED:
            state = HSE_KVDB_TXN_ABORTED;
            break;

        default:
            state = HSE_KVDB_TXN_INVALID;
            break;
    }

    return state;
}

hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               prefix,
    size_t                     pfx_len,
    struct hse_kvs_cursor **   cursor)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !cursor || (pfx_len && !prefix) || flags & ~HSE_FLAG_CURSOR_ALL))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_CREATE);

    err = ikvdb_kvs_cursor_create(handle, flags, txn, prefix, pfx_len, cursor);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_update(
    struct hse_kvs_cursor *    cursor,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || flags & ~HSE_FLAG_CURSOR_ALL))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE);

    err = ikvdb_kvs_cursor_update(cursor, flags, txn);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    const unsigned int     flags,
    const void *           key,
    size_t                 len,
    const void **          found,
    size_t *               flen)
{
    struct kvs_ktuple kt;
    merr_t            err;

    if (HSE_UNLIKELY(!cursor || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, flags, key, len, 0, 0, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor *cursor,
    const unsigned int     flags,
    const void *           key,
    size_t                 key_len,
    const void *           limit,
    size_t                 limit_len,
    const void **          found,
    size_t *               flen)
{
    struct kvs_ktuple kt;
    merr_t            err;

    if (HSE_UNLIKELY(!cursor || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, flags, key, key_len, limit, limit_len, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor *cursor,
    const unsigned int     flags,
    const void **          key,
    size_t *               klen,
    const void **          val,
    size_t *               vlen,
    bool *                 eof)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || !key || !klen || !val || !vlen || !eof || flags != HSE_FLAG_NONE))
        return merr_to_hse_err(merr(EINVAL));

    err = ikvdb_kvs_cursor_read(cursor, flags, key, klen, val, vlen, eof);
    ev(err);

    if (!err && !*eof) {
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_READ, PERFC_RA_KVDBOP_KVS_GETB, *klen + *vlen);
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_DESTROY);

    err = ikvdb_kvs_cursor_destroy(cursor);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_compact(struct hse_kvdb *handle, int flags)
{
    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    ikvdb_compact((struct ikvdb *)handle, flags);

    return 0;
}

hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *handle, struct hse_kvdb_compact_status *status)
{
    if (HSE_UNLIKELY(!handle || !status))
        return merr_to_hse_err(merr(EINVAL));

    memset(status, 0, sizeof(*status));
    ikvdb_compact_status_get((struct ikvdb *)handle, status);

    return 0;
}

char *
hse_err_to_string(hse_err_t err, char *buf, size_t buf_sz, size_t *need_sz)
{
    return merr_strinfo(err, buf, buf_sz, need_sz);
}

int
hse_err_to_errno(hse_err_t err)
{
    return merr_errno(err);
}

/* Includes necessary files for mocking */
#if HSE_MOCKING
#include "hse_ut_impl.i"
#endif /* HSE_MOCKING */
