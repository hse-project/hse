/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include "build_config.h"

#include <mpool/mpool.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/kvdb_home.h>

#include <hse/version.h>

#include <hse_util/platform.h>
#include <hse_util/rest_api.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>
#include <hse_util/vlb.h>

#include <bsd/libutil.h>
#include <pidfile/pidfile.h>

/* clang-format off */

#define HSE_KVDB_SYNC_MASK     (HSE_KVDB_SYNC_ASYNC)
#define HSE_KVS_PUT_MASK       (HSE_KVS_PUT_PRIO | HSE_KVS_PUT_VCOMP_OFF)
#define HSE_CURSOR_CREATE_MASK (HSE_CURSOR_CREATE_REV)

/* clang-format on */

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
bool hse_initialized = false;

static void
hse_lowmem_adjust(unsigned long *memgb)
{
    struct hse_gparams gpdef = hse_gparams_defaults();
    unsigned long mavail;

    hse_meminfo(NULL, &mavail, 30);

    if (mavail <= HSE_LOWMEM_THRESHOLD_GB_DFLT) {
        uint32_t scale = ikvdb_lowmem_scale(mavail);

        /* Scale various caches based on the available memory */
        if (hse_gparams.gp_c0kvs_ccache_sz_max == gpdef.gp_c0kvs_ccache_sz_max)
            hse_gparams.gp_c0kvs_ccache_sz_max =
                min_t(uint64_t, HSE_C0_CCACHE_SZ_MIN * scale, HSE_C0_CCACHE_SZ_MAX);

        if (hse_gparams.gp_c0kvs_cheap_sz == gpdef.gp_c0kvs_cheap_sz)
            hse_gparams.gp_c0kvs_cheap_sz =
                min_t(uint64_t, HSE_C0_CHEAP_SZ_MIN * scale, HSE_C0_CHEAP_SZ_MAX);

        if (hse_gparams.gp_vlb_cache_sz == gpdef.gp_vlb_cache_sz)
            hse_gparams.gp_vlb_cache_sz =
                min_t(uint64_t, HSE_VLB_CACHESZ_MIN * scale, HSE_VLB_CACHESZ_MAX);
    }

    assert(memgb);
    *memgb = mavail;
}

hse_err_t
hse_init(const char *const config, const size_t paramc, const char *const *const paramv)
{
    merr_t         err;
    ulong          memgb;
    struct config *conf;

    if (hse_initialized)
        return 0;

    hse_gparams = hse_gparams_defaults();

    err = argv_deserialize_to_hse_gparams(paramc, paramv, &hse_gparams);
    if (err) {
        fprintf(stderr, "Failed to deserialize paramv for HSE gparams\n");
        return merr_to_hse_err(err);
    }

    err = config_from_hse_conf(config, &conf);
    if (err) {
        fprintf(stderr, "Failed to read HSE config file (%s)\n", config);
        return merr_to_hse_err(err);
    }

    err = config_deserialize_to_hse_gparams(conf, &hse_gparams);
    config_destroy(conf);
    if (err) {
        fprintf(stderr, "Failed to deserialize config file (%s) for HSE gparams\n", config);
        return merr_to_hse_err(err);
    }

    hse_lowmem_adjust(&memgb);

    err = hse_platform_init();
    if (err)
        return merr_to_hse_err(err);

    log_info("Memory available: %lu GiB", memgb);

    err = ikvdb_init();
    if (err) {
        hse_platform_fini();

        return merr_to_hse_err(err);
    }

    if (hse_gparams.gp_socket.enabled) {
        err = rest_server_start(hse_gparams.gp_socket.path);
        if (ev(err)) {
            log_warn("Could not start rest server on %s", hse_gparams.gp_socket.path);
            err = 0;
        } else {
            log_info("Rest server started: %s", hse_gparams.gp_socket.path);
        }
    }

    log_info("%s, version %s", HSE_KVDB_DESC, HSE_VERSION_STRING);

    hse_initialized = true;

    return 0;
}

void
hse_fini(void)
{
    if (!hse_initialized)
        return;

    rest_server_stop();

    ikvdb_fini();
    hse_platform_fini();
    hse_initialized = false;
}

hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *const paramv)
{
    struct kvdb_cparams  dbparams = kvdb_cparams_defaults();
    merr_t               err;
    u64                  tstart;
    char                 pidfile_path[PATH_MAX];
    struct pidfh *       pfh = NULL;
    struct pidfile       content = {};

    if (HSE_UNLIKELY(!kvdb_home)) {
        log_err("A KVDB home must be provided");
        return merr_to_hse_err(EINVAL);
    }

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CREATE);

    err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &dbparams);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVDB (%s) cparams: @@e", err, kvdb_home);
        return merr_to_hse_err(err);
    }

    err = kvdb_cparams_resolve(&dbparams, kvdb_home);
    if (ev(err)) {
        log_errx("Failed to resolve KVDB (%s) cparams: @@e", err, kvdb_home);
        goto out;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s/kvdb.pid): @@e", err, kvdb_home);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = merr(errno);
        log_errx("Failed to open KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    content.pid = getpid();

    err = merr(pidfile_serialize(pfh, &content));
    if (err) {
        log_errx("Failed to serialize data to the KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    err = ikvdb_create(kvdb_home, &dbparams);
    if (ev(err))
        goto out;

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_CREATE, tstart);

out:
    if (pidfile_remove(pfh) == -1 && !err)
        err = merr(errno);
    pfh = NULL;

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_drop(const char *kvdb_home)
{
    char                pidfile_path[PATH_MAX];
    struct pidfh *      pfh = NULL;
    merr_t              err;

    if (HSE_UNLIKELY(!kvdb_home)) {
        log_err("A KVDB home must be provided");
        return merr_to_hse_err(EINVAL);
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid: @@e", err, kvdb_home);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        if (errno == EEXIST)
            errno = EBUSY;
        err = merr(errno);
        log_errx("Failed to open KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    err = ikvdb_drop(kvdb_home);
    if (ev(err))
        goto out;

out:
    if (pfh)
        pidfile_remove(pfh);

    return merr_to_hse_err(err);
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
    struct kvdb_rparams params = kvdb_rparams_defaults();
    u64                 tstart;
    char                pidfile_path[PATH_MAX];
    struct config *     conf = NULL;
    struct pidfh *      pfh = NULL;
    struct pidfile      content = {};

    if (HSE_UNLIKELY(!kvdb_home)) {
        log_err("A KVDB home must be provided");
        return merr_to_hse_err(EINVAL);
    }

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_OPEN);

    err = argv_deserialize_to_kvdb_rparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVDB (%s) rparams: @@e", err, kvdb_home);
        goto out;
    }

    err = config_from_kvdb_conf(kvdb_home, &conf);
    if (ev(err)) {
        log_errx("Failed to read KVDB config file (%s/kvdb.conf): @@e", err, kvdb_home);
        goto out;
    }

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize config file for KVDB (%s) rparams: @@e", err, kvdb_home);
        goto out;
    }

    err = kvdb_rparams_resolve(&params, kvdb_home);
    if (ev(err)) {
        log_errx("Failed to resolve KVDB (%s) rparams: @@e", err, kvdb_home);
        goto out;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid: @@e", err, kvdb_home);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = errno == EEXIST ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    content.pid = getpid();
    static_assert(sizeof(content.socket.path) == sizeof(hse_gparams.gp_socket.path),
                  "Unequal socket buffer sizes");

    if (hse_gparams.gp_socket.enabled)
        strlcpy(content.socket.path, hse_gparams.gp_socket.path, sizeof(content.socket.path));

    err = merr(pidfile_serialize(pfh, &content));
    if (err) {
        log_errx("Failed to serialize data to the KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    err = ikvdb_open(kvdb_home, &params, &ikvdb);
    if (ev(err))
        goto out;

    ikvdb_config_attach(ikvdb, conf);
    ikvdb_pidfh_attach(ikvdb, pfh);

    *handle = (struct hse_kvdb *)ikvdb;

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_OPEN, tstart);

out:
    if (err) {
        if (pfh)
            pidfile_remove(pfh);
        config_destroy(conf);
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_close(struct hse_kvdb *handle)
{
    merr_t         err = 0;
    struct pidfh * pfh;
    struct config *conf;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CLOSE);

    conf = ikvdb_config((struct ikvdb *)handle);
    pfh = ikvdb_pidfh((struct ikvdb *)handle);
    assert(pfh);

    err = ikvdb_close((struct ikvdb *)handle);
    ev(err);

    if (pidfile_remove(pfh) == -1 && !err)
        err = merr(errno);

    config_destroy(conf);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_names_get(struct hse_kvdb *handle, size_t *namec, char ***namev)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !namev))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_NAMES_GET);

    err = ikvdb_kvs_names_get((struct ikvdb *)handle, namec, namev);
    ev(err);

    return merr_to_hse_err(err);
}

void
hse_kvdb_kvs_names_free(struct hse_kvdb *handle, char **namev)
{
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_NAMES_FREE);

    ikvdb_kvs_names_free((struct ikvdb *)handle, namev);
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

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CREATE);

    err = validate_kvs_name(kvs_name);
    if (ev(err)) {
        log_errx("Invalid KVS name: %s, must match the regex [-_A-Za-z0-9]: @@e", err, kvs_name);
        return merr_to_hse_err(err);
    }

    err = argv_deserialize_to_kvs_cparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVS (%s) cparams: @@e", err, kvs_name);
        return merr_to_hse_err(err);
    }

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

    if (HSE_UNLIKELY(!handle || !kvs_name || !kvs_out))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_OPEN);

    err = argv_deserialize_to_kvs_rparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVS (%s) rparams: @@e", err, kvs_name);
        return merr_to_hse_err(err);
    }

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

    memset(info, 0, sizeof(*info));

    return merr_to_hse_err(ikvdb_storage_info_get((struct ikvdb *)kvdb, info));
}

hse_err_t
hse_kvdb_storage_add(const char *kvdb_home, size_t paramc, const char *const *const paramv)
{
    struct kvdb_cparams  cparams = kvdb_cparams_defaults();
    merr_t               err;
    char                 pidfile_path[PATH_MAX];
    struct pidfh        *pfh;
    struct pidfile       content = {};

    if (HSE_UNLIKELY(!kvdb_home)) {
        log_err("A KVDB home must be provided");
        return merr_to_hse_err(EINVAL);
    }

    if (HSE_UNLIKELY(!paramv || paramc == 0)) {
        log_err("Cannot add storage to the the KVDB (%s) if paramv is empty", kvdb_home);
        return merr_to_hse_err(merr(EINVAL));
    }

    /* Make the default capacity path an empty string. This is to catch the usage
     * error of attempting to add a capacity media class dynamically.
     */
    cparams.storage.mclass[MP_MED_CAPACITY].path[0] = '\0';

    err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &cparams);
    if (err) {
        log_errx("Failed to deserialize paramv for KVDB (%s) cparams: @@e", err, kvdb_home);
        return merr_to_hse_err(err);
    }

    err = kvdb_cparams_resolve(&cparams, kvdb_home);
    if (err) {
        log_errx("Failed to resolve KVDB (%s) cparams: @@e", err, kvdb_home);
        return merr_to_hse_err(err);
    }

    if (cparams.storage.mclass[MP_MED_CAPACITY].path[0] != '\0') {
        log_err(
            "Cannot add %s to %s: capacity media class path must be provided only at KVDB create",
            cparams.storage.mclass[MP_MED_CAPACITY].path, kvdb_home);
        return merr_to_hse_err(merr(EINVAL));
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid: @@e", err, kvdb_home);
        return merr_to_hse_err(err);
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = errno == EEXIST ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    content.pid = getpid();

    err = merr(pidfile_serialize(pfh, &content));
    if (err) {
        log_errx("Failed to serialize data to the KVDB pidfile (%s): @@e", err, pidfile_path);
        goto out;
    }

    err = ikvdb_storage_add(kvdb_home, &cparams);

out:
    if (pidfile_remove(pfh) == -1 && !err)
        err = merr(errno);

    return merr_to_hse_err(err);
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

    if (HSE_UNLIKELY(!handle || !key || (val_len > 0 && !val) || flags & ~HSE_KVS_PUT_MASK))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
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

    if (HSE_UNLIKELY(!handle || !key || !found || !val_len || flags != 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(!valbuf && valbuf_sz > 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
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

    if (HSE_UNLIKELY(!handle || !key || flags != 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
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
    const void *               pfx,
    size_t                     pfx_len)
{
    merr_t            err;
    struct kvs_ktuple kt;

    if (HSE_UNLIKELY(!handle || flags != 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(pfx_len > HSE_KVS_PFX_LEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    kvs_ktuple_init(&kt, pfx, pfx_len);

    err = ikvdb_kvs_prefix_delete(handle, flags, txn, &kt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_PFX_DEL, PERFC_RA_KVDBOP_KVS_PFX_DELB, pfx_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_sync(struct hse_kvdb *handle, const unsigned int flags)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || flags & ~HSE_KVDB_SYNC_MASK))
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
    if (HSE_UNLIKELY(!handle))
        return NULL;

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ALLOC);

    return ikvdb_txn_alloc((struct ikvdb *)handle);
}

void
hse_kvdb_txn_free(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    if (HSE_UNLIKELY(!handle || !txn))
        return;

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

    if (HSE_UNLIKELY(!handle || !txn))
        return merr_to_hse_err(merr(EINVAL));

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

    if (HSE_UNLIKELY(!handle || !txn))
        return merr_to_hse_err(merr(EINVAL));

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_ABORT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ABORT);

    err = ikvdb_txn_abort((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_ABORT, tstart);

    return merr_to_hse_err(err);
}

enum hse_kvdb_txn_state
hse_kvdb_txn_state_get(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    enum hse_kvdb_txn_state state = 0;
    enum kvdb_ctxn_state    istate;
    struct kvdb_ctxn *      ctxn;

    if (HSE_UNLIKELY(!handle || !txn))
        return HSE_KVDB_TXN_INVALID;

    ctxn = kvdb_ctxn_h2h(txn);

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

#define MAX_CUR_TIME (10 * NSEC_PER_SEC)

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
    u64 t_cur;

    if (HSE_UNLIKELY(!handle || !cursor || (pfx_len && !prefix) || flags & ~HSE_CURSOR_CREATE_MASK))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_CREATE);

    t_cur = get_time_ns();
    err = ikvdb_kvs_cursor_create(handle, flags, txn, prefix, pfx_len, cursor);
    ev(err);

    t_cur = get_time_ns() - t_cur;
    if (t_cur > MAX_CUR_TIME)
        log_errx("cursor create taking too long: %lus: @@e", err, t_cur / NSEC_PER_SEC);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_update_view(
    struct hse_kvs_cursor *    cursor,
    const unsigned int         flags)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || flags != 0))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE);

    err = ikvdb_kvs_cursor_update_view(cursor, flags);
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

    if (HSE_UNLIKELY(!cursor || flags != 0))
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

    if (HSE_UNLIKELY(!cursor || flags != 0))
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

    if (HSE_UNLIKELY(!cursor || !key || !klen || !val || !vlen || !eof || flags != 0))
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
hse_kvdb_compact(struct hse_kvdb *handle, unsigned int flags)
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

size_t
hse_strerror(hse_err_t err, char *buf, size_t buf_sz)
{
    size_t need_sz;

    merr_strinfo(err, buf, buf_sz, &need_sz);

    return need_sz;
}

int
hse_err_to_errno(hse_err_t err)
{
    return merr_errno(err);
}

/* Includes necessary files for mocking */
#if HSE_MOCKING
#define HSE_EXPORT
#define HSE_EXPORT_EXPERIMENTAL
#include "hse_ut_impl.i"
#undef HSE_EXPORT_EXPERIMENTAL
#undef HSE_EXPORT
#endif /* HSE_MOCKING */
