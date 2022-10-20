/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include "build_config.h"

#include <string.h>

#include <mpool/mpool.h>

#include <hse/hse.h>
#include <hse/experimental.h>
#include <hse/logging/logging.h>
#include <hse/pidfile/pidfile.h>
#include <hse/rest/headers.h>
#include <hse/rest/params.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/rest/server.h>
#include <hse/rest/status.h>
#include <hse/version.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/kvdb_home.h>
#include <hse_ikvdb/kvs.h>

#include <hse_util/err_ctx.h>
#include <hse_util/event_counter.h>
#include <hse_util/mutex.h>
#include <hse_util/platform.h>
#include <hse_util/vlb.h>

#include <bsd/libutil.h>
#include <bsd/string.h>

/* clang-format off */

#define HSE_KVDB_COMPACT_MASK  (HSE_KVDB_COMPACT_CANCEL | HSE_KVDB_COMPACT_SAMP_LWM)
#define HSE_KVDB_SYNC_MASK     (HSE_KVDB_SYNC_ASYNC)
#define HSE_KVS_PUT_MASK       (HSE_KVS_PUT_PRIO | HSE_KVS_PUT_VCOMP_OFF | HSE_KVS_PUT_VCOMP_ON)
#define HSE_KVS_PUT_VCOMP_MASK (HSE_KVS_PUT_VCOMP_OFF | HSE_KVS_PUT_VCOMP_ON)
#define HSE_CURSOR_CREATE_MASK (HSE_CURSOR_CREATE_REV)

/* clang-format on */

#define ENDPOINT_FMT_EVENTS      "/events"
#define ENDPOINT_FMT_KMC_VMSTAT  "/kmc/vmstat"
#define ENDPOINT_FMT_PARAMS      "/params"
#define ENDPOINT_FMT_PERFC       "/perfc"
#define ENDPOINT_FMT_WORKQUEUES  "/workqueues"

static DEFINE_MUTEX(hse_lock);

/* Accessing hse_initialized is not thread safe, but it is only used
 * in hse_init() and hse_fini(), which must be serialized with all other HSE
 * APIs.
 */
static bool hse_initialized = false;

extern enum rest_status
rest_get_workqueues(const struct rest_request *req, struct rest_response *resp, void *arg);

extern enum rest_status
rest_kmc_get_vmstat(const struct rest_request *req, struct rest_response *resp, void *arg);

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

static void
hse_lowmem_adjust(unsigned long *memgb)
{
    struct hse_gparams gpdef = hse_gparams_defaults();
    unsigned long      mavail = 0;

    /* [HSE_REVISIT] mapi breaks initialization of mavail.
     */
    hse_meminfo(NULL, &mavail, 30);

    if (mavail <= HSE_LOWMEM_THRESHOLD_GB_DFLT) {
        unsigned long scale = ikvdb_lowmem_scale(mavail);

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

static enum rest_status
rest_get_dt(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    enum rest_status status = REST_STATUS_OK;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = dt_emit(&root, "%s%s", DT_PATH_ROOT, req->rr_actual);
    if (err) {
        switch (merr_errno(err)) {
        case ENAMETOOLONG:
            return REST_STATUS_BAD_REQUEST;
        case ENOENT:
            return REST_STATUS_NOT_FOUND;
        default:
            return REST_STATUS_INTERNAL_SERVER_ERROR;
        }
    }

    data = (pretty ? cJSON_Print : cJSON_PrintUnformatted)(root);
    if (ev(!data)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
    }

    fputs(data, resp->rr_stream);
    cJSON_free(data);

    err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
    if (ev(err)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
    }

out:
    cJSON_Delete(root);

    return status;
}

static enum rest_status
rest_global_params_get(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool pretty;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    /* Check for single parameter or all parameters */
    if (strcmp(req->rr_matched, req->rr_actual)) {
        char *tmp;
        char *buf;
        merr_t err;
        size_t needed_sz;
        const char *param;
        size_t buf_sz = 128;

        buf = malloc(buf_sz * sizeof(*buf));
        if (ev(!buf))
            return REST_STATUS_INTERNAL_SERVER_ERROR;

        /* move past the final '/' */
        param = req->rr_actual + strlen(req->rr_matched) + 1;

        err = hse_gparams_get(&hse_gparams, param, buf, buf_sz, &needed_sz);
        if (ev(err)) {
            log_errx("Failed to read HSE global param (%s): @@e", err, param);
            free(buf);

            switch (merr_errno(err)) {
            case EINVAL:
                return REST_STATUS_NOT_FOUND;
            case EROFS:
                return REST_STATUS_LOCKED;
            default:
                return REST_STATUS_INTERNAL_SERVER_ERROR;
            }
        }

        if (needed_sz >= buf_sz) {
            buf_sz = needed_sz + 1;
            tmp = realloc(buf, buf_sz);
            if (ev(!tmp)) {
#if !defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 12
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuse-after-free"
#endif
                free(buf);
#if !defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 12
#pragma GCC diagnostic pop
#endif
                return REST_STATUS_INTERNAL_SERVER_ERROR;
            }

            buf = tmp;

            err = hse_gparams_get(&hse_gparams, param, buf, buf_sz, NULL);
            assert(err == 0);
        }

        /* No way to support pretty printing here. API might need to be
         * expanded. We could also just re-parse the buffer to JSON.
         */
        fputs(buf, resp->rr_stream);
        free(buf);
    } else {
        char *data;
        cJSON *root;

        root = hse_gparams_to_json(&hse_gparams);
        if (ev(!root))
            return REST_STATUS_INTERNAL_SERVER_ERROR;

        data = (pretty ? cJSON_Print : cJSON_PrintUnformatted)(root);
        cJSON_Delete(root);
        if (ev(!data))
            return REST_STATUS_INTERNAL_SERVER_ERROR;

        fputs(data, resp->rr_stream);
        cJSON_free(data);
    }

    err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
    if (ev(err))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    return REST_STATUS_OK;
}

static enum rest_status
rest_global_params_put(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    const char *param;
    const char *content_type;
    const bool has_param = strcmp(req->rr_matched, req->rr_actual);

    /* Check for case when no parameter is specified, /params */
    if (!has_param)
        return REST_STATUS_METHOD_NOT_ALLOWED;

    content_type = rest_headers_get(req->rr_headers, REST_HEADER_CONTENT_TYPE);
    if (!content_type || strcmp(content_type, REST_APPLICATION_JSON) != 0)
        return REST_STATUS_BAD_REQUEST;

    /* move past the final '/' */
    param = req->rr_actual + strlen(req->rr_matched) + 1;

    err = hse_gparams_set(&hse_gparams, param, req->rr_data);
    if (ev(err)) {
        log_errx("Failed to set HSE global parameter (%s): @@e", err, param);

        switch (merr_errno(err)) {
        case ENOMEM:
            return REST_STATUS_INTERNAL_SERVER_ERROR;
        case EROFS:
            return REST_STATUS_LOCKED;
        default:
            return REST_STATUS_BAD_REQUEST;
        }
    }

    return REST_STATUS_CREATED;
}

static void
remove_global_endpoints(void)
{
    rest_server_remove_endpoint(ENDPOINT_FMT_EVENTS);
    rest_server_remove_endpoint(ENDPOINT_FMT_KMC_VMSTAT);
    rest_server_remove_endpoint(ENDPOINT_FMT_PARAMS);
    rest_server_remove_endpoint(ENDPOINT_FMT_PERFC);
    rest_server_remove_endpoint(ENDPOINT_FMT_WORKQUEUES);
}

static merr_t
add_global_endpoints(void)
{
    static rest_handler *handlers[][REST_METHOD_COUNT] = {
        {
            [REST_METHOD_GET] = rest_get_dt,
        },
        {
            [REST_METHOD_GET] = rest_kmc_get_vmstat,
        },
        {
            [REST_METHOD_GET] = rest_global_params_get,
            [REST_METHOD_PUT] = rest_global_params_put,
        },
        {
            [REST_METHOD_GET] = rest_get_workqueues,
        },
    };

    merr_t err;

    err = rest_server_add_endpoint(0, handlers[0], NULL, ENDPOINT_FMT_EVENTS);
    if (err) {
        log_errx("Failed to add REST endpoint (" ENDPOINT_FMT_EVENTS ")", err);
        goto out;
    }

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[1], NULL, ENDPOINT_FMT_KMC_VMSTAT);
    if (err) {
        log_errx("Failed to add REST endpoint (" ENDPOINT_FMT_KMC_VMSTAT ")", err);
        goto out;
    }

    err = rest_server_add_endpoint(0, handlers[2], &hse_gparams, ENDPOINT_FMT_PARAMS);
    if (err) {
        log_errx("Failed to add REST endpoint (" ENDPOINT_FMT_PARAMS ")", err);
        goto out;
    }

    err = rest_server_add_endpoint(0, handlers[0], NULL, ENDPOINT_FMT_PERFC);
    if (err) {
        log_errx("Failed to add REST endpoint (" ENDPOINT_FMT_PERFC ")", err);
        goto out;
    }

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[3], NULL, ENDPOINT_FMT_WORKQUEUES);
    if (err) {
        log_errx("Failed to add REST endpoint (" ENDPOINT_FMT_WORKQUEUES ")", err);
        goto out;
    }

out:
    if (err)
        remove_global_endpoints();

    return err;
}

hse_err_t
hse_init(const char *const config, const size_t paramc, const char *const *const paramv)
{
    ulong memgb;
    merr_t err = 0;
    struct config *conf = NULL;

    if (HSE_UNLIKELY(paramc > 0 && !paramv))
        return merr(EINVAL);

    mutex_lock(&hse_lock);

    if (hse_initialized)
        goto out;

    hse_progname = program_invocation_name ? program_invocation_name : __func__;

    hse_gparams = hse_gparams_defaults();

    err = argv_deserialize_to_hse_gparams(paramc, paramv, &hse_gparams);
    if (err) {
        log_errx("Failed to deserialize paramv for HSE gparams", err);
        goto out;
    }

    err = config_from_hse_conf(config, &conf);
    if (err) {
        log_errx("Failed to read HSE config file (%s)", err, config);
        goto out;
    }

    err = config_deserialize_to_hse_gparams(conf, &hse_gparams);
    config_destroy(conf);
    if (err) {
        log_errx("Failed to deserialize config file (%s) for HSE gparams", err, config);
        goto out;
    }

    err = logging_init(&hse_gparams.gp_logging, err_ctx_strerror);
    if (err) {
        log_errx("Failed to initialize logging", err);
        goto out;
    }

    /* First log message w/ HSE version - after deserializing global params */
    log_info("version %s, program %s", HSE_VERSION_STRING, hse_progname);

    hse_lowmem_adjust(&memgb);
    log_info("Memory available: %lu GiB", memgb);

    err = hse_platform_init();
    if (err)
        goto out;

    if (hse_gparams.gp_rest.enabled) {
        err = rest_server_start(hse_gparams.gp_rest.socket_path);
        if (err) {
            log_errx("Failed to start rest server on %s", err, hse_gparams.gp_rest.socket_path);
            goto out;
        } else {
            log_info("Rest server started on %s", hse_gparams.gp_rest.socket_path);

            err = add_global_endpoints();
            if (err) {
                rest_server_stop();
                goto out;
            }
        }
    }

    err = ikvdb_init();
    if (err)
        goto out;

out:
    if (err) {
        hse_platform_fini();
        logging_fini();
    } else {
        hse_initialized = true;
    }

    mutex_unlock(&hse_lock);

    return err;
}

void
hse_fini(void)
{
    mutex_lock(&hse_lock);

    if (hse_initialized) {
        if (hse_gparams.gp_rest.enabled)
            remove_global_endpoints();
        rest_server_stop();
        ikvdb_fini();
        hse_platform_fini();
        logging_fini();
        hse_initialized = false;
    }

    mutex_unlock(&hse_lock);
}

hse_err_t
hse_param_get(
    const char *const param,
    char *const       buf,
    const size_t      buf_sz,
    size_t *const     needed_sz)
{
    if (!param || (buf_sz > 0 && !buf))
        return merr(EINVAL);

    return hse_gparams_get(&hse_gparams, param, buf, buf_sz, needed_sz);
}

hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *const paramv)
{
    size_t n;
    merr_t err;
    u64 tstart;
    bool pmem_only;
    struct pidfh *pfh = NULL;
    char pidfile_path[PATH_MAX];
    struct kvdb_cparams dbparams = kvdb_cparams_defaults();

    if (!kvdb_home) {
        log_err("A KVDB home must be provided");
        return merr(EINVAL);
    }

    if (paramc > 0 && !paramv) {
        log_err("paramc cannot be greater than 0 if paramv is NULL");
        return merr(EINVAL);
    }

    n = strnlen(kvdb_home, PATH_MAX);
    if (n == PATH_MAX) {
        log_err("KVDB home path length must be shorter than PATH_MAX");
        return merr(ENAMETOOLONG);
    } else if (n == 0) {
        log_err("KVDB home must be a non-zero length path");
        return merr(EINVAL);
    }

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CREATE);

    err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &dbparams);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVDB (%s) cparams", err, kvdb_home);
        return err;
    }

    err = ikvdb_pmem_only_from_cparams(kvdb_home, &dbparams, &pmem_only);
    if (err)
        return err;

    err = kvdb_cparams_resolve(&dbparams, kvdb_home, pmem_only);
    if (ev(err)) {
        log_errx("Failed to resolve KVDB (%s) cparams", err, kvdb_home);
        return err;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s/kvdb.pid)", err, kvdb_home);
        return err;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        return err;
    }

    mutex_lock(&hse_lock);
    err = ikvdb_create(kvdb_home, &dbparams);
    mutex_unlock(&hse_lock);

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_CREATE, tstart);

    pidfile_remove(pfh);

    return err;
}

hse_err_t
hse_kvdb_drop(const char *kvdb_home)
{
    size_t n;
    merr_t err;
    struct pidfh *pfh = NULL;
    char pidfile_path[PATH_MAX];

    if (!kvdb_home) {
        log_err("A KVDB home must be provided");
        return merr(EINVAL);
    }

    n = strnlen(kvdb_home, PATH_MAX);
    if (n == PATH_MAX) {
        log_err("KVDB home path length cannot be must be shorter than PATH_MAX");
        return merr(ENAMETOOLONG);
    } else if (n == 0) {
        log_err("KVDB home must be a non-zero length path");
        return merr(EINVAL);
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid", err, kvdb_home);
        return err;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        return err;
    }

    mutex_lock(&hse_lock);
    err = ikvdb_drop(kvdb_home);
    mutex_unlock(&hse_lock);

    pidfile_remove(pfh);

    return err;
}

hse_err_t
hse_kvdb_open(
    const char *             kvdb_home,
    size_t                   paramc,
    const char *const *const paramv,
    struct hse_kvdb **       handle)
{
    size_t n;
    merr_t err;
    uint64_t tstart;
    struct pidfh *pfh = NULL;
    char pidfile_path[PATH_MAX];
    struct ikvdb *ikvdb = NULL;
    struct config *conf = NULL;
    struct pidfile content = {};
    struct kvdb_rparams params = kvdb_rparams_defaults();

    if (!kvdb_home) {
        log_err("A KVDB home must be provided");
        return merr(EINVAL);
    }

    if (paramc > 0 && !paramv) {
        log_err("paramc cannot be greater than 0 if paramv is NULL");
        return merr(EINVAL);
    }

    if (!handle)
        return merr(EINVAL);

    n = strnlen(kvdb_home, PATH_MAX);
    if (n == PATH_MAX) {
        log_err("KVDB home path length cannot be must be shorter than PATH_MAX");
        return merr(ENAMETOOLONG);
    } else if (n == 0) {
        log_err("KVDB home must be a non-zero length path");
        return merr(EINVAL);
    }

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_OPEN);

    err = argv_deserialize_to_kvdb_rparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVDB (%s) rparams", err, kvdb_home);
        return err;
    }

    err = config_from_kvdb_conf(kvdb_home, &conf);
    if (ev(err)) {
        log_errx("Failed to read KVDB config file (%s/kvdb.conf)", err, kvdb_home);
        return err;
    }

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize config file for KVDB (%s) rparams", err, kvdb_home);
        goto out;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid", err, kvdb_home);
        goto out;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = errno == EEXIST ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    mutex_lock(&hse_lock);
    err = ikvdb_open(kvdb_home, &params, &ikvdb);
    mutex_unlock(&hse_lock);
    if (ev(err))
        goto out;

    content.pid = getpid();
    static_assert(
        sizeof(content.rest.socket_path) == sizeof(hse_gparams.gp_rest.socket_path),
        "Unequal REST socket path buffer sizes");

    /* Infallible since the buffers are the same size. */
    n = strlcpy(content.alias, ikvdb_alias(ikvdb), sizeof(content.alias));
    assert(n < sizeof(content.alias));
    if (hse_gparams.gp_rest.enabled)
        strlcpy(content.rest.socket_path, hse_gparams.gp_rest.socket_path,
            sizeof(content.rest.socket_path));

    err = pidfile_serialize(pfh, &content);
    if (err) {
        log_errx("Failed to serialize data to the KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    ikvdb_config_attach(ikvdb, conf);
    ikvdb_pidfh_attach(ikvdb, pfh);

    *handle = (struct hse_kvdb *)ikvdb;

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_OPEN, tstart);

out:
    if (err) {
        pidfile_remove(pfh);
        config_destroy(conf);
        ikvdb_close(ikvdb);
    }

    return err;
}

hse_err_t
hse_kvdb_close(struct hse_kvdb *handle)
{
    merr_t err;
    struct pidfh *pfh;
    struct config *conf;

    if (!handle)
        return merr(EINVAL);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CLOSE);

    conf = ikvdb_config((struct ikvdb *)handle);
    pfh = ikvdb_pidfh((struct ikvdb *)handle);
    assert(pfh);

    mutex_lock(&hse_lock);

    err = ikvdb_close((struct ikvdb *)handle);
    ev(err);

    mutex_unlock(&hse_lock);

    pidfile_remove(pfh);
    config_destroy(conf);

    return err;
}

hse_err_t
hse_kvdb_attach(
    const char *kvdb_home_tgt,
    const char *kvdb_home_src,
    const char *paths[static HSE_MCLASS_COUNT])
{
    merr_t err;
    size_t tlen, slen;
    char pidfile_path[PATH_MAX];
    struct pidfh *pfh_tgt = NULL, *pfh_src = NULL;

    if (!kvdb_home_tgt || !kvdb_home_src) {
        log_err("KVDB attach target and source home dirs must be provided");
        return merr(EINVAL);
    }

    tlen = strnlen(kvdb_home_tgt, PATH_MAX);
    slen = strnlen(kvdb_home_src, PATH_MAX);
    if (tlen == PATH_MAX || slen == PATH_MAX) {
        log_err("KVDB attach target and source home dir lengths cannot be longer than PATH_MAX");
        return merr(ENAMETOOLONG);
    } else if (tlen == 0 || slen == 0) {
        log_err("KVDB attach target and source home dirs must both be non-zero length paths");
        return merr(EINVAL);
    }

    mutex_lock(&hse_lock);

    /* Keep both the source and target kvdb busy during the attach operation */
    err = kvdb_home_pidfile_path_get(kvdb_home_tgt, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s/kvdb.pid)", err, kvdb_home_tgt);
        goto out;
    }

    pfh_tgt = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh_tgt) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home_src, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s/kvdb.pid)", err, kvdb_home_src);
        goto out;
    }

    pfh_src = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh_src) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    err = ikvdb_attach(kvdb_home_tgt, kvdb_home_src, paths);

out:
    mutex_unlock(&hse_lock);

    pidfile_remove(pfh_src);
    pidfile_remove(pfh_tgt);

    return err;
}

hse_err_t
hse_kvdb_param_get(
    struct hse_kvdb *const handle,
    const char *const      param,
    char *const            buf,
    const size_t           buf_sz,
    size_t *const          needed_sz)
{
    if (!handle || !param || (buf_sz > 0 && !buf))
        return merr(EINVAL);

    return ikvdb_param_get((struct ikvdb *)handle, param, buf, buf_sz, needed_sz);
}

hse_err_t
hse_kvdb_kvs_names_get(struct hse_kvdb *handle, size_t *namec, char ***namev)
{
    merr_t err;

    if (!handle || !namev)
        return merr(EINVAL);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_NAMES_GET);

    err = ikvdb_kvs_names_get((struct ikvdb *)handle, namec, namev);
    ev(err);

    return err;
}

void
hse_kvdb_kvs_names_free(struct hse_kvdb *handle, char **namev)
{
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_NAMES_FREE);

    ikvdb_kvs_names_free((struct ikvdb *)handle, namev);
}

hse_err_t
hse_kvdb_mclass_info_get(
    struct hse_kvdb *const        handle,
    const enum hse_mclass         mclass,
    struct hse_mclass_info *const info)
{
    if (!handle || !(mclass >= HSE_MCLASS_BASE && mclass <= HSE_MCLASS_MAX) || !info)
        return merr(EINVAL);

    memset(info, 0, sizeof(*info));

    return ikvdb_mclass_info_get((struct ikvdb *)handle, mclass, info);
}

bool
hse_kvdb_mclass_is_configured(struct hse_kvdb *const handle, const enum hse_mclass mclass)
{
    if (!handle || !(mclass >= HSE_MCLASS_BASE && mclass <= HSE_MCLASS_MAX))
        return false;

    return ikvdb_mclass_is_configured((struct ikvdb *)handle, mclass);
}

hse_err_t
hse_kvdb_mclass_reconfigure(const char *kvdb_home, enum hse_mclass mclass, const char *path)
{
    merr_t         err;
    char           pidfile_path[PATH_MAX];
    struct pidfh  *pfh;

    if (!kvdb_home) {
        log_err("A KVDB home must be provided");
        return merr(EINVAL);
    }

    if (!path) {
        log_err("Cannot reconfigure %s mclass path for the KVDB (%s) if path is NULL",
                hse_mclass_name_get(mclass), kvdb_home);
        return merr(EINVAL);
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid", err, kvdb_home);
        return err;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = (errno == EEXIST) ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    err = ikvdb_mclass_reconfigure(kvdb_home, mclass, path);

out:
    pidfile_remove(pfh);

    return err;
}


hse_err_t
hse_kvdb_kvs_create(
    struct hse_kvdb *        handle,
    const char *             kvs_name,
    size_t                   paramc,
    const char *const *const paramv)
{
    merr_t err;
    struct kvs_cparams params = kvs_cparams_defaults();

    if (!handle || !kvs_name)
        return merr(EINVAL);

    if (paramc > 0 && !paramv) {
        log_err("paramc cannot be greater than 0 if paramv is NULL");
        return merr(EINVAL);
    }

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CREATE);

    err = validate_kvs_name(kvs_name);
    if (ev(err)) {
        log_errx("Invalid KVS name: %s, must match the regex [-_A-Za-z0-9]", err, kvs_name);
        return err;
    }

    err = argv_deserialize_to_kvs_cparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVS (%s) cparams", err, kvs_name);
        return err;
    }

    mutex_lock(&hse_lock);

    err = ikvdb_kvs_create((struct ikvdb *)handle, kvs_name, &params);
    ev(err);

    mutex_unlock(&hse_lock);

    return err;
}

hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *handle, const char *const kvs_name)
{
    merr_t err;

    if (!handle || !kvs_name)
        return merr(EINVAL);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_DROP);

    mutex_lock(&hse_lock);

    err = ikvdb_kvs_drop((struct ikvdb *)handle, kvs_name);
    ev(err);

    mutex_unlock(&hse_lock);

    return err;
}

hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *        handle,
    const char *             kvs_name,
    size_t                   paramc,
    const char *const *const paramv,
    struct hse_kvs **        kvs_out)
{
    merr_t err;
    uint64_t tstart;
    struct kvs_rparams params = kvs_rparams_defaults();

    if (!handle || !kvs_name || !kvs_out)
        return merr(EINVAL);

    if (HSE_UNLIKELY(paramc > 0 && !paramv)) {
        log_err("paramc cannot be greater than 0 if paramv is NULL");
        return merr(EINVAL);
    }

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_OPEN);

    err = argv_deserialize_to_kvs_rparams(paramc, paramv, &params);
    if (ev(err)) {
        log_errx("Failed to deserialize paramv for KVS (%s) rparams", err, kvs_name);
        return err;
    }

    mutex_lock(&hse_lock);

    err = ikvdb_kvs_open((struct ikvdb *)handle, kvs_name, &params, IKVS_OFLAG_NONE, kvs_out);
    ev(err);

    mutex_unlock(&hse_lock);

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVS_OPEN, tstart);

    return err;
}

hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *handle)
{
    merr_t err;

    if (!handle)
        return merr(EINVAL);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CLOSE);

    mutex_lock(&hse_lock);

    err = ikvdb_kvs_close((struct hse_kvs *)handle);
    ev(err);

    mutex_unlock(&hse_lock);

    return err;
}

const char *
hse_kvdb_home_get(struct hse_kvdb *const handle)
{
    if (!handle)
        return NULL;

    return ikvdb_home((struct ikvdb *)handle);
}

hse_err_t
hse_kvdb_storage_add(const char *kvdb_home, size_t paramc, const char *const *const paramv)
{
    struct kvdb_cparams cparams = kvdb_cparams_defaults();
    merr_t              err;
    char                pidfile_path[PATH_MAX];
    struct pidfh *      pfh;
    size_t              n;

    if (!kvdb_home) {
        log_err("A KVDB home must be provided");
        return merr(EINVAL);
    }

    if (!paramv || paramc == 0) {
        log_err("Cannot add storage to the KVDB (%s) if paramv is empty", kvdb_home);
        return merr(EINVAL);
    }

    n = strnlen(kvdb_home, PATH_MAX);

    if (n == PATH_MAX) {
        log_err("KVDB home path length cannot be must be shorter than PATH_MAX");
        return merr(ENAMETOOLONG);
    }

    if (n == 0) {
        log_err("KVDB home must be a non-zero length path");
        return merr(EINVAL);
    }

    err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &cparams);
    if (err) {
        log_errx("Failed to deserialize paramv for KVDB (%s) cparams", err, kvdb_home);
        return err;
    }

    err = kvdb_home_pidfile_path_get(kvdb_home, pidfile_path, sizeof(pidfile_path));
    if (err) {
        log_errx("Failed to create KVDB pidfile path (%s)/kvdb.pid", err, kvdb_home);
        return err;
    }

    pfh = pidfile_open(pidfile_path, S_IRUSR | S_IWUSR, NULL);
    if (!pfh) {
        err = errno == EEXIST ? merr(EBUSY) : merr(errno);
        log_errx("Failed to open KVDB pidfile (%s)", err, pidfile_path);
        goto out;
    }

    err = ikvdb_storage_add(kvdb_home, &cparams);

out:
    pidfile_remove(pfh);

    return err;
}

const char *
hse_kvs_name_get(struct hse_kvs *const handle)
{
    if (!handle)
        return NULL;

    return kvdb_kvs_name((struct kvdb_kvs *)handle);
}

hse_err_t
hse_kvs_param_get(
    struct hse_kvs *const handle,
    const char *const     param,
    char *const           buf,
    const size_t          buf_sz,
    size_t *const         needed_sz)
{
    if (!handle || !param || (buf_sz > 0 && !buf))
        return merr(EINVAL);

    return ikvdb_kvs_param_get(handle, param, buf, buf_sz, needed_sz);
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

    if (HSE_UNLIKELY(!handle || !key || (val_len > 0 && !val) || flags & ~HSE_KVS_PUT_MASK ||
            (flags & HSE_KVS_PUT_VCOMP_MASK) == HSE_KVS_PUT_VCOMP_MASK))
        return merr(EINVAL);

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
        return merr(ENAMETOOLONG);

    if (HSE_UNLIKELY(key_len == 0))
        return merr(ENOENT);

    if (HSE_UNLIKELY(val_len > HSE_KVS_VALUE_LEN_MAX))
        return merr(EMSGSIZE);

    kvs_ktuple_init_nohash(&kt, key, key_len);
    kvs_vtuple_init(&vt, (void *)val, val_len);

    err = ikvdb_kvs_put(handle, flags, txn, &kt, &vt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_PUT, PERFC_RA_KVDBOP_KVS_PUTB, key_len + val_len);

    return err;
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
        return merr(EINVAL);

    if (HSE_UNLIKELY(!valbuf && valbuf_sz > 0))
        return merr(EINVAL);

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
        return merr(ENAMETOOLONG);

    if (HSE_UNLIKELY(key_len == 0))
        return merr(ENOENT);

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
        return err;

    /* If the key is found then vbuf.b_len contains the length of the value
     * stored in the kvs.  We expect it to fit into output buffer.
     */
    *found = (res == FOUND_VAL);
    *val_len = vbuf.b_len;

    if (ev(res == FOUND_MULTIPLE))
        return merr(EPROTO);

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
        return merr(EINVAL);

    if (HSE_UNLIKELY(key_len > HSE_KVS_KEY_LEN_MAX))
        return merr(ENAMETOOLONG);

    if (HSE_UNLIKELY(key_len == 0))
        return merr(ENOENT);

    kvs_ktuple_init_nohash(&kt, key, key_len);

    err = ikvdb_kvs_del(handle, flags, txn, &kt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_DEL, PERFC_RA_KVDBOP_KVS_DELB, key_len);

    return err;
}

hse_err_t
hse_kvs_prefix_probe(
    struct hse_kvs *            handle,
    const unsigned int          flags,
    struct hse_kvdb_txn *const  txn,
    const void *                pfx,
    size_t                      pfx_len,
    enum hse_kvs_pfx_probe_cnt *found,
    void *                      keybuf,
    size_t                      keybuf_sz,
    size_t *                    key_len,
    void *                      valbuf,
    size_t                      valbuf_sz,
    size_t *                    val_len)
{
    merr_t err = 0;
    struct kvs_ktuple kt;
    enum key_lookup_res res;
    struct kvs_buf kbuf;
    struct kvs_buf vbuf;

    if (!handle || !pfx || !found || !val_len || flags != 0)
        err = merr(EINVAL);
    else if (!valbuf && valbuf_sz > 0)
        err = merr(EINVAL);
    else if (!pfx_len)
        err = merr(ENOENT);
    else if (pfx_len > HSE_KVS_KEY_LEN_MAX)
        err = merr(ENAMETOOLONG);
    else if (keybuf_sz != HSE_KVS_KEY_LEN_MAX)
        err = merr(EINVAL);

    if (ev(err))
        return err;

    kvs_ktuple_init_nohash(&kt, pfx, pfx_len);

    /* If valbuf is NULL and valbuf_sz is zero, this call is meant as a
     * probe for the existence of the key and length of its value.
     */
    kvs_buf_init(&kbuf, keybuf, keybuf_sz);
    kvs_buf_init(&vbuf, valbuf, valbuf_sz);

    err = ikvdb_kvs_pfx_probe(handle, flags, txn, &kt, &res, &kbuf, &vbuf);
    if (err)
        return err;

    switch (res) {
    case NOT_FOUND:
    case FOUND_TMB:
    case FOUND_PTMB:
        *found = HSE_KVS_PFX_FOUND_ZERO;
        break;
    case FOUND_VAL:
        *found = HSE_KVS_PFX_FOUND_ONE;
        if (key_len)
            *key_len = kbuf.b_len;
        if (val_len)
            *val_len = vbuf.b_len;
        break;
    case FOUND_MULTIPLE:
        *found = HSE_KVS_PFX_FOUND_MUL;
        if (key_len)
            *key_len = kbuf.b_len;
        if (val_len)
            *val_len = vbuf.b_len;
        break;
    }

    PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_PFXPROBE, PERFC_RA_KVDBOP_KVS_GETB,
                    kbuf.b_len + vbuf.b_len);

    return 0;
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

    if (HSE_UNLIKELY(!handle || !pfx || flags != 0))
        return merr(EINVAL);

    if (HSE_UNLIKELY(pfx_len > HSE_KVS_PFX_LEN_MAX))
        return merr(ENAMETOOLONG);

    if (HSE_UNLIKELY(pfx_len == 0))
        return merr(ENOENT);

    kvs_ktuple_init(&kt, pfx, pfx_len);

    err = ikvdb_kvs_prefix_delete(handle, flags, txn, &kt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(
            &kvdb_pc, PERFC_RA_KVDBOP_KVS_PFX_DEL, PERFC_RA_KVDBOP_KVS_PFX_DELB, pfx_len);

    return err;
}

hse_err_t
hse_kvdb_sync(struct hse_kvdb *handle, const unsigned int flags)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || flags & ~HSE_KVDB_SYNC_MASK))
        return merr(EINVAL);

    tstart = perfc_lat_startl(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_SYNC);

    err = ikvdb_sync((struct ikvdb *)handle, flags);
    ev(err);

    perfc_sl_record(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC, tstart);

    return err;
}

const char *
hse_mclass_name_get(const enum hse_mclass mclass)
{
    switch (mclass) {
    case HSE_MCLASS_CAPACITY:
        return HSE_MCLASS_CAPACITY_NAME;
    case HSE_MCLASS_STAGING:
        return HSE_MCLASS_STAGING_NAME;
    case HSE_MCLASS_PMEM:
        return HSE_MCLASS_PMEM_NAME;
    }

    return NULL;
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
        return merr(EINVAL);

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_BEGIN);

    err = ikvdb_txn_begin((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN, tstart);

    return err;
}

hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || !txn))
        return merr(EINVAL);

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_COMMIT);

    err = ikvdb_txn_commit((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT, tstart);

    return err;
}

hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || !txn))
        return merr(EINVAL);

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_ABORT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ABORT);

    err = ikvdb_txn_abort((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_ABORT, tstart);

    return err;
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
    u64    t_cur;

    if (HSE_UNLIKELY(!handle || !cursor || (pfx_len && !prefix) || flags & ~HSE_CURSOR_CREATE_MASK))
        return merr(EINVAL);

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_CREATE);

    t_cur = get_time_ns();
    err = ikvdb_kvs_cursor_create(handle, flags, txn, prefix, pfx_len, cursor);
    ev(err);

    t_cur = get_time_ns() - t_cur;
    if (t_cur > MAX_CUR_TIME)
        log_errx("cursor create taking too long: %lus", err, t_cur / NSEC_PER_SEC);

    return err;
}

hse_err_t
hse_kvs_cursor_update_view(struct hse_kvs_cursor *cursor, const unsigned int flags)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || flags != 0))
        return merr(EINVAL);

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE);

    err = ikvdb_kvs_cursor_update_view(cursor, flags);
    ev(err);

    return err;
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
        return merr(EINVAL);

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, flags, key, len, 0, 0, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return err;
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
        return merr(EINVAL);

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, flags, key, key_len, limit, limit_len, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return err;
}

hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void **          key,
    size_t *               klen,
    const void **          val,
    size_t *               vlen,
    bool *                 eof)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || !key || !klen || !eof || flags != 0))
        return merr(EINVAL);

    if (HSE_UNLIKELY(!!val ^ !!vlen))
        return merr(EINVAL);

    err = ikvdb_kvs_cursor_read(cursor, flags, key, klen, val, vlen, eof);
    ev(err);

    if (!err && !*eof) {
        size_t len = *klen;

        if (vlen)
            len += *vlen;

        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_READ, PERFC_RA_KVDBOP_KVS_GETB, len);
    }

    return err;
}

hse_err_t
hse_kvs_cursor_read_copy(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    void *                 keybuf,
    size_t                 keybuf_sz,
    size_t *               key_len,
    void *                 valbuf,
    size_t                 valbuf_sz,
    size_t *               val_len,
    bool *                 eof)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || !keybuf || !key_len || !eof || flags != 0))
        return merr(EINVAL);

    if (HSE_UNLIKELY(!valbuf && valbuf_sz > 0))
        return merr(EINVAL);

    err = ikvdb_kvs_cursor_read_copy(cursor, flags, keybuf, keybuf_sz, key_len,
        valbuf, valbuf_sz, val_len, eof);
    ev(err);

    if (!err && !*eof) {
        size_t len = *key_len;

        if (val_len)
            len += *val_len;

        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_READ, PERFC_RA_KVDBOP_KVS_GETB, len);
    }

    return err;
}


hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor))
        return merr(EINVAL);

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_DESTROY);

    err = ikvdb_kvs_cursor_destroy(cursor);
    ev(err);

    return err;
}

hse_err_t
hse_kvdb_compact(struct hse_kvdb *handle, unsigned int flags)
{
    if (!handle || flags & ~HSE_KVDB_COMPACT_MASK)
        return merr(EINVAL);

    ikvdb_compact((struct ikvdb *)handle, flags);

    return 0;
}

hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *handle, struct hse_kvdb_compact_status *status)
{
    if (!handle || !status)
        return merr(EINVAL);

    memset(status, 0, sizeof(*status));
    ikvdb_compact_status_get((struct ikvdb *)handle, status);

    return 0;
}

size_t
hse_strerror(hse_err_t err, char *buf, size_t buf_sz)
{
    size_t need_sz;

    merr_strinfo(err, buf, buf_sz, err_ctx_strerror, &need_sz);

    return need_sz;
}

int
hse_err_to_errno(hse_err_t err)
{
    return merr_errno(err);
}

enum hse_err_ctx
hse_err_to_ctx(const hse_err_t err)
{
    return merr_ctx(err);
}

/* Includes necessary files for mocking */
#if HSE_MOCKING
#include "hse_ut_impl.i"
#endif /* HSE_MOCKING */
