/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <string.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/hse.h>
#include <hse/flags.h>
#include <hse/experimental.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse/rest/headers.h>
#include <hse/rest/method.h>
#include <hse/rest/params.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/rest/server.h>
#include <hse/rest/status.h>
#include <hse_util/event_counter.h>
#include <hse_util/fmt.h>
#include <hse_util/printbuf.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_tree_view.h>
#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/hse_gparams.h>

#include "kvdb_rest.h"
#include "kvdb_kvs.h"

#define HUMAN_THRESHOLD 10000

static enum rest_status
rest_kvdb_get_kvs_names(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    bool pretty;
    cJSON *root;
    size_t namec;
    char **namev;
    struct ikvdb *ikvdb;
    enum rest_status status = REST_STATUS_OK;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    ikvdb = ctx;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = ikvdb_kvs_names_get(ikvdb, &namec, &namev);
    if (ev(err))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    root = cJSON_CreateArray();
    if (ev(!root)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
    }

    for (size_t i = 0; i < namec; i++) {
        cJSON *kvs = cJSON_CreateString(namev[i]);
        if (ev(!kvs)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
        }

        if (ev(!cJSON_AddItemToArray(root, kvs))) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
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
    ikvdb_kvs_names_free(ikvdb, namev);

    return status;
}

static enum rest_status
rest_kvdb_get_home(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool pretty;
    const char *home;
    struct ikvdb *kvdb;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;
    home = ikvdb_home(kvdb);

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    fprintf(resp->rr_stream, "\"%s\"", home);

    err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
    if (ev(err))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    return REST_STATUS_OK;
}

static enum rest_status
rest_kvdb_get_mclass(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    struct ikvdb *kvdb;
    enum rest_status status = REST_STATUS_OK;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    root = cJSON_CreateArray();
    if (ev(!root))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    for (int i = 0; i < HSE_MCLASS_COUNT; i++) {
        if (mpool_mclass_is_configured(ikvdb_mpool_get(kvdb), i)) {
            cJSON *mclass = cJSON_CreateString(hse_mclass_name_get(i));
            if (ev(!mclass)) {
                status = REST_STATUS_INTERNAL_SERVER_ERROR;
                goto out;
            }

            if (ev(!cJSON_AddItemToArray(root, mclass))) {
                status = REST_STATUS_INTERNAL_SERVER_ERROR;
                goto out;
            }
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
rest_kvdb_params_get(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool pretty;
    struct ikvdb *kvdb;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;

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

        err = ikvdb_param_get(kvdb, param, buf, buf_sz, &needed_sz);
        if (ev(err)) {
            log_errx("Failed to read KVDB param (%s): @@e", err, param);
            free(buf);

            switch (merr_errno(err)) {
            case EINVAL:
                return REST_STATUS_NOT_FOUND;
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

            err = ikvdb_param_get(kvdb, param, buf, buf_sz, NULL);
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

        root = kvdb_rparams_to_json(ikvdb_rparams(kvdb));
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
rest_kvdb_params_put(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool has_param;
    const char *param;
    struct ikvdb *kvdb;
    const char *content_type;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;
    has_param = strcmp(req->rr_matched, req->rr_actual);

    /* Check for case when no parameter is specified, /params */
    if (!has_param)
        return REST_STATUS_METHOD_NOT_ALLOWED;

    content_type = rest_headers_get(req->rr_headers, REST_HEADER_CONTENT_TYPE);
    if (!content_type || strcmp(content_type, REST_APPLICATION_JSON) != 0)
        return REST_STATUS_BAD_REQUEST;

    /* move past the final '/' */
    param = req->rr_actual + strlen(req->rr_matched) + 1;

    err = kvdb_rparams_set(ikvdb_rparams(kvdb), param, req->rr_data);
    if (ev(err)) {
        log_errx("Failed to set KVDB parameter (%s): @@e", err, param);

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

static enum rest_status
rest_kvdb_get_perfc(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    bool filtered;
    const char *alias;
    const char *filter;
    struct ikvdb *kvdb;
    enum rest_status status = REST_STATUS_OK;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;
    alias = ikvdb_alias(kvdb);
    filtered = strcmp(req->rr_actual, req->rr_matched);
    filter = filtered ? req->rr_actual + strlen(req->rr_matched) + 1 : NULL;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = dt_emit(&root, DT_PATH_PERFC "/kvdbs/%s%s%s", alias, filtered ? "/" : "",
        filtered ? filter : "");
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
rest_kvs_params_get(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool pretty;
    struct kvdb_kvs *kvs;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvs = ctx;

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

        err = ikvdb_kvs_param_get((struct hse_kvs *)kvs, param, buf, buf_sz, &needed_sz);
        if (ev(err)) {
            log_errx("Failed to read KVS param (%s): @@e", err, param);
            free(buf);

            switch (merr_errno(err)) {
            case EINVAL:
                return REST_STATUS_NOT_FOUND;
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

            err = ikvdb_kvs_param_get((struct hse_kvs *)kvs, param, buf, buf_sz, NULL);
            assert(err == 0);
        }

        /* No way to support pretty printing here. API might need to be
         * expanded. We could also just re-parse the buffer to JSON.
         */
        fputs(buf, resp->rr_stream);
        free(buf);
    } else {
        char *data;
        cJSON *merged, *cp_json, *rp_json;

        cp_json = kvs_cparams_to_json(kvs->kk_cparams);
        if (ev(!cp_json))
            return REST_STATUS_INTERNAL_SERVER_ERROR;

        rp_json = kvs_rparams_to_json(&kvs->kk_ikvs->ikv_rp);
        if (ev(!rp_json)) {
            cJSON_Delete(cp_json);
            return REST_STATUS_INTERNAL_SERVER_ERROR;
        }

        merged = cJSONUtils_MergePatchCaseSensitive(cp_json, rp_json);
        if (ev(!merged)) {
            cJSON_Delete(cp_json);
            cJSON_Delete(rp_json);
            return REST_STATUS_INTERNAL_SERVER_ERROR;
        }

        data = (pretty ? cJSON_Print : cJSON_PrintUnformatted)(merged);
        cJSON_Delete(merged);
        cJSON_Delete(rp_json);
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
rest_kvs_params_put(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    merr_t err;
    bool has_param;
    const char *param;
    struct kvdb_kvs *kvs;
    const char *content_type;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvs = ctx;
    has_param = strcmp(req->rr_matched, req->rr_actual);

    /* Check for case when no parameter is specified, /params */
    if (!has_param)
        return REST_STATUS_METHOD_NOT_ALLOWED;

    content_type = rest_headers_get(req->rr_headers, REST_HEADER_CONTENT_TYPE);
    if (!content_type || strcmp(content_type, REST_APPLICATION_JSON) != 0)
        return REST_STATUS_BAD_REQUEST;

    /* move past the final '/' */
    param = req->rr_actual + strlen(req->rr_matched) + 1;

    err = kvs_rparams_set(&kvs->kk_ikvs->ikv_rp, param, req->rr_data);
    if (ev(err)) {
        log_errx("Failed to set KVS parameter (%s): @@e", err, param);

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

static enum rest_status
rest_kvs_get_perfc(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    bool filtered;
    const char *alias;
    const char *filter;
    struct ikvdb *kvdb;
    struct kvdb_kvs *kvs;
    enum rest_status status = REST_STATUS_OK;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvs = ctx;
    kvdb = ikvdb_kvdb_handle(kvs->kk_parent);
    filtered = strcmp(req->rr_actual, req->rr_matched);
    filter = filtered ? req->rr_actual + strlen(req->rr_matched) + 1 : NULL;
    alias = ikvdb_alias(kvdb);

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = dt_emit(&root, DT_PATH_PERFC "/kvdbs/%s/kvs/%s%s%s", alias, kvs->kk_ikvs->ikv_kvs_name,
        filtered ? "/" : "", filtered ? filter : "");
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
rest_kvdb_mclass_info_get(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    bool pretty;
    cJSON *root;
    bool bad = false;
    struct hse_mclass_info mc_info;
    enum rest_status status = REST_STATUS_OK;
    enum hse_mclass mclass = HSE_MCLASS_INVALID;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (strstr(req->rr_actual, hse_mclass_name_get(i))) {
            mclass = i;
            break;
        }
    }
    assert(mclass != HSE_MCLASS_INVALID);

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = ikvdb_mclass_info_get((struct ikvdb *)ctx, mclass, &mc_info);
    if (merr_errno(err) == ENOENT)
        return REST_STATUS_NOT_FOUND;

    root = cJSON_CreateObject();
    if (ev(!root))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    bad |= !cJSON_AddNumberToObject(root, "allocated_bytes", mc_info.mi_allocated_bytes);
    bad |= !cJSON_AddNumberToObject(root, "used_bytes", mc_info.mi_used_bytes);
    bad |= !cJSON_AddStringToObject(root, "path", mc_info.mi_path);

    if (ev(bad)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
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
rest_kvdb_compact_request(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    struct ikvdb *kvdb;
    const int flags = HSE_KVDB_COMPACT_SAMP_LWM;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;

    ikvdb_compact(kvdb, flags);

    return REST_STATUS_ACCEPTED;
}

static enum rest_status
rest_kvdb_compact_cancel(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    struct ikvdb *kvdb;
    const int flags = HSE_KVDB_COMPACT_CANCEL;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;

    ikvdb_compact(kvdb, flags);

    return REST_STATUS_ACCEPTED;
}

static enum rest_status
rest_kvdb_compact_status_get(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    bool bad = false;
    struct ikvdb *kvdb;
    enum rest_status status = REST_STATUS_OK;
    struct hse_kvdb_compact_status compact_status = { 0 };

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvdb = ctx;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    ikvdb_compact_status_get(kvdb, &compact_status);

    root = cJSON_CreateObject();
    if (ev(!root))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    bad |= !cJSON_AddNumberToObject(root, "samp_lwm_pct", compact_status.kvcs_samp_lwm);
    bad |= !cJSON_AddNumberToObject(root, "samp_hwm_pct", compact_status.kvcs_samp_hwm);
    bad |= !cJSON_AddNumberToObject(root, "samp_hwm_pct", compact_status.kvcs_samp_hwm);
    bad |= !cJSON_AddNumberToObject(root, "samp_curr_pct", compact_status.kvcs_samp_curr);
    bad |= !cJSON_AddBoolToObject(root, "active", compact_status.kvcs_active);
    bad |= !cJSON_AddBoolToObject(root, "canceled", compact_status.kvcs_canceled);

    if (ev(bad)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
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

merr_t
kvdb_rest_add_endpoints(struct ikvdb *const kvdb)
{
    static rest_handler *handlers[][REST_METHOD_COUNT] = {
        {
            [REST_METHOD_GET] = rest_kvdb_compact_status_get,
            [REST_METHOD_POST] = rest_kvdb_compact_request,
            [REST_METHOD_DELETE] = rest_kvdb_compact_cancel,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_get_home,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_get_kvs_names,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_get_mclass,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_mclass_info_get,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_params_get,
            [REST_METHOD_PUT] = rest_kvdb_params_put,
        },
        {
            [REST_METHOD_GET] = rest_kvdb_get_perfc,
        },
    };

    merr_t status, err = 0;
    const char *alias;

    if (ev(!kvdb))
        return merr(EINVAL);

    alias = ikvdb_alias(kvdb);

    status = rest_server_add_endpoint(0, handlers[0], kvdb, "/kvdbs/%s/compact", alias);
    if (ev(status) && !err)
        err = status;

    status = rest_server_add_endpoint(
        REST_ENDPOINT_EXACT, handlers[1], kvdb, "/kvdbs/%s/home", alias);
    if (ev(status) && !err)
        err = status;

    status =
        rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[2], kvdb, "/kvdbs/%s/kvs", alias);
    if (ev(status) && !err)
        err = status;

    status = rest_server_add_endpoint(
        REST_ENDPOINT_EXACT, handlers[3], kvdb, "/kvdbs/%s/mclass", alias);
    if (ev(status) && !err)
        err = status;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        status = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[4], kvdb,
            "/kvdbs/%s/mclass/%s", alias, hse_mclass_name_get(i));
        if (ev(status) && !err)
            err = status;
    }

    status = rest_server_add_endpoint(0, handlers[5], kvdb, "/kvdbs/%s/params", alias);
    if (ev(status) && !err)
        err = status;

    status = rest_server_add_endpoint(0, handlers[6], kvdb, "/kvdbs/%s/perfc", alias);
    if (ev(status) && !err)
        err = status;

    return err;
}

merr_t
kvdb_rest_remove_endpoints(struct ikvdb *const kvdb)
{
    merr_t err1 = 0, err2;
    const char *alias = ikvdb_alias(kvdb);

    err2 = rest_server_remove_endpoint("/kvdbs/%s/compact", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/home", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/kvs", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/mclass", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        err2 = rest_server_remove_endpoint("/kvdbs/%s/mclass/%s", alias, hse_mclass_name_get(i));
        if (ev(err2) && !err1)
        err1 = err2;
    }

    err2 = rest_server_remove_endpoint("/kvdbs/%s/params", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/perfc", alias);
    if (ev(err2) && !err1)
        err1 = err2;

    return err1;
}

/*---------------------------------------------------------------
 * rest: get handler for kvs
 */

struct stats {
    uint64_t compc;
    uint64_t vgroups;
    uint64_t dgen;
    uint64_t nkeys;
    uint64_t ntombs;
    uint64_t nptombs;
    uint64_t nkblks;
    uint64_t nvblks;
    uint64_t nhblks;
    uint64_t hlen;
    uint64_t klen;
    uint64_t vlen;
};

static void
u64_to_human(char *buf, size_t bufsz, uint64_t val, uint64_t thresh)
{
    if (val >= thresh) {
        const char *sep = "\0kmgtpezy";
        val *= 10;
        while (val >= thresh) {
            val /= 1000;
            ++sep;
        }
        snprintf(buf, bufsz, "%5.1lf%c", val / 10.0, *sep);
    } else {
        u64_to_string(buf, bufsz, val);
    }
}

static merr_t HSE_NONNULL(1, 2)
stats_add_to_object(const struct stats *const stats, cJSON *const object, const bool human)
{
    char buf[64];
    bool bad = false;

    INVARIANT(stats);
    INVARIANT(object);

    bad |= !cJSON_AddNumberToObject(object, "dgen", stats->dgen);
    bad |= !cJSON_AddNumberToObject(object, "compc", stats->compc);
    bad |= !cJSON_AddNumberToObject(object, "vgroups", stats->vgroups);
    bad |= !cJSON_AddNumberToObject(object, "keys", stats->nkeys);
    bad |= !cJSON_AddNumberToObject(object, "tombs", stats->ntombs);
    bad |= !cJSON_AddNumberToObject(object, "ptombs", stats->nptombs);

    if (human) {
        u64_to_human(buf, sizeof(buf), stats->hlen, 10000);

        bad |= !cJSON_AddStringToObject(object, "hlen", buf);
    } else {
        bad |= !cJSON_AddNumberToObject(object, "hlen", stats->hlen);
    }

    if (human) {
        u64_to_human(buf, sizeof(buf), stats->klen, 10000);

        bad |= !cJSON_AddStringToObject(object, "klen", buf);
    } else {
        bad |= !cJSON_AddNumberToObject(object, "klen", stats->klen);
    }

    if (human) {
        u64_to_human(buf, sizeof(buf), stats->vlen, 10000);

        bad |= !cJSON_AddStringToObject(object, "vlen", buf);
    } else {
        bad |= !cJSON_AddNumberToObject(object, "vlen", stats->vlen);
    }

    bad |= !cJSON_AddNumberToObject(object, "hblocks", stats->nhblks);
    bad |= !cJSON_AddNumberToObject(object, "kblocks", stats->nkblks);
    bad |= !cJSON_AddNumberToObject(object, "vblocks", stats->nvblks);

    return bad ? merr(ENOMEM) : 0;
}

static merr_t
kvs_query_tree(
    struct kvdb_kvs *const kvs,
    const bool human,
    const bool kvsets,
    cJSON **const tree)
{
    merr_t err;
    struct cn *cn;
    bool bad = false;
    cJSON *root, *nodes;
    struct table *tree_view;
    uint64_t num_tree_kvsets = 0;
    struct stats tree_stats = { 0 };
    char kbuf[sizeof(((struct kvset_view *)NULL)->ekbuf) + 1];

    INVARIANT(kvs);
    INVARIANT(tree);

    *tree = NULL;

    cn = kvs_cn(kvs->kk_ikvs);

    root = cJSON_CreateObject();
    if (ev(!root))
        return merr(ENOMEM);

    nodes = cJSON_AddArrayToObject(root, "nodes");
    if (ev(!nodes)) {
        err = merr(ENOMEM);
        goto out;
    }

    err = cn_tree_view_create(cn, &tree_view);
    if (ev(err))
        goto out;

    for (unsigned int i = 0; i < table_len(tree_view);) {
        cJSON *node, *kvsetv = NULL;
        uint64_t num_node_kvsets = 0;
        struct stats node_stats = { 0 };
        const struct kvset_view *view = table_at(tree_view, i);

        node = cJSON_CreateObject();
        if (ev(!node)) {
            err = merr(ENOMEM);
            goto out;
        }

        if (ev(!cJSON_AddItemToArray(nodes, node))) {
            err = merr(ENOMEM);
            goto out;
        }

        bad |= !cJSON_AddNumberToObject(node, "id", view->nodeid);

        if (kvsets) {
            kvsetv = cJSON_AddArrayToObject(node, "kvsets");
            if (ev(!kvsetv)) {
                err = merr(ENOMEM);
                goto out;
            }
        }

        if (view->eklen > 0) {
            for (size_t i = 0; i < sizeof(view->ekbuf); i++)
                snprintf(kbuf + i, sizeof(kbuf) - i, "%x", view->ekbuf[i]);
            bad |= !cJSON_AddStringToObject(node, "edge_key", kbuf);
        } else {
            bad |= !cJSON_AddNullToObject(node, "edge_key");
        }

        /* Node entries have a NULL kvset. `view` no longer points to the
         * original node after this point.
         */
        for (i += 1; i < table_len(tree_view); i++, num_node_kvsets++) {
            char buf[64];
            cJSON *kvset;
            uint64_t dgen;
            struct kvset_metrics metrics;

            view = table_at(tree_view, i);
            if (!view->kvset)
                break;

            dgen = kvset_get_dgen(view->kvset);
            kvset_get_metrics(view->kvset, &metrics);

            node_stats.compc += metrics.compc;
            node_stats.vgroups += metrics.vgroups;
            node_stats.nkeys += metrics.num_keys;
            node_stats.ntombs += metrics.num_tombstones;
            node_stats.nptombs += metrics.nptombs;
            node_stats.nhblks += metrics.num_hblocks;
            node_stats.nkblks += metrics.num_kblocks;
            node_stats.nvblks += metrics.num_vblocks;
            node_stats.hlen += metrics.header_bytes;
            node_stats.klen += metrics.tot_key_bytes;
            node_stats.vlen += metrics.tot_val_bytes;
            if (node_stats.dgen < dgen)
                node_stats.dgen = dgen;

            if (!kvsetv)
                continue;

            kvset = cJSON_CreateObject();
            if (ev(!kvset)) {
                err = merr(ENOMEM);
                goto out;
            }

            if (ev(!cJSON_AddItemToArray(kvsetv, kvset))) {
                err = merr(ENOMEM);
                goto out;
            }

            bad |= !cJSON_AddNumberToObject(kvset, "dgen", dgen);
            bad |= !cJSON_AddNumberToObject(kvset, "compc", metrics.compc);
            bad |= !cJSON_AddNumberToObject(kvset, "vgroups", metrics.vgroups);
            bad |= !cJSON_AddNumberToObject(kvset, "keys", metrics.num_keys);
            bad |= !cJSON_AddNumberToObject(kvset, "tombs", metrics.num_tombstones);
            bad |= !cJSON_AddNumberToObject(kvset, "ptombs", metrics.nptombs);

            if (human) {
                u64_to_human(buf, sizeof(buf), metrics.header_bytes, 10000);

                bad |= !cJSON_AddStringToObject(kvset, "hlen", buf);
            } else {
                bad |= !cJSON_AddNumberToObject(kvset, "hlen", metrics.header_bytes);
            }

            if (human) {
                u64_to_human(buf, sizeof(buf), metrics.tot_key_bytes, 10000);

                bad |= !cJSON_AddStringToObject(kvset, "klen", buf);
            } else {
                bad |= !cJSON_AddNumberToObject(kvset, "klen", metrics.tot_key_bytes);
            }

            if (human) {
                u64_to_human(buf, sizeof(buf), metrics.tot_val_bytes, 10000);

                bad |= !cJSON_AddStringToObject(kvset, "vlen", buf);
            } else {
                bad |= !cJSON_AddNumberToObject(kvset, "vlen", metrics.tot_val_bytes);
            }

            bad |= !cJSON_AddNumberToObject(kvset, "hblocks", metrics.num_hblocks);
            bad |= !cJSON_AddNumberToObject(kvset, "kblocks", metrics.num_kblocks);
            bad |= !cJSON_AddNumberToObject(kvset, "vblocks", metrics.num_vblocks);
            bad |= !cJSON_AddStringToObject(kvset, "rule", cn_rule2str(metrics.rule));

            if (ev(bad)) {
                err = merr(ENOMEM);
                goto out;
            }
        }

        if (!kvsets)
            bad |= !cJSON_AddNumberToObject(node, "kvsets", num_node_kvsets);

        err = stats_add_to_object(&node_stats, node, human);
        if (ev(err))
            goto out;

        tree_stats.nkeys += node_stats.nkeys;
        tree_stats.ntombs += node_stats.ntombs;
        tree_stats.nptombs += node_stats.nptombs;
        tree_stats.compc += node_stats.compc;
        tree_stats.vgroups += node_stats.vgroups;
        tree_stats.nhblks += node_stats.nhblks;
        tree_stats.nkblks += node_stats.nkblks;
        tree_stats.nvblks += node_stats.nvblks;
        tree_stats.hlen += node_stats.hlen;
        tree_stats.klen += node_stats.klen;
        tree_stats.vlen += node_stats.vlen;
        if (tree_stats.dgen < node_stats.dgen)
            tree_stats.dgen = node_stats.dgen;

        num_tree_kvsets += num_node_kvsets;
    }

    cn_tree_view_destroy(tree_view);

    bad |= !cJSON_AddStringToObject(root, "name", kvs->kk_name);
    bad |= !cJSON_AddNumberToObject(root, "cnid", kvs->kk_cnid);
    bad |= !cJSON_AddNumberToObject(root, "kvsets", num_tree_kvsets);

    if (ev(bad)) {
        err = merr(ENOMEM);
        goto out;
    }

    err = stats_add_to_object(&tree_stats, root, human);
    if (ev(err))
        goto out;

    *tree = root;

out:
    if (err)
        cJSON_Delete(root);

    return err;
}

static enum rest_status
rest_kvs_cn_tree(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const ctx)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    bool human;
    bool kvsets;
    struct kvdb_kvs *kvs;
    enum rest_status status = REST_STATUS_OK;

    INVARIANT(req);
    INVARIANT(resp);
    INVARIANT(ctx);

    kvs = ctx;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = rest_params_get(req->rr_params, "human", &human, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = rest_params_get(req->rr_params, "kvsets", &kvsets, false);
    if (err)
        return REST_STATUS_BAD_REQUEST;

    err = kvs_query_tree(kvs, human, kvsets, &root);
    if (ev(err)) {
        status = REST_STATUS_INTERNAL_SERVER_ERROR;
        goto out;
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

merr_t
kvs_rest_add_endpoints(struct ikvdb *const kvdb, struct kvdb_kvs *const kvs)
{
    static rest_handler *handlers[][REST_METHOD_COUNT] = {
        {
            [REST_METHOD_GET] = rest_kvs_cn_tree,
        },
        {
            [REST_METHOD_GET] = rest_kvs_params_get,
            [REST_METHOD_PUT] = rest_kvs_params_put,
        },
        {
            [REST_METHOD_GET] = rest_kvs_get_perfc,
        },
    };

    merr_t err1 = 0, err2;
    const char *alias;

    if (!kvdb || !kvs)
        return merr(EINVAL);

    if (!hse_gparams.gp_socket.enabled)
        goto out;

    alias = ikvdb_alias(kvdb);

    err2 = rest_server_add_endpoint(
        REST_ENDPOINT_EXACT,
        handlers[0],
        kvs,
        "/kvdbs/%s/kvs/%s/cn/tree",
        alias,
        kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_add_endpoint(
        0,
        handlers[1],
        kvs,
        "/kvdbs/%s/kvs/%s/params",
        alias,
        kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_add_endpoint(
        0,
        handlers[2],
        kvs,
        "/kvdbs/%s/kvs/%s/perfc",
        alias,
        kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

out:
    atomic_inc(&kvs->kk_refcnt);

    return err1;
}

merr_t
kvs_rest_remove_endpoints(struct ikvdb *const kvdb, struct kvdb_kvs *const kvs)
{
    merr_t err1 = 0, err2;
    const char *alias;

    if (!kvdb || !kvs)
        return merr(ev(EINVAL));

    if (!hse_gparams.gp_socket.enabled)
        goto out;

    alias = ikvdb_alias(kvdb);

    err2 = rest_server_remove_endpoint("/kvdbs/%s/kvs/%s/cn/tree", alias, kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/kvs/%s/params", alias, kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

    err2 = rest_server_remove_endpoint("/kvdbs/%s/kvs/%s/perfc", alias, kvs->kk_name);
    if (ev(err2) && !err1)
        err1 = err2;

out:
    atomic_dec(&kvs->kk_refcnt);

    return err1;
}
