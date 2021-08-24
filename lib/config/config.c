/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "build_config.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cjson/cJSON.h>
#include <bsd/string.h>

#include <hse_util/hse_err.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>

#include "logging.h"

#define DEFAULT_KEY "default"
#define KVS_KEY     "kvs"

/**
 * Walk and deserialize a JSON object recursively
 *
 * @param node: the current node to walk through
 * @param pspecs: array of param_spec to search through
 * @param pspecs_sz: size of \p pspecs
 * @param params: pointer to a params struct (kvdb_rparams, kvs_rparams)
 * @param ignore_keys: keys to ignore while recursing ("kvs" key in the kvdb object for example); must be null terminated
 * @param ignore_keys_sz: size of \p ignore_keys
 * @param prefix: prefix for keys; used to create hierarchical keys (x.y.z)
 * @param bypass: bypass current recurse (so keys don't get prefixed with "kvdb" or "default"/name of kvs)
 * @return error status
 * @retval non-zero on error
 */
static merr_t
json_walk(
    const cJSON *const         node,
    const struct param_spec *  pspecs,
    const size_t               pspecs_sz,
    const struct params *const params,
    const char *const *const   ignore_keys,
    const size_t               ignore_keys_sz,
    const char *const          prefix,
    const bool                 bypass)
{
    merr_t                   err = 0;
    char *                   key = NULL;
    const struct param_spec *ps = NULL;

    const size_t prefix_sz = prefix ? strlen(prefix) : 0;
    const size_t node_str_sz = node->string ? strlen(node->string) : 0;
    /* +2 for NUL byte and potential '.' separator */
    const size_t key_sz = prefix_sz + node_str_sz + 2;

    assert(pspecs);
    assert(pspecs_sz > 0);
    assert(node);
    assert(ignore_keys ? ignore_keys_sz > 0 : true);
    assert(bypass ? cJSON_IsObject(node) : true);

    if (!bypass) {
        /* Protect against configs like { "prefix.length": 5 } */
        if (strchr(node->string, '.')) {
            CLOG_ERR("Keys in config files cannot contain a '.'");
            err = merr(EINVAL);
            goto out;
        }

        assert(key_sz > 0);
        key = malloc(key_sz);
        if (!key) {
            err = merr(ENOMEM);
            goto out;
        }

        if (prefix) {
            const int overflow = snprintf(key, key_sz, "%s.%s", prefix, node->string);
            assert(overflow == key_sz - 1);
            if (overflow < 0) {
                err = merr(EBADMSG);
                goto out;
            }
        } else {
            HSE_MAYBE_UNUSED const size_t sz = strlcpy(key, node->string, key_sz);
            assert(sz == node_str_sz);
        }

        for (size_t i = 0; i < ignore_keys_sz; i++) {
            const char *ignore_key = ignore_keys[i];
            if (!strcmp(ignore_key, key))
                goto out;
        }

        for (size_t i = 0; i < pspecs_sz; i++) {
            if (!strcmp(pspecs[i].ps_name, key)) {
                ps = &pspecs[i];
                break;
            }
        }
    }

    if ((cJSON_IsObject(node) && !ps) || bypass) {
        for (cJSON *n = node->child; n; n = n->next) {
            err = json_walk(n, pspecs, pspecs_sz, params, ignore_keys, ignore_keys_sz, key, false);
            if (err)
                goto out;
        }
    } else {
        /* Key not found */
        if (!ps) {
            CLOG_ERR("Unknown parameter %s", key);
            err = merr(EINVAL);
            goto out;
        }

        CLOG_DEBUG("Applying %s %s from config file", params_logging_context(params), ps->ps_name);

        if (cJSON_IsNull(node) && !(ps->ps_flags & PARAM_FLAG_NULLABLE)) {
            CLOG_ERR("%s %s cannot be null", params_logging_context(params), ps->ps_name);
            err = merr(EINVAL);
            goto out;
        }

        void *data = ((char *)params->p_params.as_generic) + ps->ps_offset;

        assert(ps->ps_convert);
        if (!ps->ps_convert(ps, node, data)) {
            CLOG_ERR("Failed to convert %s %s", params_logging_context(params), key);
            err = merr(EINVAL);
            goto out;
        }

        /* Some param_specs may not have validate functions if their
         * conversion functions are well thought out, for instance when
         * deserializing an array.
         */
        if (ps->ps_validate && !ps->ps_validate(ps, data)) {
            CLOG_ERR("Failed to validate %s %s", params_logging_context(params), key);
            err = merr(EINVAL);
            goto out;
        }
    }

out:
    if (key)
        free(key);

    return err;
}

/**
 * Deserialize multiple JSON objects (providers) into a params struct
 *
 * @param pspecs: array of param_spec to search through
 * @param pspecs_sz: size of \p pspecs
 * @param params: params object
 * @param ignore_keys: keys to ignore while recursing ("kvs" key in the kvdb object for example)
 * @param ignore_keys_sz: size of \p ignore_keys
 * @param num_providers: number of providers for populating the @params object
 * @returns error status
 * @retval non-zero on error
 */
static merr_t
json_deserialize(
    const struct param_spec *  pspecs,
    const size_t               pspecs_sz,
    const struct params *const params,
    const char *const *const   ignore_keys,
    const size_t               ignore_keys_sz,
    const size_t               num_providers,
    ...)
{
    merr_t err = 0;

    assert(pspecs);
    assert(pspecs_sz > 0);

    va_list providers;
    va_start(providers, num_providers);

    /* Walk each provider to set params which will overwrite the previous provider */
    size_t j = 0;
    while (j < num_providers) {
        const cJSON *provider = va_arg(providers, const cJSON *);
        if (!provider || cJSON_IsNull(provider))
            continue;

        err =
            json_walk(provider, pspecs, pspecs_sz, params, ignore_keys, ignore_keys_sz, NULL, true);
        if (err)
            goto va_cleanup;

        j++;
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        if (ps->ps_validate_relations && !ps->ps_validate_relations(ps, params)) {
            CLOG_ERR(
                "Failed to validate parameter relationships for %s %s",
                params_logging_context(params),
                ps->ps_name);
            err = merr(EINVAL);
            goto va_cleanup;
        }
    }

va_cleanup:
    va_end(providers);
    return err;
}

static merr_t
kvs_node_get(const cJSON *kvdb, cJSON **kvs)
{
    assert(kvdb);
    assert(kvs);

    *kvs = cJSON_GetObjectItemCaseSensitive(kvdb, KVS_KEY);
    if (*kvs && !cJSON_IsObject(*kvs))
        return merr(EINVAL);

    return 0;
}

static merr_t
default_kvs_node_get(const cJSON *kvs, cJSON **default_kvs)
{
    assert(kvs);
    assert(default_kvs);

    *default_kvs = cJSON_GetObjectItemCaseSensitive(kvs, DEFAULT_KEY);
    if (*default_kvs && !cJSON_IsObject(*default_kvs))
        return merr(EINVAL);

    return 0;
}

static merr_t
named_kvs_node_get(const char *kvs_name, const cJSON *kvs, cJSON **named_kvs)
{
    assert(kvs);
    assert(named_kvs);

    *named_kvs = cJSON_GetObjectItemCaseSensitive(kvs, kvs_name);
    if (*named_kvs && !cJSON_IsObject(*named_kvs))
        return merr(EINVAL);

    return 0;
}

merr_t
config_deserialize_to_hse_gparams(const struct config *conf, struct hse_gparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs = hse_gparams_pspecs_get(&pspecs_sz);
    const struct params      p = { .p_type = PARAMS_HSE_GP, .p_params = { .as_hse_gp = params } };

    assert(params);

    if (!conf)
        return 0;

    return json_deserialize(pspecs, pspecs_sz, &p, NULL, 0, 1, (cJSON *)conf);
}

merr_t
config_deserialize_to_kvdb_rparams(const struct config *conf, struct kvdb_rparams *params)
{
    merr_t                   err = 0;
    const char *             ignore_keys[] = { "kvs" };
    const size_t             ignore_keys_sz = NELEM(ignore_keys);
    size_t                   rpspecs_sz;
    const struct param_spec *rpspecs = kvdb_rparams_pspecs_get(&rpspecs_sz);
    const struct params      p = { .p_type = PARAMS_KVDB_RP, .p_params = { .as_kvdb_rp = params } };

    assert(params);

    if (!conf)
        return err;

    err = json_deserialize(rpspecs, rpspecs_sz, &p, ignore_keys, ignore_keys_sz, 1, (cJSON *)conf);

    return err;
}

merr_t
config_deserialize_to_kvs_rparams(
    const struct config *conf,
    const char *         kvs_name,
    struct kvs_rparams * params)
{
    merr_t                   err = 0;
    cJSON *                  kvs = NULL;
    cJSON *                  named_kvs = NULL, *default_kvs = NULL;
    size_t                   rpspecs_sz;
    const struct param_spec *rpspecs = kvs_rparams_pspecs_get(&rpspecs_sz);
    const struct params      p = { .p_type = PARAMS_KVS_RP, .p_params = { .as_kvs_rp = params } };

    assert(kvs_name);
    assert(params);

    if (!conf)
        return err;

    err = kvs_node_get((cJSON *)conf, &kvs);
    if (err || !kvs)
        return err;

    size_t num_providers = 0;
    err = default_kvs_node_get(kvs, &default_kvs);
    if (err)
        return err;
    if (default_kvs) {
        hse_log(HSE_DEBUG "Found a default config node for KVS (%s)", kvs_name);
        num_providers++;
    }

    err = named_kvs_node_get(kvs_name, kvs, &named_kvs);
    if (err)
        return err;
    if (named_kvs) {
        hse_log(HSE_DEBUG "Found a named config node for KVS (%s)", kvs_name);
        num_providers++;
    }

    err = json_deserialize(rpspecs, rpspecs_sz, &p, NULL, 0, num_providers, default_kvs, named_kvs);

    return err;
}

static merr_t
config_create(const char *path, cJSON **conf)
{
    char *      config = NULL;
    FILE *      file = NULL;
    merr_t      err = 0;
    int         fd;
    struct stat st;

    assert(path);
    assert(conf);

    *conf = NULL;

    file = fopen(path, "r");
    if (!file) {
        err = merr(errno);
        goto out;
    }

    fd = fileno(file);
    if (fd == -1) {
        err = merr(errno);
        goto out;
    }

    if (fstat(fd, &st) == -1) {
        err = merr(errno);
        goto out;
    }

    config = malloc(st.st_size + 1);
    if (!config) {
        err = merr(ENOMEM);
        goto out;
    }

    if (fread(config, st.st_size, 1, file) != 1 || ferror(file)) {
        err = merr(EIO);
        goto out;
    }

    config[st.st_size] = '\0';

    *conf = cJSON_ParseWithLength(config, st.st_size);
    if (!*conf) {
        CLOG_ERR("Failed to parse file as valid JSON (%s)", path);
        err = merr(EINVAL);
        goto out;
    }

out:
    if (config)
        free(config);
    if (file && fclose(file) == EOF && !err) {
        err = merr(errno);
        cJSON_Delete(*conf);
    }

    return err;
}

merr_t
config_from_hse_conf(const char *const config, struct config **conf)
{
    cJSON      *impl = NULL;
    merr_t      err;

    if (HSE_UNLIKELY(!conf)) {
        return merr(EINVAL);
    }

    *conf = NULL;

    if (!config || config[0] == '\0')
        return 0;

    err = config_create(config, &impl);
    if (err) {
        if (merr_errno(err) == ENOENT) {
            err = 0;
        } else {
            hse_log(HSE_ERR "Failed to read %s", config);
        }
        goto out;
    }

    if (!cJSON_IsObject(impl)) {
        err = merr(EINVAL);
        goto out;
    }

out:
    if (err && impl)
        cJSON_Delete(impl);

    *conf = (struct config *)impl;

    return err;
}

merr_t
config_from_kvdb_conf(const char *kvdb_home, struct config **conf)
{
    cJSON *impl = NULL;
    char   conf_file_path[PATH_MAX];
    int    n;
    merr_t err = 0;

    if (HSE_UNLIKELY(!kvdb_home || !conf))
        return merr(EINVAL);

    n = snprintf(conf_file_path, sizeof(conf_file_path), "%s/kvdb.conf", kvdb_home);
    if (n >= sizeof(conf_file_path)) {
        hse_log(
            HSE_ERR "Failed to create the %s/kvdb.conf file path because the path was too large",
            kvdb_home);
        err = merr(ENAMETOOLONG);
        goto out;
    } else if (n < 0) {
        err = merr(EBADMSG);
        goto out;
    }

    err = config_create(conf_file_path, &impl);
    if (err) {
        if (merr_errno(err) == ENOENT) {
            hse_log(HSE_DEBUG "No config file (%s)", conf_file_path);
            err = 0;
        } else {
            hse_log(HSE_ERR "Failed to read %s", conf_file_path);
        }
        goto out;
    }

    if (!cJSON_IsObject(impl)) {
        hse_log(HSE_ERR "Content of %s/kvdb.conf must be a JSON object", kvdb_home);
        err = merr(EINVAL);
        goto out;
    }

out:
    if (err && impl)
        cJSON_Delete(impl);

    *conf = (struct config *)impl;

    return err;
}

void
config_destroy(struct config *conf)
{
    cJSON_Delete((cJSON *)conf);
}
