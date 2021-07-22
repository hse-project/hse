/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "_config.h"

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
#include <hse_ikvdb/runtime_home.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#ifdef HSE_CONF_EXTENDED
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_dparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#endif

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
    const cJSON *const       node,
    const struct param_spec *pspecs,
    const size_t             pspecs_sz,
    const union params       params,
    const char *const *const ignore_keys,
    const size_t             ignore_keys_sz,
    const char *const        prefix,
    const bool               bypass)
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
        assert(key_sz > 0);
        key = malloc(key_sz);
        if (!key) {
            err = merr(ENOMEM);
            goto out;
        }

        if (prefix) {
            const int overflow =
                snprintf(key, key_sz, "%s.%s", prefix, node->string);
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
            if (!strcmp(ignore_key, node->string))
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
            err = merr(EINVAL);
            goto out;
        }

        if (cJSON_IsNull(node) && !(ps->ps_flags & PARAM_FLAG_NULLABLE)) {
            err = merr(EINVAL);
            goto out;
        }

        void *data = ((char *)params.as_generic) + ps->ps_offset;

        assert(ps->ps_convert);
        if (!ps->ps_convert(ps, node, data)) {
            err = merr(EINVAL);
            goto out;
        }

        /* Some param_specs may not have validate functions if their
         * conversion functions are well thought out, for instance when
         * deserializing an array.
         */
        if (ps->ps_validate && !ps->ps_validate(ps, data)) {
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
    const struct param_spec *pspecs,
    const size_t             pspecs_sz,
    const union params       params,
    const char *const *const ignore_keys,
    const size_t             ignore_keys_sz,
    const size_t             num_providers,
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
    const union params       p = { .as_hse_gp = params };

    assert(params);

    if (!conf)
        return 0;

    return json_deserialize(pspecs, pspecs_sz, p, NULL, 0, 1, (cJSON *)conf);
}

#ifdef HSE_CONF_EXTENDED
merr_t
config_deserialize_to_kvdb_cparams(const struct config *conf, struct kvdb_cparams *params)
{
    merr_t                   err = 0;
    const char **            ignore_keys = NULL;
    size_t                   cpspecs_sz, dpspecs_sz, rpspecs_sz;
    const struct param_spec *cpspecs = kvdb_cparams_pspecs_get(&cpspecs_sz);
    const struct param_spec *dpspecs = kvdb_dparams_pspecs_get(&dpspecs_sz);
    const struct param_spec *rpspecs = kvdb_rparams_pspecs_get(&rpspecs_sz);
    const size_t             ignore_keys_sz = rpspecs_sz + dpspecs_sz + 1;
    const union params       p = { .as_kvdb_cp = params };

    assert(params);

    if (!conf)
        return err;

    ignore_keys = malloc(sizeof(char *) * ignore_keys_sz);
    if (!ignore_keys)
        return merr(ENOMEM);

    size_t idx = 0;
    ignore_keys[idx++] = "kvs";
    for (size_t i = 0; i < rpspecs_sz; i++, idx++)
        ignore_keys[idx] = rpspecs[i].ps_name;
    for (size_t i = 0; i < dpspecs_sz; i++, idx++)
        ignore_keys[idx] = dpspecs[i].ps_name;

    err = json_deserialize(cpspecs, cpspecs_sz, p, ignore_keys, ignore_keys_sz, 1, (cJSON *)conf);

    free(ignore_keys);

    return err;
}

merr_t
config_deserialize_to_kvdb_dparams(const struct config *conf, struct kvdb_dparams *params)
{
    merr_t                   err = 0;
    const char **            ignore_keys = NULL;
    size_t                   cpspecs_sz, dpspecs_sz, rpspecs_sz;
    const struct param_spec *cpspecs = kvdb_cparams_pspecs_get(&cpspecs_sz);
    const struct param_spec *dpspecs = kvdb_dparams_pspecs_get(&dpspecs_sz);
    const struct param_spec *rpspecs = kvdb_rparams_pspecs_get(&rpspecs_sz);
    const size_t             ignore_keys_sz = rpspecs_sz + cpspecs_sz + 1;
    const union params       p = { .as_kvdb_dp = params };

    assert(params);

    if (!conf)
        return err;

    ignore_keys = malloc(sizeof(char *) * ignore_keys_sz);
    if (!ignore_keys)
        return merr(ENOMEM);

    size_t idx = 0;
    ignore_keys[idx++] = "kvs";
    for (size_t i = 0; i < cpspecs_sz; i++, idx++)
        ignore_keys[idx] = cpspecs[i].ps_name;
    for (size_t i = 0; i < rpspecs_sz; i++, idx++)
        ignore_keys[idx] = rpspecs[i].ps_name;

    err = json_deserialize(dpspecs, dpspecs_sz, p, ignore_keys, ignore_keys_sz, 1, (cJSON *)conf);

    free(ignore_keys);

    return err;
}
#endif

merr_t
config_deserialize_to_kvdb_rparams(const struct config *conf, struct kvdb_rparams *params)
{
    merr_t err = 0;
#ifndef HSE_CONF_EXTENDED
    const char * ignore_keys[] = { "kvs" };
    const size_t ignore_keys_sz = NELEM(ignore_keys);
#else
    const char **            ignore_keys = NULL;
    size_t                   cpspecs_sz, dpspecs_sz;
    const struct param_spec *cpspecs = kvdb_cparams_pspecs_get(&cpspecs_sz);
    const struct param_spec *dpspecs = kvdb_dparams_pspecs_get(&dpspecs_sz);
    const size_t             ignore_keys_sz = cpspecs_sz + dpspecs_sz + 1;
#endif
    size_t                   rpspecs_sz;
    const struct param_spec *rpspecs = kvdb_rparams_pspecs_get(&rpspecs_sz);
    const union params       p = { .as_kvdb_rp = params };

    assert(params);

    if (!conf)
        return err;

#ifdef HSE_CONF_EXTENDED
    ignore_keys = malloc(sizeof(char *) * ignore_keys_sz);
    if (!ignore_keys)
        return merr(ENOMEM);

    size_t idx = 0;
    ignore_keys[idx++] = "kvs";
    for (size_t i = 0; i < cpspecs_sz; i++, idx++)
        ignore_keys[idx] = cpspecs[i].ps_name;
    for (size_t i = 0; i < dpspecs_sz; i++, idx++)
        ignore_keys[idx] = dpspecs[i].ps_name;
#endif

    err = json_deserialize(rpspecs, rpspecs_sz, p, ignore_keys, ignore_keys_sz, 1, (cJSON *)conf);

#ifdef HSE_CONF_EXTENDED
    free(ignore_keys);
#endif

    return err;
}

#ifdef HSE_CONF_EXTENDED
merr_t
config_deserialize_to_kvs_cparams(
    const struct config *conf,
    const char *         kvs_name,
    struct kvs_cparams * params)
{
    merr_t                   err = 0;
    cJSON *                  kvs = NULL;
    cJSON *                  named_kvs = NULL, *default_kvs = NULL;
    const char **            ignore_keys = NULL;
    size_t                   cpspecs_sz, rpspecs_sz;
    const struct param_spec *cpspecs = kvs_cparams_pspecs_get(&cpspecs_sz);
    const struct param_spec *rpspecs = kvs_rparams_pspecs_get(&rpspecs_sz);
    const union params       p = { .as_kvs_cp = params };

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
    if (default_kvs)
        num_providers++;

    err = named_kvs_node_get(kvs_name, kvs, &named_kvs);
    if (err)
        return err;
    if (named_kvs)
        num_providers++;

    ignore_keys = malloc(sizeof(char *) * rpspecs_sz);
    if (!ignore_keys)
        return merr(ENOMEM);
    for (size_t i = 0; i < rpspecs_sz; i++)
        ignore_keys[i] = rpspecs[i].ps_name;

    err = json_deserialize(
        cpspecs, cpspecs_sz, p, ignore_keys, rpspecs_sz, num_providers, default_kvs, named_kvs);

    free(ignore_keys);

    return err;
}
#endif

merr_t
config_deserialize_to_kvs_rparams(
    const struct config *conf,
    const char *         kvs_name,
    struct kvs_rparams * params)
{
    merr_t err = 0;
    cJSON *kvs = NULL;
    cJSON *named_kvs = NULL, *default_kvs = NULL;
#ifdef HSE_CONF_EXTENDED
    const char **            ignore_keys = NULL;
    size_t                   cpspecs_sz;
    const struct param_spec *cpspecs = kvs_cparams_pspecs_get(&cpspecs_sz);
#endif
    size_t                   rpspecs_sz;
    const struct param_spec *rpspecs = kvs_rparams_pspecs_get(&rpspecs_sz);
    const union params       p = { .as_kvs_rp = params };

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
    if (default_kvs)
        num_providers++;

    err = named_kvs_node_get(kvs_name, kvs, &named_kvs);
    if (err)
        return err;
    if (named_kvs)
        num_providers++;

#ifndef HSE_CONF_EXTENDED
    err = json_deserialize(rpspecs, rpspecs_sz, p, NULL, 0, num_providers, default_kvs, named_kvs);
#else
    ignore_keys = malloc(sizeof(char *) * cpspecs_sz);
    if (!ignore_keys)
        return merr(ENOMEM);

    for (size_t i = 0; i < cpspecs_sz; i++)
        ignore_keys[i] = cpspecs[i].ps_name;

    err = json_deserialize(
        rpspecs, rpspecs_sz, p, ignore_keys, cpspecs_sz, num_providers, default_kvs, named_kvs);

    free(ignore_keys);
#endif

    return err;
}

static merr_t
config_create(const char *path, cJSON **conf)
{
    size_t n;
    char * config = NULL;
    FILE * file = NULL;
    merr_t err = 0;

    assert(path);
    assert(conf);

    file = fopen(path, "r");
    if (!file) {
        err = merr(errno);
        *conf = NULL;
        goto out;
    }

    if (fseek(file, 0, SEEK_END)) {
        err = merr(errno);
        goto out;
    }

    const long size = ftell(file);
    if (size == -1) {
        err = merr(errno);
        goto out;
    }

    rewind(file);

    config = malloc(size);
    if (!config) {
        err = merr(ENOMEM);
        goto out;
    }

    n = fread(config, 1, size, file);
    if (n != size || ferror(file)) {
        err = merr(EIO);
        goto out;
    }

    *conf = cJSON_ParseWithLength(config, size);
    if (!*conf) {
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
config_from_hse_conf(const char *const runtime_home, struct config **conf)
{
    cJSON *impl = NULL;
    char   conf_file_path[PATH_MAX];
    int    n;
    merr_t err;

    assert(conf);

    n = snprintf(conf_file_path, sizeof(conf_file_path), "%s/hse.conf", runtime_home);
    if (n >= sizeof(conf_file_path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    } else if (n < 0) {
        err = merr(EBADMSG);
        goto out;
    }

    err = config_create(conf_file_path, &impl);
    if (err) {
        if (merr_errno(err) == ENOENT)
        err = 0;
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

    assert(kvdb_home);
    assert(conf);

    n = snprintf(conf_file_path, sizeof(conf_file_path), "%s/kvdb.conf", kvdb_home);
    if (n >= sizeof(conf_file_path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    } else if (n < 0) {
        err = merr(EBADMSG);
        goto out;
    }

    err = config_create(conf_file_path, &impl);
    if (err) {
        if (merr_errno(err) == ENOENT)
            err = 0;
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

void
config_destroy(struct config *conf)
{
    cJSON_Delete((cJSON *)conf);
}
