/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <event.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <event2/http.h>
#include <sys/queue.h>

#include <hse/rest/params.h>
#include <hse/util/assert.h>
#include <hse/util/compiler.h>

static const char *
get_value(const struct rest_params * const params, const char * const key)
{
    struct evkeyval *param;

    INVARIANT(key);

    if (!params)
        return NULL;

    TAILQ_FOREACH(param, (struct evkeyvalq *)params, next) {
        if (strcmp(param->key, key) == 0)
            return param->value;
    }

    return NULL;
}

merr_t
rest_params_get_bool(
    const struct rest_params * const params,
    const char * const key,
    bool * const value,
    const bool def)
{
    const char *data;

    if (!key || !value)
        return merr(EINVAL);

    data = get_value(params, key);
    if (!data) {
        *value = def;
        return 0;
    }

    if (strcmp(data, "true") == 0) {
        *value = true;
        return 0;
    }

    if (strcmp(data, "false") == 0) {
        *value = false;
        return 0;
    }

    return merr(EBADMSG);
}

merr_t
rest_params_get_size(
    const struct rest_params * const params,
    const char * const key,
    size_t * const value,
    const size_t def)
{
    char *endptr;
    const char *data;
    unsigned long long tmp;

    if (!key || !value)
        return merr(EINVAL);

    data = get_value(params, key);
    if (!data) {
        *value = def;
        return 0;
    }

    tmp = strtoull(data, &endptr, 10);
    if (endptr != NULL)
        return merr(EINVAL);

    *value = tmp;

    return 0;
}

merr_t
rest_params_get_string(
    const struct rest_params * const params,
    const char * const key,
    const char **value,
    const char * const def)
{
    const char *data;

    if (!key || !value)
        return merr(EINVAL);

    data = get_value(params, key);
    if (!data) {
        *value = def;
        return 0;
    }

    *value = data;

    return 0;
}
