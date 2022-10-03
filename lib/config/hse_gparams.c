/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <bsd/string.h>

#include <hse/logging/logging.h>

#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/limits.h>
#include <hse_util/compiler.h>
#include <hse_util/perfc.h>
#include <hse_util/vlb.h>

#include <hse_ikvdb/limits.h>

#include "logging.h"

struct hse_gparams hse_gparams;

static bool HSE_NONNULL(1, 2, 3)
logging_destination_converter(
    const struct param_spec *const ps,
    const cJSON *const             node,
    void *const                    data)
{
    assert(ps);
    assert(node);
    assert(data);

    if (!cJSON_IsString(node))
        return false;

    const char *         setting = cJSON_GetStringValue(node);
    enum log_destination log_dest;

    if (strcmp(setting, "stdout") == 0) {
        log_dest = LOG_DEST_STDOUT;
    } else if (strcmp(setting, "stderr") == 0) {
        log_dest = LOG_DEST_STDERR;
    } else if (strcmp(setting, "file") == 0) {
        log_dest = LOG_DEST_FILE;
    } else if (strcmp(setting, "syslog") == 0) {
        log_dest = LOG_DEST_SYSLOG;
    } else {
        log_err(
            "Invalid logging.destination value: %s, must be one of stdout, stderr, file, or syslog",
            setting);
        return false;
    }

    *(enum log_destination *)data = log_dest;

    return true;
}

static merr_t
logging_destination_stringify(
    const struct param_spec *const ps,
    const void *const              value,
    char *const                    buf,
    const size_t                   buf_sz,
    size_t *const                  needed_sz)
{
    static const char *values[] = { "stdout", "stderr", "file", "syslog" };

    const int n = snprintf(buf, buf_sz, "\"%s\"", values[*(enum log_destination *)value]);
    if (n < 0)
        return merr(EBADMSG);

    if (needed_sz)
        *needed_sz = n;

    return 0;
}

static cJSON *
logging_destination_jsonify(const struct param_spec *const ps, const void *const value)
{
    assert(ps);
    assert(value);

    switch (*(enum log_destination *)value) {
        case LOG_DEST_STDOUT:
            return cJSON_CreateString("stdout");
        case LOG_DEST_STDERR:
            return cJSON_CreateString("stderr");
        case LOG_DEST_FILE:
            return cJSON_CreateString("file");
        case LOG_DEST_SYSLOG:
            return cJSON_CreateString("syslog");
        default:
            abort();
    }
}

static void
socket_path_default(const struct param_spec *ps, void *value)
{
    const char *dir;
    HSE_MAYBE_UNUSED int n;

    INVARIANT(ps);
    INVARIANT(value);

    /* All paths set in these environment variables must be absolute. If an
     * implementation encounters a relative path in any of these variables it
     * should consider the path invalid and ignore it.
     *
     * https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
     */
    dir = getenv("XDG_RUNTIME_DIR");
    if (!dir || *dir != '/')
        dir = "/tmp";

    n = snprintf(value, sizeof(hse_gparams.gp_socket.path), "%s%shse-%d.sock", dir,
        dir[strlen(dir) - 1] == '/' ? "" : "/", getpid());
    assert(n < sizeof(hse_gparams.gp_socket.path) && n > 0);
}

static const struct param_spec pspecs[] = {
    {
        .ps_name = "logging.enabled",
        .ps_description = "Whether logging is enabled",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct hse_gparams, gp_logging.lp_enabled),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_logging.lp_enabled),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = true,
        },
    },
    {
        .ps_name = "logging.destination",
        .ps_description = "Where log messages should be written to",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_ENUM,
        .ps_offset = offsetof(struct hse_gparams, gp_logging.lp_destination),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_logging.lp_destination),
        .ps_convert = logging_destination_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = logging_destination_stringify,
        .ps_jsonify = logging_destination_jsonify,
        .ps_default_value = {
            .as_enum = LOG_DEST_SYSLOG,
        },
        .ps_bounds = {
            .as_enum = {
                .ps_min = LOG_DEST_MIN,
                .ps_max = LOG_DEST_MAX,
            }
        },
    },
    {
        .ps_name = "logging.path",
        .ps_description = "Name of log file when destination == file",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct hse_gparams, gp_logging.lp_path),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_logging.lp_path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_string = "hse.log",
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = PARAM_SZ(struct hse_gparams, gp_logging.lp_path),
            },
        },
    },
    {
        .ps_name = "logging.level",
        .ps_description = "Maximum log level which will be written",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_INT,
        .ps_offset = offsetof(struct hse_gparams, gp_logging.lp_level),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_logging.lp_level),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_scalar = LOG_DEFAULT,
        },
        .ps_bounds = {
            .as_scalar = {
                .ps_min = LOG_EMERG,
                .ps_max = LOG_DEBUG,
            }
        }
    },
    {
        .ps_name = "logging.squelch_ns",
        .ps_description = "drop messages repeated within nsec window",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, gp_logging.lp_squelch_ns),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_logging.lp_squelch_ns),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = LOG_SQUELCH_NS_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "vlb_cache_sz",
        .ps_description = "size of vlb cache (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, gp_vlb_cache_sz),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_vlb_cache_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = HSE_VLB_CACHESZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = HSE_VLB_CACHESZ_MIN,
                .ps_max = HSE_VLB_CACHESZ_MAX,
            },
        },
    },
    {
        .ps_name = "c0kvs_ccache_sz_max",
        .ps_description = "max size of c0kvs cheap cache (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, gp_c0kvs_ccache_sz_max),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_c0kvs_ccache_sz_max),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = HSE_C0_CCACHE_SZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_C0_CCACHE_SZ_MAX,
            },
        },
    },
    {
        .ps_name = "c0kvs_ccache_sz",
        .ps_description = "size of c0kvs cheap cache (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, gp_c0kvs_ccache_sz),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_c0kvs_ccache_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = HSE_C0_CCACHE_SZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_C0_CCACHE_SZ_MAX,
            },
        },
    },
    {
        .ps_name = "c0kvs_cheap_sz",
        .ps_description = "set c0kvs cheap size (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, gp_c0kvs_cheap_sz),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_c0kvs_cheap_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = HSE_C0_CHEAP_SZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = HSE_C0_CHEAP_SZ_MIN,
                .ps_max = HSE_C0_CHEAP_SZ_MAX,
            },
        },
    },
    {
        .ps_name = "workqueue_tcdelay",
        .ps_description = "set workqueue thread-create delay (milliseconds)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct hse_gparams, gp_workqueue_tcdelay),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_workqueue_tcdelay),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 1000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "workqueue_idle_ttl",
        .ps_description = "set workqueue idle thread time-to-live (seconds)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct hse_gparams, gp_workqueue_idle_ttl),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_workqueue_idle_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 300,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "perfc.level",
        .ps_description = "set kvs perf counter enagagement level (min:0 default:2 max:9)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct hse_gparams, gp_perfc_level),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_perfc_level),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = PERFC_LEVEL_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = PERFC_LEVEL_MIN,
                .ps_max = PERFC_LEVEL_MAX,
            },
        },
    },
    {
        .ps_name = "socket.enabled",
        .ps_description = "Enable the REST server",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct hse_gparams, gp_socket.enabled),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_socket.enabled),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = true,
        }
    },
    {
        .ps_name = "socket.path",
        .ps_description = "UNIX socket path",
        .ps_flags = PARAM_FLAG_DEFAULT_BUILDER,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct hse_gparams, gp_socket.path),
        .ps_size = PARAM_SZ(struct hse_gparams, gp_socket.path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_builder = socket_path_default,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = PARAM_SZ(struct hse_gparams, gp_socket.path),
            },
        },
    },
};

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct hse_gparams
hse_gparams_defaults()
{
    struct hse_gparams  params;
    const struct params p = { .p_type = PARAMS_HSE_GP, .p_params = { .as_hse_gp = &params } };

    param_default_populate(pspecs, NELEM(pspecs), &p);
    return params;
}

merr_t
hse_gparams_get(
    const struct hse_gparams *const params,
    const char *const               param,
    char *const                     buf,
    const size_t                    buf_sz,
    size_t *const                   needed_sz)
{
    const struct params p = { .p_params = { .as_hse_gp = params }, .p_type = PARAMS_HSE_GP };

    return param_get(&p, pspecs, NELEM(pspecs), param, buf, buf_sz, needed_sz);
}

merr_t
hse_gparams_set(
    const struct hse_gparams *const params,
    const char *const               param,
    const char *const               value)
{
    if (!params || !param || !value)
        return merr(EINVAL);

    const struct params p = { .p_params = { .as_hse_gp = params }, .p_type = PARAMS_HSE_GP };

    return param_set(&p, pspecs, NELEM(pspecs), param, value);
}

cJSON *
hse_gparams_to_json(const struct hse_gparams *const params)
{
    if (!params)
        return NULL;

    const struct params p = { .p_params = { .as_hse_gp = params }, .p_type = PARAMS_HSE_GP };

    return param_to_json(&p, pspecs, NELEM(pspecs));
}
