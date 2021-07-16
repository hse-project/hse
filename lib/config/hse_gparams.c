/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "_config.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef WITH_CJSON_FROM_SUBPROJECT
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif

#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/limits.h>
#include <hse_util/logging.h>

bool
logging_destination_converter(const struct param_spec *ps, const cJSON *node, void *value)
{
    assert(ps);
    assert(node);
    assert(value);

    if (!cJSON_IsString(node))
        return false;

    const char *setting = cJSON_GetStringValue(node);

    if (strcmp(setting, "stdout") == 0) {
        *(enum log_destination *)value = LD_STDOUT;
    } else if (strcmp(setting, "stderr")) {
        *(enum log_destination *)value = LD_STDERR;
    } else if (strcmp(setting, "file") == 0) {
        *(enum log_destination *)value = LD_FILE;
    } else if (strcmp(setting, "syslog") == 0) {
        *(enum log_destination *)value = LD_SYSLOG;
    } else {
        return false;
    }

    return true;
}

bool
logging_destination_validator(const struct param_spec *ps, const void *value)
{
    assert(ps);
    assert(value);

    const enum log_destination dest = *(enum log_destination *)value;

    return dest == LD_STDOUT || dest == LD_STDERR || dest == LD_FILE || dest == LD_SYSLOG;
}

static const struct param_spec pspecs[] = {
	{
		.ps_name = "logging.enabled",
		.ps_description = "Whether logging is enabled",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_BOOL,
		.ps_offset = offsetof(struct hse_gparams, logging.enabled),
		.ps_size = sizeof(bool),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_bool = false,
		},
	},
	/* [HSE_TODO]: Implement this toggle, currently everything seems to be structured.
	{
		.ps_name = "logging.structured",
		.ps_description = "Whether logging is structured",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_BOOL,
		.ps_offset = offsetof(struct hse_gparams, logging.structured),
		.ps_size = sizeof(bool),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_bool = false,
		},
	},
	*/
	{
		.ps_name = "logging.destination",
		.ps_description = "Where log messages should be written to",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_ENUM,
		.ps_offset = offsetof(struct hse_gparams, logging.destination),
		.ps_size = sizeof(enum log_destination),
		.ps_convert = logging_destination_converter,
		.ps_validate = logging_destination_validator,
		.ps_default_value = {
			.as_enum = "syslog",
		},
		.ps_bounds = {
			.as_enum = {
				.ps_values = {
					"stdout",
					"stderr",
					"file",
					"syslog",
				},
				.ps_num_values = LD_SYSLOG + 1,
			},
		},
	},
	{
		.ps_name = "logging.path",
		.ps_description = "Name of log file when destination == file",
		.ps_flags = PARAM_FLAG_NULLABLE,
		.ps_type = PARAM_TYPE_STRING,
		.ps_offset = offsetof(struct hse_gparams, logging.path),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_string = "hse.log",
		},
		.ps_bounds = {
			.as_string = {
				.ps_max_len = sizeof(((struct hse_gparams *)0)->logging.path),
			},
		},
	},
	{
		.ps_name = "logging.level",
		.ps_description = "Maximum log level which will be written",
		.ps_flags = 0,
		.ps_type = PARAM_TYPE_I32,
		.ps_offset = offsetof(struct hse_gparams, logging.level),
		.ps_size = sizeof(log_priority_t),
		.ps_convert = param_default_converter,
		.ps_validate = param_default_validator,
		.ps_default_value = {
			.as_scalar = HSE_LOG_PRI_DEFAULT,
		},
		.ps_bounds = {
			.as_scalar = {
				.ps_min = HSE_EMERG_VAL,
				.ps_max = HSE_DEBUG_VAL,
			}
		}
	},
    {
        .ps_name = "logging.squelch_ns",
        .ps_description = "drop messages repeated within nsec window",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, logging.squelch_ns),
        .ps_size = sizeof(((struct hse_gparams *) 0)->logging.squelch_ns),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_LOG_SQUELCH_NS_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
	    {
        .ps_name = "c0kvs_ccache_sz_max",
        .ps_description = "max size of c0kvs cheap cache (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct hse_gparams, c0kvs_ccache_sz_max),
        .ps_size = sizeof(((struct hse_gparams *) 0)->c0kvs_ccache_sz_max),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
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
        .ps_offset = offsetof(struct hse_gparams, c0kvs_ccache_sz),
        .ps_size = sizeof(((struct hse_gparams *) 0)->c0kvs_ccache_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
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
        .ps_offset = offsetof(struct hse_gparams, c0kvs_cheap_sz),
        .ps_size = sizeof(((struct hse_gparams *) 0)->c0kvs_cheap_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
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
};

struct hse_gparams hse_gparams = {
    .c0kvs_ccache_sz_max = HSE_C0_CCACHE_SZ_DFLT,
    .c0kvs_ccache_sz = HSE_C0_CCACHE_SZ_DFLT,
    .c0kvs_cheap_sz = HSE_C0_CHEAP_SZ_DFLT,
	.logging = {
		.enabled = true,
		.destination = LD_SYSLOG,
		.path = "hse.log",
		.level = HSE_LOG_PRI_DEFAULT,
		.squelch_ns = HSE_LOG_SQUELCH_NS_DEFAULT,
	},
};

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}
