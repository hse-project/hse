/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>

#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvdb_dparams.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_home.h>
#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>
#include <mpool/mpool.h>

static const struct param_spec pspecs[] = {
    {
        .ps_name = "storage.capacity.path",
        .ps_description = "Storage path for capacity mclass",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_dparams, storage.mclass[MP_MED_CAPACITY].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_string = MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len =
                    sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_CAPACITY].path),
            },
        },
    },
        {
        .ps_name = "storage.staging.path",
        .ps_description = "Storage path for staging mclass",
        .ps_flags = PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_dparams, storage.mclass[MP_MED_STAGING].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_string = NULL,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len =
                    sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_STAGING].path),
            },
        },
    },
};

static_assert(sizeof(((struct kvdb_dparams *) 0)->storage.mclass[MP_MED_CAPACITY].path) == sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_CAPACITY].path), "buffer sizes for capacity path should match");
static_assert(sizeof(((struct kvdb_dparams *) 0)->storage.mclass[MP_MED_STAGING].path) == sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_STAGING].path), "buffer sizes for staging path should match");

const struct param_spec *
kvdb_dparams_pspecs_get(size_t *pspecs_sz)
{
	if (pspecs_sz)
		*pspecs_sz = NELEM(pspecs);
	return pspecs;
}

struct kvdb_dparams
kvdb_dparams_defaults()
{
	struct kvdb_dparams params;
    const union params p = { .as_kvdb_dp = &params };
	param_default_populate(pspecs, NELEM(pspecs), p);
	return params;
}

merr_t
kvdb_dparams_resolve(struct kvdb_dparams *params, const char *home)
{
    assert(params);
    assert(home);

    char   buf[PATH_MAX];
    merr_t err;

    err = kvdb_home_storage_capacity_path_get(home, params->storage.mclass[MP_MED_CAPACITY].path,
                                            buf, sizeof(buf));
    if (err)
        return err;
    strlcpy(params->storage.mclass[MP_MED_CAPACITY].path, buf,
            sizeof(params->storage.mclass[MP_MED_CAPACITY].path));

    err = kvdb_home_storage_staging_path_get(home, params->storage.mclass[MP_MED_STAGING].path,
                                             buf, sizeof(buf));
    if (err)
        return err;
    strlcpy(params->storage.mclass[MP_MED_STAGING].path, buf,
            sizeof(params->storage.mclass[MP_MED_STAGING].path));

    return 0;
}
