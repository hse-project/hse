/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>

#include <bsd/string.h>

#include <hse_util/storage.h>

#include <hse_ikvdb/kvdb_home.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/wal.h>
#include <mpool/mpool.h>

static const struct param_spec pspecs[] = {
    {
        .ps_name = "storage.capacity.file.max_size",
        .ps_description = "file size in capacity mclass (GiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].fmaxsz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].fmaxsz),
        .ps_convert = param_convert_to_bytes_from_GB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_GB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILESZ_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            }
        }
    },
    {
        .ps_name = "storage.capacity.mblock.size",
        .ps_description = "object size in capacity mclass (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].mblocksz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].mblocksz),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_MB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_SIZE_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            }
        }
    },
    {
        .ps_name = "storage.capacity.file.count",
        .ps_description = "file count in capacity mclass",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].filecnt),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].filecnt),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILECNT_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        }
    },
    {
        .ps_name = "storage.capacity.path",
        .ps_description = "Storage path for capacity mclass",
        .ps_flags = PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].path),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_string = NULL,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = sizeof(((struct mpool_cparams *)0)->mclass[MP_MED_CAPACITY].path),
            },
        },
    },
    {
        .ps_name = "storage.staging.file.max_size",
        .ps_description = "file size in staging mclass (GiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].fmaxsz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].fmaxsz),
        .ps_convert = param_convert_to_bytes_from_GB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_GB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILESZ_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "storage.staging.mblock.size",
        .ps_description = "object size in staging mclass (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].mblocksz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].mblocksz),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_MB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_SIZE_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "storage.staging.file.count",
        .ps_description = "file count in staging mclass",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].filecnt),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].filecnt),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILECNT_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "storage.staging.path",
        .ps_description = "Storage path for staging mclass",
        .ps_flags = PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].path),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_string = NULL,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = sizeof(((struct mpool_cparams *)0)->mclass[MP_MED_STAGING].path),
            },
        },
    },
    {
        .ps_name = "storage.pmem.file.max_size",
        .ps_description = "file size in pmem mclass (GiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].fmaxsz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].fmaxsz),
        .ps_convert = param_convert_to_bytes_from_GB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_GB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILESZ_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "storage.pmem.mblock.size",
        .ps_description = "object size in pmem mclass (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].mblocksz),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].mblocksz),
        .ps_convert = param_convert_to_bytes_from_MB,
        .ps_validate = param_default_validator,
        .ps_stringify = param_stringify_bytes_to_MB,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_SIZE_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "storage.pmem.file.count",
        .ps_description = "file count in pmem mclass",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].filecnt),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].filecnt),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_uscalar = MPOOL_MBLOCK_FILECNT_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "storage.pmem.path",
        .ps_description = "Storage path for pmem mclass",
        .ps_flags = PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].path),
        .ps_size = PARAM_SZ(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_default_value = {
            .as_string = NULL,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = sizeof(((struct mpool_cparams *)0)->mclass[MP_MED_PMEM].path),
            },
        },
    },
};

const struct param_spec *
kvdb_cparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct kvdb_cparams
kvdb_cparams_defaults()
{
    struct kvdb_cparams params;
    const struct params p = { .p_type = PARAMS_KVDB_CP, .p_params = { .as_kvdb_cp = &params } };

    param_default_populate(pspecs, NELEM(pspecs), &p);
    return params;
}

static HSE_ALWAYS_INLINE void
kvdb_storage_defaults_set(struct kvdb_cparams *params, bool pmem_only)
{
    if (pmem_only) {
        if (params->storage.mclass[MP_MED_PMEM].path[0] == '\0')
            strlcpy(params->storage.mclass[MP_MED_PMEM].path, MPOOL_PMEM_MCLASS_DEFAULT_PATH,
                    sizeof(params->storage.mclass[MP_MED_PMEM].path));
    } else {
        if (params->storage.mclass[MP_MED_CAPACITY].path[0] == '\0')
            strlcpy(params->storage.mclass[MP_MED_CAPACITY].path, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
                    sizeof(params->storage.mclass[MP_MED_CAPACITY].path));
    }
}

merr_t
kvdb_cparams_resolve(struct kvdb_cparams *params, const char *home, bool pmem_only)
{
    int i;

    assert(params);
    assert(home);

    char   buf[PATH_MAX];
    merr_t err;

    static_assert(
        sizeof(buf) == sizeof(params->storage.mclass[MP_MED_BASE].path), "mismatched buffer sizes");

    kvdb_storage_defaults_set(params, pmem_only);

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        err = kvdb_home_storage_path_get(home, params->storage.mclass[i].path, buf, sizeof(buf));
        if (err)
            return err;

        strlcpy(params->storage.mclass[i].path, buf, sizeof(params->storage.mclass[i].path));
    }

    return 0;
}

merr_t
kvdb_cparams_get(
    const struct kvdb_cparams *const params,
    const char *const                param,
    char *const                      buf,
    const size_t                     buf_sz,
    size_t *const                    needed_sz)
{
    const struct params p = { .p_params = { .as_kvdb_cp = params }, .p_type = PARAMS_KVDB_CP };

    return param_get(&p, pspecs, NELEM(pspecs), param, buf, buf_sz, needed_sz);
}
