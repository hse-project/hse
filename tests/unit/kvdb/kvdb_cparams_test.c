/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_util/storage.h>

#include <stdarg.h>

MTF_BEGIN_UTEST_COLLECTION(kvdb_cparams_test)

struct kvdb_cparams params;

int
test_pre(struct mtf_test_info *ti)
{
    params = kvdb_cparams_defaults();

	return 0;
}

const struct param_spec *
ps_get(const char *const name)
{
	size_t                   sz = 0;
	const struct param_spec *pspecs = kvdb_cparams_pspecs_get(&sz);

	assert(name);

	for (size_t i = 0; i < sz; i++) {
		if (!strcmp(pspecs[i].ps_name, name))
			return &pspecs[i];
	}

	return NULL;
}

/**
 * Check the validity of various key=value combinations
 */
merr_t HSE_SENTINEL
check(const char *const arg, ...)
{
    merr_t      err;
    bool        success;
    const char *a = arg;
    va_list     ap;

	assert(arg);

    va_start(ap, arg);

	do {
        const char * paramv[] = { a };
        const size_t paramc = NELEM(paramv);

		success = !!va_arg(ap, int);

        err = argv_deserialize_to_kvdb_cparams(paramc, paramv, &params);

        if (success != !err) {
            break;
		} else {
			/* Reset err because we expected it */
			err = 0;
		}
	} while ((a = va_arg(ap, char *)));

    va_end(ap);

	return err;
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_file_max_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.capacity.file.max_size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_GB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_FILESZ_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].fmaxsz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = check("storage.capacity.file.max_size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * GB, params.storage.mclass[MP_MED_CAPACITY].fmaxsz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_mblock_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.capacity.mblock.size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].mblocksz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = check("storage.capacity.mblock.size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * MB, params.storage.mclass[MP_MED_CAPACITY].mblocksz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_file_count, test_pre)
{
	const struct param_spec *ps = ps_get("storage.capacity.file.count");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_FILECNT_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].filecnt);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT8_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_path, test_pre)
{
	const struct param_spec *ps = ps_get("storage.capacity.path");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(0, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_STRING, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_STREQ(MPOOL_CAPACITY_MCLASS_DEFAULT_PATH, params.storage.mclass[MP_MED_CAPACITY].path);
	ASSERT_EQ(PATH_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_file_max_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.staging.file.max_size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_GB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_FILESZ_DEFAULT, params.storage.mclass[MP_MED_STAGING].fmaxsz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = check("storage.staging.file.max_size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * GB, params.storage.mclass[MP_MED_STAGING].fmaxsz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_mblock_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.staging.mblock.size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, params.storage.mclass[MP_MED_STAGING].mblocksz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = check("storage.staging.mblock.size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * MB, params.storage.mclass[MP_MED_STAGING].mblocksz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_file_count, test_pre)
{
	const struct param_spec *ps = ps_get("storage.staging.file.count");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ(MPOOL_MBLOCK_FILECNT_DEFAULT, params.storage.mclass[MP_MED_STAGING].filecnt);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT8_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_path, test_pre)
{
	const struct param_spec *ps = ps_get("storage.staging.path");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_NULLABLE, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_STRING, ps->ps_type);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ('\0', params.storage.mclass[MP_MED_STAGING].path[0]);
	ASSERT_EQ(PATH_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_END_UTEST_COLLECTION(kvdb_cparams_test)
