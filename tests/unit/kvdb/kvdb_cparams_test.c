/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/param.h>

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
	char                     buf[128];
	const struct param_spec *ps = ps_get("storage.capacity.file.max_size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].fmaxsz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_GB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_GB);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_GB);
	ASSERT_EQ(MPOOL_MBLOCK_FILESZ_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].fmaxsz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = ps->ps_stringify(ps, &params.storage.mclass[MP_MED_CAPACITY].fmaxsz, buf, sizeof(buf), NULL);
	ASSERT_EQ(0, err);
	ASSERT_STREQ("2048", buf);

	err = check("storage.capacity.file.max_size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * GB, params.storage.mclass[MP_MED_CAPACITY].fmaxsz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_mblock_size, test_pre)
{
	merr_t                   err;
	char                     buf[128];
	const struct param_spec *ps = ps_get("storage.capacity.mblock.size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].mblocksz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_MB);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_MB);
	ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].mblocksz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = ps->ps_stringify(ps, &params.storage.mclass[MP_MED_CAPACITY].mblocksz, buf, sizeof(buf), NULL);
	ASSERT_EQ(0, err);
	ASSERT_STREQ("32", buf);

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
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].filecnt), ps->ps_offset);
	ASSERT_EQ(sizeof(uint8_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
	ASSERT_EQ(MPOOL_MBLOCK_FILECNT_DEFAULT, params.storage.mclass[MP_MED_CAPACITY].filecnt);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT8_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_capacity_path, test_pre)
{
	const struct param_spec *ps = ps_get("storage.capacity.path");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_NULLABLE, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_STRING, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_CAPACITY].path), ps->ps_offset);
	ASSERT_EQ(PATH_MAX, ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
	ASSERT_EQ('\0', params.storage.mclass[MP_MED_CAPACITY].path[0]);
	ASSERT_EQ(PATH_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_file_max_size, test_pre)
{
	merr_t                   err;
	char                     buf[128];
	const struct param_spec *ps = ps_get("storage.staging.file.max_size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].fmaxsz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_GB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_GB);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_GB);
	ASSERT_EQ(MPOOL_MBLOCK_FILESZ_DEFAULT, params.storage.mclass[MP_MED_STAGING].fmaxsz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = ps->ps_stringify(ps, &params.storage.mclass[MP_MED_STAGING].fmaxsz, buf, sizeof(buf), NULL);
	ASSERT_EQ(0, err);
	ASSERT_STREQ("2048", buf);

	err = check("storage.staging.file.max_size=5", true, NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(5 * GB, params.storage.mclass[MP_MED_STAGING].fmaxsz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_staging_mblock_size, test_pre)
{
	merr_t                   err;
	char                     buf[128];
	const struct param_spec *ps = ps_get("storage.staging.mblock.size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].mblocksz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_MB);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_MB);
	ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, params.storage.mclass[MP_MED_STAGING].mblocksz);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);

	err = ps->ps_stringify(ps, &params.storage.mclass[MP_MED_STAGING].mblocksz, buf, sizeof(buf), NULL);
	ASSERT_EQ(0, err);
	ASSERT_STREQ("32", buf);

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
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].filecnt), ps->ps_offset);
	ASSERT_EQ(sizeof(uint8_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
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
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_STAGING].path), ps->ps_offset);
	ASSERT_EQ(PATH_MAX, ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
	ASSERT_EQ('\0', params.storage.mclass[MP_MED_STAGING].path[0]);
	ASSERT_EQ(PATH_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_pmem_file_max_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.pmem.file.max_size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].fmaxsz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_GB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_GB);
    ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_GB);
    ASSERT_EQ(MPOOL_MBLOCK_FILESZ_DEFAULT, params.storage.mclass[MP_MED_PMEM].fmaxsz);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

    err = check("storage.pmem.file.max_size=5", true, NULL);
    ASSERT_EQ(0, err);
    ASSERT_EQ(5 * GB, params.storage.mclass[MP_MED_PMEM].fmaxsz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_pmem_mblock_size, test_pre)
{
	merr_t                   err;
	const struct param_spec *ps = ps_get("storage.pmem.mblock.size");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].mblocksz), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_stringify_bytes_to_MB);
    ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_jsonify_bytes_to_MB);
    ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, params.storage.mclass[MP_MED_PMEM].mblocksz);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);

    err = check("storage.pmem.mblock.size=5", true, NULL);
    ASSERT_EQ(0, err);
    ASSERT_EQ(5 * MB, params.storage.mclass[MP_MED_PMEM].mblocksz);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_pmem_file_count, test_pre)
{
	const struct param_spec *ps = ps_get("storage.pmem.file.count");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].filecnt), ps->ps_offset);
	ASSERT_EQ(sizeof(uint8_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
	ASSERT_EQ(MPOOL_MBLOCK_FILECNT_DEFAULT, params.storage.mclass[MP_MED_PMEM].filecnt);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT8_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_cparams_test, storage_pmem_path, test_pre)
{
	const struct param_spec *ps = ps_get("storage.pmem.path");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_NULLABLE, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_STRING, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvdb_cparams, storage.mclass[MP_MED_PMEM].path), ps->ps_offset);
	ASSERT_EQ(PATH_MAX, ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
	ASSERT_EQ('\0', params.storage.mclass[MP_MED_PMEM].path[0]);
	ASSERT_EQ(PATH_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_DEFINE_UTEST(kvdb_cparams_test, get)
{
	merr_t err;
	char   buf[128];
	size_t needed_sz;

	const struct kvdb_cparams p = kvdb_cparams_defaults();

    err = kvdb_cparams_get(&p, "storage.capacity.path", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("null", buf);
    ASSERT_EQ(4, needed_sz);

    err = kvdb_cparams_get(&p, "storage.capacity.path", buf, sizeof(buf), NULL);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("null", buf);

	err = kvdb_cparams_get(&p, "does.not.exist", buf, sizeof(buf), NULL);
	ASSERT_EQ(EINVAL, merr_errno(err));

	err = kvdb_cparams_get(NULL, "storage.capacity.path", buf, sizeof(buf), NULL);
	ASSERT_EQ(EINVAL, merr_errno(err));

	err = kvdb_cparams_get(&p, NULL, buf, sizeof(buf), NULL);
	ASSERT_EQ(EINVAL, merr_errno(err));

	err = kvdb_cparams_get(&p, "storage.capacity.path", NULL, 0, &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(4, needed_sz);
}

MTF_DEFINE_UTEST(kvdb_cparams_test, to_json)
{
	cJSON *root;

	const struct kvdb_cparams p = kvdb_cparams_defaults();

	root = kvdb_cparams_to_json(&p);
	ASSERT_NE(NULL, root);

	cJSON_Delete(root);

	root = kvdb_cparams_to_json(NULL);
	ASSERT_EQ(NULL, NULL);
}

MTF_END_UTEST_COLLECTION(kvdb_cparams_test)
