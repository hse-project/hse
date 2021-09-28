/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvs_cparams.h>

#include <stdarg.h>

MTF_BEGIN_UTEST_COLLECTION(kvs_cparams_test)

struct kvs_cparams params;

int
test_pre(struct mtf_test_info *ti)
{
    params = kvs_cparams_defaults();

	return 0;
}

const struct param_spec *
ps_get(const char *name)
{
	size_t                   sz = 0;
	const struct param_spec *pspecs = kvs_cparams_pspecs_get(&sz);

	assert(name);

	for (size_t i = 0; i < sz; i++) {
		if (!strcmp(pspecs[i].ps_name, name))
			return &pspecs[i];
	}

	return NULL;
}

MTF_DEFINE_UTEST_PRE(kvs_cparams_test, fanout, test_pre)
{
	const struct param_spec *ps = ps_get("fanout");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvs_cparams, fanout), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ(CN_FANOUT_MAX, params.fanout);
	ASSERT_EQ(CN_FANOUT_MIN, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(CN_FANOUT_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_cparams_test, prefix_length, test_pre)
{
	const struct param_spec *ps = ps_get("prefix.length");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(0, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvs_cparams, pfx_len), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ(0, params.pfx_len);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(HSE_KVS_PFX_LEN_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_cparams_test, prefix_pivot, test_pre)
{
	const struct param_spec *ps = ps_get("prefix.pivot");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvs_cparams, pfx_pivot), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ(2, params.pfx_pivot);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_cparams_test, kvs_ext01, test_pre)
{
	const struct param_spec *ps = ps_get("kvs_ext01");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvs_cparams, kvs_ext01), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ(0, params.kvs_ext01);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_cparams_test, suffix_length, test_pre)
{
	const struct param_spec *ps = ps_get("suffix.length");

	ASSERT_NE(NULL, ps);
	ASSERT_NE(NULL, ps->ps_description);
	ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
	ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
	ASSERT_EQ(offsetof(struct kvs_cparams, sfx_len), ps->ps_offset);
	ASSERT_EQ(sizeof(uint32_t), ps->ps_size);
	ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
	ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
	ASSERT_EQ((uintptr_t)ps->ps_stringify, (uintptr_t)param_default_stringify);
	ASSERT_EQ(0, params.sfx_len);
	ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
	ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_END_UTEST_COLLECTION(kvs_cparams_test)
