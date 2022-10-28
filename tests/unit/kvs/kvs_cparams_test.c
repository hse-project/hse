/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse/ikvdb/argv.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/param.h>

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
    ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
    ASSERT_EQ(0, params.pfx_len);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_KVS_PFX_LEN_MAX, ps->ps_bounds.as_uscalar.ps_max);
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
    ASSERT_EQ((uintptr_t)ps->ps_jsonify, (uintptr_t)param_default_jsonify);
    ASSERT_EQ(0, params.kvs_ext01);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST(kvs_cparams_test, get)
{
    merr_t err;
    char   buf[128];
    size_t needed_sz;

    const struct kvs_cparams p = kvs_cparams_defaults();

    err = kvs_cparams_get(&p, "prefix.length", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("0", buf);
    ASSERT_EQ(1, needed_sz);

    err = kvs_cparams_get(&p, "prefix.length", buf, sizeof(buf), NULL);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_STREQ("0", buf);

    err = kvs_cparams_get(&p, "does.not.exist", buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvs_cparams_get(NULL, "prefix.length", buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvs_cparams_get(&p, NULL, buf, sizeof(buf), NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvs_cparams_get(&p, "prefix.length", NULL, 0, &needed_sz);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, needed_sz);
}

MTF_DEFINE_UTEST(kvs_cparams_test, to_json)
{
    cJSON *root;

    const struct kvs_cparams p = kvs_cparams_defaults();

    root = kvs_cparams_to_json(&p);
    ASSERT_NE(NULL, root);

    cJSON_Delete(root);

    root = kvs_cparams_to_json(NULL);
    ASSERT_EQ(NULL, NULL);
}

MTF_END_UTEST_COLLECTION(kvs_cparams_test)
