/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_util/storage.h>

#include <stdarg.h>

MTF_BEGIN_UTEST_COLLECTION(kvs_rparams_test)

    struct kvs_rparams params;

int
test_pre(struct mtf_test_info *ti)
{
    params = kvs_rparams_defaults();

    return 0;
}

const struct param_spec *
ps_get(const char *const name)
{
    size_t                   sz = 0;
    const struct param_spec *pspecs = kvs_rparams_pspecs_get(&sz);

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

        err = argv_deserialize_to_kvs_rparams(paramc, paramv, &params);

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

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, kvs_cursor_ttl, test_pre)
{
    const struct param_spec *ps = ps_get("kvs_cursor_ttl");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, kvs_cursor_ttl), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(1500, params.kvs_cursor_ttl);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, transactions_enabled, test_pre)
{
    const struct param_spec *ps = ps_get("transactions.enabled");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, transactions_enable), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.transactions_enable);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, perfc_level, test_pre)
{
    const struct param_spec *ps = ps_get("perfc.level");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, perfc_level), ps->ps_offset);
    ASSERT_EQ(sizeof(uint8_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(PERFC_LEVEL_DEFAULT, params.perfc_level);
    ASSERT_EQ(PERFC_LEVEL_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(PERFC_LEVEL_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_node_sisze_lo, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("cn_node_size_lo");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_node_size_lo), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_NE(NULL, ps->ps_validate_relations);
    ASSERT_EQ(20 * 1024, params.cn_node_size_lo);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

    /* clang-format off */
    err = check(
        "cn_node_size_lo=50000", true,
        "cn_node_size_hi=40000", true,
        NULL
        );
    /* clang-format on */

    ASSERT_NE(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_node_size_hi, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("cn_node_size_hi");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_node_size_hi), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_NE(NULL, ps->ps_validate_relations);
    ASSERT_EQ(28 * 1024, params.cn_node_size_hi);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);

    /* clang-format off */
    err = check(
        "cn_node_size_lo=50000", true,
        "cn_node_size_hi=40000", true,
        NULL
        );
    /* clang-format on */

    ASSERT_NE(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_compact_vblk_ra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_compact_vblk_ra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_compact_vblk_ra), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(256 * 1024, params.cn_compact_vblk_ra);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_compact_vra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_compact_vra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_compact_vra), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(128 * 1024, params.cn_compact_vra);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_compact_kblk_ra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_compact_kblk_ra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_compact_kblk_ra), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(512 * 1024, params.cn_compact_kblk_ra);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_capped_ttl, test_pre)
{
    const struct param_spec *ps = ps_get("cn_capped_ttl");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_capped_ttl), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(9000, params.cn_capped_ttl);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_capped_vra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_capped_vra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_capped_vra), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(512 * 1024, params.cn_capped_vra);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_cursor_vra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_cursor_vra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_cursor_vra), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_cursor_vra);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_cursor_kra, test_pre)
{
    const struct param_spec *ps = ps_get("cn_cursor_kra");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_cursor_kra), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.cn_cursor_kra);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_cursor_seq, test_pre)
{
    const struct param_spec *ps = ps_get("cn_cursor_seq");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_cursor_seq), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_cursor_seq);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_wbt, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_wbt");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_wbt), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_mcache_wbt);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(3, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_vminlvl, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_vminlvl");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_vminlvl), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(UINT16_MAX, params.cn_mcache_vminlvl);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_vmin, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_vmin");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_vmin), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(256, params.cn_mcache_vmin);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_vmax, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_vmax");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_vmax), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(4096, params.cn_mcache_vmax);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_kra_params, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_kra_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_kra_params), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((50u << 16) | (4u << 8) | 4u, params.cn_mcache_kra_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_mcache_vra_params, test_pre)
{
    const struct param_spec *ps = ps_get("cn_mcache_vra_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_mcache_vra_params), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ((40u << 16) | (2u << 8) | 1u, params.cn_mcache_vra_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_diag_mode, test_pre)
{
    const struct param_spec *ps = ps_get("cn_diag_mode");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_diag_mode), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.cn_diag_mode);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_maint_disable, test_pre)
{
    const struct param_spec *ps = ps_get("cn_maint_disable");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_maint_disable), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.cn_maint_disable);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_bloom_create, test_pre)
{
    const struct param_spec *ps = ps_get("cn_bloom_create");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_bloom_create), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(true, params.cn_bloom_create);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_bloom_lookup, test_pre)
{
    const struct param_spec *ps = ps_get("cn_bloom_lookup");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_bloom_lookup), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_bloom_lookup);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(2, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_bloom_prob, test_pre)
{
    const struct param_spec *ps = ps_get("cn_bloom_prob");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_bloom_prob), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(10000, params.cn_bloom_prob);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_bloom_capped, test_pre)
{
    const struct param_spec *ps = ps_get("cn_bloom_capped");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_bloom_capped), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_bloom_capped);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_bloom_preload, test_pre)
{
    const struct param_spec *ps = ps_get("cn_bloom_preload");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_bloom_preload), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_bloom_preload);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_compaction_debug, test_pre)
{
    const struct param_spec *ps = ps_get("cn_compaction_debug");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_compaction_debug), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_compaction_debug);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_maint_delay, test_pre)
{
    const struct param_spec *ps = ps_get("cn_maint_delay");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_maint_delay), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(100, params.cn_maint_delay);
    ASSERT_EQ(20, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_io_threads, test_pre)
{
    const struct param_spec *ps = ps_get("cn_io_threads");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_io_threads), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(13, params.cn_io_threads);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_close_wait, test_pre)
{
    const struct param_spec *ps = ps_get("cn_close_wait");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_close_wait), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cn_close_wait);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_verify, test_pre)
{
    const struct param_spec *ps = ps_get("cn_verify");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_verify), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.cn_verify);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, cn_kcachesz, test_pre)
{
    const struct param_spec *ps = ps_get("cn_kcachesz");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, cn_kcachesz), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(1024 * 1024, params.cn_kcachesz);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, kblock_size, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("kblock_size_mb");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, kblock_size), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(32 * MB, params.kblock_size);
    ASSERT_EQ(KBLOCK_MIN_SIZE, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(KBLOCK_MAX_SIZE, ps->ps_bounds.as_uscalar.ps_max);

    err = check("kblock_size_mb=32", true, NULL);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(32 * MB, params.kblock_size);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, vblock_size, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("vblock_size_mb");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, vblock_size), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_convert_to_bytes_from_MB);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(32 * MB, params.vblock_size);
    ASSERT_EQ(VBLOCK_MIN_SIZE, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(VBLOCK_MAX_SIZE, ps->ps_bounds.as_uscalar.ps_max);

    err = check("kblock_size_mb=32", true, NULL);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(32 * MB, params.kblock_size);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, capped_evict_ttl, test_pre)
{
    const struct param_spec *ps = ps_get("capped_evict_ttl");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, capped_evict_ttl), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(120, params.capped_evict_ttl);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, read_only, test_pre)
{
    const struct param_spec *ps = ps_get("read_only");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, read_only), ps->ps_offset);
    ASSERT_EQ(sizeof(bool), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.read_only);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, mclass_policy, test_pre)
{
    const struct param_spec *ps = ps_get("mclass.policy");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_STRING, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, mclass_policy), ps->ps_offset);
    ASSERT_EQ(HSE_MPOLICY_NAME_LEN_MAX, ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_STREQ("capacity_only", params.mclass_policy);
    ASSERT_EQ(HSE_MPOLICY_NAME_LEN_MAX, ps->ps_bounds.as_string.ps_max_len);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, compression_value_min_length, test_pre)
{
    const struct param_spec *ps = ps_get("compression.value.min_length");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, vcompmin), ps->ps_offset);
    ASSERT_EQ(sizeof(uint64_t), ps->ps_size);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(12, params.vcompmin);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvs_rparams_test, compression_value_algorithm, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("compression.value.algorithm");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_ENUM, ps->ps_type);
    ASSERT_EQ(offsetof(struct kvs_rparams, value_compression), ps->ps_offset);
    ASSERT_EQ(sizeof(enum vcomp_algorithm), ps->ps_size);
    ASSERT_NE((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(VCOMP_ALGO_NONE, params.value_compression);
    ASSERT_EQ(VCOMP_ALGO_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(VCOMP_ALGO_MAX, ps->ps_bounds.as_uscalar.ps_max);

    /* clang-format off */
    err = check(
        "compression.value.algorithm=none", true,
        "compression.value.algorithm=lz4", true,
        "compression.value.algorithm=does-not-exist", false,
        NULL);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(kvs_rparams_test)
