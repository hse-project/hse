/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/wal.h>

#include <stdarg.h>

MTF_BEGIN_UTEST_COLLECTION(kvdb_rparams_test)

    struct kvdb_rparams params;

int
test_pre(struct mtf_test_info *ti)
{
    params = kvdb_rparams_defaults();

    return 0;
}

const struct param_spec *
ps_get(const char *const name)
{
    size_t                   sz = 0;
    const struct param_spec *pspecs = kvdb_rparams_pspecs_get(&sz);

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

        err = argv_deserialize_to_kvdb_rparams(paramc, paramv, &params);

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

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, read_only, test_pre)
{
    const struct param_spec *ps = ps_get("read_only");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.read_only);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, perfc_level, test_pre)
{
    const struct param_spec *ps = ps_get("perfc.level");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(2, params.perfc_level);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(4, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, c0_debug, test_pre)
{
    const struct param_spec *ps = ps_get("c0_debug");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.c0_debug);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT8_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, c0_ingest_width, test_pre)
{
    const struct param_spec *ps = ps_get("c0_ingest_width");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_C0_INGEST_WIDTH_DFLT, params.c0_ingest_width);
    ASSERT_EQ(HSE_C0_INGEST_WIDTH_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_C0_INGEST_WIDTH_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, txn_timeout, test_pre)
{
    const struct param_spec *ps = ps_get("txn_timeout");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(1000 * 60 * 5, params.txn_timeout);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_policy, test_pre)
{
    const struct param_spec *ps = ps_get("csched_policy");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_NE((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(csched_policy_sp3, params.csched_policy);
    ASSERT_EQ(csched_policy_old, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(csched_policy_noop, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_debug_mask, test_pre)
{
    const struct param_spec *ps = ps_get("csched_debug_mask");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_debug_mask);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_samp_max, test_pre)
{
    const struct param_spec *ps = ps_get("csched_samp_max");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(150, params.csched_samp_max);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_lo_th_pct, test_pre)
{
    const struct param_spec *ps = ps_get("csched_lo_th_pct");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(25, params.csched_lo_th_pct);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_hi_th_pct, test_pre)
{
    const struct param_spec *ps = ps_get("csched_hi_th_pct");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(75, params.csched_hi_th_pct);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_leaf_pct, test_pre)
{
    const struct param_spec *ps = ps_get("csched_leaf_pct");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(90, params.csched_leaf_pct);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_vb_scatter_pct, test_pre)
{
    const struct param_spec *ps = ps_get("csched_vb_scatter_pct");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(100, params.csched_vb_scatter_pct);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_qthreads, test_pre)
{
    const struct param_spec *ps = ps_get("csched_qthreads");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_qthreads);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_node_len_max, test_pre)
{
    const struct param_spec *ps = ps_get("csched_node_len_max");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_node_len_max);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_rspill_params, test_pre)
{
    const struct param_spec *ps = ps_get("csched_rspill_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_rspill_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_ispill_params, test_pre)
{
    const struct param_spec *ps = ps_get("csched_ispill_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_ispill_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_leaf_comp_params, test_pre)
{
    const struct param_spec *ps = ps_get("csched_leaf_comp_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_leaf_comp_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_leaf_len_params, test_pre)
{
    const struct param_spec *ps = ps_get("csched_leaf_len_params");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.csched_leaf_len_params);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, csched_node_min_ttl, test_pre)
{
    const struct param_spec *ps = ps_get("csched_node_min_ttl");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(17, params.csched_node_min_ttl);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_enabled, test_pre)
{
    const struct param_spec *ps = ps_get("durability.enabled");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(true, params.dur_enable);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_interval, test_pre)
{
    const struct param_spec *ps = ps_get("durability.interval_ms");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_WAL_DUR_MS_DFLT, params.dur_intvl_ms);
    ASSERT_EQ(HSE_WAL_DUR_MS_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_WAL_DUR_MS_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_buffer_size, test_pre)
{
    const struct param_spec *ps = ps_get("durability.buffer.size");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_roundup_pow2);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_WAL_DUR_BUFSZ_MB_DFLT, params.dur_bufsz_mb);
    ASSERT_EQ(HSE_WAL_DUR_BUFSZ_MB_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_WAL_DUR_BUFSZ_MB_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_throttling_threshold_low, test_pre)
{
    const struct param_spec *ps = ps_get("durability.throttling.threshold.low");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(13, params.dur_throttle_lo_th);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_throttling_threshold_high, test_pre)
{
    const struct param_spec *ps = ps_get("durability.throttling.threshold.high");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U8, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(87, params.dur_throttle_hi_th);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(100, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_buffer_managed, test_pre)
{
    const struct param_spec *ps = ps_get("durability.buffer.managed");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.dur_buf_managed);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, durability_mclass, test_pre)
{
    merr_t                   err;
    const struct param_spec *ps = ps_get("durability.mclass");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_ENUM, ps->ps_type);
    ASSERT_NE((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(MP_MED_CAPACITY, params.dur_mclass);
    ASSERT_EQ(MP_MED_BASE, ps->ps_bounds.as_enum.ps_min);
    ASSERT_EQ(MP_MED_MAX, ps->ps_bounds.as_enum.ps_max);

    /* clang-format off */
    err = check(
        "durability.mclass=none", false,
        "durability.mclass=capacity", true,
        "durability.mclass=staging", true,
        NULL
	);
    /* clang-format on */

    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_disable, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_disable");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.throttle_disable);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_update_ns, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_update_ns");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(25 * 1000 * 1000, params.throttle_update_ns);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_debug_intvl_s, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_debug");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(300, params.throttle_debug_intvl_s);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_c0_hi_th, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_c0_hi_th");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(35, params.throttle_c0_hi_th);
    ASSERT_EQ(30, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, thorttling_init_policy, test_pre)
{
    const struct param_spec *ps = ps_get("throttling.init_policy");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(0, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_ENUM, ps->ps_type);
    ASSERT_NE((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(THROTTLE_DELAY_START_DEFAULT, params.throttle_init_policy);
    ASSERT_EQ(THROTTLE_DELAY_START_LIGHT, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(THROTTLE_DELAY_START_DEFAULT, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_burst, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_burst");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(1ul << 20, params.throttle_burst);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, throttle_rate, test_pre)
{
    const struct param_spec *ps = ps_get("throttle_rate");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(10UL << 20, params.throttle_rate);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, txn_wkth_delay, test_pre)
{
    const struct param_spec *ps = ps_get("txn_wkth_delay");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U64, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(1000 * 60, params.txn_wkth_delay);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT64_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, cndb_entries, test_pre)
{
    const struct param_spec *ps = ps_get("cndb_entries");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(0, params.cndb_entries);
    ASSERT_EQ(0, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(UINT32_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, cndb_debug, test_pre)
{
    const struct param_spec *ps = ps_get("cndb_debug");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_BOOL, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(false, params.cndb_debug);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, c0_maint_threads, test_pre)
{
    const struct param_spec *ps = ps_get("c0_maint_threads");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_C0_MAINT_THREADS_DFLT, params.c0_maint_threads);
    ASSERT_EQ(HSE_C0_MAINT_THREADS_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_C0_MAINT_THREADS_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, c0_ingest_threads, test_pre)
{
    const struct param_spec *ps = ps_get("c0_ingest_threads");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_C0_INGEST_THREADS_DFLT, params.c0_ingest_threads);
    ASSERT_EQ(HSE_C0_INGEST_THREADS_MIN, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(HSE_C0_INGEST_THREADS_MAX, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, keylock_tables, test_pre)
{
    const struct param_spec *ps = ps_get("keylock_tables");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_U32, ps->ps_type);
    ASSERT_EQ((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_EQ((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(761, params.keylock_tables);
    ASSERT_EQ(16, ps->ps_bounds.as_uscalar.ps_min);
    ASSERT_EQ(8192, ps->ps_bounds.as_uscalar.ps_max);
}

MTF_DEFINE_UTEST_PRE(kvdb_rparams_test, mclass_policies, test_pre)
{
    /* [HSE_REVISIT]: mclass_policies has its own test. It should maybe be moved
     * into this test at some point for checking conversion and validation
     * specific tests.
     */
    const struct param_spec *ps = ps_get("mclass_policies");

    ASSERT_NE(NULL, ps);
    ASSERT_NE(NULL, ps->ps_description);
    ASSERT_EQ(PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_DEFAULT_BUILDER, ps->ps_flags);
    ASSERT_EQ(PARAM_TYPE_ARRAY, ps->ps_type);
    ASSERT_NE((uintptr_t)ps->ps_convert, (uintptr_t)param_default_converter);
    ASSERT_NE((uintptr_t)ps->ps_validate, (uintptr_t)param_default_validator);
    ASSERT_EQ(HSE_MPOLICY_COUNT, ps->ps_bounds.as_array.ps_max_len);
}

MTF_END_UTEST_COLLECTION(kvdb_rparams_test)
