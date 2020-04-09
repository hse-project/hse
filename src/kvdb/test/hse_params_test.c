/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc. All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_ut/common.h>

#include <hse_util/hse_params_helper.h>

#include <hse_ikvdb/hse_params_internal.h>

#include <hse/hse.h>
#include <hse/hse_experimental.h>

MTF_MODULE_UNDER_TEST(hse_params);

MTF_BEGIN_UTEST_COLLECTION(hse_params)

MTF_DEFINE_UTEST(hse_params, basic_usage)
{
    merr_t             err;
    char               buf[32];
    char *             result;
    struct hse_params *params;

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.dur_enable", "8080");
    ASSERT_EQ(err, 0);

    result = hse_params_get(params, "kvdb.dur_enable", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "8080"), 0);

    err = hse_params_set(params, "kvdb.dur_enable", "5000");
    ASSERT_EQ(err, 0);

    result = hse_params_get(params, "kvdb.dur_enable", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "5000"), 0);

    err = hse_params_set(params, "kvdb.dur_intvl_ms", "600");
    ASSERT_EQ(err, 0);

    result = hse_params_get(params, "kvdb.dur_intvl_ms", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "600"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(hse_params, validate_set)
{
    merr_t             err;
    char               buf[32];
    char *             result;
    struct hse_params *params;

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.uid", "cat");
    ASSERT_NE(err, 0);

    result = hse_params_get(params, "kvdb.uid", buf, sizeof(buf), 0);
    ASSERT_EQ(result, NULL);

    printf("%s\n", hse_params_err_exp(params, buf, sizeof(buf)));

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(hse_params, parsing_cli_valid)
{
    char               buf[32];
    char *             result;
    struct hse_params *params;
    int                next_arg = 0;

    int   argc = 2;
    char *argv[2] = { "kvs.pfx_len=16", "kvs.other=abc" };

    hse_params_create(&params);

    hse_parse_cli(argc, argv, &next_arg, 0, params);

    result = hse_params_get(params, "kvs.pfx_len", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "16"), 0);

    result = hse_params_get(params, "kvs.other", buf, sizeof(buf), 0);
    ASSERT_EQ(result, NULL);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(hse_params, parsing_cli_invalid)
{
    char               buf[32];
    char *             result;
    struct hse_params *params;
    int                next_arg = 0;

    int   argc = 2;
    char *argv[2] = { "xfs.pfx_len=16", "kvdbz.dur_intvl_ms=50" };

    hse_params_create(&params);

    hse_parse_cli(argc, argv, &next_arg, 0, params);

    result = hse_params_get(params, "xfs.pfx_len", buf, sizeof(buf), 0);
    ASSERT_EQ(result, NULL);

    result = hse_params_get(params, "kvdbz.dur_intvl_ms", buf, sizeof(buf), 0);
    ASSERT_EQ(result, NULL);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(hse_params, param_conversion)
{
    merr_t              err;
    char                buf[32];
    char *              result;
    struct hse_params * params;
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.low_mem", "1");
    ASSERT_EQ(err, 0);

    err = hse_params_set(params, "kvs.c0_cursor_ttl", "567");
    ASSERT_EQ(err, 0);

    result = hse_params_get(params, "kvdb.low_mem", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.c0_cursor_ttl", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "567"), 0);

    kvdb_rp = hse_params_to_kvdb_rparams(params, NULL);
    ASSERT_EQ(kvdb_rp.low_mem, 1);

    kvs_rp = hse_params_to_kvs_rparams(params, NULL, NULL);
    ASSERT_EQ(kvs_rp.c0_cursor_ttl, 567);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(hse_params, global_params)
{
    merr_t             err;
    struct hse_params *params;
    struct kvs_cparams kvs_cp;

    hse_params_create(&params);

    err = hse_params_set(params, "kvs.fanout", "32");
    ASSERT_EQ(err, 0);

    err = hse_params_set(params, "kvs.kvs_test.fanout", "8");
    ASSERT_EQ(err, 0);

    kvs_cp = hse_params_to_kvs_cparams(params, NULL, NULL);
    ASSERT_EQ(kvs_cp.cp_fanout, 32);

    kvs_cp = hse_params_to_kvs_cparams(params, "kvs_test", NULL);
    ASSERT_EQ(kvs_cp.cp_fanout, 8);

    kvs_cp = hse_params_to_kvs_cparams(params, "kvs_other", NULL);
    ASSERT_EQ(kvs_cp.cp_fanout, 32);

    hse_params_destroy(params);
}

MTF_END_UTEST_COLLECTION(hse_params)
