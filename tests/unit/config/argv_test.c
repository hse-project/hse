/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/param.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ut/framework.h>

MTF_BEGIN_UTEST_COLLECTION(argv_test)

MTF_DEFINE_UTEST(argv_test, deserialize_to_params_malformed_kv_pair)
{
    merr_t             err;
    const char * const paramv[] = { "fanout", "fanout=" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(1, paramv, &params);
    ASSERT_NE(0, err);

    err = argv_deserialize_to_kvs_cparams(1, paramv + 1, &params);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(argv_test, deserialize_to_params_invalid_param)
{
    merr_t             err;
    const char * const paramv[] = { "invalid=0" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(1, paramv, &params);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(argv_test, deserialize_to_params_invalid_value)
{
    merr_t             err;
    const char * const paramv[] = { "fanout=0" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(1, paramv, &params);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(argv_test, deserialize_to_params_invalid_relation_validation)
{
    merr_t             err;
    const char * const paramv[] = { "cn_node_size_lo=51", "cn_node_size_hi=49" };
    struct kvs_rparams params;

    err = argv_deserialize_to_kvs_rparams(2, paramv, &params);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(argv_test, deserialize_to_params)
{
    merr_t             err;
    const char * const paramv[] = { "fanout=8", "pfx_len=7" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(2, paramv, &params);
    ASSERT_EQ(0, err);
    ASSERT_EQ(8, params.fanout);
    ASSERT_EQ(7, params.pfx_len);
}

MTF_DEFINE_UTEST(argv_test, deserialize_overwrite)
{
    merr_t             err;
    const char * const paramv[] = { "pfx_len=8", "pfx_len=7" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(2, paramv, &params);
    ASSERT_EQ(0, err);
    ASSERT_EQ(7, params.pfx_len);
}

MTF_END_UTEST_COLLECTION(argv_test)
