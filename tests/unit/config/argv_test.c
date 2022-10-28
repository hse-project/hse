/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/ikvdb/param.h>
#include <hse/ikvdb/argv.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(argv_test)

MTF_DEFINE_UTEST(argv_test, deserialize_to_params_malformed_kv_pair)
{
    merr_t             err;
    const char * const paramv[] = { "prefix.length", "prefix.length=" };
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
    const char * const paramv[] = { "prefix.length=-1" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(1, paramv, &params);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(argv_test, deserialize_to_params)
{
    merr_t             err;
    const char * const paramv[] = { "prefix.length=7" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);
    ASSERT_EQ(7, params.pfx_len);
}

MTF_DEFINE_UTEST(argv_test, deserialize_overwrite)
{
    merr_t             err;
    const char * const paramv[] = { "prefix.length=8", "prefix.length=7" };
    struct kvs_cparams params;

    err = argv_deserialize_to_kvs_cparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);
    ASSERT_EQ(7, params.pfx_len);
}

MTF_END_UTEST_COLLECTION(argv_test)
