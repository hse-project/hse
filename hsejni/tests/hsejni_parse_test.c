/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016-2019,2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/base.h>

#include <hsejni_internal.h>

MTF_BEGIN_UTEST_COLLECTION(hsejni_parse_test)

MTF_DEFINE_UTEST(hsejni_parse_test, kvdb_open_normal_parse)
{
    char        raw_arg_list[] = "kvdb.open.csched_vb_scatter_pct=1,kvdb.open.read_only=false";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvdb.open.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("csched_vb_scatter_pct=1", paramv[0]));
    ASSERT_EQ(0, strcmp("read_only=false", paramv[1]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, kvs_open_normal_parse)
{
    char        raw_arg_list[] = "kvs.open.rdonly=true,kvs.open.cn_diag_mode=true";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvs.open.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("rdonly=true", paramv[0]));
    ASSERT_EQ(0, strcmp("cn_diag_mode=true", paramv[1]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, kvs_create_normal_parse)
{
    char        raw_arg_list[] = "kvs.create.prefix.length=7,kvs.create.prefix.pivot=2";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvs.create.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("prefix.length=7", paramv[0]));
    ASSERT_EQ(0, strcmp("prefix.pivot=2", paramv[1]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, leading_comma)
{
    char        raw_arg_list[] = ",kvs.open.rdonly=true,kvs.open.cn_diag_mode=true";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvs.open.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("rdonly=true", paramv[0]));
    ASSERT_EQ(0, strcmp("cn_diag_mode=true", paramv[1]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, trailing_comma)
{
    char        raw_arg_list[] = "kvs.open.rdonly=true,kvs.open.cn_diag_mode=true,";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvs.open.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("rdonly=true", paramv[0]));
    ASSERT_EQ(0, strcmp("cn_diag_mode=true", paramv[1]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, blank_list)
{
    char        raw_arg_list[] = "";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "none.", NELEM(paramv));
    ASSERT_EQ(paramc, 0);
}

MTF_DEFINE_UTEST(hsejni_parse_test, no_commas)
{
    char        raw_arg_list[] = "kvdb.open.durability.enabled=false";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvdb.open.", NELEM(paramv));

    ASSERT_EQ(1, paramc);
    ASSERT_EQ(0, strcmp("durability.enabled=false", paramv[0]));
}

MTF_DEFINE_UTEST(hsejni_parse_test, too_many_commas)
{
    char        raw_arg_list[] = ",,kvs.open.rdonly=true,,,,,kvs.open.cn_diag_mode=true";
    size_t      paramc = 0;
    const char *paramv[32];

    jni_hse_config_parse(&paramc, paramv, raw_arg_list, "kvs.open.", NELEM(paramv));

    ASSERT_EQ(2, paramc);
    ASSERT_EQ(0, strcmp("rdonly=true", paramv[0]));
    ASSERT_EQ(0, strcmp("cn_diag_mode=true", paramv[1]));
}

MTF_END_UTEST_COLLECTION(hsejni_parse_test)
