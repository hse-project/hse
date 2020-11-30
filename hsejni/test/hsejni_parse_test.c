/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016-2019 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/hse_err.h>
#include <hse_util/platform.h>
#include <hse_util/string.h>

#include <hse/hse_params.h>

#include <hsejni_internal.h>

struct hse_params *params;

MTF_BEGIN_UTEST_COLLECTION(nfjni_parse_test)

MTF_DEFINE_UTEST(nfjni_parse_test, normal_parse)
{
    struct hse_params *params;
    char               raw_arg_list1[] = "rdonly=1,cn_diag_mode=1";
    char               raw_arg_list2[] = "dur_enable=0,dur_vbldr=0";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list1);

    result = hse_params_get(params, "kvs.rdonly");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    jni_hse_params_parse(params, raw_arg_list2);

    result = hse_params_get(params, "kvdb.dur_enable");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "0"), 0);

    result = hse_params_get(params, "kvdb.dur_vbldr");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "0"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, leading_comma)
{
    struct hse_params *params;
    char               raw_arg_list[] = ",cn_verify=1,cn_diag_mode=1";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, trailing_comma)
{
    struct hse_params *params;
    char               raw_arg_list[] = "cn_verify=1,cn_diag_mode=1,";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, blank_list)
{
    int                rc;
    struct hse_params *params;
    char               raw_arg_list[] = "";

    hse_params_create(&params);

    rc = jni_hse_params_parse(params, raw_arg_list);
    ASSERT_EQ(rc, 0);

    rc = jni_hse_params_parse(params, raw_arg_list);
    ASSERT_EQ(rc, 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, no_commas)
{
    struct hse_params *params;
    char               raw_arg_list1[] = "cn_verify=1";
    char               raw_arg_list2[] = "dur_enable=0";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list1);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    jni_hse_params_parse(params, raw_arg_list2);

    result = hse_params_get(params, "kvdb.dur_enable");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "0"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, too_many_commas)
{
    struct hse_params *params;
    char               raw_arg_list[] = ",,cn_verify=1,cn_diag_mode=1,,,,rdonly=1";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.rdonly");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, junk_args)
{
    struct hse_params *params;
    char               raw_arg_list[] = ",,cn_verify=1,junk=garbage,,,,rdonly=0";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.junk");
    ASSERT_EQ(result, NULL);

    result = hse_params_get(params, "kvs.rdonly");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "0"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, invalid_arg)
{
    struct hse_params *params;
    char               raw_arg_list[] = ",,cn_verify=1,cn_diag_mode,,,,rdonly=8979";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_EQ(result, NULL);

    result = hse_params_get(params, "kvs.rdonly");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "8979"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, spaces_in_args)
{
    struct hse_params *params;
    char               raw_arg_list[] = ",,cn_verify=1, cn_diag_mode=1,, ,,rdonly=1";
    char *             result;

    hse_params_create(&params);

    jni_hse_params_parse(params, raw_arg_list);

    result = hse_params_get(params, "kvs.cn_verify");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_EQ(result, NULL);

    result = hse_params_get(params, "kvs.rdonly");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, extraneous_parameters)
{
    int                i = 0;
    size_t             rc;
    struct hse_params *params;
    const int          MAX_ARGS = 32;
    char               arglist[(MAX_ARGS + 1) * DT_PATH_ELEMENT_LEN];
    char *             result;

    hse_params_create(&params);

    memset(arglist, 0, sizeof(arglist));

    for (i = 0; i < MAX_ARGS - 1; i++) {
        rc = strlcat(arglist, ",cn_diag_mode=1", sizeof(arglist));
        ASSERT_LT(rc, sizeof(arglist));
    }

    rc = strlcat(arglist, ",cn_diag_mode=4", sizeof(arglist)); /* MAX_ARGS */
    ASSERT_LT(rc, sizeof(arglist));
    rc = strlcat(arglist, ",cn_diag_mode=8\0", sizeof(arglist)); /* MAX_ARGS + 1 */
    ASSERT_LT(rc, sizeof(arglist));

    jni_hse_params_parse(params, arglist);

    result = hse_params_get(params, "kvs.cn_diag_mode");
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "4"), 0);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(nfjni_parse_test, split_str_test)
{
    int rc;

    char  str[50];
    char *s1, *s2;

    strlcpy(str, "jsutonestring", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(-1, rc);

    strlcpy(str, "just/one", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("just", s1);
    ASSERT_STREQ("one", s2);

    strlcpy(str, "many/////slashes", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("many////", s1);
    ASSERT_STREQ("slashes", s2);

    strlcpy(str, "/////many", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("////", s1);
    ASSERT_STREQ("many", s2);

    strlcpy(str, "/onlyone", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("", s1);
    ASSERT_STREQ("onlyone", s2);

    strlcpy(str, "oneatend/", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("oneatend", s1);
    ASSERT_STREQ("", s2);

    strlcpy(str, "manyatend//////", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("manyatend/////", s1);
    ASSERT_STREQ("", s2);

    strlcpy(str, "aa/bb/", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("aa/bb", s1);
    ASSERT_STREQ("", s2);

    strlcpy(str, "//aa/bb/", sizeof(str));
    rc = split_str(&s1, &s2, str);
    ASSERT_EQ(0, rc);
    ASSERT_STREQ("//aa/bb", s1);
    ASSERT_STREQ("", s2);
}

MTF_END_UTEST_COLLECTION(nfjni_parse_test)
