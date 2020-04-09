/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/hse_err.h>
#include <hse_util/data_tree.h>
#include <hse_util/config.h>
#include <hse_util/param.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/kvs_cparams.h> /* hse_kvs public header file for cparams */

#include "../kvs_params.h" /* kvs internal params file */

#include <hse_ikvdb/limits.h>

void
callback(const char *key, const char *value, void *count)
{
    *((int *)count) = *((int *)count) + 1;
}

MTF_BEGIN_UTEST_COLLECTION(kvs_cparams)

MTF_DEFINE_UTEST(kvs_cparams, print)
{
    struct kvs_cparams cp = kvs_cparams_defaults();

    kvs_cparams_print(NULL);
    kvs_cparams_print(&cp);
}

MTF_DEFINE_UTEST(kvs_cparams, validate)
{
    merr_t             err;
    int                next = 0;
    struct kvs_cparams kvs_cp;

    /* fanout is a power of 2 */
    char *argv1[] = { "fanout=4" };
    int   argc1 = sizeof(argv1) / sizeof(*argv1);

    kvs_cp = kvs_cparams_defaults();
    err = kvs_cparams_parse(argc1, argv1, &kvs_cp, &next);
    ASSERT_EQ(err, 0);
    err = kvs_cparams_validate(&kvs_cp);
    ASSERT_EQ(err, 0);

    /* fanout is NOT a power of 2 */
    char *argv2[] = { "fanout=5" };
    int   argc2 = sizeof(argv2) / sizeof(*argv2);

    next = 0;
    kvs_cp = kvs_cparams_defaults();
    err = kvs_cparams_parse(argc2, argv2, &kvs_cp, &next);
    ASSERT_EQ(err, 0);
    err = kvs_cparams_validate(&kvs_cp);
    ASSERT_EQ(merr_errno(err), EINVAL);

    char argbuf[20];

    /* prefix length is set to a valid value */
    snprintf(argbuf, sizeof(argbuf), "pfx_len=%u", HSE_KVS_MAX_PFXLEN);
    char *argv3[] = { argbuf };
    int   argc3 = sizeof(argv3) / sizeof(*argv3);

    next = 0;
    kvs_cp = kvs_cparams_defaults();
    err = kvs_cparams_parse(argc3, argv3, &kvs_cp, &next);
    ASSERT_EQ(err, 0);
    err = kvs_cparams_validate(&kvs_cp);
    ASSERT_EQ(err, 0);

    /* prefix length is larger than max prefix length */
    snprintf(argbuf, sizeof(argbuf), "pfx_len=%u", HSE_KVS_MAX_PFXLEN + 1);
    char *argv4[] = { argbuf };
    int   argc4 = sizeof(argv4) / sizeof(*argv4);

    next = 0;
    kvs_cp = kvs_cparams_defaults();
    err = kvs_cparams_parse(argc4, argv4, &kvs_cp, &next);
    ASSERT_EQ(err, 0);
    err = kvs_cparams_validate(&kvs_cp);
    ASSERT_EQ(merr_errno(err), EINVAL);

    /* NULL arg */
    err = kvs_cparams_validate(NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(kvs_cparams, help)
{
    struct kvs_cparams p = kvs_cparams_defaults();
    char *             buf;
    size_t             bufsz;
    char *             help;

    help = kvs_cparams_help(0, 0, 0);
    ASSERT_EQ(NULL, help);

    help = kvs_cparams_help(0, 0, &p);
    ASSERT_EQ(NULL, help);

    bufsz = 8192;
    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);

    memset(buf, 0xff, bufsz);
    help = kvs_cparams_help(buf, 16, &p);
    ASSERT_EQ(help, buf);
    ASSERT_EQ(buf[15], 0);
    ASSERT_EQ(buf[16], (char)0xff);
    printf("%s\n", help);

    free(buf);
}

MTF_DEFINE_UTEST(kvs_cparams, diff)
{
    struct kvs_cparams cp = kvs_cparams_defaults();
    int                count = 0;

    cp.cp_fanout = 32;
    cp.cp_pfx_len = 10;

    kvs_cparams_diff(&cp, &count, *callback);
    ASSERT_EQ(count, 2);
}

MTF_END_UTEST_COLLECTION(kvs_cparams);
