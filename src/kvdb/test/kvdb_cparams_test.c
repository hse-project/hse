/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/hse_err.h>
#include <hse_util/data_tree.h>
#include <hse_util/config.h>
#include <hse_util/param.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_cparams.h>

#include "../kvdb_params.h" /* kvdb internal params file */

void
callback(const char *key, const char *value, void *count)
{
    *((int *)count) = *((int *)count) + 1;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_cparams)

MTF_DEFINE_UTEST(kvdb_cparams, print)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();

    kvdb_cparams_print(NULL);
    kvdb_cparams_print(&cp);
}

MTF_DEFINE_UTEST(kvdb_cparams, validate)
{
    merr_t err;
    int    next = 0;

    /* fanout is a power of 2 */
    struct kvdb_cparams kvdb_cp = kvdb_cparams_defaults();
    char *              argv1[] = { "uid=5775" };
    int                 argc1 = sizeof(argv1) / sizeof(*argv1);

    err = kvdb_cparams_parse(argc1, argv1, &kvdb_cp, &next, 0);
    ASSERT_EQ(err, 0);
    err = kvdb_cparams_validate(&kvdb_cp);
    ASSERT_EQ(err, 0);

    /* NULL arg */
    err = kvdb_cparams_validate(NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(kvdb_cparams, help)
{
    struct kvdb_cparams p = kvdb_cparams_defaults();
    char *              buf;
    size_t              bufsz;
    char *              help;

    help = kvdb_cparams_help(0, 0, 0);
    ASSERT_EQ(NULL, help);

    help = kvdb_cparams_help(0, 0, &p);
    ASSERT_EQ(NULL, help);

    bufsz = 8192;
    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);

    memset(buf, 0xff, bufsz);
    help = kvdb_cparams_help(buf, 16, &p);
    ASSERT_EQ(help, buf);
    ASSERT_EQ(buf[15], 0);
    ASSERT_EQ(buf[16], (char)0xff);
    printf("%s\n", help);

    free(buf);
}

MTF_DEFINE_UTEST(kvdb_cparams, diff)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    int                 count = 0;

    cp.dur_capacity = 100;

    kvdb_cparams_diff(&cp, &count, *callback);
    ASSERT_EQ(count, 1);
}

MTF_END_UTEST_COLLECTION(kvdb_cparams);
