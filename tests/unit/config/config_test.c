/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <bsd/string.h>

#include <hse/limits.h>

#include <hse/config/config.h>
#include <hse/ikvdb/kvdb_home.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/kvs_rparams.h>

#include <hse/test/mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(config_test)

MTF_DEFINE_UTEST(config_test, t_open)
{
    cJSON *conf;
    merr_t err;

    err = config_open("C:\\does\\not\\exist.conf", NULL, &conf);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = config_open(NULL, NULL, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = config_open("not null", NULL, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(config_test)
