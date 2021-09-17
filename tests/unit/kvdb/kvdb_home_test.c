/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <string.h>

#include <hse_util/hse_err.h>
#include <hse_ikvdb/kvdb_home.h>
#include <hse_ut/framework.h>
#include <pidfile/pidfile.h>

static const char *capdir = "capacity";
static char cappath[PATH_MAX + 16];

int
test_pre(struct mtf_test_info *info)
{
    snprintf(cappath, sizeof(cappath), "%s/%s", home, capdir);

    return mkdir(cappath, S_IRWXU | S_IRWXG);
}

int
test_post(struct mtf_test_info *info)
{
    return remove(cappath);
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_home_test)

MTF_DEFINE_UTEST(kvdb_home_test, storage_path)
{
	merr_t err;
	char   buf[PATH_MAX];

	err = kvdb_home_storage_path_get("/var/lib/hse", capdir, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, "/var/lib/hse/capacity", sizeof(buf)));

	err = kvdb_home_storage_path_get("/var/lib/hse", "/var/local/lib/hse/capacity", buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, "/var/local/lib/hse/capacity", sizeof(buf)));
}

MTF_DEFINE_UTEST_PREPOST(kvdb_home_test, storage_realpath, test_pre, test_post)
{
    merr_t err;
    char   buf[PATH_MAX];

    err = kvdb_home_storage_realpath_get(home, capdir, buf, false);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(cappath, buf);

    err = kvdb_home_storage_realpath_get(home, cappath, buf, true);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(cappath, buf);
}

MTF_DEFINE_UTEST(kvdb_home_test, pidfile_path)
{
	merr_t err;
	char   buf[PATH_MAX];

	err = kvdb_home_pidfile_path_get("/var/run/hse", buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, "/var/run/hse/" PIDFILE_NAME, sizeof(buf)));
}

MTF_END_UTEST_COLLECTION(kvdb_home_test)
