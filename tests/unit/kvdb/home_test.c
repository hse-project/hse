/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <hse_util/hse_err.h>
#include <hse_ikvdb/home.h>
#include <hse_ut/framework.h>
#include <pidfile/pidfile.h>

MTF_BEGIN_UTEST_COLLECTION(home_test)

MTF_DEFINE_UTEST(home_test, translation_null)
{
	merr_t err;
	char cwd[PATH_MAX];
	char buf[PATH_MAX];

	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));

	err = kvdb_home_translate(NULL, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(cwd, buf, sizeof(cwd)));
}

MTF_DEFINE_UTEST(home_test, translation_dne)
{
	merr_t err;
	char buf[PATH_MAX];

	err = kvdb_home_translate("/this/does/not/exist", buf, sizeof(buf));
	ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(home_test, storage_capacity_path)
{
	size_t n;
	char buf[PATH_MAX];

	n = kvdb_home_storage_capacity_path_get("/var/lib/hse", "capacity", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/lib/hse/capacity", sizeof(buf)));

	n = kvdb_home_storage_capacity_path_get("/var/lib/hse", "/var/local/lib/hse/capacity", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/local/lib/hse/capacity", sizeof(buf)));
}

MTF_DEFINE_UTEST(home_test, storage_staging_path)
{
	size_t n;
	char buf[PATH_MAX];

	n = kvdb_home_storage_staging_path_get("/var/lib/hse", "staging", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/lib/hse/staging", sizeof(buf)));

	n = kvdb_home_storage_staging_path_get("/var/lib/hse", "/var/local/lib/hse/staging", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/local/lib/hse/staging", sizeof(buf)));
}

MTF_DEFINE_UTEST(home_test, socket_path)
{
	size_t n;
	char buf[PATH_MAX];

	n = kvdb_home_storage_capacity_path_get("/var/run/hse", "hse.sock", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/run/hse/hse.sock", sizeof(buf)));

	n = kvdb_home_storage_capacity_path_get("/var/run/hse", "/var/local/run/hse/hse.sock", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/local/run/hse/hse.sock", sizeof(buf)));
}

MTF_DEFINE_UTEST(home_test, pidfile_path)
{
	size_t n;
	char buf[PATH_MAX];

	n = kvdb_home_pidfile_path_get("/var/run/hse", buf, sizeof(buf));
	ASSERT_LT(n, sizeof(buf));
	ASSERT_EQ(0, strncmp(buf, "/var/run/hse/" PIDFILE_NAME, sizeof(buf)));
}

MTF_END_UTEST_COLLECTION(home_test)
