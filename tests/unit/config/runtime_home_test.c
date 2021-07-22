/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <string.h>

#include <bsd/string.h>
#include <bsd/stringlist.h>

#include <hse_util/hse_err.h>
#include <hse_ikvdb/runtime_home.h>
#include <hse_ut/framework.h>
#include <pidfile/pidfile.h>

#define RUNTIME_HOME "/home/hse"

MTF_BEGIN_UTEST_COLLECTION(runtime_home_test)

MTF_DEFINE_UTEST(runtime_home_test, set_null)
{
	merr_t err;
	char   buf[PATH_MAX];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	getcwd(buf, sizeof(buf));
#pragma GCC diagnostic pop

	err = runtime_home_set(NULL);
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, runtime_home_get(), sizeof(buf)));
}

MTF_DEFINE_UTEST(runtime_home_test, logging_path)
{
	merr_t             err;
	char               buf[PATH_MAX] = { 0 };
	char               ex[2 * PATH_MAX] = { 0 };
	struct hse_gparams params;

	params.gp_logging.enabled = false;

	err = runtime_home_logging_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, memcmp(buf, ex, sizeof(buf)));

	params.gp_logging.enabled = true;

	/* Reset the logging path because it already got resolved */
	strlcpy(params.gp_logging.path, "hse.log", sizeof(params.gp_logging.path));

	snprintf(ex, sizeof(ex), RUNTIME_HOME "/%s", params.gp_logging.path);

	err = runtime_home_logging_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, ex, sizeof(buf)));

	strlcpy(params.gp_logging.path, "/var/local/log/hse/hse.log", sizeof(params.gp_logging.path));

	err = runtime_home_logging_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, "/var/local/log/hse/hse.log", sizeof(buf)));
}

MTF_DEFINE_UTEST(runtime_home_test, socket_path)
{
	merr_t             err;
	char               buf[PATH_MAX] = { 0 };
	char               ex[2 * PATH_MAX] = { 0 };
	struct hse_gparams params;

	params.gp_socket.enabled = false;

	err = runtime_home_socket_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, memcmp(buf, ex, sizeof(buf)));

	params.gp_socket.enabled = true;

	/* Reset the logging path because it already got resolved */
	strlcpy(params.gp_socket.path, "hse.sock", sizeof(params.gp_socket.path));

	snprintf(ex, sizeof(ex), RUNTIME_HOME "/%s", params.gp_socket.path);

	err = runtime_home_socket_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, ex, sizeof(buf)));

	strlcpy(params.gp_socket.path, "/var/local/run/hse/hse.sock", sizeof(params.gp_socket.path));

	err = runtime_home_socket_path_get(RUNTIME_HOME, &params, buf, sizeof(buf));
	ASSERT_EQ(0, err);
	ASSERT_EQ(0, strncmp(buf, "/var/local/run/hse/hse.sock", sizeof(buf)));
}

MTF_END_UTEST_COLLECTION(runtime_home_test)
