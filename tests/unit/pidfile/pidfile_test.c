/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>

#include <bsd/libutil.h>

#include <mtf/framework.h>

#include <pidfile/pidfile.h>

const char *config_root;

static int
collection_pre(struct mtf_test_info *ti)
{
    if (ti->ti_coll->tci_argc - ti->ti_coll->tci_optind != 1) {
        fprintf(stderr, "Usage: %s [test framework options] <configs-dir>\n", ti->ti_coll->tci_argv[0]);
        return -1;
    }

    config_root = ti->ti_coll->tci_argv[ti->ti_coll->tci_optind];
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(pidfile_test, collection_pre)

MTF_DEFINE_UTEST(pidfile_test, serialize_null_pfh)
{
    int rc;

    rc = pidfile_serialize(NULL, (struct pidfile *)-1);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, serialize_null_content)
{
    int rc;

    rc = pidfile_serialize((struct pidfh *)-1, NULL);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_null_home)
{
    int rc;

    rc = pidfile_deserialize(NULL, (struct pidfile *)-1);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_null_content)
{
    int rc;

    rc = pidfile_deserialize("", NULL);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_empty)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-empty", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EIO, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_not_json)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-not-json", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EPROTO, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_alias)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-alias", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_pid)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-pid", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_socket)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-socket", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_socket_path)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-socket-path", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_root_wrong_type)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-root-wrong-type", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_alias_wrong_type)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-alias-wrong-type", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_pid_wrong_type)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-pid-wrong-type", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_socket_wrong_type)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-socket-wrong-type", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_socket_path_wrong_type)
{
    int rc;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-socket-path-wrong-type", config_root);

    rc = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_home_dne)
{
    int rc;
    struct pidfile content;

    rc = pidfile_deserialize("/this-does-not-exist", &content);
    ASSERT_EQ(ENOENT, rc);
}

MTF_END_UTEST_COLLECTION(pidfile_test)
