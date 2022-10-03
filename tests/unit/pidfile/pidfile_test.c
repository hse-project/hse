/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>

#include <bsd/libutil.h>

#include <mtf/framework.h>

#include <hse/error/merr.h>
#include <hse/pidfile/pidfile.h>

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
    merr_t err;

    err = pidfile_serialize(NULL, (struct pidfile *)-1);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, serialize_null_content)
{
    merr_t err;

    err = pidfile_serialize((struct pidfh *)-1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_null_home)
{
    merr_t err;

    err = pidfile_deserialize(NULL, (struct pidfile *)-1);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_null_content)
{
    merr_t err;

    err = pidfile_deserialize("", NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_empty)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-empty", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EIO, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_not_json)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-not-json", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EPROTO, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_alias)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-alias", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_pid)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-pid", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_rest)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-rest", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_missing_rest_socket_path)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-missing-rest-socket-path", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_root_wrong_type)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-root-wrong-type", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_alias_wrong_type)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-alias-wrong-type", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_pid_wrong_type)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-pid-wrong-type", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_rest_wrong_type)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-rest-wrong-type", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_rest_socket_path_wrong_type)
{
    merr_t err;
    char home[PATH_MAX];
    struct pidfile content;

    snprintf(home, sizeof(home), "%s/deserialize-rest-socket-path-wrong-type", config_root);

    err = pidfile_deserialize(home, &content);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(pidfile_test, deserialize_home_dne)
{
    merr_t err;
    struct pidfile content;

    err = pidfile_deserialize("/this-does-not-exist", &content);
    ASSERT_EQ(ENOENT, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(pidfile_test)
