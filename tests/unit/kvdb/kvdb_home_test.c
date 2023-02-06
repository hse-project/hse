/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/kvdb_home.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <hse/test/mtf/framework.h>
#include <hse/pidfile/pidfile.h>

static const char *capdir = "capacity";
static char cappath[PATH_MAX + 16];

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

int
test_pre(struct mtf_test_info *info)
{
    snprintf(cappath, sizeof(cappath), "%s/%s", mtf_kvdb_home, capdir);

    return mkdir(cappath, S_IRWXU | S_IRWXG);
}

int
test_post(struct mtf_test_info *info)
{
    return remove(cappath);
}

MTF_BEGIN_UTEST_COLLECTION_PRE(kvdb_home_test, collection_pre)

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

    err = kvdb_home_storage_realpath_get(mtf_kvdb_home, capdir, buf, false);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(cappath, buf);

    err = kvdb_home_storage_realpath_get(mtf_kvdb_home, cappath, buf, true);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(cappath, buf);
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_hierarchical_param)
{
    char home[PATH_MAX];
    struct kvdb_rparams params = kvdb_rparams_defaults();
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-hierarchical-params", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_NE(NULL, conf);

    err = kvdb_rparams_from_config(&params, conf);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_FALSE(params.dio_enable[HSE_MCLASS_CAPACITY]);

    cJSON_Delete(conf);
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_incorrect_type)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-incorrect-type", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_kvs_params_no_kvs)
{
    char home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-params-no-kvs", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_NE(NULL, conf);

    err = kvs_rparams_from_config(&params, conf, "kvs");
    ASSERT_EQ(0, merr_errno(err));

    cJSON_Delete(conf);
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_root_incorrect_type)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-root-incorrect-type", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_kvs_default_override)
{
    merr_t err;
    cJSON *conf;
    char home[PATH_MAX];
    struct kvs_rparams kvs_params = kvs_rparams_defaults();

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-override", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_NE(NULL, conf);

    err = kvs_rparams_from_config(&kvs_params, conf, "named");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(88, kvs_params.cn_maint_delay);

    cJSON_Delete(conf);
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_invalid_key)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-invalid-key", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_kvs_incorrect_type)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-incorrect-type", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_kvs_default_incorrect_type)
{
    char home[PATH_MAX];
    cJSON *conf = NULL;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-incorrect-type", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_kvs_named_incorrect_type)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-named-incorrect-type", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, deserialize_keys_with_dots)
{
    char home[PATH_MAX];
    cJSON *conf;
    merr_t err;

    snprintf(home, sizeof(home), "%s/deserialize-keys-with-dots", config_root);

    err = kvdb_home_get_config(home, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvdb_home_test, get_config)
{
    cJSON *conf;
    merr_t err;

    err = kvdb_home_get_config("C:\\does\\not\\exist", &conf);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = kvdb_home_get_config(NULL, &conf);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvdb_home_get_config("not null", NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(kvdb_home_test)
