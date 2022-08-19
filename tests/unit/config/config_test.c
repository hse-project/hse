/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <bsd/string.h>

#include <hse/limits.h>
#include <mtf/framework.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>

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

MTF_BEGIN_UTEST_COLLECTION_PRE(config_test, collection_pre)

MTF_DEFINE_UTEST(config_test, deserialize_hierarchical_param)
{
    char                home[PATH_MAX];
    struct hse_gparams  params = hse_gparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-hierarchical-params/hse.conf", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_hse_gparams(conf, &params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(false, params.gp_logging.lp_enabled);
}

MTF_DEFINE_UTEST(config_test, deserialize_incorrect_type)
{
    char                home[PATH_MAX];
    struct config *     conf = NULL;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-incorrect-type", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_params_no_kvs)
{
    char               home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-params-no-kvs", config_root);

    err = config_from_kvdb_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "kvs", &params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_root_incorrect_type)
{
    char           home[PATH_MAX];
    struct config *conf;
    merr_t         err;

    snprintf(home, sizeof(home), "%s/deserialize-root-incorrect-type", config_root);

    err = config_from_kvdb_conf(home, &conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_default_override)
{
    char               home[PATH_MAX];
    struct kvs_rparams kvs_params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-override", config_root);

    err = config_from_kvdb_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "named", &kvs_params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(88, kvs_params.cn_maint_delay);
}

MTF_DEFINE_UTEST(config_test, deserialize_invalid_key)
{
    char                home[PATH_MAX];
    struct config *     conf = NULL;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-invalid-key", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);

}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_incorrect_type)
{
    char               home[PATH_MAX];
    struct config *    conf = NULL;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-incorrect-type", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_default_incorrect_type)
{
    char               home[PATH_MAX];
    struct config *    conf = NULL;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-incorrect-type", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_named_incorrect_type)
{
    char               home[PATH_MAX];
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-named-incorrect-type", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_keys_with_dots)
{
    char               home[PATH_MAX];
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-keys-with-dots", config_root);

    err = config_from_kvdb_conf(home, &conf);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, from_hse_conf)
{
    struct config *conf;
    merr_t         err;

    err = config_from_hse_conf("C:\\does\\not\\exist.conf", &conf);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = config_from_hse_conf(NULL, &conf);
    ASSERT_EQ(0, merr_errno(err));

    err = config_from_hse_conf("not null", NULL);
    ASSERT_NE(0, merr_errno(err));
}

MTF_DEFINE_UTEST(config_test, from_kvdb_conf)
{
    struct config *conf;
    merr_t         err;

    err = config_from_kvdb_conf("C:\\does\\not\\exist", &conf);
    ASSERT_EQ(0, merr_errno(err));

    err = config_from_kvdb_conf(NULL, &conf);
    ASSERT_NE(0, merr_errno(err));

    err = config_from_kvdb_conf("not null", NULL);
    ASSERT_NE(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(config_test)
