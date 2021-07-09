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
#include <hse_ut/framework.h>
#include <hse_ikvdb/config.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>

const char *config_root;

static int
collection_pre(struct mtf_test_info *ti)
{
    if (ti->ti_coll->tci_argc != 2)
        return -1;

    config_root = ti->ti_coll->tci_argv[1];
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(config_test, collection_pre)

MTF_DEFINE_UTEST(config_test, deserialize_hierarchical_param)
{
    char                home[PATH_MAX];
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-hierarchical-params", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp(params.storage.mclass[MP_MED_CAPACITY].path, "/var/lib/capacity"));
    ASSERT_EQ(0, strcmp(params.socket.path, "/var/run/hse.sock"));
}

MTF_DEFINE_UTEST(config_test, deserialize_incorrect_type)
{
    char                home[PATH_MAX];
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-incorrect-type", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvdb_params_no_kvdb)
{
    char                home[PATH_MAX];
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-kvdb-params-no-kvdb", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_params_no_kvs)
{
    char               home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-params-no-kvs", config_root);

    err = config_from_hse_conf(home, &conf);
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

    err = config_from_hse_conf(home, &conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_default_override)
{
    char               home[PATH_MAX];
    struct kvs_rparams kvs_params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-override", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "named", &kvs_params);
    config_destroy(conf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(88, kvs_params.cn_io_threads);
}

MTF_DEFINE_UTEST(config_test, deserialize_invalid_key)
{
    char                home[PATH_MAX];
    struct kvdb_rparams kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-invalid-key", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvdb_rparams(conf, &kvdb_rp);
    ASSERT_NE(0, err);
    err = config_deserialize_to_kvs_rparams(conf, "kvs", &kvs_rp);
    ASSERT_NE(0, err);

    config_destroy(conf);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvdb_incorrect_type)
{
    char                home[PATH_MAX];
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct config *     conf;
    merr_t              err;

    snprintf(home, sizeof(home), "%s/deserialize-kvdb-incorrect-type", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvdb_rparams(conf, &params);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_incorrect_type)
{
    char               home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-incorrect-type", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "kvs", &params);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_default_incorrect_type)
{
    char               home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-default-incorrect-type", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "kvs", &params);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST(config_test, deserialize_kvs_named_incorrect_type)
{
    char               home[PATH_MAX];
    struct kvs_rparams params = kvs_rparams_defaults();
    struct config *    conf;
    merr_t             err;

    snprintf(home, sizeof(home), "%s/deserialize-kvs-named-incorrect-type", config_root);

    err = config_from_hse_conf(home, &conf);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, conf);

    err = config_deserialize_to_kvs_rparams(conf, "named", &params);
    config_destroy(conf);
    ASSERT_NE(0, err);
}

MTF_END_UTEST_COLLECTION(config_test)
