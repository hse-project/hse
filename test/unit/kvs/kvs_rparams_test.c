/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/slab.h>
#include <hse_util/hse_err.h>
#include <hse_util/data_tree.h>
#include <hse_util/config.h>

#include <kvs/kvs_params.h> /* kvs internal params file */

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvs_rparams.h>

int
config_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
config_test_post(struct mtf_test_info *ti)
{
    return 0;
}

void
callback(const char *key, const char *value, void *count)
{
    *((int *)count) = *((int *)count) + 1;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvs_rparams, config_test_pre, config_test_post);

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_parse_test)
{
    merr_t             err;
    char *             argv[] = { "cn_maint_disable=1", "rdonly=1" };
    int                argc = sizeof(argv) / sizeof(*argv);
    struct kvs_rparams p = kvs_rparams_defaults();
    struct kvs_rparams reference_rp = kvs_rparams_defaults();
    int                next = 0;

    /* Normal working */
    err = kvs_rparams_parse(argc, argv, &p, &next);

    ASSERT_EQ(err, 0);
    ASSERT_NE(memcmp(&p, &reference_rp, sizeof(p)), 0);
    ASSERT_EQ(p.cn_maint_disable, 1);
    ASSERT_EQ(p.rdonly, 1);
    ASSERT_EQ(next, 2);

    /* NULL args */
    next = 0;
    err = kvs_rparams_parse(argc, argv, NULL, &next);
    ASSERT_EQ(merr_errno(err), EINVAL);
    ASSERT_EQ(next, 0);

    next = 0;
    err = kvs_rparams_parse(argc, NULL, &p, &next);
    ASSERT_EQ(merr_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_validate_basic)
{
    struct kvs_rparams p = kvs_rparams_defaults();
    merr_t             err;

    /* Normal Working */
    p = kvs_rparams_defaults();
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(err, 0);

    p = kvs_rparams_defaults();
    p.kblock_size_mb = 0;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));

    p.kblock_size_mb = 33;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));
    p.kblock_size_mb = 32;

    p.vblock_size_mb = 0;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));

    p.vblock_size_mb = 40;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));
    p.vblock_size_mb = 32;

    p.c1_vblock_cap = 1025;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));
    p.c1_vblock_cap = 256;

    p.c1_vblock_size_mb = 33;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));
    p.c1_vblock_size_mb = 32;

    p.c1_vblock_size_mb = 0;
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(EINVAL, merr_errno(err));
    p.c1_vblock_size_mb = 32;

    /* NULL arg */
    err = kvs_rparams_validate(NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);

    /* Invalid magic (the intent of which is to catch improperly
     * initialized param structures.
     */
    memset(&p, 0, sizeof(p));
    err = kvs_rparams_validate(&p);
    ASSERT_EQ(merr_errno(err), EBADR);
}

#define EXP_SUCCESS(INIT_CODE)          \
    do {                                \
        struct kvs_rparams p;           \
        merr_t             err;         \
                                        \
        p = kvs_rparams_defaults();     \
        INIT_CODE;                      \
        err = kvs_rparams_validate(&p); \
        ASSERT_EQ(0, err);              \
    } while (0)

#define EXP_INVALID(INIT_CODE)              \
    do {                                    \
        struct kvs_rparams p;               \
        merr_t             err;             \
                                            \
        p = kvs_rparams_defaults();         \
        INIT_CODE;                          \
        err = kvs_rparams_validate(&p);     \
        ASSERT_EQ(merr_errno(err), EINVAL); \
    } while (0)

#define TEST_MIN(param, min_value)          \
    do {                                    \
        EXP_SUCCESS(param = (min_value));   \
        EXP_INVALID(param = (min_value)-1); \
    } while (0)

#define TEST_MAX(param, max_value)            \
    do {                                      \
        EXP_SUCCESS(param = (max_value));     \
        EXP_INVALID(param = (max_value) + 1); \
    } while (0)

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_validate_test)
{
    EXP_SUCCESS(p.cn_node_size_lo = p.cn_node_size_lo);
    EXP_INVALID(p.cn_node_size_hi = p.cn_node_size_lo - 1);

    EXP_SUCCESS(p.cn_close_wait = 0);
    EXP_SUCCESS(p.cn_close_wait = 1);

    TEST_MIN(p.cn_maint_delay, 20);
}

static u64
get_cfg_data(char *param_name, char *mp_name, char *kvs_name)
{
    char               path[DT_PATH_LEN];
    struct dt_element *dte;
    struct hse_config *rp;

    snprintf(
        path, sizeof(path), "/data/config/%s/%s/%s/%s", COMPNAME, mp_name, kvs_name, param_name);

    dte = dt_find(dt_data_tree, path, 1);
    rp = dte->dte_data;

    return *(u64 *)rp->data;
}

static int
is_writable(char *param_name, char *mp_name, char *kvs_name)
{
    char               path[DT_PATH_LEN];
    struct dt_element *dte;
    struct hse_config *rp;

    snprintf(
        path, sizeof(path), "/data/config/%s/%s/%s/%s", COMPNAME, mp_name, kvs_name, param_name);

    dte = dt_find(dt_data_tree, path, 1);
    rp = dte->dte_data;

    /* Check writability */
    if (!strcmp(rp->instance, "ingest_debug") || !strcmp(rp->instance, "cn_compaction_debug"))
        if (rp->writable)
            return 0;
        else
            return -1;
    else if (!rp->writable)
        return 0;
    else
        return -1;
}

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_add_to_dt_test)
{
    struct kvs_rparams p = kvs_rparams_defaults();
    size_t             bigsz;
    merr_t             err;
    char *             big;

    /* NULL args */
    err = kvs_rparams_add_to_dt(NULL, "kvs1", &p);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = kvs_rparams_add_to_dt("mp1", NULL, &p);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = kvs_rparams_add_to_dt("mp1", "kvs1", NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);

    char *mp = "an_mpool_name";
    char *kvs = "a_kvs_name";

    p.cn_diag_mode = 1;
    err = kvs_rparams_add_to_dt(mp, kvs, &p);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(1, get_cfg_data("cn_diag_mode", mp, kvs));

    /* Check some params at random */
    ASSERT_EQ(is_writable("cn_bloom_lookup", mp, kvs), 0);
    ASSERT_EQ(is_writable("cn_compaction_debug", mp, kvs), 0);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = kvs_rparams_remove_from_dt(mp, kvs);
    ASSERT_NE(0, err);

    bigsz = DT_PATH_ELEMENT_LEN * 8;
    big = malloc(bigsz);
    ASSERT_NE(NULL, big);

    memset(big, 'x', bigsz);
    big[bigsz - 1] = '\000';
    err = kvs_rparams_remove_from_dt(mp, big);
    ASSERT_NE(0, err);
    free(big);

    err = kvs_rparams_remove_from_dt(mp, kvs);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_diff_test)
{
    struct kvs_rparams rp = kvs_rparams_defaults();
    int                count = 0;

    rp.cn_bloom_create = 0;
    rp.cn_mcache_wbt = 3;
    rp.cn_maint_delay = 300;
    rp.cn_cursor_ttl = 2000;

    kvs_rparams_diff(&rp, &count, *callback);
    ASSERT_EQ(count, 4);
}

MTF_DEFINE_UTEST(kvs_rparams, kvs_rparams_table_test)
{
    struct param_inst *table = NULL;

    kvs_rparams_table_reset();
    table = kvs_rparams_table();

    ASSERT_NE(table, NULL);
}

MTF_END_UTEST_COLLECTION(kvs_rparams);
