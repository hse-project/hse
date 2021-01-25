/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/hse_err.h>
#include <hse_util/data_tree.h>
#include <hse_util/config.h>
#include <hse_util/string.h>

#include "../kvdb_params.h" /* kvdb internal params file */

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_rparams.h>

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

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvdb_rparams, config_test_pre, config_test_post);

MTF_DEFINE_UTEST(kvdb_rparams, kvdb_rparams_parse_test)
{
    merr_t              err;
    char *              argv[] = { "read_only=1" };
    int                 argc = sizeof(argv) / sizeof(*argv);
    struct kvdb_rparams p = kvdb_rparams_defaults();
    struct kvdb_rparams reference_rp = kvdb_rparams_defaults();
    int                 next = 0;

    /* Correct defaults */
    ASSERT_EQ(p.read_only, 0);

    /* Normal working */
    err = kvdb_rparams_parse(argc, argv, &p, &next);

    ASSERT_EQ(merr_errno(err), 0);
    ASSERT_NE(memcmp(&p, &reference_rp, sizeof(p)), 0);
    ASSERT_EQ(p.read_only, 1);
    ASSERT_EQ(next, 1);

    /* NULL args */
    next = 0;
    err = kvdb_rparams_parse(argc, argv, NULL, &next);
    ASSERT_EQ(merr_errno(err), EINVAL);
    ASSERT_EQ(next, 0);

    next = 0;
    err = kvdb_rparams_parse(argc, NULL, &p, &next);
    ASSERT_EQ(merr_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(kvdb_rparams, kvdb_rparams_validate_test)
{
    struct kvdb_rparams p = kvdb_rparams_defaults();
    char                buf[128], *str;
    merr_t              err;
    u32                 n;

    /* Normal Working */
    err = kvdb_rparams_validate(&p);
    ASSERT_EQ(merr_errno(err), 0);

    /* NULL arg */
    err = kvdb_rparams_validate(NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);

    n = kvdb_get_num_rparams();
    ASSERT_GT(n, 0);

    p.rpmagic = 0xDEADBEEF;
    err = kvdb_rparams_validate(&p);
    ASSERT_EQ(merr_errno(err), EINVAL);

    str = kvdb_rparams_help(buf, sizeof(buf), &p);
    ASSERT_EQ(buf, str);

    str = kvdb_rparams_help(buf, sizeof(buf), NULL);
    ASSERT_EQ(buf, str);

    str = kvdb_rparams_help(buf, 0, NULL);
    ASSERT_EQ(NULL, str);

    str = kvdb_rparams_help(NULL, sizeof(buf), NULL);
    ASSERT_EQ(NULL, str);
}

static u64
get_cfg_data(char *param_name, char *mp_name)
{
    char               path[DT_PATH_LEN];
    struct dt_element *dte;
    struct hse_config *rp;

    snprintf(path, sizeof(path), "/data/config/%s/%s/%s", COMPNAME, mp_name, param_name);

    dte = dt_find(dt_data_tree, path, 1);
    if (!dte)
        abort();

    rp = dte->dte_data;

    /* [HSE_REVISIT] Don't we have a "config get" function?
     */
    switch (rp->data_sz) {
    case 1:
        return *(u8 *)rp->data;

    case 2:
        return *(u16 *)rp->data;

    case 4:
        return *(u32 *)rp->data;

    case 8:
        return *(u64 *)rp->data;
    }

    abort();
}

static int
is_writable(char *param_name, char *mp_name)
{
    char               path[DT_PATH_LEN];
    struct dt_element *dte;
    struct hse_config *rp;

    snprintf(path, sizeof(path), "/data/config/%s/%s/%s", COMPNAME, mp_name, param_name);

    dte = dt_find(dt_data_tree, path, 1);
    rp = dte->dte_data;

    /* Check writability */
    return rp->writable;
}

MTF_DEFINE_UTEST(kvdb_rparams, kvdb_rparams_add_to_dt_test)
{
    struct kvdb_rparams p = kvdb_rparams_defaults();
    merr_t              err;

    /* NULL args */
    err = kvdb_rparams_add_to_dt(NULL, &p);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = kvdb_rparams_add_to_dt("mp1", NULL);
    ASSERT_EQ(merr_errno(err), EINVAL);

    /* Normal operation */
    char *mp_name = "an_mpool_name";

    err = kvdb_rparams_add_to_dt(mp_name, &p);
    ASSERT_EQ(merr_errno(err), 0);
    kvdb_rparams_remove_from_dt(mp_name);

    /* c0_debug is a uint8_t
     */
    p.c0_debug = 0xab;
    err = kvdb_rparams_add_to_dt(mp_name, &p);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0xab, get_cfg_data("c0_debug", mp_name));

    /* c0_ingest_width is a uint32_t
     */
    p.c0_ingest_width = 0x12345678;
    err = kvdb_rparams_add_to_dt(mp_name, &p);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0x12345678, get_cfg_data("c0_ingest_width", mp_name));

    /* c0_heap_sz is a uint64_t
     */
    p.c0_heap_sz = 0x9988776655443322ul;
    err = kvdb_rparams_add_to_dt(mp_name, &p);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0x9988776655443322ul, get_cfg_data("c0_heap_sz", mp_name));

    /* Check some params at random */
    ASSERT_EQ(0, is_writable("read_only", mp_name));
    ASSERT_EQ(0, is_writable("c0_ingest_width", mp_name));
    ASSERT_NE(0, is_writable("c0_debug", mp_name));
    kvdb_rparams_remove_from_dt(mp_name);
}

MTF_DEFINE_UTEST(kvdb_rparams, kvdb_rparams_diff_test)
{
    struct kvdb_rparams rp = kvdb_rparams_defaults();
    int                 count = 0;

    rp.csched_samp_max = 200;
    rp.c0_ingest_width = 5;
    rp.low_mem = 1;

    kvdb_rparams_diff(&rp, &count, callback);
    ASSERT_EQ(count, 3);
}

MTF_END_UTEST_COLLECTION(kvdb_rparams);
