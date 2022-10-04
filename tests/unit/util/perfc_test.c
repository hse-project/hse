/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <mtf/framework.h>

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse_util/parse_num.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(perfc);

MTF_DEFINE_UTEST(perfc, perfc_basic_create_find_and_remove)
{
    size_t count;
    struct dt_element *dte;
    int rc, n;
    char path[DT_PATH_MAX];
    struct perfc_name ctrnames = { 0 };
    struct perfc_set set = { 0 };
    size_t before;
    merr_t err;
    cJSON *root = cJSON_CreateArray();
    union dt_iterate_parameters dip = { .root = root };

    ASSERT_NE(NULL, root);

    before = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_PERFC, NULL, NULL, NULL, NULL);

    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames.pcn_hdr = "whysoserious";
    ctrnames.pcn_desc = "joker";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 1;

    err = perfc_alloc_impl(1, "villains", &ctrnames, 1, "joker", REL_FILE(__FILE__), __LINE__, &set);
    ASSERT_EQ(0, err);

    count = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_PERFC, NULL, NULL, NULL, NULL);
    ASSERT_EQ(before + 1, count);

    count = dt_iterate_cmd(DT_OP_EMIT, DT_PATH_PERFC, &dip, NULL, NULL, NULL);

    /* 3, /data/perfc, /data/perfc/joker */
    ASSERT_EQ(before + 1, count);

    n = snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%s",
        DT_PATH_PERFC,
        "villains",
        "FAM",
        "joker");
    ASSERT_TRUE(n > 0 && n < sizeof(path));

    dte = dt_find(path, 1);
    ASSERT_NE(dte, NULL);

    rc = dt_remove(dte);
    ASSERT_EQ(rc, 0);

    dte = dt_find(path, 1);
    ASSERT_EQ(dte, NULL);

    cJSON_Delete(root);
}

MTF_DEFINE_UTEST(perfc, perfc_basic_set)
{
    size_t count;
    union dt_iterate_parameters dip;
    struct dt_element *dte;
    int rc, n;
    char path[DT_PATH_MAX];
    u64 new_value = 42;
    cJSON *root;
    char *output;

    struct perfc_name ctrnames = { 0 };
    struct perfc_set  set = { 0 };
    size_t            before;
    merr_t            err;

    before = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_PERFC, NULL, NULL, NULL, NULL);

    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames.pcn_hdr = "whysoserious";
    ctrnames.pcn_desc = "poison_ivy";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 1;

    err = perfc_alloc_impl(1, "villains", &ctrnames, 1, "poison_ivy", REL_FILE(__FILE__), __LINE__, &set);
    ASSERT_EQ(0, err);

    perfc_set(&set, 0, new_value);

    n = snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%s",
        DT_PATH_PERFC,
        "villains",
        "FAM",
        "poison_ivy");
    ASSERT_TRUE(n > 0 && n < sizeof(path));

    root = cJSON_CreateArray();
    ASSERT_NE(NULL, root);

    dip.root = root;
    count = dt_iterate_cmd(DT_OP_EMIT, DT_PATH_PERFC, &dip, NULL, NULL, NULL);

    /* 3, for /data/perfc, /data/perfc/poison_ivy */
    ASSERT_EQ(before + 1, count);

    output = cJSON_PrintUnformatted(root);
    ASSERT_NE(NULL, output);
    ASSERT_NE(NULL, strstr(output, "\"value\":42"));

    dte = dt_find(path, 1);
    ASSERT_NE(dte, NULL);

    rc = dt_remove(dte);
    ASSERT_EQ(rc, 0);

    dte = dt_find(path, 1);
    ASSERT_EQ(dte, NULL);

    free(output);
    cJSON_Delete(root);
}

MTF_DEFINE_UTEST(perfc, perfc_ctr_name2type_fail)
{
    const char *namev[] = {
        "PERFC_BASIC_FAM_TEST",
        "PERFC_B_FAM_TEST",
        "PERF_BA_FAM_TEST",
        "PERFC_XX_FAM_TEST",
        "PERFC_ra_FAM_TEST",
        "PERFC__RA_FAM_TEST",
        "PERFC_RA__FAM_TEST",
        "PERFC_RA___TEST",
        "PERFC_DI_fam_TEST",
        "PERFC_LT_FAM_",
        "PERFC_LT_FAM",
        "PERFC_LT_",
        "PERFC_LT",
        "PERFC_",
        "PERFC",
        "",
    };
    size_t i;
    struct perfc_name ctrv[] = {
        NE(0, 1, "mygroup", "set"),
    };
    struct perfc_set set;
    merr_t err;


    for (i = 0; i < NELEM(namev); ++i) {
        ctrv[0].pcn_name = namev[i];

        err = perfc_alloc_impl(1, "mygroup", ctrv, 1, "set", REL_FILE(__FILE__), __LINE__, &set);
        ASSERT_NE(0, err);
    }
}

MTF_DEFINE_UTEST(perfc, ctrset_path)
{
    struct perfc_name ctrnames = { 0 };
    struct perfc_set  set;
    merr_t            err;

    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames.pcn_hdr = "mycounterhdr";
    ctrnames.pcn_desc = "mycounter";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 1;

    err = perfc_alloc_impl(1, "n", &ctrnames, 1, "s", REL_FILE(__FILE__), __LINE__, &set);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp(DT_PATH_PERFC "/n/FAM/s", perfc_ctrseti_path(&set)));

    perfc_free(&set);
}

MTF_DEFINE_UTEST(perfc, perfc_rollup)
{
    enum perfc_rollup_sidx {
        PERFC_BA_RUTEST_INC,
        PERFC_BA_RUTEST_INC2,
        PERFC_BA_RUTEST_ADD2,
        PERFC_EN_RUTEST
    };
    struct perfc_name perfc_rollup_op[] = {
        NE(PERFC_BA_RUTEST_INC, 0, "rutest_inc", "rutest_inc"),
        NE(PERFC_BA_RUTEST_INC2, 0, "rutest_inc2", "rutest_inc2"),
        NE(PERFC_BA_RUTEST_ADD2, 0, "rutest_add2", "rutest_add2"),
    };

    struct perfc_set perfc_rollup_pc;
    uint64_t vadd, vsub, val, sum, i;
    merr_t err;

    err = perfc_alloc_impl(
        1, "rollup", perfc_rollup_op, PERFC_EN_RUTEST, "set", REL_FILE(__FILE__), __LINE__, &perfc_rollup_pc);
    ASSERT_EQ(err, 0);

    for (i = 0, sum = 0; i < 1024 * 1024; ++i, sum += i) {
        PERFC_INC_RU(&perfc_rollup_pc, PERFC_BA_RUTEST_INC);

        PERFC_INCADD_RU(&perfc_rollup_pc, PERFC_BA_RUTEST_INC2, PERFC_BA_RUTEST_ADD2, i);
    }

#ifdef PERFC_RU_MAX
    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_INC, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, i - PERFC_RU_MAX);

    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_INC2, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, i - PERFC_RU_MAX);

    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_ADD2, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, sum - i - PERFC_RU_MAX);
#else
    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_INC, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, i);

    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_INC2, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, i);

    vadd = vsub = 0;
    perfc_read(&perfc_rollup_pc, PERFC_BA_RUTEST_ADD2, &vadd, &vsub);
    val = vadd - vsub;
    ASSERT_GE(val, sum - i);
#endif

    perfc_free(&perfc_rollup_pc);
}

MTF_END_UTEST_COLLECTION(perfc)
