/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <hse_ut/framework.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/parse_num.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>

char yamlbuf[128 * 1024];

int
platform_pre(struct mtf_test_info *ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PRE(perfc, platform_pre);

#undef COMPNAME
#define COMPNAME __func__

/* Test that calls to get_cycles() always return a count greater
 * than any previous call and are accurately measuring elapsed
 * time w.r.t get_time_ns().  This might fail on amd64 if the TSC
 * isn't p-state invariant.  This test primarily exists to test
 * verify that successive reads of the s390x TOD clock go foward
 * in time.
 */
MTF_DEFINE_UTEST(perfc, perfc_get_cycles)
{
    const uint cyclec = 16 * 1024 * 1024;
    uint64_t tstart, tstop;
    uint64_t cstart, cstop;
    uint64_t *cyclev;

    cyclev = malloc(sizeof(*cyclev) * cyclec);
    ASSERT_NE(NULL, cyclev);

  again:
    usleep(133 * 1000); /* attempt to get a fresh time slice */

    tstart = get_time_ns();
    cstart = get_cycles();

    for (uint i = 0; i < cyclec; i += 8) {
        cyclev[i + 0] = get_cycles();
        cyclev[i + 1] = get_cycles();
        cyclev[i + 2] = get_cycles();
        cyclev[i + 3] = get_cycles();
        cyclev[i + 4] = get_cycles();
        cyclev[i + 5] = get_cycles();
        cyclev[i + 6] = get_cycles();
        cyclev[i + 7] = get_cycles();

        if (i % (1u << 20) == 0)
            usleep(1); /* attempt to elicit a cpu migration */
    }

    cstop = get_cycles();
    tstop = get_time_ns();

    for (uint i = 1; i < cyclec; ++i) {
        ASSERT_GE(cyclev[i], cyclev[i - 1]);
    }

    ASSERT_GT(cstop, cstart);
    ASSERT_GT(tstop, tstart);

    /* [HSE_REVISIT] The get_cycles() delta should always be less than the
     * get_time_ns() delta, but on a github VM this check fails.  Need to
     * investigate...
     */
    if ((tstop - tstart) < cycles_to_nsecs(cstop - cstart)) {
        hse_log(HSE_WARNING "%s: get_time_ns %lu < get_cycles %lu\n",
                __func__, (tstop - tstart), cycles_to_nsecs(cstop - cstart));
        free(cyclev);
        return;
    }

    /* If we get preempted between the paired calls to get_cycles()
     * and get_time_ns() the delta could be huge, so try again.
     * Otherwise we expect the delta to be much less than 1us,
     * but we set a higher threshold so that the test will pass
     * when run in a VM with a non-optimized build on a very
     * busy machine.
     */
    if ((tstop - tstart) - cycles_to_nsecs(cstop - cstart) > 5000) {
        hse_log(HSE_NOTICE "%s: %lu %lu, %lu\n", __func__,
                (tstop - tstart), cycles_to_nsecs(cstop - cstart),
                (tstop - tstart) - cycles_to_nsecs(cstop - cstart));
        goto again;
    }

    free(cyclev);
}

MTF_DEFINE_UTEST(perfc, perfc_basic_create_find_and_remove)
{
    size_t              count;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    struct dt_element *         dte;
    int                         rc, n;
    char                        path[128];
    struct perfc_name           ctrnames = { 0 };
    struct perfc_set            set = { 0 };
    size_t                      before;
    merr_t                      err;

    before = dt_iterate_cmd(dt_data_tree, DT_OP_COUNT, PERFC_ROOT_PATH, NULL, NULL, NULL, NULL);

    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames.pcn_hdr = "whysoserious";
    ctrnames.pcn_desc = "joker";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 1;

    err = perfc_ctrseti_alloc(COMPNAME, "batman_villains", &ctrnames, 1, "joker", &set);
    ASSERT_EQ(0, err);

    count = dt_iterate_cmd(dt_data_tree, DT_OP_COUNT, PERFC_ROOT_PATH, NULL, NULL, NULL, NULL);
    ASSERT_EQ(before + 1, count);

    yc.yaml_buf = yamlbuf;
    yc.yaml_buf_sz = sizeof(yamlbuf);
    yc.yaml_emit = NULL;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, PERFC_ROOT_PATH, &dip, NULL, NULL, NULL);

    /* 3, for /data, /data/perfc, /data/perfc/joker */
    ASSERT_EQ(before + 3, count);

    n = snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%s/%s",
        PERFC_ROOT_PATH,
        COMPNAME,
        "batman_villains",
        "FAM",
        "joker");
    ASSERT_TRUE(n > 0 && n < sizeof(path));

    dte = dt_find(dt_data_tree, path, 1);
    ASSERT_NE(dte, NULL);

    rc = dt_remove(dt_data_tree, dte);
    ASSERT_EQ(rc, 0);

    dte = dt_find(dt_data_tree, path, 1);
    ASSERT_EQ(dte, NULL);
}

MTF_DEFINE_UTEST(perfc, perfc_basic_set)
{
    size_t              count;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip;
    struct dt_element *         dte;
    int                         rc, n;
    char                        path[128];
    u64                         new_value = 42;

    struct perfc_name ctrnames = { 0 };
    struct perfc_set  set = { 0 };
    size_t            before;
    merr_t            err;

    before = dt_iterate_cmd(dt_data_tree, DT_OP_COUNT, PERFC_ROOT_PATH, NULL, NULL, NULL, NULL);

    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames.pcn_hdr = "whysoserious";
    ctrnames.pcn_desc = "poison_ivy";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 1;

    err = perfc_ctrseti_alloc(COMPNAME, "batman_villains", &ctrnames, 1, "poison_ivy", &set);
    ASSERT_EQ(0, err);

    perfc_set(&set, 0, new_value);

    n = snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%s/%s",
        PERFC_ROOT_PATH,
        COMPNAME,
        "batman_villains",
        "FAM",
        "poison_ivy");
    ASSERT_TRUE(n > 0 && n < sizeof(path));

    dip.yc = &yc;
    yc.yaml_buf = yamlbuf;
    yc.yaml_buf_sz = sizeof(yamlbuf);
    yc.yaml_emit = NULL;
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, PERFC_ROOT_PATH, &dip, NULL, NULL, NULL);

    /* 3, for /data, /data/perfc, /data/perfc/poison_ivy */
    ASSERT_EQ(before + 3, count);

    ASSERT_NE(NULL, strstr(yamlbuf, "value: 42"));

    dte = dt_find(dt_data_tree, path, 1);
    ASSERT_NE(dte, NULL);

    rc = dt_remove(dt_data_tree, dte);
    ASSERT_EQ(rc, 0);

    dte = dt_find(dt_data_tree, path, 1);
    ASSERT_EQ(dte, NULL);
}

static inline void
perfc_test_ctrs(struct perfc_set *set)
{
    perfc_set(set, 0, 0);
    perfc_add(set, 0, 10);
    perfc_inc(set, 0);
    perfc_dec(set, 0);
    perfc_sub(set, 0, 2);
    perfc_sub(set, 0, 10);
    perfc_sub(set, 0, 8);
    perfc_dec(set, 0);
}

MTF_DEFINE_UTEST(perfc, clear_counters)
{
    struct perfc_name *         ctrnames;
    struct perfc_set            set = { 0 };
    merr_t                      err;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip;
    char *                      name;
    int                         i, ctrc = 4;
    int                         count;

    ctrnames = calloc(ctrc, sizeof(*ctrnames) + 32);
    ASSERT_NE(0, ctrnames);
    name = (void *)(ctrnames + ctrc);

    for (i = 0; i < ctrc; i++) {
        snprintf(name, 32, "mycounter-%d", i);
        ctrnames[i].pcn_desc = name;
        ctrnames[i].pcn_flags = 0;
        ctrnames[i].pcn_prio = 1;
        ctrnames[i].pcn_hdr = "mycounterhdr";
        name += 32;
    }

    ctrnames[0].pcn_name = "PERFC_BA_FAM_TEST";
    ctrnames[1].pcn_name = "PERFC_RA_FAM_TEST";
    ctrnames[2].pcn_name = "PERFC_LT_FAM_TEST";
    ctrnames[3].pcn_name = "PERFC_SL_FAM_TEST";

    err = perfc_ctrseti_alloc("mycomp", "myset", ctrnames, ctrc, "alltypes", &set);
    ASSERT_EQ(0, err);

    perfc_test_ctrs(&set);

    perfc_ctrseti_path(&set);

    dsp.path = "/data/perfc/mycomp/myset/FAM/alltypes";
    dsp.value = "1";
    dsp.value_len = strlen(dsp.value);
    dsp.field = DT_FIELD_CLEAR;
    dip.dsp = &dsp;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, dsp.path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(1, count);

    perfc_ctrseti_free(&set);
    free(ctrnames);
}

MTF_DEFINE_UTEST(perfc, enable_counters)
{
    struct perfc_name           ctrnames = { 0 };
    struct perfc_set            set = { 0 };
    merr_t                      err;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip;
    int                         count;
    char *                      path;

    perfc_verbosity = 1;
    ctrnames.pcn_desc = "mycounter";
    ctrnames.pcn_hdr = "mycounterhdr";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 3;
    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";

    err = perfc_ctrseti_alloc("mycomp", "myset", &ctrnames, 1, "basic", &set);
    ASSERT_EQ(0, err);

    perfc_test_ctrs(&set);

    path = perfc_ctrseti_path(&set);
    ASSERT_EQ(0, strcmp(path, "/data/perfc/mycomp/myset/FAM/basic"));

    dsp.path = path;
    dsp.value = "1";
    dsp.value_len = strlen(dsp.value);
    dsp.field = DT_FIELD_ENABLED;
    dip.dsp = &dsp;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, dsp.path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(1, count);

    dsp.value = "0";
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, dsp.path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(1, count);

    perfc_ctrseti_free(&set);
}

/* [HSE_TODO]: Data tree disabled during config refactor */
#if 0
MTF_DEFINE_UTEST(perfc, perfc_verbosity_set_test)
{
    struct perfc_name           ctrnames = { 0 };
    struct perfc_set            set = { 0 };
    merr_t                      err;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip;
    int                         count;

    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };

    ctrnames.pcn_desc = "mycounter";
    ctrnames.pcn_hdr = "mycounterhdr";
    ctrnames.pcn_flags = 0;
    ctrnames.pcn_prio = 3;
    ctrnames.pcn_name = "PERFC_BA_FAM_TEST";

    err = perfc_ctrseti_alloc("mycomp", "myset", &ctrnames, 1, "basic", &set);
    ASSERT_EQ(0, err);
    perfc_add(&set, 0, 3);

    dsp.path = "/data/config/kvdb/perfc/perfc_verbosity";
    dsp.value = "4";
    dsp.value_len = strlen(dsp.value);
    dsp.field = DT_FIELD_ENABLED;
    dip.dsp = &dsp;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, dsp.path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(1, count);

    perfc_add(&set, 0, 7);

    /* Emit */
    dip.yc = &yc;
    yc.yaml_buf = yamlbuf;
    yc.yaml_buf_sz = sizeof(yamlbuf);
    yc.yaml_emit = NULL;
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, dsp.path, &dip, NULL, NULL, NULL);
    ASSERT_NE(NULL, strstr(yamlbuf, "current: 0x4"));

    perfc_ctrseti_free(&set);
}
#endif

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

    err = perfc_ctrseti_alloc("c", "n", &ctrnames, 1, "s", &set);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp(PERFC_ROOT_PATH "/c/n/FAM/s", perfc_ctrseti_path(&set)));

    perfc_ctrseti_free(&set);
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

    err = perfc_ctrseti_alloc(
        COMPNAME, "rollup", perfc_rollup_op, PERFC_EN_RUTEST, "set", &perfc_rollup_pc);
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

    perfc_ctrseti_free(&perfc_rollup_pc);
}

MTF_END_UTEST_COLLECTION(perfc)
