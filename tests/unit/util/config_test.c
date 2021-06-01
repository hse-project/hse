/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/slab.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/time.h>
#include <hse_util/parse_num.h>

#include <hse_util/data_tree.h>
#include <hse_util/config.h>

#undef COMPNAME
#define COMPNAME __func__

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

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(config, config_test_pre, config_test_post);

/* 1. Test that the CFG() macro creates an event counter that is
 *    accessible via dt_find(), dt_iterate_next(), and dt_iterate_cmd().
 */
MTF_DEFINE_UTEST(config, config_create_and_find)
{
    struct dt_element *fuzzy, *direct, *iterate_next;
    size_t             count;

    /* Normally, COMPNAME is set for the whole file, but for testing
     * purposes, we'll be setting it with the individual functions.
     */
    char fuzzy_path[DT_PATH_LEN];
    char direct_path[DT_PATH_LEN];

    u64 default_apple = 2;
    u64 apple = default_apple;

    snprintf(fuzzy_path, sizeof(fuzzy_path), "/data/config/%s", COMPNAME);

    /* Create a Config Variable using the macro.  */

    CFG("fruit",
        "apple",
        &apple,
        sizeof(apple),
        &default_apple,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        true);

    /* Try to find the EC with a fuzzy find */
    fuzzy = dt_find(dt_data_tree, fuzzy_path, 0);

    /* Better have found something. */
    ASSERT_NE(fuzzy, NULL);

    /* Try to find the EC with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/fruit/apple", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);

    ASSERT_NE(direct, NULL);
    ASSERT_EQ(direct, fuzzy);

    /* Try to access the dte with dt_iterate_next */
    iterate_next = dt_iterate_next(dt_data_tree, fuzzy_path, NULL);
    ASSERT_EQ(direct, iterate_next);

    /* Try to access the dte with dt_iterate_cmd */
    count = dt_iterate_cmd(dt_data_tree, DT_OP_COUNT, fuzzy_path, NULL, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);
}

#define MY_BUF_SIZE 512
int
validate_buf(
    const char *       buf,
    size_t             bytes_in_buf,
    const char *       component,
    const char *       path,
    const char *       instance,
    u64                dfault,
    u64                val,
    struct hse_config *mc,
    bool               writable)
{
    char        my_buf[MY_BUF_SIZE], *mb = my_buf;
    const char *b = buf;
    size_t      offset = 0;
    size_t      remaining;
    int         ret;
    int         i;
    char        my_path[DT_PATH_LEN];
    char        value[100];

    memset(my_buf, 0, MY_BUF_SIZE);

    snprintf(my_path, DT_PATH_LEN, "%s/%s/%s", component, path, instance);

    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "config:\n");
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "- path: %s\n", my_path);
    remaining = MY_BUF_SIZE - offset;

    if (mc->show) {
        mc->show(value, sizeof(value), &val, 0);
        offset += snprintf(my_buf + offset, remaining, "  current: %s\n", value);
    } else {
        offset += snprintf(my_buf + offset, remaining, "  current: 0x%lx\n", val);
    }
    remaining = MY_BUF_SIZE - offset;

    if (mc->show) {
        mc->show(value, sizeof(value), &dfault, 0);
        offset += snprintf(my_buf + offset, remaining, "  default: %s\n", value);
    } else {
        offset += snprintf(my_buf + offset, remaining, "  default: 0x%lx\n", dfault);
    }
    remaining = MY_BUF_SIZE - offset;

    if (writable) {
        offset += snprintf(my_buf + offset, remaining, "  writable: true\n");
        remaining = MY_BUF_SIZE - offset;
    } else {
        offset += snprintf(my_buf + offset, remaining, "  writable: false\n");
        remaining = MY_BUF_SIZE - offset;
    }

    i = 0;
    while (mb && b && *mb && *b && (*mb == *b)) {
        i++;
        mb++;
        b++;
    }
    if (i != bytes_in_buf) {
        printf("failed at byte %d\n", i);
        ret = -1;
    } else {
        /* Compared successfully */
        ret = 0;
    }
    printf("********************************************\n");
    printf("%s", buf);
    printf("********************************************\n");
    printf("%s", my_buf);
    printf("********************************************\n");
    return ret;
}

#define MC_EMIT_BUF_SIZE 512

/* 2. Test emit functionality */
MTF_DEFINE_UTEST(config, config_emit)
{
    char                direct_path[DT_PATH_LEN];
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    char *                      buf;
    struct dt_element *         direct;
    struct hse_config *         mc;
    size_t                      count;
    int                         ret;

    static u64                  default_nut = 42;
    static u64                  peanut = 42;
    static u32                  default_coin = 2;
    static u32                  penny = 2;
    static u16                  default_drug = 1500;
    static u16                  aspirin = 1500;
    static u8                   default_plane = 5;
    static u8                   cessna = 5;

    buf = calloc(1, MC_EMIT_BUF_SIZE);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = MC_EMIT_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Create a U64 Config Variable using the macro.  */
    CFG("nuts",
        "peanut",
        &peanut,
        sizeof(peanut),
        &default_nut,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        true);

    /* Create a U32 Config Variable using the macro.  */
    CFG("coins", "penny", &penny, sizeof(penny), &default_coin, NULL, NULL, NULL, NULL, NULL, true);

    /* Create a U16 Config Variable using the macro.  */
    CFG("drugs",
        "aspirin",
        &aspirin,
        sizeof(aspirin),
        &default_drug,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        true);

    /* Create a U8 Config Variable using the macro.  */
    CFG("plane",
        "cessna",
        &cessna,
        sizeof(cessna),
        &default_plane,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        false);

    /* U64 Test */
    memset(yc.yaml_buf, 0, yc.yaml_buf_sz);
    yc.yaml_prev = Yaml_Context_Type_Invalid;
    yc.yaml_indent = 0;
    yc.yaml_offset = 0;

    /* Try to find the u64 dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/nuts/peanut", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);

    ret = validate_buf(
        buf, yc.yaml_offset, COMPNAME, "nuts", "peanut", default_nut, peanut, mc, true);
    ASSERT_EQ(ret, 0);

    /* U32 Test */
    memset(yc.yaml_buf, 0, yc.yaml_buf_sz);
    yc.yaml_prev = Yaml_Context_Type_Invalid;
    yc.yaml_indent = 0;
    yc.yaml_offset = 0;
    yc.yaml_buf_sz = MC_EMIT_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Try to find the u32 dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/coins/penny", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);

    ret = validate_buf(
        buf, yc.yaml_offset, COMPNAME, "coins", "penny", default_coin, penny, mc, true);
    ASSERT_EQ(ret, 0);

    /* U16 Test */
    memset(yc.yaml_buf, 0, yc.yaml_buf_sz);
    yc.yaml_prev = Yaml_Context_Type_Invalid;
    yc.yaml_indent = 0;
    yc.yaml_offset = 0;

    /* Try to find the u16 dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/drugs/aspirin", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);

    ret = validate_buf(
        buf, yc.yaml_offset, COMPNAME, "drugs", "aspirin", default_drug, aspirin, mc, true);
    ASSERT_EQ(ret, 0);

    /* U8 Test */
    memset(yc.yaml_buf, 0, yc.yaml_buf_sz);
    yc.yaml_prev = Yaml_Context_Type_Invalid;
    yc.yaml_indent = 0;
    yc.yaml_offset = 0;

    /* Try to find the u8 dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/plane/cessna", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);

    ret = validate_buf(
        buf, yc.yaml_offset, COMPNAME, "plane", "cessna", default_plane, cessna, mc, false);
    ASSERT_EQ(ret, 0);

    free(buf);
}

/**
 * timestamp_compare returns -1 if one < two, 0 if one == two, 1 if one > two
 */
int
timestamp_compare(atomic64_t *o, atomic64_t *t)
{
    u64 one = atomic64_read(o);
    u64 two = atomic64_read(t);

    if (one > two)
        return 1;
    else if (one == two)
        return 0;

    return -1;
}

/* 3. Test set */
MTF_DEFINE_UTEST(config, config_set)
{
    char                        direct_path_to_walleye[DT_PATH_LEN];
    char                        direct_path_to_guppy[DT_PATH_LEN];
    char                        direct_path_to_goldfish[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    u32                         fish_default = 0xfeed;
    u32                         walleye = fish_default;
    u16                         guppy = 42;
    u8                          goldfish = 127;
    char *                      new_value = "0xdeef";
    char *                      new_8b_value = "0x34";

    /* Create writable config variable using the macro. */
    CFG("fish",
        "walleye",
        &walleye,
        sizeof(walleye),
        &fish_default,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        true);

    snprintf(
        direct_path_to_walleye,
        sizeof(direct_path_to_walleye),
        "/data/config/%s/fish/walleye",
        COMPNAME);

    /* Create non-writable config variable using the macro. */
    CFG("fish", "guppy", &guppy, sizeof(guppy), &fish_default, NULL, NULL, NULL, NULL, NULL, false);

    snprintf(
        direct_path_to_guppy, sizeof(direct_path_to_guppy), "/data/config/%s/fish/guppy", COMPNAME);

    /* Create 8b config variable using the macro. */
    CFG("fish",
        "goldfish",
        &goldfish,
        sizeof(goldfish),
        &fish_default,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        true);

    snprintf(
        direct_path_to_goldfish,
        sizeof(direct_path_to_goldfish),
        "/data/config/%s/fish/goldfish",
        COMPNAME);

    /* 32b variable */

    /* Try to find the dte with a direct find */
    direct = dt_find(dt_data_tree, direct_path_to_walleye, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u32 *)mc->data, *(u32 *)mc->dfault);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path_to_walleye, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal new_value */
    ASSERT_EQ(*(u32 *)mc->data, 0xdeef);

    /**
     * Now, execute the "Set" command without a field, which should set the
     * variable to the default and set the change_timestamp
     */

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    dsp.field = DT_FIELD_INVALID;
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path_to_walleye, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal to default */
    ASSERT_EQ(*(u32 *)mc->data, 0xfeed);

    /* 16b variable */

    /**
     * Now, execute the "Set" command on a non-writable config
     * variable. It should be ignored
     */
    /* Try to find the dte with a direct find */
    direct = dt_find(dt_data_tree, direct_path_to_guppy, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u16 *)mc->data, 42);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path_to_guppy, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ASSERT_EQ(0, atomic64_read(&mc->change_timestamp));

    /* current should still be equal to 42 */
    ASSERT_EQ(*(u16 *)mc->data, 42);

    /* 8b variable */

    /* Try to find the dte with a direct find */
    direct = dt_find(dt_data_tree, direct_path_to_goldfish, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u8 *)mc->data, 127);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_8b_value;
    dsp.value_len = strlen(new_value);
    count =
        dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path_to_goldfish, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal new_value */
    ASSERT_EQ(*(u8 *)mc->data, 0x34);
}

merr_t
test_validator(
    const char *              instance,
    const char *              path,
    struct dt_set_parameters *dsp,
    void *                    dfault,
    void *                    rock,
    char *                    errbuf,
    size_t                    errbuf_sz)
{
    u64    my_rock = (u64)rock;
    u32    val = 0;
    merr_t err;

    err = parse_u32(dsp->value, &val);
    if (err)
        return merr(EINVAL);

    switch (my_rock) {
        case 1: {
            if (val > 4) {
                snprintf(errbuf, errbuf_sz, "Value for Rock 1 too big");
                return merr(EINVAL);
            }
            return 0;
        } break;
        case 2: {
            if ((val < 5) || (val > 9)) {
                snprintf(errbuf, errbuf_sz, "Value for Rock 2 out of bounds");
                return merr(EINVAL);
            }
            return 0;
        } break;
        case 3: {
            if ((val < 10) || (val > 14)) {
                snprintf(errbuf, errbuf_sz, "Value for Rock 3 out of bounds");
                return merr(EINVAL);
            }
            return 0;
        } break;
    };

    /* Must have been an error, since the 'rock' didn't match */
    snprintf(errbuf, errbuf_sz, "Invalid Rock (%d)", (int)my_rock);
    return merr(ENOENT);
}

/* 4. Test validator */
MTF_DEFINE_UTEST(config, config_validator)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    u64                         after;
    size_t                      count;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    u32                         bird_default = 16;
    u32                         robin = bird_default;     /* Rock 1 */
    u32                         parrot = bird_default;    /* Rock 2 */
    u32                         chickadee = bird_default; /* Rock 3 */
    char                        new_value[20];

    /* Create config variables using the macro. */
    CFG("bird",
        "robin",
        &robin,
        sizeof(robin),
        &bird_default,
        test_validator,
        (void *)1,
        NULL,
        NULL,
        NULL,
        true);
    CFG("bird",
        "parrot",
        &parrot,
        sizeof(parrot),
        &bird_default,
        test_validator,
        (void *)2,
        NULL,
        NULL,
        NULL,
        true);
    CFG("bird",
        "chickadee",
        &chickadee,
        sizeof(chickadee),
        &bird_default,
        test_validator,
        (void *)3,
        NULL,
        NULL,
        NULL,
        true);

    /* Try to find the robin with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/bird/robin", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u32 *)mc->data, *(u32 *)mc->dfault);

    /**
     * Now, execute the "Set" command with an invalid value to
     * show that the validator rejects it.
     */
    sprintf(new_value, "0x27");
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);

    /* Make sure that the timestamp did not advance (since we
     * didn't set the variable.
     */
    after = atomic64_read(&mc->change_timestamp);
    ASSERT_EQ(after, 0);

    /* current should equal default */
    ASSERT_EQ(*(u32 *)mc->data, bird_default);

    /**
     * Now, execute the "Set" command with a valid value to
     * show that the validator accepts it.
     */
    sprintf(new_value, "0x2");
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Make sure that the timestamp advanced.
     */
    after = atomic64_read(&mc->change_timestamp);
    ASSERT_NE(after, 0);

    /* current should equal 2 */
    ASSERT_EQ(*(u32 *)mc->data, 0x2);
}

int
validate_custom_buf(
    const char *       buf,
    size_t             bytes_in_buf,
    const char *       component,
    const char *       path,
    const char *       instance,
    u64                dfault,
    u64                val,
    struct hse_config *mc)
{
    char        my_buf[MY_BUF_SIZE], *mb = my_buf;
    const char *b = buf;
    size_t      offset = 0;
    size_t      remaining;
    int         ret;
    int         i;
    char        my_path[DT_PATH_LEN];

    memset(my_buf, 0, MY_BUF_SIZE);

    snprintf(my_path, DT_PATH_LEN, "%s/%s/%s", component, path, instance);

    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "data:\n");
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "  config:\n");
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "  - path: %s\n", my_path);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "    fact: amphibians rule!\n");
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "    current: 0x%lx\n", val);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "    default: 0x%lx\n", dfault);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "    writable: true\n");
    remaining = MY_BUF_SIZE - offset;

    i = 0;
    while (mb && b && *mb && *b && (*mb == *b)) {
        i++;
        mb++;
        b++;
    }
    if (i != bytes_in_buf) {
        printf("failed at byte %d\n", i);
        ret = -1;
    } else {
        /* Compared successfully */
        ret = 0;
    }
    printf("********************************************\n");
    printf("%s", buf);
    printf("********************************************\n");
    printf("%s", my_buf);
    printf("********************************************\n");
    return ret;
}

static size_t
custom_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct hse_config *mc = (struct hse_config *)dte->dte_data;

    snprintf(mc->data, mc->data_sz, "%s", dsp->value);

    return 1;
}

/* 6. Test custom setter */
MTF_DEFINE_UTEST(config, config_custom_setter)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    char *                      cloud_default = "nimbus";
    char                        my_cloud[128];
    char *                      new_value = "cumulus";

    sprintf(my_cloud, "%s", cloud_default);
    /* Create config variable using the macro. */
    CFG("clouds",
        "my_cloud",
        &my_cloud,
        sizeof(my_cloud),
        &cloud_default,
        NULL,
        NULL,
        NULL,
        custom_set_handler,
        NULL,
        true);

    /* Try to find the dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/clouds/my_cloud", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(0, strcmp(mc->data, cloud_default));

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal new value */
    ASSERT_EQ(0, strcmp(mc->data, new_value));
}

/* 7. Test u64 macro */
MTF_DEFINE_UTEST(config, config_u64_macro)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    u64                         dog_default = 0x1234567887654321;
    u64                         collie = dog_default;
    char *                      new_value = "8765432112345678";
    u64                         nv = 0;

    ret = parse_u64(new_value, &nv);
    ASSERT_EQ(0, ret);

    /* Create config variable using the macro. */
    CFG_U64("dogs", "collie", &collie, &dog_default, NULL, (void *)0x42, true);

    /* Try to find the dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/dogs/collie", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u64 *)mc->data, *(u64 *)mc->dfault);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal default */
    ASSERT_EQ(*(u64 *)mc->data, nv);
}

/* 8. Test u32 macro */
MTF_DEFINE_UTEST(config, config_u32_macro)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    u32                         cat_default = 0x12345678;
    u32                         calico = cat_default;
    char *                      new_value = "87654321";
    u32                         nv = 0;

    ret = parse_u32(new_value, &nv);
    ASSERT_EQ(0, ret);

    /* Create config variable using the macro. */
    CFG_U32("cats", "calico", &calico, &cat_default, NULL, NULL, true);

    /* Try to find the dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/cats/calico", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(u32 *)mc->data, *(u32 *)mc->dfault);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal default */
    ASSERT_EQ(*(u32 *)mc->data, nv);
}

/* 9. Test bool macro */
MTF_DEFINE_UTEST(config, config_bool_macro)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    bool                        badges_default = true;
    bool                        blazing_saddles_need_badges = badges_default;
    char *                      new_value = "false";
    char *                      buf;
    struct yaml_context         yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip2 = {.yc = &yc };

    /* Create config variable using the macro. */
    CFG_BOOL(
        "badges",
        "blazing_saddles_need_badges",
        &blazing_saddles_need_badges,
        &badges_default,
        NULL,
        NULL,
        true);

    /* Try to find the dte with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "/data/config/%s/badges/blazing_saddles_need_badges",
        COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(*(bool *)mc->data, *(bool *)mc->dfault);

    buf = calloc(1, MC_EMIT_BUF_SIZE);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = MC_EMIT_BUF_SIZE;
    yc.yaml_emit = NULL;

    dip2.yc = &yc;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip2, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);
    printf("%s", buf);

    ret = validate_buf(
        buf,
        yc.yaml_offset,
        COMPNAME,
        "badges",
        "blazing_saddles_need_badges",
        badges_default,
        blazing_saddles_need_badges,
        mc,
        true);
    ASSERT_EQ(ret, 0);
    free(buf);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command, which should set the
     * variable to the new value and set the change_timestamp
     */
    dsp.field = DT_FIELD_DATA;
    dsp.value = new_value;
    dsp.value_len = strlen(new_value);
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal default */
    ASSERT_EQ(*(bool *)mc->data, 0);
}

/* 10. Test string macro */
MTF_DEFINE_UTEST(config, config_string_macro)
{
    char                        direct_path[DT_PATH_LEN];
    struct hse_config *         mc;
    struct dt_element *         direct;
    atomic64_t                  before, after;
    size_t                      count;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };
    static char                *cars_default = "cadillac";
#define CARS_MAX 20
    static char         buick[CARS_MAX];
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };

    snprintf(buick, CARS_MAX - 1, "buick");
    /* Create config variable using the macro. */
    CFG_STRING("cars", "buick", buick, sizeof(buick), cars_default, NULL, NULL, true);

    /* Try to find the dte with a direct find */
    snprintf(direct_path, sizeof(direct_path), "/data/config/%s/cars/buick", COMPNAME);
    direct = dt_find(dt_data_tree, direct_path, 1);
    ASSERT_NE(direct, NULL);

    mc = direct->dte_data;
    ASSERT_NE(mc, NULL);

    /* current should equal default */
    ASSERT_EQ(0, strcmp((char *)mc->data, "buick"));

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /**
     * Now, execute the "Set" command with no field value. This should set
     * the variable to the default value and set the change_timestamp
     */
    dsp.field = 0;
    count = dt_iterate_cmd(dt_data_tree, DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Make sure that the trip odometer's timestamp is between the
     * before and after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &mc->change_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &mc->change_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* current should equal default */
    ASSERT_EQ(0, strcmp(buick, "cadillac"));

    buf = calloc(1, MC_EMIT_BUF_SIZE);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = MC_EMIT_BUF_SIZE;
    yc.yaml_emit = NULL;

    dip.yc = &yc;

    count = dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 3);
    printf("%s", buf);
    free(buf);
}

MTF_END_UTEST_COLLECTION(config)
