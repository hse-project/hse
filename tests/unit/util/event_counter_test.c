/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <mtf/framework.h>

#include <hse_util/slab.h>
#include <hse_util/inttypes.h>
#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse_util/time.h>
#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>

int
ev_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
ev_test_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(event_counter, ev_test_pre, ev_test_post);

MTF_DEFINE_UTEST(event_counter, ev_create_and_search)
{
    cJSON *root;
    const char *path = DT_PATH_EVENT;
    union dt_iterate_parameters dip;

    char *dbg_lvl = "DEBUG";
    char *err_lvl = "ERR";
    size_t dbg_before, dbg_after;
    size_t err_before, err_after;

    root = cJSON_CreateArray();
    ASSERT_NE(NULL, root);

    dip.root = root;

    dbg_before = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "level", dbg_lvl);
    err_before = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "level", err_lvl);

    ev_info(1);
    ev_warn(1);
    ev_err(1);

    dbg_after = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "level", dbg_lvl);
    err_after = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "level", err_lvl);

    ASSERT_EQ(dbg_after - dbg_before, 3);
    ASSERT_EQ(err_after - err_before, 1);

    cJSON_Delete(root);
}

/* 1. Test that the Event Counter macro creates an event counter that is
 * accessible via dt_find(), dt_iterate_next(), and dt_iterate_cmd().
 */
MTF_DEFINE_UTEST(event_counter, ev_create_and_find)
{
    struct dt_element *   fuzzy, *direct, *iterate_next;
    size_t                count, count_entry;
    int                   line;
    struct event_counter *ev;

    const char *phile = basename(__FILE__);
    char        fuzzy_path[DT_PATH_MAX];
    char        direct_path[DT_PATH_MAX];

    snprintf(fuzzy_path, sizeof(fuzzy_path), "%s/%s", DT_PATH_EVENT, phile);

    count_entry = dt_iterate_cmd(DT_OP_COUNT, fuzzy_path, NULL, NULL, NULL, NULL);

    /* Create an EC using the macro.
     *
     * Note, keep the __LINE__ on the same line as the ev.
     * We will be using it to compose the direct name.
     */

    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a fuzzy find */
    fuzzy = dt_find(fuzzy_path, 0);

    /* Better have found something. */
    ASSERT_NE(fuzzy, NULL);

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);

    ASSERT_NE(direct, NULL);
    ASSERT_EQ(direct, fuzzy);

    /* Try to access the EC with dt_iterate_next */
    iterate_next = dt_iterate_next(fuzzy_path, NULL);
    ASSERT_EQ(direct, iterate_next);

    /* Try to access the EC with dt_iterate_cmd */
    count = dt_iterate_cmd(DT_OP_COUNT, fuzzy_path, NULL, NULL, NULL, NULL);
    ASSERT_EQ(count, count_entry + 1);

    /* Now, do the same for an ev with a priority */
    /* clang-format off */
    ev_info(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    ev = (struct event_counter *)direct->dte_data;
    ASSERT_EQ(ev->ev_level, LOG_INFO);

    /* Now, with both a priority and a rock */
    /* clang-format off */
    ev_warn(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    ev = (struct event_counter *)direct->dte_data;
    ASSERT_EQ(ev->ev_level, LOG_WARNING);
}

/**
 * timestamp_compare returns -1 if one < two, 0 if one == two, 1 if one > two
 */
int
timestamp_compare(atomic_ulong *o, atomic_ulong *t)
{
    u64 one = atomic_read(o);
    u64 two = atomic_read(t);

    if (one > two)
        return 1;
    else if (one == two)
        return 0;
    return -1;
}

/* 2. Test odometer timestamp.
 */
MTF_DEFINE_UTEST(event_counter, ev_odometer_timestamp)
{
    char                  direct_path[DT_PATH_MAX];
    struct event_counter *ec;
    struct dt_element *   direct;
    atomic_ulong          before, after;
    const char *          phile = basename(__FILE__);
    int                   line;
    int                   ret;

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);

    /* Create an EC using the macro. */
    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Take an "after" time reading. */
    ev_get_timestamp(&after);

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    ec = direct->dte_data;
    ASSERT_NE(ec, NULL);

    /* Make sure that the EC's timestamp is between the before and
     * after time readings that we took.
     *
     * Note, the granularity of the clock we are reading is such that
     * two cousecutive time reads may be equal, so, cannot check for
     * absolutely before or after, just equal or before, and equal or
     * after.
     */
    ret = timestamp_compare(&before, &ec->ev_odometer_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &ec->ev_odometer_timestamp);
    ASSERT_TRUE(ret >= 0);
}

/* 3. Test odometer counter
 */
MTF_DEFINE_UTEST(event_counter, ev_odometer_counter)
{
    char                  direct_path[DT_PATH_MAX];
    struct event_counter *ec;
    struct dt_element *   direct;
    const char *          phile = basename(__FILE__);
    int                   line;
    int                   i;

    /* Create an EC using the macro. */
    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    ec = direct->dte_data;
    ASSERT_NE(ec, NULL);

    /* Counter should be 1 */
    ASSERT_EQ(atomic_read(&ec->ev_odometer), 1);

    /* Now loop 10 times on a new event counter */
    for (i = 0; i < 10; i++) {
        /* clang-format off */
        ev(1); line = __LINE__;
        /* clang-format on */
    }

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    ec = direct->dte_data;
    ASSERT_NE(ec, NULL);

    /* Counter should be 10 */
    ASSERT_EQ(atomic_read(&ec->ev_odometer), 10);
}

/* 4. Test odometer timestamp advance
 */
MTF_DEFINE_UTEST(event_counter, ev_timestamp_advance)
{
    char                  direct_path[DT_PATH_MAX];
    struct event_counter *ec;
    struct dt_element *   direct;
    const char *          phile = basename(__FILE__);
    atomic_ulong          prev;
    int                   line;
    int                   ret;
    int                   i;

    /* Take an initial timestamp to compare with the first macro
     * invocation.
     */
    ev_get_timestamp(&prev);

    /* Loop 10 times over the macro. Sleep a little between each
     * invocation, and watch that the timestamp advances correctly.
     */
    for (i = 0; i < 10; i++) {

        /* clang-format off */
        ev(1); line = __LINE__;
        /* clang-format on */

        /* Try to find the EC with a direct find */
        snprintf(
            direct_path,
            sizeof(direct_path),
            "%s/%s/%s/%d",
            DT_PATH_EVENT,
            phile,
            __func__,
            line);

        direct = dt_find(direct_path, 1);
        ASSERT_NE(direct, NULL);

        ec = direct->dte_data;
        ASSERT_NE(ec, NULL);

        /* Counter should be equal to i+ */
        ASSERT_EQ(atomic_read(&ec->ev_odometer), i + 1);

        ret = timestamp_compare(&prev, &ec->ev_odometer_timestamp);
        ASSERT_TRUE(ret <= 0);

        usleep(100 * 1000);
    }
}

merr_t
validate(
    cJSON *const root,
    const char *const phile,
    const char *const func,
    const int line,
    struct event_counter *const ec)
{
    cJSON *elem;
    char buf[DT_PATH_MAX];

    elem = cJSON_GetArrayItem(root, 0);

    snprintf(buf, sizeof(buf), "%s/%s/%s/%d", DT_PATH_EVENT, phile, func, line);
    if (strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(elem, "path")), buf) != 0)
        return merr(EINVAL);

    if (strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(elem, "level")), "INFO") != 0)
        return merr(EINVAL);

    if (cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(elem, "odometer"))
            != atomic_read(&ec->ev_odometer))
        return merr(EINVAL);

    snprintf_timestamp(buf, sizeof(buf), &ec->ev_odometer_timestamp);
    if (strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(elem, "odometer_timestamp")),
            buf) != 0)
        return merr(EINVAL);

    return 0;
}

/* 5. Test emit functionality
 */
MTF_DEFINE_UTEST(event_counter, ev_emit)
{
    merr_t err;
    cJSON *root;
    const char *phile = basename(__FILE__);
    char direct_path[DT_PATH_MAX];
    union dt_iterate_parameters dip;
    struct dt_element *direct;
    struct event_counter *ec;
    size_t count;
    int line;
    bool rbool;

    /* Create an EC using the macro.
     *
     * Note, keep the __LINE__ on the same line as the ev.
     * We will be using it to compose the direct name.
     */

    /* clang-format off */
    ev_info(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(NULL, direct);

    ec = direct->dte_data;
    ASSERT_NE(NULL, ec);

    root = cJSON_CreateArray();
    ASSERT_NE(NULL, root);

    dip.root = root;

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(2, count);

    err = validate(root, phile, __func__, line, ec);
    ASSERT_EQ(0, merr_errno(err));

    cJSON_Delete(root);

    rbool = ev_root_match_select_handler(NULL, NULL, NULL);
    ASSERT_EQ(true, rbool);
}

/* 6. Test count functionality
 */
MTF_DEFINE_UTEST(event_counter, ev_counts)
{
    char   fuzzy_path[DT_PATH_MAX];
    size_t count;

    snprintf(fuzzy_path, sizeof(fuzzy_path), "%s/%s/%s",
             DT_PATH_EVENT, basename(__FILE__), __func__);

    /* Create an EC using the macro. */
    ev(1);

    /* Use dt_iterate_cmd to count it */
    count = dt_iterate_cmd(DT_OP_COUNT, fuzzy_path, NULL, NULL, NULL, NULL);
    ASSERT_EQ(count, 1);

    /* Create several more ECs using the macro. */
    ev(1);
    ev(1);
    ev(1);

    /* Use dt_iterate_cmd to count it */
    count = dt_iterate_cmd(DT_OP_COUNT, fuzzy_path, NULL, NULL, NULL, NULL);
    ASSERT_EQ(count, 4);
}

/* 7. Show that EC cannot be deleted.
 */
MTF_DEFINE_UTEST(event_counter, ev_delete_protect)
{
    const char *       phile = basename(__FILE__);
    char               direct_path[DT_PATH_MAX];
    struct dt_element *direct_before, *direct_after;
    int                line;
    int                ret;

    /* Create an EC using the macro. */
    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct_before = dt_find(direct_path, 1);
    ASSERT_NE(direct_before, NULL);

    /* Try to remove the EC */
    ret = dt_remove(direct_before);
    ASSERT_EQ(ret, EACCES);

    /* Should still be able to find it */
    direct_after = dt_find(direct_path, 1);
    ASSERT_EQ(direct_before, direct_after);
}

#define EV_EMIT_OVERFLOW_BUF_SIZE 20
#define FALSE_OFFSET 100

/* 8. Test emit overflow protection
 */
MTF_DEFINE_UTEST(event_counter, ev_emit_overflow)
{
    cJSON *root;
    const char *phile = basename(__FILE__);
    char direct_path[DT_PATH_MAX];
    union dt_iterate_parameters dip;
    struct dt_element *direct;
    struct event_counter *ec;
    size_t count;
    int line;

    /* Create an EC using the macro.
     *
     * Note, keep the __LINE__ on the same line as the ev.
     * We will be using it to compose the direct name.
     */

    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        phile,
        __func__,
        line);
    direct = dt_find(direct_path, 1);
    ASSERT_NE(NULL, direct);

    ec = direct->dte_data;
    ASSERT_NE(NULL, ec);

    root = cJSON_CreateArray();
    ASSERT_NE(NULL, root);

    dip.root = root;

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(2, count);
    ASSERT_EQ(1, cJSON_GetArraySize(root));

    cJSON_Delete(root);
}

MTF_END_UTEST_COLLECTION(event_counter)
