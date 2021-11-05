/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <mtf/framework.h>

#include <hse_util/slab.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
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
    const char          path[] = DT_PATH_EVENT;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };

    char *dbg_lvl = "DEBUG";
    char *err_lvl = "ERR";
    size_t dbg_before, dbg_after;
    size_t err_before, err_after;
    char * buf;

    buf = calloc(1, 32768);
    ASSERT_NE(buf, NULL);

    yc.yaml_buf = buf;
    yc.yaml_buf_sz = 32768;
    yc.yaml_emit = NULL;

    dbg_before = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "ev_pri", dbg_lvl);
    printf("%s: %s before, %zu items ---->\n%s\n<----\n", __func__, dbg_lvl, dbg_before, buf);

    err_before = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "ev_pri", err_lvl);
    printf("%s: %s before, %zu items ---->\n%s\n<----\n", __func__, err_lvl, err_before, buf);

    ev_info(1);
    ev_warn(1);
    ev_err(1);

    dbg_after = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "ev_pri", dbg_lvl);
    printf("%s: %s before, %zu items ---->\n%s\n<----\n", __func__, dbg_lvl, dbg_after, buf);

    err_after = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, "ev_pri", err_lvl);
    printf("%s: %s before, %zu items ---->\n%s\n<----\n", __func__, err_lvl, err_after, buf);

    ASSERT_EQ(dbg_after - dbg_before, 3);
    ASSERT_EQ(err_after - err_before, 1);

    free(buf);
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
    ASSERT_EQ(ev->ev_pri, HSE_LOGPRI_INFO);

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
    ASSERT_EQ(ev->ev_pri, HSE_LOGPRI_WARN);
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

/* 5. Test trip odometer timestamp
 */
MTF_DEFINE_UTEST(event_counter, ev_trip_odometer_timestamp)
{
    char                        direct_path[DT_PATH_MAX];
    struct event_counter *      ec;
    struct dt_element *         direct;
    atomic_ulong                before, after;
    const char *                phile = basename(__FILE__);
    size_t                      count;
    int                         line;
    int                         ret;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };

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

    /* Trip odometer should be zeroed */
    ASSERT_EQ(ec->ev_trip_odometer, 0);

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);
    ev_get_timestamp(&after);

    /* Now, execute the "Set" command, which should set the
     * trip odometer to equal the odometer, and initialize the
     * trip odometer's timestamp.
     */
    dsp.field = DT_FIELD_TRIP_ODOMETER;
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
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
    ret = timestamp_compare(&before, &ec->ev_trip_odometer_timestamp);
    ASSERT_TRUE(ret <= 0);

    ret = timestamp_compare(&after, &ec->ev_trip_odometer_timestamp);
    ASSERT_TRUE(ret >= 0);

    /* The trip odometer should now be set to 1 (copy of the odometer's
     * value at the time of the set operation.
     */
    ASSERT_EQ(ec->ev_trip_odometer, 1);
}

/* 6. Test trip odometer counter
 */
MTF_DEFINE_UTEST(event_counter, ev_trip_odometer_counter)
{
    char                        direct_path[DT_PATH_MAX];
    struct event_counter *      ec;
    struct dt_element *         direct;
    const char *                phile = basename(__FILE__);
    int                         line;
    int                         count;
    int                         i;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };

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

        if (i % 2) {
            /* Now, execute the "Set" command, which should set
             * the trip odometer to equal the odometer, and
             * update the trip odometer's timestamp.
             */
            dsp.field = DT_FIELD_TRIP_ODOMETER;
            count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
            ASSERT_EQ(count, 1);

            ASSERT_EQ(ec->ev_trip_odometer, i + 1);
        } else {
            /* The trip_odometer should lag by 1 */
            ASSERT_EQ(ec->ev_trip_odometer, i);
        }
    }
}

#define MY_BUF_SIZE 512
int
validate_buf(
    const char *          buf,
    size_t                bytes_in_buf,
    const char *          phile,
    const char *          func,
    int                   line,
    struct event_counter *ec)
{
    char        my_buf[MY_BUF_SIZE], *mb = my_buf;
    const char *b = buf;
    size_t      offset = 0;
    size_t      remaining;
    int         ret;
    int         i;

    memset(my_buf, 0, MY_BUF_SIZE);

    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "%s:\n", DT_PATH_EVENT + strlen(DT_PATH_ROOT) + 1);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining,
                       "- path: %s/%s/%s/%d\n", DT_PATH_EVENT, phile, func, line);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "  level: INFO\n");
    remaining = MY_BUF_SIZE - offset;

    offset +=
        snprintf(my_buf + offset, remaining, "  odometer: %lu\n", atomic_read(&ec->ev_odometer));
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "  odometer timestamp: ");
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf_timestamp(my_buf + offset, remaining, &ec->ev_odometer_timestamp);
    remaining = MY_BUF_SIZE - offset;

    offset += snprintf(my_buf + offset, remaining, "\n");
    remaining = MY_BUF_SIZE - offset;

    if (ec->ev_trip_odometer != 0) {
        offset += snprintf(
            my_buf + offset,
            remaining,
            "  trip odometer: %lu\n",
            atomic_read(&ec->ev_odometer) - ec->ev_trip_odometer);
        remaining = MY_BUF_SIZE - offset;

        offset += snprintf(my_buf + offset, remaining, "  trip odometer timestamp: ");
        remaining = MY_BUF_SIZE - offset;

        offset += snprintf_timestamp(my_buf + offset, remaining, &ec->ev_trip_odometer_timestamp);
        remaining = MY_BUF_SIZE - offset;

        offset += snprintf(my_buf + offset, remaining, "\n");
        remaining = MY_BUF_SIZE - offset;
    }

    offset += snprintf(my_buf + offset, remaining, "  source: events\n");

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

#define EV_EMIT_BUF_SIZE 512
/* 7. Test emit functionality
 */
MTF_DEFINE_UTEST(event_counter, ev_emit)
{
    const char *        phile = basename(__FILE__);
    char                direct_path[DT_PATH_MAX];
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    char *                      buf;
    struct dt_element *         direct;
    struct event_counter *      ec;
    size_t                      count;
    int                         line;
    int                         ret;
    bool                        rbool;

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
    ASSERT_NE(direct, NULL);

    ec = direct->dte_data;
    ASSERT_NE(ec, NULL);

    buf = calloc(1, EV_EMIT_BUF_SIZE);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = EV_EMIT_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 2);

    ret = validate_buf(buf, yc.yaml_offset, phile, __func__, line, ec);
    ASSERT_EQ(ret, 0);

    free(buf);

    rbool = ev_root_match_select_handler(NULL, NULL, NULL);
    ASSERT_EQ(rbool, true);
}

/* 8. Test count functionality
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

/* 13. Show that EC cannot be deleted.
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

/* 15. Test emit overflow protection
 */
MTF_DEFINE_UTEST(event_counter, ev_emit_overflow)
{
    const char *        phile = basename(__FILE__);
    char                direct_path[DT_PATH_MAX];
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    char *                      buf, *false_buf;
    struct dt_element *         direct;
    struct event_counter *      ec;
    size_t                      count;
    int                         line;
    int                         i;

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
    ASSERT_NE(direct, NULL);

    ec = direct->dte_data;
    ASSERT_NE(ec, NULL);

    /* Allocate a large buffer, and we will seed it with a known
     * value. We'll tell emit to use a small part of it, then
     * we'll check that the emit hasn't corrupted the out-lying
     * buffer.
     */
    buf = calloc(1, EV_EMIT_BUF_SIZE);
    ASSERT_NE(buf, NULL);

    memset(buf, 42, EV_EMIT_BUF_SIZE);
    false_buf = buf + FALSE_OFFSET;
    yc.yaml_buf = false_buf;
    yc.yaml_buf_sz = EV_EMIT_OVERFLOW_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_iterate_cmd(DT_OP_EMIT, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 2);

    for (i = 0; i < FALSE_OFFSET; i++) {
        if (buf[i] != 42) {
            fprintf(stderr, "%s: event at byte %d\n", __func__, i);
            ASSERT_TRUE(0);
        }
    }

    for (i = FALSE_OFFSET + EV_EMIT_OVERFLOW_BUF_SIZE; i < EV_EMIT_BUF_SIZE; i++) {
        if (buf[i] != 42) {
            fprintf(stderr, "%s: event at byte %d\n", __func__, i);
            ASSERT_TRUE(0);
        }
    }

    free(buf);
}

/* 17. Test fields that haven't been
 * implemented or are invalid
 */
MTF_DEFINE_UTEST(event_counter, ev_put_invalid_field)
{
    char                        direct_path[DT_PATH_MAX];
    const char *                phile = basename(__FILE__);
    int                         line;
    int                         count;
    struct dt_element *         direct, *dte;
    struct dt_set_parameters    dsp;
    union dt_iterate_parameters dip = {.dsp = &dsp };

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

    /* Get the current dt element struct
     * to use as reference for later comparisons
     */
    direct = dt_find(direct_path, 1);
    ASSERT_NE(direct, NULL);

    /* For each field val, test the following:
     * 1. the count is zero - i.e. SET didn't do anything
     *    on any of the nodes encountered.
     * 2. get the dte, and verify that it is not NULL
     * 3. Compare the retreived dte with direct (reference dt element)
     */
    dsp.field = DT_FIELD_CLEAR;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));

    dsp.field = DT_FIELD_ODOMETER_TIMESTAMP;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));

    dsp.field = DT_FIELD_TRIP_ODOMETER_TIMESTAMP;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));

    dsp.field = DT_FIELD_ODOMETER;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));

    dsp.field = DT_FIELD_INVALID;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));

    dsp.field = -2;
    dsp.value = "somevalue";
    count = dt_iterate_cmd(DT_OP_SET, direct_path, &dip, NULL, NULL, NULL);
    ASSERT_EQ(count, 0);
    dte = dt_find(direct_path, 1);
    ASSERT_NE(dte, NULL);
    if (dte)
        ASSERT_EQ(0, memcmp(dte, direct, sizeof(struct dt_element)));
}

/* 18. Test the match_select handlers
 */
MTF_DEFINE_UTEST(event_counter, ev_match_select_test)
{
    struct dt_element    dte;
    struct event_counter ec;
    bool                 boolean;

    memset(&dte, 0, sizeof(dte));
    memset(&ec, 0, sizeof(ec));
    dte.dte_data = &ec;
    dte.dte_ops = &event_counter_ops;

    /* make the EC 'come from a hse_logpri_warn message' */
    ec.ev_flags = EV_FLAGS_HSE_LOG;

    /* Should match with "hse_log" */
    boolean = ev_match_select_handler(&dte, "source", "hse_log");
    ASSERT_EQ(boolean, true);

    /* Should match with "all" */
    boolean = ev_match_select_handler(&dte, "source", "all");
    ASSERT_EQ(boolean, true);

    /* Should not match with "event_counter" */
    boolean = ev_match_select_handler(&dte, "source", "event_counter");
    ASSERT_EQ(boolean, false);

    /* Should not match with random other string */
    boolean = ev_match_select_handler(&dte, "source", "the_moon");
    ASSERT_EQ(boolean, false);

    /* Should not match if field is not 'source' */
    boolean = ev_match_select_handler(&dte, "src", "hse_log");
    ASSERT_EQ(boolean, false);

    /* make the EC not /come from a hse_log message' */
    ec.ev_flags = 0;

    /* Should not match with "hse_log" */
    boolean = ev_match_select_handler(&dte, "source", "hse_log");
    ASSERT_EQ(boolean, false);

    /* Should match with "all" */
    boolean = ev_match_select_handler(&dte, "source", "all");
    ASSERT_EQ(boolean, true);

    /* Should match with "event_counter" */
    boolean = ev_match_select_handler(&dte, "source", "events");
    ASSERT_EQ(boolean, true);

    /* Should not match with random other string */
    boolean = ev_match_select_handler(&dte, "source", "the_moon");
    ASSERT_EQ(boolean, false);

    /* Should not match if field is not 'source' */
    boolean = ev_match_select_handler(&dte, "src", "hse_log");
    ASSERT_EQ(boolean, false);
}

MTF_END_UTEST_COLLECTION(event_counter)
