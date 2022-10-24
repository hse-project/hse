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

static merr_t
check_level(void *data, void *ctx)
{
    const struct event_counter *ec = data;
    const int level = *(int *)ctx;

    if (ec->ev_level != level)
        return merr(EINVAL);

    return 0;
}

/* 1. Test that the Event Counter macro creates an event counter that is
 * accessible via dt_access().
 */
MTF_DEFINE_UTEST(event_counter, ev_create_and_find)
{
    merr_t err;
    int    line, level;

    const char *phile = basename(__FILE__);
    char        path[DT_PATH_MAX];

    /* clang-format off */
    ev_warn(1); line = __LINE__;
    /* clang-format on */

    snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%d",
        EV_DT_PATH,
        phile,
        __func__,
        line);

    level = LOG_WARNING;
    err = dt_access(path, check_level, &level);
    ASSERT_EQ(0, merr_errno(err));
}

/**
 * timestamp_compare returns -1 if one < two, 0 if one == two, 1 if one > two
 */
int
timestamp_compare(ulong one, ulong two)
{
    if (one > two)
        return 1;
    else if (one == two)
        return 0;
    return -1;
}

static merr_t
check_timestamp(void *data, void *ctx)
{
    int ret;
    struct event_counter *ec = data;
    ulong *before = ctx;

    ret = timestamp_compare(*before, atomic_load(&ec->ev_odometer_timestamp));
    if (ret > 0)
        return merr(EINVAL);

    return 0;
}

static merr_t
retrieve_ec(void *data, void *ctx)
{
    struct event_counter **ec = ctx;

    *ec = data;

    return 0;
}

static merr_t
check_odometer(void *data, void *ctx)
{
    const struct event_counter *ec = data;
    const int odometer = *(int *)ctx;

    if (atomic_load(&ec->ev_odometer) != odometer)
        return merr(EINVAL);

    return 0;
}

/* Test odometer counter
 */
MTF_DEFINE_UTEST(event_counter, ev_odometer_counter)
{
    merr_t                err;
    char                  direct_path[DT_PATH_MAX];
    const char *          phile = basename(__FILE__);
    int                   line;
    int                   odometer;

    /* Create an EC using the macro. */
    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        EV_DT_PATH,
        phile,
        __func__,
        line);

    odometer = 1;
    err = dt_access(direct_path, check_odometer, &odometer);
    ASSERT_EQ(0, merr_errno(err));

    /* Now loop 10 times on a new event counter */
    for (int i = 0; i < 10; i++) {
        /* clang-format off */
        ev(1); line = __LINE__;
        /* clang-format on */
    }

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        EV_DT_PATH,
        phile,
        __func__,
        line);

    odometer = 10;
    err = dt_access(direct_path, check_odometer, &odometer);
    ASSERT_EQ(0, merr_errno(err));
}

/* Test odometer timestamp advance
 */
MTF_DEFINE_UTEST(event_counter, ev_timestamp_advance)
{
    struct event_counter *ec;
    char        direct_path[DT_PATH_MAX];
    const char *phile = basename(__FILE__);
    ulong       prev;
    int         line;
    int         i;

    /* Loop 10 times over the macro. Sleep a little between each
     * invocation, and watch that the timestamp advances correctly.
     */
    for (i = 0; i < 10; i++) {
        merr_t err;
        int odometer = i + 1;

        /* clang-format off */
        ev(1); line = __LINE__;
        /* clang-format on */

        /* Try to find the EC with a direct find */
        snprintf(
            direct_path,
            sizeof(direct_path),
            "%s/%s/%s/%d",
            EV_DT_PATH,
            phile,
            __func__,
            line);

        err = dt_access(direct_path, check_odometer, &odometer);
        ASSERT_EQ(0, merr_errno(err));

        err = dt_access(direct_path, retrieve_ec, &ec);
        ASSERT_EQ(0, merr_errno(err));

        if (i != 0) {
            err = dt_access(direct_path, check_timestamp, &prev);
            ASSERT_EQ(0, merr_errno(err));
        }

        prev = atomic_load(&ec->ev_odometer_timestamp);

        usleep(100 * 1000);
    }
}

merr_t
validate(
    cJSON *const root,
    const char *path,
    struct event_counter *const ec)
{
    cJSON *item;
    cJSON *elem;

    item = cJSON_GetArrayItem(root, 0);
    if (!cJSON_IsObject(item))
        return merr(EINVAL);

    elem = cJSON_GetObjectItemCaseSensitive(item, "path");
    if (!cJSON_IsString(elem))
        return merr(EINVAL);
    if (strcmp(cJSON_GetStringValue(elem), path) != 0)
        return merr(EINVAL);

    elem = cJSON_GetObjectItemCaseSensitive(item, "level");
    if (!cJSON_IsString(elem))
        return merr(EINVAL);
    if (strcmp(cJSON_GetStringValue(elem), "INFO") != 0)
        return merr(EINVAL);

    elem = cJSON_GetObjectItemCaseSensitive(item, "odometer");
    if (!cJSON_IsNumber(elem))
        return merr(EINVAL);
    if (cJSON_GetNumberValue(elem) != atomic_read(&ec->ev_odometer))
        return merr(EINVAL);

    elem = cJSON_GetObjectItemCaseSensitive(item, "odometer_timestamp");
    if (!cJSON_IsString(elem))
        return merr(EINVAL);

    return 0;
}

struct validate_args {
    const char *path;
    cJSON *root;
};

static merr_t
check_emit(void *data, void *ctx)
{
    struct event_counter *ec = data;
    const struct validate_args *args = ctx;

    return validate(args->root, args->path, ec);
}

/* Test emit functionality
 */
MTF_DEFINE_UTEST(event_counter, ev_emit)
{
    merr_t err;
    cJSON *root;
    const char *phile = basename(__FILE__);
    char direct_path[DT_PATH_MAX];
    size_t count;
    int line;
    struct validate_args args;

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
        EV_DT_PATH,
        phile,
        __func__,
        line);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_count(direct_path);
    ASSERT_EQ(1, count);

    err = dt_emit(direct_path, &root);
    ASSERT_EQ(0, merr_errno(err));

    args.path = direct_path;
    args.root = root;
    err = dt_access(direct_path, check_emit, &args);
    ASSERT_EQ(0, merr_errno(err));

    cJSON_Delete(root);
}

/* Test count functionality
 */
MTF_DEFINE_UTEST(event_counter, ev_counts)
{
    char   fuzzy_path[DT_PATH_MAX];
    size_t count;

    snprintf(fuzzy_path, sizeof(fuzzy_path), "%s/%s/%s",
             EV_DT_PATH, basename(__FILE__), __func__);

    /* Create an EC using the macro. */
    ev(1);

    /* Use dt_iterate_cmd to count it */
    count = dt_count(fuzzy_path);
    ASSERT_EQ(count, 1);

    /* Create several more ECs using the macro. */
    ev(1);
    ev(1);
    ev(1);

    count = dt_count(fuzzy_path);
    ASSERT_EQ(count, 4);
}

/* Show that EC cannot be deleted.
 */
MTF_DEFINE_UTEST(event_counter, ev_delete_protect)
{
    merr_t             err;
    const char *       phile = basename(__FILE__);
    char               direct_path[DT_PATH_MAX];
    int                line;

    /* Create an EC using the macro. */
    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    /* Try to find the EC with a direct find */
    snprintf(
        direct_path,
        sizeof(direct_path),
        "%s/%s/%s/%d",
        EV_DT_PATH,
        phile,
        __func__,
        line);

    /* Try to remove the EC */
    err = dt_remove(direct_path);
    ASSERT_EQ(EACCES, merr_errno(err));

    /* Should still be able to find it */
    err = dt_access(direct_path, NULL, NULL);
    ASSERT_EQ(0, merr_errno(err));
}

#define EV_EMIT_OVERFLOW_BUF_SIZE 20
#define FALSE_OFFSET 100

/* Test emit overflow protection
 */
MTF_DEFINE_UTEST(event_counter, ev_emit_overflow)
{
    merr_t err;
    cJSON *root;
    const char *phile = basename(__FILE__);
    char direct_path[DT_PATH_MAX];
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
        EV_DT_PATH,
        phile,
        __func__,
        line);

    /* Generate an emit command with dt_iterate_cmd */
    count = dt_count(direct_path);
    ASSERT_EQ(1, count);

    err = dt_emit(direct_path, &root);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, cJSON_GetArraySize(root));

    cJSON_Delete(root);
}

MTF_END_UTEST_COLLECTION(event_counter)
