/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/logging.h>

#include "../src/logging_util.h"
#include "../src/logging_impl.h"

__attribute((constructor(110))) static void
pre_platform_initialization(void)
{
    hse_logging_disable_init = true;
}

__attribute((destructor(110))) static void
unload(void)
{
    hse_logging_disable_init = false;
}

/* ========================================================================= */

/* Test Collection Definition */

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(logging_ut);

/* ------------------------------------------------------------------------- */

/* Normal initialization and teardown of logging */

MTF_DEFINE_UTEST(logging_ut, normal_init)
{
    int rc;

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(0, hse_logging_inf.mli_active);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);

    hse_logging_disable_init = false;
    rc = hse_logging_init();
    ASSERT_EQ(0, rc);

    ASSERT_NE(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_NE(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_NE(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(HSE_LOG_PRI_DEFAULT, hse_logging_control.mlc_cur_pri);

    hse_logging_fini();

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);
}

/* ------------------------------------------------------------------------- */

/* Error paths for initialization and teardown of logging */

int cbl_call_cnt = 0;

void
count_backstop_log_calls(const char *msg)
{
    ++cbl_call_cnt;
}

int
alloc_error_init_pre(struct mtf_test_info *info)
{
    int rc;

    rc = fail_nth_alloc_test_pre(info);
    if (rc)
        return rc;
    mtfm_logging_util_backstop_log_set(count_backstop_log_calls);
    return 0;
}

int
alloc_error_init_post(struct mtf_test_info *info)
{
    fail_nth_alloc_test_post(info);
    mtfm_logging_util_backstop_log_set(0);
    cbl_call_cnt = 0;

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(logging_ut, alloc_error_init, alloc_error_init_pre, alloc_error_init_post)
{
    merr_t rc;

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 0;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(1, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);
    ASSERT_EQ(0, hse_logging_inf.mli_active);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 1;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(2, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);
    ASSERT_EQ(0, hse_logging_inf.mli_active);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 2;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(3, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);
    ASSERT_EQ(0, hse_logging_inf.mli_active);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 3;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(4, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 4;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(5, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 5;
    rc = hse_logging_init();
    ASSERT_EQ(ENOMEM, merr_errno(rc));
    ASSERT_EQ(6, cbl_call_cnt);

    ASSERT_EQ(NULL, hse_logging_inf.mli_nm_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_fmt_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_sd_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_name_buf);
    ASSERT_EQ(NULL, hse_logging_inf.mli_value_buf);

    ASSERT_EQ(NULL, hse_logging_inf.mli_async.al_entries);
    ASSERT_EQ(NULL, hse_logging_inf.mli_async.al_wq);
    ASSERT_EQ(0, hse_logging_inf.mli_active);
    ASSERT_EQ(0, hse_logging_control.mlc_verbose);
    ASSERT_EQ(-1, hse_logging_control.mlc_cur_pri);

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 7;
    rc = hse_logging_init();
    ASSERT_EQ(0, rc);

    hse_logging_fini();
}

/* ------------------------------------------------------------------------- */

/* Initialization of logging when it's already been marked as initialized */

MTF_DEFINE_UTEST(logging_ut, busy_error_init)
{
    merr_t rc;

    hse_logging_inf.mli_active = 1;
    rc = hse_logging_init();
    ASSERT_EQ(EBUSY, merr_errno(rc));
    hse_logging_inf.mli_active = 0;
}

/* ------------------------------------------------------------------------- */

/*
 * Initialization of logging when it loses a race to another thread that is
 * also trying to initialize the logging subsystem. The hse_logging_init()
 * function initially acquires a spin lock protecting the state of the logging
 * subsystem and checks to see if it has already been initialized. This is
 * the check tested by the test instance "busy_error_init" above. After the
 * check the lock is dropped.
 *
 * If the logging subsystem was not yet initialized, then the code allocates
 * memory for the utility buffers used by the subsystem but we prefer to do
 * so w/o the spin lock being held. Thus we grab the spin lock after we do the
 * allocations, checks whether someone else already initialized the subsystem
 * (i.e., we lost a race) and if so frees the 3 buffers.
 *
 * This test instance marks the logging subsystem as initialized (active) on
 * the first allocation (so the called code thinks it's good to go to
 * initialize the subsystem. It then tracks the addresses returned by the
 * kmalloc calls and those given to the kfree calls for the error path.
 *
 * At the end, it asserts that the hse_logging_init() function correctly
 * freed all the memory it allocated during its race.
 */

int   g_allocated_cnt = 0;
void *g_allocated_ptrs[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; /* for growth */

void *
my_malloc(size_t sz)
{
    int index = g_allocated_cnt++;

    if (index == 0)
        hse_logging_inf.mli_active = 1;

    g_allocated_ptrs[index] = mtfm_allocation_malloc_getreal()(sz);

    return g_allocated_ptrs[index];
}

void
my_free(void *p)
{
    int i;

    for (i = 0; i < g_allocated_cnt; i++)
        if (g_allocated_ptrs[i] == p) {
            g_allocated_ptrs[i] = 0;
            break;
        }

    (mtfm_allocation_free_getreal())(p);
}

int
race_error_init_pre(struct mtf_test_info *info)
{
    mtfm_allocation_malloc_set(my_malloc);
    mtfm_allocation_free_set(my_free);
    return 0;
}

int
race_error_init_post(struct mtf_test_info *info)
{
    mtfm_allocation_malloc_set(0);
    mtfm_allocation_free_set(0);
    return 0;
}

MTF_DEFINE_UTEST_PREPOST(logging_ut, race_error_init, race_error_init_pre, race_error_init_post)
{
    merr_t rc;
    int    i;

    rc = hse_logging_init();
    ASSERT_EQ(EBUSY, merr_errno(rc));

    for (i = 0; i < g_allocated_cnt; i++)
        ASSERT_EQ(NULL, g_allocated_ptrs[i]);
}

MTF_END_UTEST_COLLECTION(logging_ut)
