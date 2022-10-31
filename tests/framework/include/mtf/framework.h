/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019,2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef MTF_FRAMEWORK_H
#define MTF_FRAMEWORK_H

#include <hse/hse.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/hse_gparams.h>

#if HSE_MOCKING
#include <mock/api.h>
#endif

#include "common.h"
#include "conditions.h"
#include "framework_cp.h"

#include <math.h>
#include <time.h>
#include <sysexits.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>

extern int         mtf_verify_flag;
extern int         mtf_verify_line;
extern const char *mtf_verify_file;

extern char mtf_kvdb_home[PATH_MAX];

#define MTF_MODULE_UNDER_TEST(module) const char *___mtf_module_under_test = #module

/* ========================================================================= */

#define ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(name, pre_hook, post_hook)            \
                                                                                         \
    int utest_collection_##name __attribute__((unused)) = 0;                             \
                                                                                         \
    struct mtf_test_coll_info    _mtf_##name##_tci = { .tci_coll_name = #name,           \
                                                    .tci_num_tests = 0,               \
                                                    .tci_pre_run_hook = (pre_hook),   \
                                                    .tci_post_run_hook = (post_hook), \
                                                    .tci_state = ST_INITIALIZING,     \
                                                    .tci_res_rd_state = RD_READY,     \
                                                    .tci_res_rd_index = 0,            \
                                                    .tci_out_rd_state = RD_READY,     \
                                                    .tci_rock = 0 };                  \
    static uint16_t __mtf_tci_testidx HSE_MAYBE_UNUSED = 0;

#define ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, pre_hook, post_hook)            \
    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(name, pre_hook, post_hook)         \
                                                                                  \
    union ___mtf_floatint {                                                       \
        float fv;                                                                 \
        int   iv;                                                                 \
    };                                                                            \
                                                                                  \
    __attribute__((unused)) static int ___mtf_almost_equal_ulps_and_abs(          \
        float x, float y, float max_diff, int max_ulps_diff)                      \
    {                                                                             \
        union ___mtf_floatint x_fi = { .fv = x };                                 \
        union ___mtf_floatint y_fi = { .fv = y };                                 \
                                                                                  \
        int   x_i = x_fi.iv;                                                      \
        int   y_i = y_fi.iv;                                                      \
        float x_f = x_fi.fv;                                                      \
        float y_f = y_fi.fv;                                                      \
                                                                                  \
        float abs_diff = fabsf(x_f - y_f);                                        \
        if (abs_diff <= max_diff)                                                 \
            return 1;                                                             \
                                                                                  \
        if (((x_i >> 31) != 0) != ((y_i >> 31) != 0))                             \
            return 0;                                                             \
                                                                                  \
        if (abs(x_i - y_i) <= max_ulps_diff)                                      \
            return 1;                                                             \
                                                                                  \
        return 0;                                                                 \
    }                                                                             \
    /*                                                                          \
     * Constructor priority for user test init routines.                        \
     */ \
    enum { __MTF_TEST_PRI = 500 };

#define MTF_BEGIN_UTEST_COLLECTION(name) ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, 0, 0)

#define MTF_BEGIN_UTEST_COLLECTION_PRE(name, pre_hook) \
    ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, pre_hook, 0)

#define MTF_BEGIN_UTEST_COLLECTION_POST(name, post_hook) \
    ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, 0, post_hook)

#define MTF_BEGIN_UTEST_COLLECTION_PREPOST(name, pre_hook, post_hook) \
    ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, pre_hook, post_hook)

/* ========================================================================= */

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                    \
                                                                                                \
    static int ___mtf_##coll_name##_##test_name##_check __attribute__((unused)) =               \
        sizeof(utest_collection_##coll_name);                                                   \
                                                                                                \
    void test_name(struct mtf_test_info *);                                                     \
                                                                                                \
    __attribute__((                                                                             \
        constructor(__COUNTER__ + __MTF_TEST_PRI))) static void ___mtf_##test_name##_init(void) \
    {                                                                                           \
        int index = __mtf_tci_testidx++;                                                        \
                                                                                                \
        if (index >= ___MTF_MAX_UTEST_INSTANCES) {                                              \
            fprintf(stderr, "max unit test count (%d) exceeded, aborting", index);              \
            exit(1);                                                                            \
        }                                                                                       \
        _mtf_##coll_name##_tci.tci_test_pointers[index] = (test_name);                          \
        _mtf_##coll_name##_tci.tci_test_names[index] = #test_name;                              \
        _mtf_##coll_name##_tci.tci_test_prehooks[index] = (pre_hook);                           \
        _mtf_##coll_name##_tci.tci_test_posthooks[index] = (post_hook);                         \
        _mtf_##coll_name##_tci.tci_num_tests += 1;                                              \
    }                                                                                           \
                                                                                                \
    void test_name(struct mtf_test_info *lcl_ti)

#define MTF_DEFINE_UTEST(coll_name, test_name) ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, 0, 0)

#define MTF_DEFINE_UTEST_PRE(coll_name, test_name, pre_hook) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, 0)

#define MTF_DEFINE_UTEST_POST(coll_name, test_name, post_hook) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, 0, post_hook)

#define MTF_DEFINE_UTEST_PREPOST(coll_name, test_name, pre_hook, post_hook) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)

/* ------------------------------------------------------------------------- */

merr_t
mtf_run_tests(struct mtf_test_coll_info *tci);

int
mtf_main(int argc, char **argv, struct mtf_test_coll_info *tci);

#if HSE_MOCKING
#define mtf_mapi_init() mapi_init()
#else
#define mtf_mapi_init()
#endif

#define MTF_END_UTEST_COLLECTION(coll_name)                   \
    int main(int argc, char **argv)                           \
    {                                                         \
        mtf_mapi_init();                                      \
        return mtf_main(argc, argv, &_mtf_##coll_name##_tci); \
    }

/* ------------------------------------------------------------------------- */

/*
 * Given a struct mtf_test_coll_info pointer, run all the tests therein.
 */

merr_t
mtf_run_tests_preamble(struct mtf_test_coll_info *tci);

int
mtf_run_test(
    struct mtf_test_coll_info *tci,
    int                        test_index,
    int *                      success_cnt,
    int *                      failed_cnt,
    int *                      elapsed_time);

merr_t
mtf_run_tests_postamble(struct mtf_test_coll_info *tci);

void
mtf_run_tests_wrapup(
    struct mtf_test_coll_info *tci,
    int                        success_cnt,
    int                        failed_cnt,
    int                        total_time);

merr_t
mtf_run_tests(struct mtf_test_coll_info *tci);

/* ------------------------------------------------------------------------- */

/* ========================================================================= */

enum MTF_SET_TYPE { MTF_ST_IRANGE = 1, MTF_ST_IVALUES, MTF_ST_EVALUES, MTF_ST_BOOLS };

#define MTF_DEFINE_IVALUES(var, length, vector)        \
    int ___mtf_##var##_values[___MTF_MAX_VALUE_COUNT]; \
    int ___mtf_##var##_length;                         \
                                                       \
    int ___mtf_##var##_generator(void)                 \
    {                                                  \
        int i;                                         \
                                                       \
        for (i = 0; i < length; ++i) {                 \
            ___mtf_##var##_values[i] = vector[i];      \
        }                                              \
        ___mtf_##var##_length = i;                     \
                                                       \
        return 1;                                      \
    }

/* ------------------------------------------------------------------------- */

#define MTF_DEFINE_EVALUES(type, var, length, vector)  \
    int ___mtf_##var##_values[___MTF_MAX_VALUE_COUNT]; \
    int ___mtf_##var##_length;                         \
                                                       \
    int ___mtf_##var##_generator(void)                 \
    {                                                  \
        int i;                                         \
                                                       \
        for (i = 0; i < length; ++i) {                 \
            ___mtf_##var##_values[i] = vector[i];      \
        }                                              \
        ___mtf_##var##_length = i;                     \
                                                       \
        return 1;                                      \
    }

/* ------------------------------------------------------------------------- */
#define MTF_DEFINE_BOOLS(var)         \
    int ___mtf_##var##_values[2];     \
    int ___mtf_##var##_length;        \
                                      \
    int ___mtf_##var##_generator()    \
    {                                 \
        ___mtf_##var##_values[0] = 1; \
        ___mtf_##var##_values[1] = 0; \
        ___mtf_##var##_length = 2;    \
                                      \
        return 1;                     \
    }

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_IRANGE(var, begin, end, step) \
    int ___mtf_##var##_values[___MTF_MAX_VALUE_COUNT];    \
    int ___mtf_##var##_length;                            \
                                                          \
    int ___mtf_##var##_generator(void)                    \
    {                                                     \
        int i = 0, value = begin;                         \
                                                          \
        while (value < end) {                             \
            ___mtf_##var##_values[i++] = value;           \
            value += step;                                \
        }                                                 \
        ___mtf_##var##_length = i;                        \
                                                          \
        return 1;                                         \
    }

#define MTF_DEFINE_IRANGE(var, begin, end) ___MTF_INNER_DEFINE_IRANGE(var, begin, end, 1)

#define MTF_DEFINE_IRANGE_STEP(var, begin, end, step) \
    ___MTF_INNER_DEFINE_IRANGE(var, begin, end, step)

/* ========================================================================= */

#define ___MTF_VALUE_DECLARE(N, type, var) \
    int  index##N;                         \
    type var;

#define ___MTF_CALL_GENERATOR(var)     \
    if (!___mtf_##var##_generator()) { \
        lcl_ti->ti_status = 0;         \
        goto early_return_check;       \
    }

#define ___MTF_CP_FOR(N, var)                                          \
    for (index##N = 0; index##N < ___mtf_##var##_length; ++index##N) { \
        var = ___mtf_##var##_values[index##N];

/* ------------------------------------------------------------------------- */

#endif
