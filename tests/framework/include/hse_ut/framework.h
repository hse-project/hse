/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_UTEST_FRAMEWORK_H
#define HSE_UTEST_FRAMEWORK_H

#include <hse/hse.h>

#include <hse_util/logging.h>
#ifdef HSE_UNIT_TEST_MODE
#include <hse_test_support/mock_api.h>
#endif

#include "common.h"
#include "conditions.h"
#include "framework_cp.h"

#include <math.h>
#include <time.h>

/*
 * These values must remain 5 bytes long. They form part of the public API of
 * the testing framework so changing them is actively discouraged. At the
 * very least, all the protocol strings have to have the same length.
 */
const int   STATUS_CODE_LEN = 5;
const char *FINAL_SUCCESS = "200\r\n";
const char *PARTIAL_SUCCESS = "206\r\n";

int         mtf_verify_flag;
int         mtf_verify_line;
const char *mtf_verify_file;

#define MTF_MODULE_UNDER_TEST(module) const char *___mtf_module_under_test = #module

/* ========================================================================= */

#define ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(name, pre_hook, post_hook)        \
                                                                                     \
    int utest_collection_##name __attribute__((unused)) = 0;                         \
                                                                                     \
    struct mtf_test_coll_info _mtf_##name##_tci = {.tci_coll_name = #name,           \
                                                   .tci_num_tests = 0,               \
                                                   .tci_pre_run_hook = (pre_hook),   \
                                                   .tci_post_run_hook = (post_hook), \
                                                   .tci_state = ST_INITIALIZING,     \
                                                   .tci_res_rd_state = RD_READY,     \
                                                   .tci_res_rd_index = 0,            \
                                                   .tci_out_rd_state = RD_READY,     \
                                                   .tci_rock = 0 };                  \
    static u16 __mtf_tci_testidx HSE_MAYBE_UNUSED = 0;

#define ___MTF_INNER_BEGIN_UTEST_COLLECTION(name, pre_hook, post_hook)                                                                                                                                                                                                                                                                  \
    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(name, pre_hook, post_hook)                                                                                                                                                                                                                                                               \
                                                                                                                                                                                                                                                                                                                                        \
    union ___mtf_floatint {                                                                                                                                                                                                                                                                                                             \
        float fv;                                                                                                                                                                                                                                                                                                                       \
        int   iv;                                                                                                                                                                                                                                                                                                                       \
    };                                                                                                                                                                                                                                                                                                                                  \
                                                                                                                                                                                                                                                                                                                                        \
    __attribute__((unused)) static int ___mtf_almost_equal_ulps_and_abs(                                                                                                                                                                                                                                                                \
        float x, float y, float max_diff, int max_ulps_diff)                                                                                                                                                                                                                                                                            \
    {                                                                                                                                                                                                                                                                                                                                   \
        union ___mtf_floatint x_fi = {.fv = x };                                                                                                                                                                                                                                                                                        \
        union ___mtf_floatint y_fi = {.fv = y };                                                                                                                                                                                                                                                                                        \
                                                                                                                                                                                                                                                                                                                                        \
        int   x_i = x_fi.iv;                                                                                                                                                                                                                                                                                                            \
        int   y_i = y_fi.iv;                                                                                                                                                                                                                                                                                                            \
        float x_f = x_fi.fv;                                                                                                                                                                                                                                                                                                            \
        float y_f = y_fi.fv;                                                                                                                                                                                                                                                                                                            \
                                                                                                                                                                                                                                                                                                                                        \
        float abs_diff = fabsf(x_f - y_f);                                                                                                                                                                                                                                                                                              \
        if (abs_diff <= max_diff)                                                                                                                                                                                                                                                                                                       \
            return 1;                                                                                                                                                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                                                                        \
        if (((x_i >> 31) != 0) != ((y_i >> 31) != 0))                                                                                                                                                                                                                                                                                   \
            return 0;                                                                                                                                                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                                                                        \
        if (abs(x_i - y_i) <= max_ulps_diff)                                                                                                                                                                                                                                                                                            \
            return 1;                                                                                                                                                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                                                                        \
        return 0;                                                                                                                                                                                                                                                                                                                       \
    }                                                                                                                                                                                                                                                                                                                                   \
    /*                                                                            \
 * Constructor priority for user test init routines.                          \
 * This priority value must be higher than all the constructor priorities     \
 * in our product code and that's why 500 was chosen.                         \
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

#define ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                     \
                                                                                                 \
    static int ___mtf_##coll_name##_##test_name##_check __attribute__((unused)) =                \
        sizeof(utest_collection_##coll_name);                                                    \
                                                                                                 \
    void test_name(struct mtf_test_info *);                                                      \
                                                                                                 \
    __attribute__(                                                                               \
        (constructor(__COUNTER__ + __MTF_TEST_PRI))) static void ___mtf_##test_name##_init(void) \
    {                                                                                            \
        int index = __mtf_tci_testidx++;                                                         \
                                                                                                 \
        if (index >= ___MTF_MAX_UTEST_INSTANCES) {                                               \
            fprintf(stderr, "max unit test count (%d) exceeded, aborting", index);               \
            exit(1);                                                                             \
        }                                                                                        \
        _mtf_##coll_name##_tci.tci_test_pointers[index] = (test_name);                           \
        _mtf_##coll_name##_tci.tci_test_names[index] = #test_name;                               \
        _mtf_##coll_name##_tci.tci_test_prehooks[index] = (pre_hook);                            \
        _mtf_##coll_name##_tci.tci_test_posthooks[index] = (post_hook);                          \
        _mtf_##coll_name##_tci.tci_num_tests += 1;                                               \
    }                                                                                            \
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

static inline unsigned long
___mtf_get_time_ns(void)
{
    int             rc;
    unsigned long   result;
    struct timespec ts;

    rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc == 0)
        result = (unsigned long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    else
        result = 0;
    return result;
}

/* ------------------------------------------------------------------------- */

static inline int
___mtf_time_delta_in_ms(unsigned long start, unsigned long stop)
{
    return (int)((stop - start) / 1000000);
}

/* ------------------------------------------------------------------------- */

static inline void
reset_mtf_test_coll_info(struct mtf_test_coll_info *tci)
{
    int i;
    for (i = 0; i < tci->tci_num_tests; ++i) {
        tci->tci_failed_tests[i] = 0;
        tci->tci_test_results[i] = TR_NONE;
    }

    if (tci->tci_outbuf)
        memset(tci->tci_outbuf, 0, tci->tci_outbuf_len);
    tci->tci_outbuf_pos = 0;
}

/* ------------------------------------------------------------------------- */

int
run_tests(void *tci);

static inline char
test_result_to_char(enum mtf_test_result result)
{
    if (result == TR_NONE)
        return '-';
    else if (result == TR_PASS)
        return 'p';
    else if (result == TR_FAIL)
        return 'f';
    else
        return '!';
}

__attribute__((unused)) static ssize_t
inner_attr_show(struct mtf_test_coll_info *tci, const char *attr_name, char *buf)
{
    int cnt = 0;

    if (strcmp(attr_name, "status") == 0) {
        switch (tci->tci_state) {
            case ST_INITIALIZING:
                cnt = sprintf(buf, "initializing\n");
                break;
            case ST_READY:
                cnt = sprintf(buf, "ready\n");
                break;
            case ST_RUNNING:
                cnt = sprintf(buf, "running\n");
                break;
            case ST_DONE:
                cnt = sprintf(buf, "done\n");
                break;
            case ST_ERROR:
                cnt = sprintf(buf, "error\n");
                break;
        }
    } else if (strcmp(attr_name, "result") == 0) {
        if (tci->tci_state == ST_DONE) {
            int rem = MTF_PAGE_SIZE - STATUS_CODE_LEN;
            int cw;
            int i;

            /*
             * If there are no records we still need a NULL to terminate the
             * result string which will consist solely of FINAL_SUCCESS.
             */
            memset(buf, 0, STATUS_CODE_LEN + 1);
            cnt = STATUS_CODE_LEN;

            if (tci->tci_res_rd_state == RD_READY) {
                tci->tci_res_rd_index = 0;
                tci->tci_res_rd_state = RD_STARTED;
            }

            for (i = tci->tci_res_rd_index; i < tci->tci_num_tests; ++i) {
                char tr = test_result_to_char(tci->tci_test_results[i]);

                cw = snprintf(buf + cnt, rem, "%d\t%s\t%c\n", i, tci->tci_test_names[i], tr);
                if (cw < rem) {
                    rem -= cw;
                    cnt += cw;
                } else {
                    buf[cnt] = 0;
                    tci->tci_res_rd_index = i;
                    break;
                }
            }

            if (i == tci->tci_num_tests) {
                /* all remaining results have been written */
                memcpy(buf, FINAL_SUCCESS, STATUS_CODE_LEN);
                tci->tci_res_rd_index = 0;
                tci->tci_res_rd_state = RD_READY;
            } else {
                memcpy(buf, PARTIAL_SUCCESS, STATUS_CODE_LEN);
            }
        }
    } else if (strcmp(attr_name, "output") == 0) {
        if (tci->tci_state == ST_DONE) {
            int sz;
            int complete;
            int rem = MTF_PAGE_SIZE - STATUS_CODE_LEN;

            /*
             * If there are no records we still need a NULL to terminate the
             * result string which will consist solely of FINAL_SUCCESS.
             */
            memset(buf, 0, STATUS_CODE_LEN + 1);
            cnt = STATUS_CODE_LEN;

            if (tci->tci_out_rd_state == RD_READY) {
                tci->tci_out_rd_state = RD_STARTED;
                tci->tci_out_rd_offst = 0;
            }

            sz = tci->tci_outbuf_pos - tci->tci_out_rd_offst;
            if (sz < (rem - 1)) {
                complete = 1;
            } else {
                sz = rem - 1;
                complete = 0;
            }

            memcpy(buf + STATUS_CODE_LEN, tci->tci_outbuf + tci->tci_out_rd_offst, sz);
            while (buf[STATUS_CODE_LEN + sz - 1] != '\n')
                --sz;
            buf[STATUS_CODE_LEN + sz] = 0;
            tci->tci_out_rd_offst += sz;

            if (complete) {
                memcpy(buf, FINAL_SUCCESS, STATUS_CODE_LEN);
                tci->tci_out_rd_state = RD_READY;
                tci->tci_out_rd_offst = 0;
            } else {
                memcpy(buf, PARTIAL_SUCCESS, STATUS_CODE_LEN);
            }
            cnt = STATUS_CODE_LEN + sz;
        }
    }

    return cnt;
}

#define MTF_END_UTEST_COLLECTION(coll_name)                                        \
                                                                                   \
    int main(int argc, char **argv)                                                \
    {                                                                              \
        char *verbose, *logpri;                                                    \
        int   c, rc;                                                               \
                                                                                   \
        rc = hse_kvdb_init();                                                      \
        if (rc)                                                                    \
            return rc;                                                             \
                                                                                   \
        logpri = getenv("HSE_UT_LOGPRI");                                          \
        if (logpri)                                                                \
            hse_logging_control.mlc_cur_pri = atoi(logpri);                        \
                                                                                   \
        verbose = getenv("HSE_UT_VERBOSE");                                        \
        if (verbose)                                                               \
            hse_openlog(argv[0], atoi(verbose));                                   \
                                                                                   \
        _mtf_##coll_name##_tci.tci_named = 0;                                      \
        while (-1 != (c = getopt(argc, argv, "+:1:d:hv"))) {                       \
            switch (c) {                                                           \
                case 'h':                                                          \
                    printf("usage: %s [-v] [-d logpri] [-1 testname]\n", argv[0]); \
                    printf("usage: %s -h\n", argv[0]);                             \
                    exit(0);                                                       \
                                                                                   \
                case 'd':                                                          \
                    hse_logging_control.mlc_cur_pri = atoi(optarg);                \
                    break;                                                         \
                                                                                   \
                case 'v':                                                          \
                    hse_openlog(argv[0], 1);                                       \
                    break;                                                         \
                                                                                   \
                case '1':                                                          \
                    _mtf_##coll_name##_tci.tci_named = optarg;                     \
                    break;                                                         \
                                                                                   \
                case ':':                                                          \
                    printf(                                                        \
                        "invalid argument for option '-%c',"                       \
                        " use -h for help\n",                                      \
                        optopt);                                                   \
                    exit(64); /* EX_USAGE */                                       \
                                                                                   \
                default: /* silently ignore all other errors */                    \
                    break;                                                         \
            }                                                                      \
        }                                                                          \
                                                                                   \
        _mtf_##coll_name##_tci.tci_argc = argc;                                    \
        _mtf_##coll_name##_tci.tci_argv = argv;                                    \
                                                                                   \
        rc = run_tests(&_mtf_##coll_name##_tci);                                   \
                                                                                   \
        hse_kvdb_fini();                                                           \
                                                                                   \
        return rc;                                                                 \
    }

/* ------------------------------------------------------------------------- */

/*
 * Given a struct mtf_test_coll_info pointer, run all the tests therein.
 */

int
run_tests_preamble(struct mtf_test_coll_info *tci)
{
    struct mtf_test_info ti;

#if HSE_UNIT_TEST_MODE
    mapi_init();
#endif

    reset_mtf_test_coll_info(tci);

    ti.ti_coll = tci;
    ti.ti_name = "";
    ti.ti_index = 0;
    ti.ti_status = 1;

    mtf_print(
        tci,
        "[==========] Running %d test%s from collection %s.\n",
        tci->tci_named ? 1 : tci->tci_num_tests,
        tci->tci_named ? "" : "s",
        tci->tci_coll_name);

    if (tci->tci_pre_run_hook && tci->tci_pre_run_hook(&ti)) {
        mtf_print(tci, "pre-run hook for %s failed, aborting run.\n", tci->tci_coll_name);
        return -1;
    }
    mtf_print(tci, "[----------] Global test environment set-up.\n\n");
    mtf_print(tci, "[----------]\n");

    return 0;
}

int
run_test(
    struct mtf_test_coll_info *tci,
    int                        test_index,
    int *                      success_cnt,
    int *                      failed_cnt,
    int *                      elapsed_time)
{
    struct mtf_test_info ti;
    unsigned long        start, stop;
    int                  elapsed;
    int                  i = test_index;

    mtf_verify_flag = 0;
    ti.ti_coll = tci;
    ti.ti_index = i;
    ti.ti_name = tci->tci_test_names[i];
    ti.ti_status = 1;

    if (tci->tci_named && strcmp(tci->tci_named, ti.ti_name)) {
        tci->tci_test_results[i] = TR_NONE;
        return 0;
    }

    mtf_print(tci, "[ RUN      ] %s.%s\n", tci->tci_coll_name, ti.ti_name);
    if (tci->tci_test_prehooks[i] && tci->tci_test_prehooks[i](&ti)) {
        mtf_print(
            tci, "pre-run hook for test %s.%s failed, skipping.\n", tci->tci_coll_name, ti.ti_name);
        tci->tci_test_results[i] = TR_FAIL;
        tci->tci_failed_tests[*failed_cnt] = ti.ti_name;
        ++(*failed_cnt);
        return 0;
    }

    start = ___mtf_get_time_ns();
    tci->tci_test_pointers[i](&ti);
    stop = ___mtf_get_time_ns();
    elapsed = ___mtf_time_delta_in_ms(start, stop);

    if (tci->tci_test_posthooks[i] && tci->tci_test_posthooks[i](&ti)) {
        mtf_print(tci, "post-run hook for test %s.%s failed.\n", tci->tci_coll_name, ti.ti_name);
        tci->tci_test_results[i] = TR_FAIL;
        tci->tci_failed_tests[*failed_cnt] = ti.ti_name;
        ti.ti_status = 0;
        ++(*failed_cnt);
    }

    if (mtf_verify_flag)
        mtf_print(
            tci,
            "verify_flag check for test %s.%s failed\nat %s:%d.\n",
            tci->tci_coll_name,
            ti.ti_name,
            mtf_verify_file,
            mtf_verify_line);

    if (ti.ti_status && mtf_verify_flag == 0) {
        ++(*success_cnt);
        tci->tci_test_results[i] = TR_PASS;
        mtf_print(tci, "[       OK ] %s.%s (%d ms)\n", tci->tci_coll_name, ti.ti_name, elapsed);
    } else {
        tci->tci_failed_tests[*failed_cnt] = ti.ti_name;
        ++(*failed_cnt);
        tci->tci_test_results[i] = TR_FAIL;
        mtf_print(tci, "[  FAILED  ] %s.%s (%d ms)\n", tci->tci_coll_name, ti.ti_name, 0);
    }

    *elapsed_time = elapsed;

    return 0;
}

int
run_tests_postamble(struct mtf_test_coll_info *tci)
{
    struct mtf_test_info ti;

    ti.ti_coll = tci;
    ti.ti_name = "";
    ti.ti_index = 0;
    ti.ti_status = 1;

    if (tci->tci_post_run_hook && tci->tci_post_run_hook(&ti)) {
        mtf_print(tci, "post-run hook for %s failed, aborting run.\n", tci->tci_coll_name);
        return -1;
    }
    mtf_print(tci, "[----------]\n\n");
    mtf_print(tci, "[----------] Global test environment tear-down.\n");

    return 0;
}

int
run_tests_wrapup(struct mtf_test_coll_info *tci, int success_cnt, int failed_cnt, int total_time)
{
    int i;

    mtf_print(
        tci,
        "[==========] %d test%s from collection %s ran "
        "(%d ms total).\n",
        tci->tci_named ? 1 : tci->tci_num_tests,
        tci->tci_named ? "" : "s",
        tci->tci_coll_name,
        total_time);

    mtf_print(tci, "[  PASSED  ] %d test%s.\n", success_cnt, ((success_cnt == 1) ? "" : "s"));

    if (failed_cnt > 0) {
        mtf_print(
            tci,
            "[  FAILED  ] %d test%s, listed below:\n",
            failed_cnt,
            ((failed_cnt == 1) ? "" : "s"));
        for (i = 0; i < failed_cnt; ++i) {
            mtf_print(tci, "[  FAILED  ] %s.%s\n", tci->tci_coll_name, tci->tci_failed_tests[i]);
        }
        mtf_print(tci, "\n %d FAILED TEST%s\n", failed_cnt, ((failed_cnt == 1) ? "" : "S"));
    }

    return 0;
}

int
run_tests(void *arg)
{
    struct mtf_test_coll_info *tci = (struct mtf_test_coll_info *)arg;

    int success_cnt = 0, failed_cnt = 0;
    int elapsed = 0, total_time = 0;
    int i;

    reset_mtf_test_coll_info(tci);

    if (run_tests_preamble(tci)) {
        return -1;
    }

    for (i = 0; i < tci->tci_num_tests; ++i) {
        if (run_test(tci, i, &success_cnt, &failed_cnt, &elapsed)) {
            return -1;
        }
        total_time += elapsed;
    }

    if (run_tests_postamble(tci)) {
        return -1;
    }

    run_tests_wrapup(tci, success_cnt, failed_cnt, total_time);

    return (failed_cnt == 0) ? 0 : -1;
}

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
