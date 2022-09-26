/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc. All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/base.h>
#include <hse_util/err_ctx.h>
#include <hse_ikvdb/hse_gparams.h>

#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <hse/hse.h>

int         mtf_verify_flag;
int         mtf_verify_line;
const char *mtf_verify_file;

char mtf_kvdb_home[PATH_MAX];

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

static inline unsigned long
mtf_get_time_ns(void)
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

static inline int
mtf_time_delta_in_ms(unsigned long start, unsigned long stop)
{
    return (int)((stop - start) / 1000000);
}

int
mtf_main(int argc, char **argv, struct mtf_test_coll_info *tci)
{
    const char *progname = program_invocation_short_name;
    const char *paramv[] = { "socket.enabled=false" };
    char *      logging_level, *config = NULL, *argv_home = NULL;
    char        errbuf[1024];
    hse_err_t   err;
    int         c;

    static const struct option long_options[] = {
        { "logging-level", required_argument, NULL, 'l' }, { "help", no_argument, NULL, 'h' },
        { "one", required_argument, NULL, '1' },           { "home", required_argument, NULL, 'C' },
        { "config", required_argument, NULL, 'c' },        { 0, 0, 0, 0 },
    };

    tci->tci_named = NULL;

    while (-1 != (c = getopt_long(argc, argv, "+:1:hC:l:", long_options, NULL))) {
        switch (c) {
            case '1':
                tci->tci_named = optarg;
                break;

            case 'C':
                argv_home = optarg;
                break;

            case 'c':
                /* [HSE_REVISIT] cheap_test uses -c, so this is a bit wonky
             * (note that we can only get here via --config).
             */
                config = optarg;
                break;

            case 'h':
                printf("usage: %s [-l logging-level] [-1 testname] [-C home]\n", progname);
                printf("usage: %s -h\n", progname);
                exit(0);

            case 'l':
                hse_gparams.gp_logging.lp_level = atoi(optarg);
                break;

            case ':':
                fprintf(
                    stderr,
                    "%s: invalid argument for option '-%c', use -h for help\n",
                    progname,
                    optopt);
                exit(EX_USAGE);

            default: /* pass on to test */
                break;
        }
    }

    tci->tci_argc = argc;
    tci->tci_argv = argv;
    tci->tci_optind = optind;

    if (argv_home && !realpath(argv_home, mtf_kvdb_home)) {
        fprintf(
            stderr,
            "%s: failed to resolve home directory %s: %s\n",
            progname,
            argv_home,
            strerror(errno));
        return EX_OSERR;
    }

    err = hse_init(config, NELEM(paramv), paramv);
    if (err) {
        fprintf(
            stderr,
            "%s: hse_init failed: %s\n",
            progname,
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL));
        return EX_SOFTWARE;
    }

    logging_level = getenv("HSE_TEST_LOGGING_LEVEL");
    if (logging_level)
        hse_gparams.gp_logging.lp_level = atoi(logging_level);

    err = mtf_run_tests(tci);
    if (err) {
        fprintf(
            stderr,
            "%s: mtf_run_tests failed: %s\n",
            progname,
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL));
    }

    hse_fini();

    return err ? EX_SOFTWARE : 0;
}

/*
 * Given a struct mtf_test_coll_info pointer, run all the tests therein.
 */
merr_t
mtf_run_tests_preamble(struct mtf_test_coll_info *tci)
{
    struct mtf_test_info ti;

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
        return merr(EBADE);
    }
    mtf_print(tci, "[----------] Global test environment set-up.\n\n");
    mtf_print(tci, "[----------]\n");

    return 0;
}

int
mtf_run_test(
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

    start = mtf_get_time_ns();
    tci->tci_test_pointers[i](&ti);
    stop = mtf_get_time_ns();
    elapsed = mtf_time_delta_in_ms(start, stop);

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

merr_t
mtf_run_tests_postamble(struct mtf_test_coll_info *tci)
{
    struct mtf_test_info ti;

    ti.ti_coll = tci;
    ti.ti_name = "";
    ti.ti_index = 0;
    ti.ti_status = 1;

    if (tci->tci_post_run_hook && tci->tci_post_run_hook(&ti)) {
        mtf_print(tci, "post-run hook for %s failed, aborting run.\n", tci->tci_coll_name);
        return merr(EBADE);
    }
    mtf_print(tci, "[----------]\n\n");
    mtf_print(tci, "[----------] Global test environment tear-down.\n");

    return 0;
}

void
mtf_run_tests_wrapup(
    struct mtf_test_coll_info *tci,
    int                        success_cnt,
    int                        failed_cnt,
    int                        total_time)
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
}

merr_t
mtf_run_tests(struct mtf_test_coll_info *tci)
{
    int       success_cnt = 0, failed_cnt = 0;
    int       elapsed = 0, total_time = 0;
    hse_err_t err;
    int       i;

    reset_mtf_test_coll_info(tci);

    err = mtf_run_tests_preamble(tci);
    if (err)
        return err;

    for (i = 0; i < tci->tci_num_tests; ++i) {
        if (mtf_run_test(tci, i, &success_cnt, &failed_cnt, &elapsed)) {
            return merr(EBADE);
        }
        total_time += elapsed;
    }

    err = mtf_run_tests_postamble(tci);
    if (err)
        return err;

    mtf_run_tests_wrapup(tci, success_cnt, failed_cnt, total_time);

    return failed_cnt ? merr(EBADE) : 0;
}
