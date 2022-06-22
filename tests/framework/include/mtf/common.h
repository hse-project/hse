/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2021 Micron Technology, Inc. All rights reserved.
 */
#ifndef MTF_COMMON_H
#define MTF_COMMON_H

#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define MTF_PAGE_SIZE getpagesize()

#define ___MTF_MAX_VALUE_COUNT 1000
#define ___MTF_MAX_UTEST_INSTANCES 250
#define ___MTF_MAX_COLL_NAME_LENGTH 100

enum mtf_test_coll_state { ST_INITIALIZING, ST_READY, ST_RUNNING, ST_DONE, ST_ERROR };

enum mtf_read_state { RD_READY, RD_STARTED };

enum mtf_test_result { TR_NONE = 1, TR_PASS, TR_FAIL };

struct mtf_test_coll_info;
struct mtf_test_info;

extern int         mtf_verify_flag;
extern int         mtf_verify_line;
extern const char *mtf_verify_file;

typedef void (*test_function)(struct mtf_test_info *);

typedef int (*prepost_hook)(struct mtf_test_info *);

struct mtf_test_info {
    struct mtf_test_coll_info *ti_coll;
    const char *               ti_name;
    int                        ti_index;
    int                        ti_status;
};

struct mtf_test_coll_info {
    /* general test collection info */
    const char *tci_coll_name;
    int         tci_num_tests;
    const char *tci_named;
    int         tci_argc;
    char **     tci_argv;
    int         tci_optind;

    /* test collection overall state */
    enum mtf_test_coll_state tci_state;
    enum mtf_read_state      tci_res_rd_state;
    int                      tci_res_rd_index;
    enum mtf_read_state      tci_out_rd_state;
    unsigned long            tci_out_rd_offst;

    /* test collection pre-/post- run hooks */
    prepost_hook tci_pre_run_hook;
    prepost_hook tci_post_run_hook;

    /* individual test cases, names, and associated pre-/post- run hooks  */
    const char *  tci_test_names[___MTF_MAX_UTEST_INSTANCES];
    test_function tci_test_pointers[___MTF_MAX_UTEST_INSTANCES];
    prepost_hook  tci_test_prehooks[___MTF_MAX_UTEST_INSTANCES];
    prepost_hook  tci_test_posthooks[___MTF_MAX_UTEST_INSTANCES];

    /* test collection info for a particular tun */
    const char *         tci_failed_tests[___MTF_MAX_UTEST_INSTANCES];
    enum mtf_test_result tci_test_results[___MTF_MAX_UTEST_INSTANCES];
    void *               tci_outbuf;
    size_t               tci_outbuf_len;
    unsigned long        tci_outbuf_pos;

    void *tci_rock;
};

#define MTF_SET_ROCK(coll_name, rock) (_mtf_##coll_name##_tci.tci_rock = (void *)rock)

#define MTF_GET_ROCK(coll_name) (_mtf_##coll_name##_tci.tci_rock)

static inline int
inner_mtf_print(struct mtf_test_coll_info *tci, const char *fmt_str, ...)

{
    va_list args;
    char *  tgt = tci->tci_outbuf + tci->tci_outbuf_pos;
    size_t  rem = tci->tci_outbuf_len - tci->tci_outbuf_pos;
    int     bc;

    va_start(args, fmt_str);
    bc = vsnprintf(tgt, rem - 1, fmt_str, args);
    va_end(args);

    if (bc >= rem || bc < 0) {
        *tgt = 0;
        return -1;
    } else {
        tci->tci_outbuf_pos += (size_t)bc;
        return 0;
    }
}

#define mtf_print(tci, ...)  \
    do {                     \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
    } while (0)

#endif
