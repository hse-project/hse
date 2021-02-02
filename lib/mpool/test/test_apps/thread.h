/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_TEST_THREAD_H
#define MPOOL_TEST_THREAD_H

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

enum thread_state { NOT_STARTED, STARTED };
extern volatile enum thread_state thread_state;

typedef void *(thread_func_t)(void *arg);

struct thread_args {
    int                instance;
    pthread_mutex_t   *start_mutex;
    pthread_cond_t    *start_line;
    atomic_t          *start_cnt;
    void              *arg;
};

struct thread_resp {
    int    instance;
    merr_t err;
    void  *resp;
};

merr_t
thread_create(
    int                    thread_cnt,
    thread_func_t          func,
    struct thread_args    *targs,
    struct thread_resp    *tresp);

void thread_wait_for_start(struct thread_args *targs);

#endif /* MPOOL_TEST_THREAD_H */

