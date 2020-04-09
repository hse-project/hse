/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_private.h"

struct c1_thread {
    struct workqueue_struct *c1thr_wq;
    struct work_struct       c1thr_wqs;
    void (*c1thr_fp)(void *arg);
    void *c1thr_arg;
};

merr_t
c1_thread_create(const char *thrname, void (*fp)(void *arg), void *arg, struct c1_thread **out)
{
    struct c1_thread *thr;
    merr_t            err;

    thr = malloc(sizeof(*thr));
    if (!thr)
        return merr(ev(ENOMEM));

    thr->c1thr_wq = alloc_workqueue(thrname, 0, 1);
    if (!thr->c1thr_wq) {
        err = merr(ev(ENOMEM));
        goto err_exit;
    }

    thr->c1thr_fp = fp;
    thr->c1thr_arg = arg;

    *out = thr;

    return 0;

err_exit:

    free(thr);
    return err;
}

merr_t
c1_thread_destroy(struct c1_thread *thr)
{
    destroy_workqueue(thr->c1thr_wq);
    free(thr);

    return 0;
}

void
c1_thread_func(struct work_struct *work)
{
    struct c1_thread *thr;

    assert(work != NULL);

    thr = container_of(work, struct c1_thread, c1thr_wqs);
    assert(thr->c1thr_fp != NULL);

    thr->c1thr_fp(thr->c1thr_arg);
}

merr_t
c1_thread_run(struct c1_thread *thr)
{
    INIT_WORK(&thr->c1thr_wqs, c1_thread_func);
    queue_work(thr->c1thr_wq, &thr->c1thr_wqs);

    return 0;
}
