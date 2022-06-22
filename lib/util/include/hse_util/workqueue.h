/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_WORKQUEUE_H
#define HSE_PLATFORM_WORKQUEUE_H

/* Resources:
 *
 *   http://www.ibm.com/developerworks/library/l-tasklets
 *   http://kukuruku.co/hub/nix/multitasking-in-the-linux-kernel-workqueues
 *   https://github.com/torvalds/linux/blob/master/Documentation/workqueue.txt
 */

#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/timer.h>
#include <hse_util/condvar.h>

#define WQ_MAX_ACTIVE (128)
#define WQ_DFL_ACTIVE (WQ_MAX_ACTIVE / 8)

struct work_struct;
struct workqueue_struct;

typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
    struct list_head entry; /* linked list of pending work */
    work_func_t      func;  /* function to be executed */
};

struct delayed_work {
    struct work_struct       work;
    struct timer_list        timer;
    struct workqueue_struct *wq;
};

#define INIT_WORK(_work, _func)                 \
    do {                                        \
        (_work)->func = (_func);                \
        INIT_LIST_HEAD(&(_work)->entry);        \
    } while (0)

#define INIT_DELAYED_WORK(_dwork, _func)                                \
    do {                                                                \
        INIT_WORK(&(_dwork)->work, (_func));                            \
        setup_timer(&(_dwork)->timer, delayed_work_timer_fn, (_dwork)); \
    } while (0)

/*
 * Allocate a workqueue.
 */
struct workqueue_struct *
alloc_workqueue(
    const char * fmt,        /* fmt string for name workqueue */
    unsigned int flags,      /* ignored */
    int          min_active, /* min number of threads servicing queue */
    int          max_active, /* max number of threads servicing queue */
    ...                      /* fmt string arguments */
) HSE_WARN_UNUSED_RESULT HSE_PRINTF(1, 5);

struct workqueue_struct *
valloc_workqueue(
    const char *fmt,
    unsigned int flags,
    int min_active,
    int max_active,
    va_list ap) HSE_WARN_UNUSED_RESULT;

/*
 * Destroy a workqueue.  Waits until all running work has finished and
 * there is no pending work.
 */
void
destroy_workqueue(struct workqueue_struct *wq);

/**
 * flush_workqueue()
 * @wq: workqueue
 *
 * Once flush_workqueue() returns, all the work items queued before
 * flush_workqueue() is called should complete
 */
void
flush_workqueue(struct workqueue_struct *wq);

void
dump_workqueue(struct workqueue_struct *wq);

/*
 * Add work to a workqueue.  Return false if work was already on a
 * queue, true otherwise.
 */
bool
queue_work(struct workqueue_struct *wq, struct work_struct *work);

/*
 * Add delayed work to a workqueue.
 */
bool
queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork, unsigned long delay);

/*
 * Cancel a delayed workitem.
 */
bool
cancel_delayed_work(struct delayed_work *work);

void
delayed_work_timer_fn(unsigned long data);

/**
 * end_stats_work() - Mark the end of a work loop iteration
 *
 * This function should be called by long-running workqueue callbacks
 * which implement a work-processing loop that rarely returns.  Such
 * callbacks should call end_stats_work() at the end of each loop
 * iteration to update workqueue statistics.
 */
void
end_stats_work(void);

/**
 * begin_stats_work() - Mark the beginning of a work loop iteration
 *
 * This function should be called by long-running workqueue callbacks
 * which implement a work-processing loop that rarely returns.  Such
 * callbacks should call begin_stats_work() at the begging of each
 * loop iteration to update workqueue statistics.
 */
void
begin_stats_work(void);

#endif /* HSE_PLATFORM_WORKQUEUE_H */
