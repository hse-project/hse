/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_STS_H
#define HSE_IKVDB_STS_H

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>
#include <hse_util/list.h>

/* MTF_MOCK_DECL(sched_sts) */

struct sts;
struct sts_job;

/**
 * sts_print_fn() - rest hook job print callback
 * @job:   The job to print
 * @priv:  Ptr to 64-byte buffer
 * @buf:   Buffer into which to print
 * @bufsz: Size of %buf
 *
 * In response to a rest-get call sts will call the print function
 * once for each active job and once thereafter with job set to NULL.
 * The priv buffer is zeroed before the first callback and passed
 * unperturbed to each call thereafter.  The callback can use it
 * to maintain state between callbacks, and clean things on the
 * last callback (i.e., when job is nil).
 */
typedef int sts_print_fn(struct sts_job *job, void *priv, char *buf, size_t bufsz);
typedef void sts_job_fn(struct sts_job *job);

/**
 * struct sts_job - short term scheduler job handle
 * @sj_link:      Job list linkage
 * @sj_job_fn:    Job handler, set by client, invoked by scheduler
 * @sj_id:        Job ID
 * @sj_sts:       Ptr to scheduler
 * @sj_wmesgp:    Ptr to wait message ptr
 */
struct sts_job {
    struct list_head       sj_link;
    sts_job_fn            *sj_job_fn;
    uint                   sj_id;
    struct sts            *sj_sts;
    const char * volatile *sj_wmesgp;
    struct work_struct     sj_work;
};

/**
 * sts_create() - create a short term scheduler for kvdb compaction work
 * @name:     name (used for rest hook)
 * @nq:       minimum number of threads for running jobs
 * @print_fn: function to print jobs via rest hook
 * @sts:      (out) short term scheduler handle
 */
/* MTF_MOCK */
merr_t
sts_create(const char *name, uint nq, sts_print_fn *print_fn, struct sts **sts);

/* MTF_MOCK */
void
sts_destroy(struct sts *s);

static inline void
sts_job_init(struct sts_job *job, sts_job_fn *job_fn, uint id)
{
    job->sj_job_fn = job_fn;
    job->sj_id = id;
}

static inline uint
sts_job_id_get(struct sts_job *job)
{
    return job->sj_id;
}

static inline const char *
sts_job_wmesg_get(struct sts_job *job)
{
    return *job->sj_wmesgp;
}

/* MTF_MOCK */
void
sts_job_submit(struct sts *s, struct sts_job *job);

/**
 * sts_job_detach() - Detach job from callback thread context
 *
 * The job function (sj_job_fn) must call sts_job_detach() directly
 * from the callback context if it intends to hand off the job to
 * another thread (e.g., enqueue it for later processing).
 */
/* MTF_MOCK */
void
sts_job_detach(struct sts_job *job);

/**
 * sts_job_done() - Notify scheduler that the job is done
 *
 * sts_job_done() must be called on the job before the job is freed.
 * It may be called directly from the callback context or at any
 * time from any other thread if it has been detached.
 */
/* MTF_MOCK */
void
sts_job_done(struct sts_job *job);

#if HSE_MOCKING
#include "sched_sts_ut.h"
#endif /* HSE_MOCKING */

#endif
