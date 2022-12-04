/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_STS_H
#define HSE_IKVDB_STS_H

#include <cjson/cJSON.h>

#include <hse/error/merr.h>
#include <hse/util/platform.h>
#include <hse/util/workqueue.h>
#include <hse/util/list.h>

/* MTF_MOCK_DECL(sched_sts) */

struct sts;
struct sts_job;

typedef merr_t sts_foreach_job_fn(struct sts_job *, void *arg);
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
    uint                   sj_progress;
    struct sts            *sj_sts;
    const char * volatile *sj_wmesgp;
    struct work_struct     sj_work;
};

/**
 * sts_create() - create a short term scheduler for kvdb compaction work
 * @fmt: format string for the workqueue name
 * @nq: minimum number of threads for running jobs
 * @sts: (out) short term scheduler handle
 */
/* MTF_MOCK */
merr_t
sts_create(const char *fmt, uint nq, struct sts **sts, ...);

/* MTF_MOCK */
void
sts_destroy(struct sts *s);

merr_t
sts_foreach_job(struct sts *s, sts_foreach_job_fn *fn, void *arg);

static inline void
sts_job_init(struct sts_job *job, sts_job_fn *job_fn, uint id)
{
    job->sj_job_fn = job_fn;
    job->sj_id = id;
    job->sj_progress = 0;
}

static inline uint
sts_job_id_get(const struct sts_job *job)
{
    return job->sj_id;
}

static inline const char *
sts_job_wmesg_get(const struct sts_job *job)
{
    return job->sj_wmesgp ? *job->sj_wmesgp : "?";
}

static inline uint
sts_job_progress_get(const struct sts_job *job)
{
    return job->sj_progress;
}

static inline void
sts_job_progress_set(struct sts_job *job, uint progress)
{
    job->sj_progress = progress;
}

/* MTF_MOCK */
void
sts_job_submit(struct sts *s, struct sts_job *job);

/* MTF_MOCK */
int
sts_jobcnt(struct sts *self);

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
