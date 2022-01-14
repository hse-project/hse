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

typedef void sts_job_fn(struct sts_job *job);
typedef int sts_print_fn(struct sts_job *job, bool hdr, char *buf, size_t bufsz);

/**
 * struct sts_job - short term scheduler job handle
 * @sj_runq_link: run queue list linkage
 * @sj_job_fn:    job handler, set by client, invoked by scheduler
 * @sj_id:        job ID
 * @sj_status:    job status code
 *
 * A job is initialized with status code 'I' (idle) and then set to 'R'
 * (run) just prior to invoking the user job function.  The callee may
 * then call sts_job_status_set() at any time to set the status code
 * (to any alphabetical character) to indicate the current job status.
 * The status code is not interpreted by sts in any way, it is simply
 * displayed by sts via the job-print rest handler.
 */
struct sts_job {
    struct list_head   sj_runq_link;
    sts_job_fn        *sj_job_fn;
    uint               sj_id;
    char               sj_status;
    struct work_struct sj_work;
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
    job->sj_status = 'I';
}

static inline void
sts_job_status_set(struct sts_job *job, char status)
{
    job->sj_status = isalpha(status) ? status : '?';
}

static inline char
sts_job_status_get(struct sts_job *job)
{
    return job->sj_status;
}

static inline uint
sts_job_id_get(struct sts_job *job)
{
    return job->sj_id;
}

/* MTF_MOCK */
void
sts_job_submit(struct sts *s, struct sts_job *job);

void
sts_job_done(struct sts *s, struct sts_job *job);

#if HSE_MOCKING
#include "sched_sts_ut.h"
#endif /* HSE_MOCKING */

#endif
