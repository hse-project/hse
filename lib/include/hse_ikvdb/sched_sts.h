/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_STS_H
#define HSE_IKVDB_STS_H

#include <hse_util/platform.h>

/* MTF_MOCK_DECL(sched_sts) */

struct sts;
struct sts_job;
struct kvdb_rparams;

/* Hard limits.  Code will break if you increase either of these values.
 * - STS_QTHREADS_MAX and STS_QWEIGHT_MAX must be 255 or less because values
 *   are stored in u8 types.
 */
#define STS_QTHREADS_MAX UINT8_MAX
#define STS_QWEIGHT_MAX UINT8_MAX

#define STS_QUEUES_MAX 5

typedef void
sts_job_fn(struct sts_job *job);
typedef void
sts_cancel_fn(struct sts_job *job);

/**
 * struct sts_job - short term scheduler job handle
 * @sj_link:      for keeping jobs on a linked list (scheduler internal use)
 * @sj_sts:       handle to scheduler that manages this job
 * @sj_job_fn:    job handler, set by client, invoked by scheduler
 * @sj_cancel_fn: job cancel function, set by client, invoked by scheduler
 * @sj_tag:       tag, set by client, used to cancel all jobs with same tag
 * @sj_qnum:      scheduler queue
 */
struct sts_job {
    /* internal use */
    struct list_head sj_link;
    /* set by scheduler, used by client */
    struct sts *sj_sts;
    /* set by client */
    sts_job_fn *   sj_job_fn;
    sts_cancel_fn *sj_cancel_fn;
    u64            sj_tag;
    uint           sj_qnum;
    uint           sj_id;
};

/**
 * sts_create() - create a short term scheduler for kvdb compaction work
 * @rp:      kvdb run-time parameters
 * @name:    name
 * @nq:      number of queues
 * @sts:     (out) short term scheduler handle
 */
/* MTF_MOCK */
merr_t
sts_create(struct kvdb_rparams *rp, const char *name, uint nq, struct sts **sts);

/* MTF_MOCK */
void
sts_destroy(struct sts *s);

/* MTF_MOCK */
void
sts_cancel_jobs(struct sts *s, u64 tag);

/* MTF_MOCK */
void
sts_wcnt_set_target(struct sts *s, uint qnum, uint target);

/* MTF_MOCK */
uint
sts_wcnt_get_target(struct sts *s, uint qnum);

/* MTF_MOCK */
uint
sts_wcnt_get_idle(struct sts *s, uint qnum);

/* MTF_MOCK */
uint
sts_wcnt_get_ready(struct sts *s);

/* MTF_MOCK */
void
sts_pause(struct sts *s);

/* MTF_MOCK */
void
sts_resume(struct sts *s);

static inline void
sts_job_init(struct sts_job *job, sts_job_fn *job_fn, sts_cancel_fn *cancel_fn, uint qnum, u64 tag)
{
    job->sj_job_fn = job_fn;
    job->sj_cancel_fn = cancel_fn;
    job->sj_qnum = qnum;
    job->sj_tag = tag;
}

/* MTF_MOCK */
void
sts_job_submit(struct sts *s, struct sts_job *job);

#if HSE_MOCKING
#include "sched_sts_ut.h"
#endif /* HSE_MOCKING */

#endif
