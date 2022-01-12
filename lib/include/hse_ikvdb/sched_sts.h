/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_STS_H
#define HSE_IKVDB_STS_H

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>

/* MTF_MOCK_DECL(sched_sts) */

struct sts;
struct sts_job;
struct kvdb_rparams;

typedef void sts_job_fn(struct sts_job *job);

/**
 * struct sts_job - short term scheduler job handle
 * @sj_job_fn:    job handler, set by client, invoked by scheduler
 * @sj_id:        job ID
 */
struct sts_job {
    sts_job_fn        *sj_job_fn;
    uint               sj_id;
    struct work_struct sj_work;
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

static inline void
sts_job_init(struct sts_job *job, sts_job_fn *job_fn, uint id)
{
    job->sj_job_fn = job_fn;
    job->sj_id = id;
}

/* MTF_MOCK */
void
sts_job_submit(struct sts *s, struct sts_job *job);

#if HSE_MOCKING
#include "sched_sts_ut.h"
#endif /* HSE_MOCKING */

#endif
