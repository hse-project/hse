/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_sched_sts

#include <hse_util/platform.h>
#include <hse_util/logging.h>
#include <hse_util/workqueue.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/csched_rp.h>
#include <hse_ikvdb/sched_sts.h>

/**
 * struct sts - HSE scheduler used for cn tree ingest and compaction operations
 */
struct sts {
    struct workqueue_struct *sts_wq HSE_L1D_ALIGNED;
    struct kvdb_rparams     *sts_rp;
    char                     sts_name[16];
};

static void
sts_job_run(struct work_struct *work)
{
    struct sts_job *job = container_of(work, struct sts_job, sj_work);

    job->sj_job_fn(job);

    pthread_setname_np(pthread_self(), "hse_sts_idle");
}

void
sts_job_submit(struct sts *self, struct sts_job *job)
{
    assert(self && job);
    assert(job->sj_job_fn);

    if (csched_rp_dbg_jobs(self->sts_rp))
        log_info("sts/job %u submit qnum %u", job->sj_id, job->sj_qnum);

    INIT_WORK(&job->sj_work, sts_job_run);
    queue_work(self->sts_wq, &job->sj_work);
}

merr_t
sts_create(struct kvdb_rparams *rp, const char *name, uint nq, struct sts **handle)
{
    struct sts *self;

    assert(rp);
    assert(name);
    assert(nq);
    assert(handle);

    *handle = NULL;

    self = aligned_alloc(alignof(*self), sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));
    self->sts_rp = rp;

    snprintf(self->sts_name, sizeof(self->sts_name), "hse_sts_%u_%s",
             rp->csched_policy, name);

    if (csched_rp_dbg_mon(rp))
        log_info("sts/mon create %s, queues %u, policy 0x%x",
                 self->sts_name, nq, rp->csched_policy);

    self->sts_wq = alloc_workqueue(self->sts_name, 0, nq, WQ_MAX_ACTIVE, 0);
    if (!self->sts_wq) {
        free(self);
        return merr(ENOMEM);
    }

    *handle = self;

    return 0;
}

void
sts_destroy(struct sts *self)
{
    if (!self)
        return;

    destroy_workqueue(self->sts_wq);
    free(self);
}

#if HSE_MOCKING
#include "sched_sts_ut_impl.i"
#endif /* HSE_MOCKING */
