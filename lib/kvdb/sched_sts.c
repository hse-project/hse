/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_sched_sts

#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse/rest/server.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse/util/event_counter.h>
#include <hse/util/mutex.h>
#include <hse/util/platform.h>
#include <hse/util/workqueue.h>

#include <bsd/string.h>

/**
 * struct sts - HSE scheduler used for cn tree ingest and compaction operations
 */
struct sts {
    struct mutex             sts_lock HSE_ACP_ALIGNED;
    struct list_head         sts_joblist;
    int                      sts_jobcnt;
    struct workqueue_struct *sts_wq;
    struct cv                sts_cv;
};


static void
sts_job_run(struct work_struct *work)
{
    struct sts_job *job = container_of(work, struct sts_job, sj_work);

    /* Reassociate sj_wmesgp to point into caller's thread-local storage.
     */
    job->sj_wmesgp = &hse_wmesg_tls;

    /* Do not touch *job after this function returns
     * as it may have already been freed.
     */
    job->sj_job_fn(job);
}

void
sts_job_submit(struct sts *self, struct sts_job *job)
{
    static const char *sts_wmesg_submit = "enqueued";

    assert(self && job);
    assert(job->sj_job_fn);

    /* Initialize sjwmesgp to point into global storage.  sts_job_run()
     * will reassociate sj_wmesgp to point into the calling thread's
     * thread-local storage.
     */
    job->sj_sts = self;
    job->sj_wmesgp = &sts_wmesg_submit;

    mutex_lock(&self->sts_lock);
    list_add_tail(&job->sj_link, &self->sts_joblist);
    ++self->sts_jobcnt;
    mutex_unlock(&self->sts_lock);

    INIT_WORK(&job->sj_work, sts_job_run);
    queue_work(self->sts_wq, &job->sj_work);
}

void
sts_job_detach(struct sts_job *job)
{
    static const char *sts_wmesg_detach = "detached";
    struct sts *self = job->sj_sts;

    /* Disassociate sj_wmesgp from the thread that called sts_job_run()
     * by pointing it into global storage.
     */
    mutex_lock(&self->sts_lock);
    job->sj_wmesgp = &sts_wmesg_detach;
    mutex_unlock(&self->sts_lock);
}

void
sts_job_done(struct sts_job *job)
{
    struct sts *self = job->sj_sts;

    mutex_lock(&self->sts_lock);
    list_del(&job->sj_link);
    if (--self->sts_jobcnt == 0)
        cv_signal(&self->sts_cv);
    mutex_unlock(&self->sts_lock);
}

merr_t
sts_create(const char *fmt, uint nq, struct sts **handle, ...)
{
    va_list ap;
    struct sts *self;

    INVARIANT(fmt);
    INVARIANT(nq);
    INVARIANT(handle);

    *handle = NULL;

    self = aligned_alloc(__alignof__(*self), sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));
    mutex_init(&self->sts_lock);
    cv_init(&self->sts_cv);
    INIT_LIST_HEAD(&self->sts_joblist);

    va_start(ap, handle);
    self->sts_wq = valloc_workqueue(fmt, 0, nq, WQ_MAX_ACTIVE, ap);
    va_end(ap);
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

    mutex_lock(&self->sts_lock);
    while (self->sts_jobcnt > 0)
        cv_wait(&self->sts_cv, &self->sts_lock, "jwait");
    mutex_unlock(&self->sts_lock);

    destroy_workqueue(self->sts_wq);

    mutex_destroy(&self->sts_lock);
    cv_destroy(&self->sts_cv);
    free(self);
}

merr_t
sts_foreach_job(struct sts *s, sts_foreach_job_fn *fn, void *arg)
{
    merr_t err = 0;
    struct sts_job *job;

    mutex_lock(&s->sts_lock);

    list_for_each_entry(job, &s->sts_joblist, sj_link) {
        err = fn(job, arg);
        if (err)
            break;
    }

    mutex_unlock(&s->sts_lock);

    return err;
}

#if HSE_MOCKING
#include "sched_sts_ut_impl.i"
#endif /* HSE_MOCKING */
