/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_sched_sts

#include <hse_util/platform.h>
#include <hse_util/logging.h>
#include <hse_util/workqueue.h>
#include <hse_util/mutex.h>
#include <hse_util/rest_api.h>

#include <hse_ikvdb/sched_sts.h>

#include <bsd/string.h>

/**
 * struct sts - HSE scheduler used for cn tree ingest and compaction operations
 */
struct sts {
    struct mutex             sts_lock HSE_ACP_ALIGNED;
    struct list_head         sts_joblist;
    int                      sts_jobcnt;
    sts_print_fn            *sts_print_fn;
    struct workqueue_struct *sts_wq;
    struct cv                sts_cv;
    char                     sts_name[16];
};


static void
sts_job_run(struct work_struct *work)
{
    struct sts_job *job = container_of(work, struct sts_job, sj_work);

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

static merr_t
sts_rest_get(
    const char       *path,
    struct conn_info *info,
    const char       *url,
    struct kv_iter   *iter,
    void             *context)
{
    struct sts *self = context;
    size_t bufsz = 128 * 128; /* jobs * columns */
    size_t privsz = 64;
    struct sts_job *job;
    char *buf, *priv;
    int n;

    assert(self->sts_print_fn);

    buf = calloc(bufsz, 1);
    if (!buf)
        return merr(ENOMEM);

    priv = buf;
    bufsz -= privsz;
    buf += privsz;

    mutex_lock(&self->sts_lock);
    list_for_each_entry(job, &self->sts_joblist, sj_link) {

        n = self->sts_print_fn(job, priv, buf, bufsz);
        if (n > 0) {
            if (n > bufsz)
                n = bufsz;

            bufsz -= n;
            buf += n;
        }
    }

    n = self->sts_print_fn(NULL, priv, buf, bufsz);
    if (n > 0) {
        if (n > bufsz)
            n = bufsz;

        bufsz -= n;
        buf += n;
    }
    mutex_unlock(&self->sts_lock);

    rest_write_safe(info->resp_fd, priv + privsz, buf - priv - privsz);
    free(priv);

    return 0;
}

merr_t
sts_create(const char *name, uint nq, sts_print_fn *print_fn, struct sts **handle)
{
    struct sts *self;

    assert(name);
    assert(nq);
    assert(handle);

    *handle = NULL;

    self = aligned_alloc(__alignof__(*self), sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));
    mutex_init(&self->sts_lock);
    cv_init(&self->sts_cv);
    INIT_LIST_HEAD(&self->sts_joblist);
    self->sts_print_fn = print_fn;
    strlcpy(self->sts_name, name, sizeof(self->sts_name));

    self->sts_wq = alloc_workqueue("hse_%s", 0, nq, WQ_MAX_ACTIVE, self->sts_name);
    if (!self->sts_wq) {
        free(self);
        return merr(ENOMEM);
    }

    if (print_fn) {
        merr_t err;

        err = rest_url_register(self, 0, sts_rest_get, NULL, self->sts_name);
        if (err) {
            log_errx("unable to register url '%s': @@e", err, self->sts_name);
            self->sts_print_fn = NULL;
            assert(0);
        }
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

    if (self->sts_print_fn) {
        merr_t err;

        err = rest_url_deregister(self->sts_name);
        if (err) {
            log_errx("unable to deregister url '%s': @@e", err, self->sts_name);
            assert(0);
        }

        self->sts_print_fn = NULL;
    }

    destroy_workqueue(self->sts_wq);

    mutex_destroy(&self->sts_lock);
    cv_destroy(&self->sts_cv);
    free(self);
}

#if HSE_MOCKING
#include "sched_sts_ut_impl.i"
#endif /* HSE_MOCKING */
