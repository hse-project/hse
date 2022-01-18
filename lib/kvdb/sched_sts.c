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
    struct mutex             sts_runq_lock HSE_L1D_ALIGNED;
    struct list_head         sts_runq_list;
    sts_print_fn            *sts_print_fn;
    struct workqueue_struct *sts_wq;
    char                     sts_name[16];
};


static void
sts_job_run(struct work_struct *work)
{
    struct sts_job *job = container_of(work, struct sts_job, sj_work);

    sts_job_status_set(job, 'R');

    /* Do not touch *job after this function returns
     * as it may have already been freed.
     */
    job->sj_job_fn(job);
}

void
sts_job_submit(struct sts *self, struct sts_job *job)
{
    assert(self && job);
    assert(job->sj_job_fn);

    mutex_lock(&self->sts_runq_lock);
    list_add_tail(&job->sj_runq_link, &self->sts_runq_list);
    mutex_unlock(&self->sts_runq_lock);

    INIT_WORK(&job->sj_work, sts_job_run);
    queue_work(self->sts_wq, &job->sj_work);
}

void
sts_job_done(struct sts *self, struct sts_job *job)
{
    mutex_lock(&self->sts_runq_lock);
    list_del(&job->sj_runq_link);
    mutex_unlock(&self->sts_runq_lock);
}

static merr_t
sts_rest_get(
    const char       *path,
    struct conn_info *info,
    const char       *url,
    struct kv_iter   *iter,
    void             *context)
{
    const size_t bufsz = 128 * 128; /* jobs * columns */
    struct sts *self = context;
    struct sts_job *job;
    size_t buflen;
    char *buf;
    bool hdr;
    int n;

    buf = malloc(bufsz);
    if (!buf)
        return merr(ENOMEM);

    buflen = 0;
    hdr = true;

    mutex_lock(&self->sts_runq_lock);
    list_for_each_entry(job, &self->sts_runq_list, sj_runq_link) {

        n = self->sts_print_fn(job, hdr, buf + buflen, bufsz - buflen);
        if (n < 1 || n >= bufsz - buflen)
            break;

        buflen += n;
        hdr = false;
    }
    mutex_unlock(&self->sts_runq_lock);

    rest_write_safe(info->resp_fd, buf, buflen);
    free(buf);

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
    mutex_init(&self->sts_runq_lock);
    INIT_LIST_HEAD(&self->sts_runq_list);
    self->sts_print_fn = print_fn;
    snprintf(self->sts_name, sizeof(self->sts_name), "hse_sts_%s", name);

    self->sts_wq = alloc_workqueue(self->sts_name, 0, nq, WQ_MAX_ACTIVE, 0);
    if (!self->sts_wq) {
        free(self);
        return merr(ENOMEM);
    }

    if (print_fn)
        rest_url_register(self, 0, sts_rest_get, NULL, name);

    *handle = self;

    return 0;
}

void
sts_destroy(struct sts *self)
{
    if (!self)
        return;

    if (self->sts_print_fn)
        rest_url_deregister(self->sts_name);

    destroy_workqueue(self->sts_wq);

    mutex_lock(&self->sts_runq_lock);
    if (!list_empty(&self->sts_runq_list))
        abort();
    mutex_unlock(&self->sts_runq_lock);

    mutex_destroy(&self->sts_runq_lock);

    free(self);
}

#if HSE_MOCKING
#include "sched_sts_ut_impl.i"
#endif /* HSE_MOCKING */
