/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_sched_sts

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/condvar.h>
#include <hse_util/mutex.h>
#include <hse_util/perfc.h>
#include <hse_util/delay.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/csched_rp.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include <hse/kvdb_perfc.h>

#include "sched_sts_perfc.h"

/* [HSE_REVISIT] - Why is this at the top of the file? */
#if HSE_MOCKING
#include "sched_sts_ut_impl.i"
#include "sched_sts_perfc_ut_impl.i"
#endif /* HSE_MOCKING */

/* Scheduler state */
#define SS_RUN 0
#define SS_PAUSE 1
#define SS_EXIT 2

/* Sleep/wait times, milliseconds */
#define EXIT_SLEEP_MS 3
#define WORKER_INIT_SLEEP_MS 3
#define WORKER_PAUSE_SLEEP_MS 100
#define JOB_GET_TIMEOUT_MS 10
#define MONITOR_TIMEOUT_MS 250
#define STATS_REPORT_PERIOD_MS 1000

/* A worker thread */
struct sts_worker {
    struct sts *sts;
    atomic_t    initializing;
    uint        wqnum;
    char        wname[16];
} HSE_ALIGNED(SMP_CACHE_BYTES);

static void *
sts_worker_main(void *rock);

/* Scheduler queue */
struct sts_queue {
    struct list_head jobs;
    atomic_t         idle_workers;
    struct perfc_set qpc;
    struct sts *     sts;
} HSE_ALIGNED(SMP_CACHE_BYTES);

/**
 * struct sts - HSE scheduler used for cn tree ingest and compaction operations
 */
struct sts {
    pthread_t            mtid;  /* m=monitor thread id */
    struct cv            mcv;   /* m=monitor cond var */
    struct mutex         mlock; /* m=monitor mutex */
    struct kvdb_rparams *rp;
    const char *         name;
    uint                 qc;
    atomic_t             state;
    atomic_t             worker_id_counter;
    atomic_t             spawned_workers;
    atomic_t             ready_workers;

    /* Current number of workers.
     * Index self->qc is for shared workers.
     * Index i, i < self->qc, is for workers dedicated to queue i.
     */
    atomic_t wcnt_current[STS_QUEUES_MAX + 1];

    uint rr_next;

    struct sts_queue *qv;
    struct cv         qcondvar;
    struct mutex      qlock;
};

/* queue lock */
#define q_lock(s) mutex_lock(&(s)->qlock)
#define q_unlock(s) mutex_unlock(&(s)->qlock)

/* monitor lock */
#define m_lock(s) mutex_lock(&(s)->mlock)
#define m_unlock(s) mutex_unlock(&(s)->mlock)

static void
q_init(struct sts *self, struct sts_queue *q, uint qnum)
{
    memset(q, 0, sizeof(*q));

    INIT_LIST_HEAD(&q->jobs);
    q->sts = self;
}

static inline uint
q_threads(u64 rparam, uint qnum)
{
    return (rparam >> (qnum * 8)) & 0xff;
}

static inline void
q_threads_set(struct sts *self, uint qnum, uint count)
{
    if (qnum <= self->qc && count <= STS_QTHREADS_MAX) {

        uint shift = 8 * qnum;
        u64  old = self->rp->csched_qthreads;
        u64 new = (old & ~(0xffu << shift)) | (count << shift);

        self->rp->csched_qthreads = new;
    }
}

/* Caller must have queue lock */
static struct sts_job *
job_get(struct sts *self)
{
    struct sts_job *  job;
    struct sts_queue *q;
    uint              qnum, i;

    for (i = 0; i < self->qc; i++) {
        qnum = (self->rr_next + i) % self->qc;
        if (!list_empty(&self->qv[qnum].jobs))
            goto found_job;
    }

    return 0;

found_job:
    q = &self->qv[qnum];
    job = list_first_entry(&q->jobs, struct sts_job, sj_link);
    list_del(&job->sj_link);
    perfc_dec(&q->qpc, PERFC_BA_STS_QDEPTH);

    self->rr_next = (qnum + 1) < self->qc ? (qnum + 1) : 0;
    return job;
}

/* Caller must have queue lock */
static struct sts_job *
job_find_tag(struct sts *self, struct sts_queue *q, u64 tag)
{
    struct sts_job *job;

    list_for_each_entry (job, &q->jobs, sj_link)
        if (job->sj_tag == tag)
            return job;

    return 0;
}

/* Caller must have queue lock */
static void
job_put(struct sts_queue *q, struct sts_job *job)
{
    perfc_inc(&q->qpc, PERFC_BA_STS_QDEPTH);
    list_add_tail(&job->sj_link, &q->jobs);
}

static void
cancel_job(struct sts_job *job)
{
    if (csched_rp_dbg_jobs(job->sj_sts->rp))
        log_info("sts/job %u canceled", job->sj_id);

    if (job->sj_cancel_fn)
        job->sj_cancel_fn(job);
    else
        log_info("canceled sts job %p has no cancel callback", job);
}

static void
cancel_jobs_all(struct sts *self)
{
    struct sts_job *job;

    do {
        q_lock(self);
        job = job_get(self);
        q_unlock(self);
        if (job)
            cancel_job(job);
    } while (job);
}

void
sts_cancel_jobs(struct sts *self, u64 tag)
{
    struct sts_job *  job;
    struct sts_queue *q;
    uint              i;

    for (i = 0; i < self->qc; i++) {

        q = self->qv + i;

        do {
            q_lock(self);
            job = job_find_tag(self, q, tag);
            if (job) {
                list_del(&job->sj_link);
                perfc_dec(&q->qpc, PERFC_BA_STS_QDEPTH);
            }
            q_unlock(self);

            if (job)
                cancel_job(job);

        } while (job);
    }
}

static merr_t
add_worker(struct sts *self, uint qnum)
{
    struct sts_worker *w;
    pthread_t          tid;
    int                wnum;
    int                rc;

    if (ev(qnum > self->qc))
        return merr(EINVAL);

    w = alloc_aligned(sizeof(*w), SMP_CACHE_BYTES);
    if (ev(!w))
        return merr(ENOMEM);

    memset(w, 0, sizeof(*w));

    atomic_inc(&self->spawned_workers);
    atomic_set(&w->initializing, 1);

    w->wqnum = qnum;
    w->sts = self;

    wnum = atomic_fetch_add(&self->worker_id_counter, 1);
    if (qnum == self->qc)
        snprintf(w->wname, sizeof(w->wname), "sts_w%u_qs", wnum);
    else
        snprintf(w->wname, sizeof(w->wname), "sts_w%u_q%u", wnum, qnum);

    rc = pthread_create(&tid, NULL, sts_worker_main, w);
    if (ev(rc)) {
        free(w);
        return merr(rc);
    }

    atomic_inc(&self->wcnt_current[qnum]);
    atomic_set(&w->initializing, 0);

    return 0;
}

/* Return a count of how many extra workers a queue has.
 * If 0, queue has correct number of workers.
 * If > 0, then some workers should exit.
 * If < 0, then new workers should be created.
 */
static int
sts_worker_surplus(struct sts *self, uint qnum)
{
    int target = q_threads(self->rp->csched_qthreads, qnum);
    int workers = atomic_read(&self->wcnt_current[qnum]);

    return workers - target;
}

static void *
sts_monitor(void *rock)
{
    struct sts *self = rock;
    int         ss;
    int         timeout_ms = MONITOR_TIMEOUT_MS;
    int         rc;

    u64 add_worker_next_ns = 0;

    u64 dbg_last = 0;
    u64 dbg_wake_signals = 0;
    u64 dbg_wake_timeouts = 0;
    u64 dbg_wake_other = 0;

    pthread_setname_np(pthread_self(), "sts_mon");

    while (true) {

        m_lock(self);

        /* Check SS_EXIT before waiting makes SS_EXIT more responsive,
         * which has the nice benefit of speeding up unit tests.
         */
        ss = atomic_read(&self->state);
        if (ss != SS_EXIT) {
            rc = cv_timedwait(&self->mcv, &self->mlock, timeout_ms);
            assert(rc == 0 || rc == ETIMEDOUT);
            if (rc == 0)
                dbg_wake_signals++;
            else if (rc == ETIMEDOUT)
                dbg_wake_timeouts++;
            else
                dbg_wake_other++;
        }
        m_unlock(self);

        ss = atomic_read(&self->state);

        if (csched_rp_dbg_mon(self->rp)) {
            u64 now = get_time_ns();
            u64 delay = 5ULL * 1000 * 1000 * 1000;

            if (now > dbg_last + delay) {
                log_info("sts/mon sig %lu timeo %lu other %lu ss %d",
                         (ulong)dbg_wake_signals,
                         (ulong)dbg_wake_timeouts,
                         (ulong)dbg_wake_other,
                         ss);

                dbg_wake_signals = 0;
                dbg_wake_timeouts = 0;
                dbg_wake_other = 0;
                dbg_last = now;
            }
        }

        if (ss == SS_EXIT)
            break;

        timeout_ms = MONITOR_TIMEOUT_MS;

        if (add_worker_next_ns <= get_time_ns()) {
            merr_t err;
            uint   i;

            for (i = 0; i <= self->qc; i++) {
                if (sts_worker_surplus(self, i) < 0) {
                    err = add_worker(self, i);
                    if (!err) {
                        add_worker_next_ns = 0;
                        timeout_ms = 10;
                    } else {
                        add_worker_next_ns = get_time_ns() + 5 * NSEC_PER_SEC;
                    }
                }
            }
        }
    }

    if (csched_rp_dbg_mon(self->rp))
        log_info("sts/mon exiting, waiting for %d workers to finish",
                 atomic_read(&self->spawned_workers));

    while (atomic_read(&self->spawned_workers) > 0)
        msleep(EXIT_SLEEP_MS);

    cancel_jobs_all(self);

    return 0;
}

static void
sts_perfc_alloc_internal(struct sts *self)
{
    char namebuf[32], qnum_str[16];
    int  i;

    snprintf(namebuf, sizeof(namebuf), "kvdb/%s", self->name);

    /* Iterate w/ <= to get shared worker stats */
    for (i = 0; i <= self->qc; i++) {
        snprintf(qnum_str, sizeof(qnum_str), "q%d", i);
        sts_perfc_alloc(self->rp->perfc_level, namebuf, qnum_str, &self->qv[i].qpc);
    }
}

static void
sts_perfc_free_internal(struct sts *self)
{
    int i;

    /* Iterate w/ <= to get shared worker stats */
    for (i = 0; i <= self->qc; i++)
        sts_perfc_free(&self->qv[i].qpc);
}

merr_t
sts_create(struct kvdb_rparams *rp, const char *name, uint nq, struct sts **handle)
{
    int         rc;
    uint        i, len;
    struct sts *self;

    assert(rp);
    assert(name);
    assert(nq);
    assert(handle);

    if (ev(nq > STS_QUEUES_MAX))
        return merr(EINVAL);

    self = alloc_aligned(sizeof(*self), SMP_CACHE_BYTES);
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));

    /* Name pointer is safe -- it will not go away */
    self->name = name;

    if (csched_rp_dbg_mon(rp))
        log_info("sts/mon create %s, queues %u, policy 0x%x",
                 self->name, nq, rp->csched_policy);

    /* Allocate cache aligned queue structs */
    len = sizeof(self->qv[0]) * (nq + 1);
    self->qv = alloc_aligned(len, SMP_CACHE_BYTES);
    if (ev(!self->qv)) {
        free_aligned(self);
        return merr(ENOMEM);
    }

    self->rp = rp;
    self->qc = nq;
    for (i = 0; i <= nq; i++)
        q_init(self, self->qv + i, i);

    mutex_init(&self->mlock);
    cv_init(&self->mcv, "sts_monitor");

    mutex_init(&self->qlock);
    cv_init(&self->qcondvar, "sts_queue");

    atomic_set(&self->state, SS_PAUSE);
    atomic_set(&self->spawned_workers, 0);
    atomic_set(&self->ready_workers, 0);

    sts_perfc_alloc_internal(self);

    rc = pthread_create(&self->mtid, NULL, sts_monitor, self);
    if (ev(rc)) {

        sts_perfc_free_internal(self);

        cv_destroy(&self->mcv);
        mutex_destroy(&self->mlock);

        cv_destroy(&self->qcondvar);
        mutex_destroy(&self->qlock);

        free_aligned(self->qv);
        free_aligned(self);

        return merr(rc);
    }

    *handle = self;
    return 0;
}

void
sts_destroy(struct sts *self)
{
    if (!self)
        return;

    m_lock(self);
    atomic_set(&self->state, SS_EXIT);
    cv_signal(&self->mcv);
    m_unlock(self);

    pthread_join(self->mtid, 0);

    sts_perfc_free_internal(self);

    cv_destroy(&self->qcondvar);
    mutex_destroy(&self->qlock);

    cv_destroy(&self->mcv);
    mutex_destroy(&self->mlock);

    free_aligned(self->qv);
    free_aligned(self);
}

static void
worker_run_slice(struct sts_worker *w, struct sts_queue *q, struct sts_job *job)
{
    bool debug;
    u64  t0, t1;
    uint qnum, id;

    assert(job->sj_job_fn);

    qnum = job->sj_qnum;

    debug = !!(csched_rp_dbg_jobs(w->sts->rp));
    if (debug)
        log_info("sts/job %u qnum %u worker %s start", job->sj_id, qnum, w->wname);

    perfc_inc(&q->qpc, PERFC_RA_STS_JOBS);
    perfc_inc(&q->qpc, PERFC_BA_STS_JOBS_RUN);

    id = job->sj_id;

    /* The job struct is no longer ours after this call. The handler
     * may free it to submit it back to the scheduler.
     */
    t0 = get_time_ns();
    job->sj_job_fn(job);
    t1 = get_time_ns();

    perfc_dec(&q->qpc, PERFC_BA_STS_JOBS_RUN);

    if (debug)
        log_info("sts/job %u qnum %u worker %s end dt(ms) %lu",
                 id, qnum, w->wname, (t1 - t0) / 1000000);
}

struct sts_queue *
sts_qsel(struct sts *self, struct sts_worker *w, int *status)
{
    struct sts_queue *q;

    /* test and decrement of worker count must be done
     * with q_lock held or else we end up with too many
     * decrements.
     */
    if (sts_worker_surplus(self, w->wqnum) > 0) {
        atomic_dec(&self->wcnt_current[w->wqnum]);
        *status = SS_EXIT;
        return 0;
    }

    *status = atomic_read(&self->state);
    if (*status != SS_RUN)
        return 0;

    if (w->wqnum < self->qc) {

        /* Worker is bound to a queue */
        q = &self->qv[w->wqnum];
        if (list_empty(&q->jobs))
            return 0;

        return q;
    }

    /* Worker services all queues */
    uint i;
    uint rr = self->rr_next;

    for (i = 0; i < self->qc; i++) {
        q = &self->qv[(i + rr) % self->qc];
        if (!list_empty(&q->jobs)) {
            self->rr_next = (rr + 1) % self->qc;
            return q;
        }
    }

    return 0;
}

static void *
sts_worker_main(void *rock)
{
    struct sts_worker *w = rock;
    struct sts *       self = w->sts;
    pthread_t          tid;
    int                state;
    bool               idle;
    atomic_t *         idle_count;

    tid = pthread_self();
    idle = false;
    idle_count = &self->qv[w->wqnum].idle_workers;
    state = SS_RUN;

    pthread_detach(tid);
    pthread_setname_np(tid, w->wname);

    if (csched_rp_dbg_worker(self->rp))
        log_info("sts/worker %s initializing", w->wname);

    /* orderly startup: wait for signal to proceed */
    while (atomic_read(&w->initializing))
        msleep(WORKER_INIT_SLEEP_MS);

    if (csched_rp_dbg_worker(self->rp))
        log_info("sts/worker %s ready state %d", w->wname, atomic_read(&self->state));

    atomic_inc(&self->ready_workers);
    perfc_inc(&self->qv[w->wqnum].qpc, PERFC_BA_STS_WORKERS);

    while (state != SS_EXIT) {

        struct sts_job *  job = 0;
        struct sts_queue *q = 0;

        q_lock(self);

        while (true) {

            int rc HSE_MAYBE_UNUSED;

            q = sts_qsel(self, w, &state);
            if (q) {
                assert(!list_empty(&q->jobs));
                job = list_first_entry(&q->jobs, struct sts_job, sj_link);
                list_del(&job->sj_link);
                perfc_dec(&q->qpc, PERFC_BA_STS_QDEPTH);
                break;
            }

            if (state != SS_RUN)
                break;

            if (!idle) {
                /* Must use 'w->wqnum' (instead of 'q') for
                 * WORKERS_IDLE to correctly track idle shared
                 * workers
                 */
                idle = true;
                atomic_inc(idle_count);
                perfc_inc(&self->qv[w->wqnum].qpc, PERFC_BA_STS_WORKERS_IDLE);
            }

            pthread_setname_np(tid, w->wname);

            rc = cv_timedwait(&self->qcondvar, &self->qlock, JOB_GET_TIMEOUT_MS);
            assert(rc == 0 || rc == ETIMEDOUT);
        }

        q_unlock(self);

        if (job) {
            if (idle) {
                idle = false;
                assert(atomic_read(idle_count) > 0);
                atomic_dec(idle_count);
                perfc_dec(&self->qv[w->wqnum].qpc, PERFC_BA_STS_WORKERS_IDLE);
            }

            worker_run_slice(w, q, job);
        }

        if (state == SS_PAUSE)
            msleep(WORKER_PAUSE_SLEEP_MS);
    }

    perfc_dec(&self->qv[w->wqnum].qpc, PERFC_BA_STS_WORKERS);

    if (csched_rp_dbg_worker(self->rp))
        log_info("sts/worker %s exit", w->wname);

    atomic_dec(&self->ready_workers);
    atomic_dec(&self->spawned_workers);
    free_aligned(w);

    return 0;
}

void
sts_job_submit(struct sts *self, struct sts_job *job)
{
    struct sts_queue *q = self->qv + job->sj_qnum;

    assert(job->sj_job_fn);
    assert(job->sj_qnum < self->qc);

    if (csched_rp_dbg_jobs(self->rp))
        log_info("sts/job %u submit qnum %u", job->sj_id, job->sj_qnum);

    job->sj_sts = self;

    q_lock(self);
    job_put(q, job);
    cv_signal(&self->qcondvar);
    q_unlock(self);
}

void
sts_pause(struct sts *self)
{
    if (csched_rp_dbg_mon(self->rp))
        log_info("sts/mon %s pausing", self->name);

    m_lock(self);
    atomic_set(&self->state, SS_PAUSE);
    cv_signal(&self->mcv);
    m_unlock(self);
}

void
sts_resume(struct sts *self)
{
    if (csched_rp_dbg_mon(self->rp))
        log_info("sts/mon %s resuming", self->name);

    m_lock(self);
    atomic_set(&self->state, SS_RUN);
    cv_signal(&self->mcv);
    m_unlock(self);
}

uint
sts_wcnt_get_ready(struct sts *self)
{
    return atomic_read(&self->ready_workers);
}

uint
sts_wcnt_get_target(struct sts *self, uint qnum)
{
    if (qnum <= self->qc)
        return q_threads(self->rp->csched_qthreads, qnum);

    return 0;
}

uint
sts_wcnt_get_idle(struct sts *self, uint qnum)
{
    int count = 0;

    if (qnum <= self->qc)
        count = atomic_read(&self->qv[self->qc].idle_workers);

    assert(count >= 0);
    return count < 0 ? 0 : (uint)count;
}

void
sts_wcnt_set_target(struct sts *self, uint qnum, uint target)
{
    q_threads_set(self, qnum, target);
}
