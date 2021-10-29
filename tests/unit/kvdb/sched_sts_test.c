/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>
#include <hse_util/xrand.h>
#include <mock/alloc_tester.h>

#include <hse_util/platform.h>
#include <hse_util/delay.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/csched_rp.h>

/* Tests:
 * Worker management:
 * - adding workers when all existing workers are running
 * - removing workers when all existing workers are running
 */
/* Tests:
 * Jobs:
 * - submit jobs w/o workers, verify no jobs executed, add worker, verify
 *   progress
 * - add workers, pause, add jobs, verify no progress, resume, verify progress
 */
/* Tests:
 * Continuation:
 *   - continue job on different queue
 *   - continue job on same queue
 *   - finish job
 */

struct kvdb_rparams *rp, rparams;
uint                 to;
int                  set_debug_rparam;

int
pre_collection(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *tci = info->ti_coll;
    int                        i;

    /* To get max branch coverage, run once with
     * debug and once without.
     */
    for (i = 1; i < tci->tci_argc; i++) {
        if (!strcmp("debug", tci->tci_argv[i]))
            set_debug_rparam = 1;
    }

    return 0;
}

static void
reset_rparams(void)
{
    rparams = kvdb_rparams_defaults();
    rp = &rparams;
    if (set_debug_rparam)
        rp->csched_debug_mask = U64_MAX;
    rp->csched_qthreads = 0x0101010101010101;
}

static int
pre_test(struct mtf_test_info *ti)
{
    to = 1000; /* microseconds, short timeout for faster unit test */
    reset_rparams();
    return 0;
}

/* Test job */
struct job {
    struct sts_job sts_job;
    int            debug;
    pthread_t      tid;
    atomic_t *     var;
    int            var_wait;
    int            var_add;
    uint           delay_msec;
    uint           size;

    u64  slice_cur;
    u64  slice_max;
    bool change_qnum;
    uint qmax;
};

#define REPEAT_FOREVER ((u64)-1)

static merr_t
atomic_read_timeout(atomic_t *var, int value, u64 timeout_usec)
{
    u64 stop = get_time_ns() + timeout_usec * 1000;

    while (atomic_read(var) != value) {
        if (get_time_ns() > stop)
            return merr(ETIMEDOUT);
        msleep(500);
    }
    return 0;
}

static void
jhandler(struct sts_job *sj)
{
    struct job *job = container_of(sj, struct job, sts_job);
    u64         count = 0;
    u64         t0 = 0, t1 = 0;
    atomic_t *  add_var = 0;
    int         add_value = 0;

    if (job->debug)
        log_info("%lu: job %p: queue %u", get_time_ns(), sj, sj->sj_qnum);

    job->tid = pthread_self();

    if (job->delay_msec)
        msleep(job->delay_msec);

    if (job->var_wait != 0) {
        /* wait for atomic var to equal var_wait */
        t0 = get_time_ns();
        while (atomic_read(job->var) != job->var_wait) {
            if (job->debug && count == 0)
                log_info("%lu: job %p: wait for v == %d", get_time_ns(), sj, job->var_wait);
            msleep(20);
            count++;
        }
        t1 = get_time_ns();
        if (job->debug)
            log_info("%lu: job %p: got v == %u after %lu waits, %lu nsecs",
                     get_time_ns(),
                     sj,
                     job->var_wait,
                     count,
                     t1 - t0);
    }

    if (job->var_add) {
        /* var and var_add must be cached in case the job struct is freed (untested) */
        if (job->debug)
            log_info("%lu: job %p: var += %d", get_time_ns(), sj, job->var_add);
        add_var = job->var;
        add_value = job->var_add;
    }

    job->slice_cur++;
    if (job->slice_max == REPEAT_FOREVER || job->slice_cur < job->slice_max) {
        if (job->change_qnum)
            sj->sj_qnum = (sj->sj_qnum + 1) % job->qmax;
        if (job->debug)
            log_info("%lu: job %p: continue on queue %u", get_time_ns(), sj, sj->sj_qnum);
        if (add_var)
            atomic_add(add_value, add_var);
        sts_job_submit(sj->sj_sts, sj);
    } else {
        atomic_add(add_value, add_var);
    }
}

static struct job *
jinit(struct job *job, uint qnum, uint delay_msec, atomic_t *var, int var_wait, int var_add)
{
    memset(job, 0, sizeof(*job));

    sts_job_init(&job->sts_job, jhandler, 0, qnum, 0);

    job->delay_msec = delay_msec;
    job->var = var;
    job->var_wait = var_wait;
    job->var_add = var_add;
    job->size = 1;

    return job;
}

static struct job *
jrepeat(struct job *job, u64 nslices, bool change_qnum, uint qmax)
{
    job->slice_cur = 0;
    job->slice_max = nslices;
    job->change_qnum = change_qnum;
    job->qmax = qmax;

    return job;
}

static void
jsubmit(struct sts *s, struct job *job)
{
    sts_job_submit(s, &job->sts_job);
}

static merr_t
job_ping(struct sts *s, uint qnum, uint wait_usec, u64 *time_nsec)
{
    struct job *job;
    atomic_t    var;
    u64         t0, t1;

    job = mapi_safe_malloc(sizeof(*job));
    VERIFY_NE_RET(job, NULL, merr(ENOMEM));

    atomic_set(&var, 0);

    t0 = get_time_ns();
    jsubmit(s, jinit(job, qnum, 0, &var, 0, 1));
    while (atomic_read(&var) == 0) {
        if (wait_usec) {
            t1 = get_time_ns();
            if (((t1 - t0) / 1000) > wait_usec)
                return merr(ETIMEDOUT);
        }
    }
    t1 = get_time_ns();
    *time_nsec = t1 - t0;

    mapi_safe_free(job);

    return 0;
}

/* Create a scheduler and wait for all workers to be ready.
 */
static merr_t
test_sts_create(const char *unique_name, uint nq, struct sts **s_out)
{
    struct sts *s;
    merr_t      err;
    u64         timeout;

    err = sts_create(rp, unique_name, nq, &s);
    if (err)
        return err;

    sts_resume(s);

    timeout = get_time_ns() + 5ULL * 1000 * 1000 * 1000;
    while (sts_wcnt_get_ready(s) == 0) {
        if (get_time_ns() > timeout)
            return merr(ETIMEDOUT);
        msleep(50);
    }

    *s_out = s;
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_sts_create_valid, pre_test)
{
    merr_t      err1, err2;
    struct sts *s1, *s2;

    err1 = sts_create(rp, "B1", 1, &s1);
    ASSERT_EQ(err1, 0);
    sts_destroy(s1);

    err1 = sts_create(rp, "B2", STS_QUEUES_MAX, &s1);
    ASSERT_EQ(err1, 0);
    sts_destroy(s1);

    /* multiple schedulers co-existing */
    err1 = sts_create(rp, "B3", 1, &s1);
    err2 = sts_create(rp, "B4", 2, &s2);
    ASSERT_EQ(err1, 0);
    ASSERT_EQ(err2, 0);
    sts_destroy(s1);
    sts_destroy(s2);
}

MTF_DEFINE_UTEST_PRE(test, t_sts_create_invalid, pre_test)
{
    merr_t      err;
    struct sts *s;

    /* too many queues */
    err = sts_create(rp, "C1", STS_QUEUES_MAX + 1, &s);
    ASSERT_NE(err, 0);
}

MTF_DEFINE_UTEST_PRE(test, t_sts_create_nomem, pre_test)
{
    struct sts *s;
    merr_t      err;
    int         rc;
    uint        nq = 3;
    int         uniqifier = 0;

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        char name[16];

        snprintf(name, sizeof(name), "XX%d", uniqifier++);
        err = sts_create(rp, name, nq, &s);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        /* Note: parent function local vars are preserved from
         * previous call to run().
         */
        if (!err)
            sts_destroy(s);
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);
}

/* set/get worker targets
 * - basic exercise for code coverage
 * Invalid cases:
 * - get w/ invalid qnum
 * - set w/ invalid qnum
 * - set w/ invalid worker count
 */
MTF_DEFINE_UTEST_PRE(test, t_sts_wcnt, pre_test)
{
    merr_t      err;
    struct sts *s;
    uint        w, loops;
    uint        nq, nw;

    nq = 2;
    nw = 3;
    rp->csched_qthreads = nw << (8 * nq);

    log_info("create nq=%u qthreads=0x%08lx", nq, rp->csched_qthreads);

    err = sts_create(rp, "E1", nq, &s);
    ASSERT_EQ(err, 0);

    /* Verify target */
    w = sts_wcnt_get_target(s, nq);
    ASSERT_EQ(w, nw);

    /* Wait for all workers to be ready */
    for (loops = 0; nw != sts_wcnt_get_ready(s); loops++) {
        msleep(20);
        ASSERT_LE(loops, 5000);
    }

    /* Bump workers, Verify target, wait for ready */
    nw += 2;
    log_info("set wcnt to %u, then wait", nw);
    sts_wcnt_set_target(s, nq, nw);
    w = sts_wcnt_get_target(s, nq);
    ASSERT_EQ(w, nw);
    for (loops = 0; nw != sts_wcnt_get_ready(s); loops++) {
        msleep(20);
        ASSERT_LE(loops, 5000);
    }

    /* Drop workers, Verify target, wait for ready */
    nw = 1;
    log_info("set wcnt to %u, then wait", nw);
    sts_wcnt_set_target(s, nq, nw);
    w = sts_wcnt_get_target(s, nq);
    ASSERT_EQ(w, nw);
    for (loops = 0; nw != sts_wcnt_get_ready(s); loops++) {
        msleep(20);
        ASSERT_LE(loops, 5000);
    }

    /* Bump workers, but with no memory */
    mapi_inject_ptr(mapi_idx_malloc, 0);
    nw++;
    sts_wcnt_set_target(s, nq, nw);
    msleep(1000);
    mapi_inject_unset(mapi_idx_malloc);

    /* set to zero workers */
    sts_wcnt_set_target(s, nq, 0);
    w = sts_wcnt_get_target(s, nq);
    ASSERT_EQ(w, 0);

    /* invalid worker count */
    sts_wcnt_set_target(s, nq, STS_QTHREADS_MAX + 1);

    sts_destroy(s);
}

/* Test: send a "ping" through each queue  */
MTF_DEFINE_UTEST_PRE(test, t_ping, pre_test)
{
    merr_t      err;
    struct sts *s;
    u64         rtt = 0;
    uint        q, nq;
    uint        timeo_usec = 600 * 1000 * 1000;
    char        name[16];

    /* Testing nq from 1 to max, so verify max is small
     * to ensure test doesn't take too long.
     */
    ASSERT_TRUE(STS_QUEUES_MAX < 20);
    for (nq = 1; nq < STS_QUEUES_MAX; nq++) {
        snprintf(name, sizeof(name), "ping%d", nq);
        err = test_sts_create(name, nq, &s);
        ASSERT_EQ(err, 0);

        log_info("create w/ %u queues", nq);

        for (q = 0; q < nq; q++) {
            err = job_ping(s, q, timeo_usec, &rtt);
            ASSERT_EQ(err, 0);
            log_info("queue %u of %u, %lu ns ping", q, nq, rtt);
        }

        sts_destroy(s);
    }
}

/* Test: verify that workers for a single queue execute concurrently */
MTF_DEFINE_UTEST_PRE(test, t_workers_concurrent, pre_test)
{
    merr_t      err;
    atomic_t    var;
    int         v;
    struct sts *s;
    struct job  job1, job2;

    atomic_set(&var, 1);

    /* one queue, two workers */
    err = test_sts_create("conc", 1, &s);
    ASSERT_EQ(err, 0);

    /* job2: wait for var == 2, then var += 1 */
    jsubmit(s, jinit(&job2, 0, 0, &var, 2, 1));

    /* since there's only one worker, job2 will not complete */
    sleep(1);
    v = atomic_read(&var);
    ASSERT_EQ(v, 1);

    /* Job1: wait for var == 1, then var += 1.
     * This should run on idle worker, and clear the way for job2.
     */
    jsubmit(s, jinit(&job1, 0, 0, &var, 1, 1));
    err = atomic_read_timeout(&var, 3, 10 * 1000 * 1000);
    ASSERT_EQ(err, 0);

    sts_destroy(s);
}

/* Test: pause / resume
 * Test: destroy with jobs in queue
 */
MTF_DEFINE_UTEST_PRE(test, t_sts_pause, pre_test)
{
    merr_t      err;
    atomic_t    var;
    int         v1, v2;
    uint        i, q;
    uint        nq = 3;
    struct sts *s;
    struct job  jobs[4];

    atomic_set(&var, 0);

    err = test_sts_create("pause", nq, &s);
    ASSERT_EQ(err, 0);

    sts_pause(s);

    v1 = atomic_read(&var);
    ASSERT_EQ(v1, 0);

    for (i = 0; i < NELEM(jobs); i++) {
        /* 1 ms delay, no wait, add one to var */
        q = i % nq;
        jinit(&jobs[i], q, 1, &var, 0, 1);
        jrepeat(&jobs[i], REPEAT_FOREVER, false, 0);
        jsubmit(s, &jobs[i]);
    }

    for (i = 0; i < 5; i++) {
        /* wait 100ms in paused state, verify var has not changed */
        msleep(50);
        v2 = atomic_read(&var);
        ASSERT_EQ(v1, v2);

        /* resume, wait, verify it has changed */
        sts_resume(s);
        msleep(100);
        v1 = atomic_read(&var);

        sts_pause(s);
        log_info("var incremented %d times after resume", v1 - v2);
        msleep(1000);
        v1 = atomic_read(&var);
    }

    sts_destroy(s);
}

/* Tests for test destroy
 *
 * The test matrix at the moment sts_destroy is called consists of the
 * following independent dimensions:
 *
 *   - queues empty or with jobs
 *   - workers waiting on queue or running a slice
 *   - SS_PAUSE or SS_RUN
 *   - with or without destroy method
 *   - many fast jobs or few slow jobs
 */
MTF_DEFINE_UTEST_PRE(test, t_sts_destroy, pre_test)
{
    sts_destroy(0);
}

MTF_END_UTEST_COLLECTION(test);
