/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/condvar.h>
#include <hse_util/timing.h>

void
cv_init(struct cv *cv, const char *desc)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

    cv->cv_desc = desc;
    cv->cv_waiters = 0;
    cv->cv_waitq = cond;
}

void
cv_destroy(struct cv *cv)
{
    int rc;

    rc = pthread_cond_destroy(&cv->cv_waitq);

    if (unlikely(rc || cv->cv_waiters > 0))
        abort();
}

int
cv_timedwait(struct cv *cv, struct mutex *mtx, const int timeout)
{
    struct timespec ts;
    int             rc;

    if (timeout < 0) {
        ++cv->cv_waiters;
        rc = pthread_cond_wait(&cv->cv_waitq, &mtx->pth_mutex);
        --cv->cv_waiters;

        if (unlikely(rc))
            abort();
        return 0;
    }

    get_realtime(&ts);

    ts.tv_nsec += (timeout % 1000) * 1000000;
    ts.tv_sec += (timeout / 1000) + (ts.tv_nsec / 1000000000);
    ts.tv_nsec %= 1000000000;

    ++cv->cv_waiters;
    rc = pthread_cond_timedwait(&cv->cv_waitq, &mtx->pth_mutex, &ts);
    --cv->cv_waiters;

    if (unlikely(rc != 0 && rc != ETIMEDOUT))
        abort();

    return rc ? ETIMEDOUT : 0;
}
