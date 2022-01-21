/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/condvar.h>

void
cv_init(struct cv *cv)
{
    pthread_condattr_t attrs;
    int rc;

    rc = pthread_condattr_init(&attrs);
    rc |= pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
    rc |= pthread_cond_init(&cv->cv_waitq, &attrs);
    rc |= pthread_condattr_destroy(&attrs);
    if (rc)
        abort();

    cv->cv_waiters = 0;
}

void
cv_destroy(struct cv *cv)
{
    int rc;

    rc = pthread_cond_destroy(&cv->cv_waitq);

    if (HSE_UNLIKELY(rc || cv->cv_waiters > 0))
        abort();
}

int
cv_timedwait(struct cv *cv, struct mutex *mtx, const long timeout, const char *wmesg)
{
    int rc;

    assert(wmesg);
    hse_wmesg_tls = wmesg;

    ++cv->cv_waiters;

    if (timeout < 0) {
        rc = pthread_cond_wait(&cv->cv_waitq, &mtx->pth_mutex);

        assert(rc == 0);
    } else {
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);

        ts.tv_nsec += (timeout % 1000) * 1000000;
        ts.tv_sec += (timeout / 1000) + (ts.tv_nsec / 1000000000);
        ts.tv_nsec %= 1000000000;

        rc = pthread_cond_timedwait(&cv->cv_waitq, &mtx->pth_mutex, &ts);

        assert(rc == 0 || rc == ETIMEDOUT);
    }

    --cv->cv_waiters;

    hse_wmesg_tls = "-";

    return rc;
}
