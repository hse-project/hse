/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_DELAY_H
#define HSE_PLATFORM_DELAY_H

#include <unistd.h>

static inline void
msleep(unsigned int msecs)
{
    /*
     * Possible usleep errors:
     *   EINTR  Interrupted by a signal; see signal(7).
     *   EINVAL usec is not smaller than 1000000.
     *
     * Instead of handling these errors, sleep in small chunks.
     * This avoids EINVAL and mitigates EINTR (ie, makes it looks
     * closer to kernel msleep() which is not interruptible).
     */
    unsigned int chunk = 250; /* 250ms chunk */
    unsigned int nap;

    while (msecs > 0) {
        nap = msecs < chunk ? msecs : chunk;
        (void)usleep(nap * 1000);
        msecs -= nap;
    }
}

#endif /* HSE_PLATFORM_DELAY_H */
