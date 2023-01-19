/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <mtf/framework.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/kvdb_health.h>

MTF_BEGIN_UTEST_COLLECTION(kvdb_health_test)

MTF_DEFINE_UTEST(kvdb_health_test, health)
{
    struct kvdb_health health;

    uint event, mask;
    merr_t err = 0;
    int i;
    merr_t healtherr = merr(ENOANO);

    memset(&health, 0, sizeof(health));

    /* Test that a non-event doesn't trip an error.
     */
    err = kvdb_health_event(&health, KVDB_HEALTH_FLAG_NONE, healtherr);
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_NONE);
    ASSERT_EQ(err, 0);

    err = kvdb_health_clear(&health, KVDB_HEALTH_FLAG_NONE);
    ASSERT_NE(err, 0);

    /* Trip, check, clear, and check each event type.
     */
    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_event(&health, event, healtherr);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL & ~event);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    /* Try to trip an invalid event.
     */
    err = kvdb_health_event(&health, event, healtherr);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvdb_health_clear(&health, event);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* Trip all events, check that each is tripped, then clear them all.
     */
    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_event(&health, event, healtherr);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, healtherr);

    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    /* errno 0 shouldn't trip an error
     */
    err = kvdb_health_error(&health, merr(0));
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    /* Check that all non-zero errnos trip an event.
     */
    for (i = 1; i < 133; ++i) {
        err = kvdb_health_error(&health, merr(i));
        ASSERT_EQ(err, 0);

        err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
        ASSERT_NE(err, 0);

        /* Clear all events...
         */
        mask = KVDB_HEALTH_FLAG_ALL;
        for (event = 1; mask; event <<= 1) {
            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }

        err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
        ASSERT_EQ(err, 0);
    }
}

MTF_END_UTEST_COLLECTION(kvdb_health_test);
