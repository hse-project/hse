/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_IKVS_CN_KVDB_H
#define HSE_IKVS_CN_KVDB_H

#include <hse/error/merr.h>
#include <hse/util/atomic.h>
#include <hse/util/workqueue.h>

/**
 * Public portion of per kvdb cN object
 */
struct cn_kvdb {
    struct workqueue_struct *cn_maint_wq;
    struct workqueue_struct *cn_io_wq;
};

merr_t
cn_kvdb_create(uint cn_maint_threads, uint cn_io_threads, struct cn_kvdb **h) HSE_MOCK;

void
cn_kvdb_destroy(struct cn_kvdb *h) HSE_MOCK;

#if HSE_MOCKING
#include "cn_kvdb_ut.h"
#endif /* HSE_MOCKING */

#endif
