/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_KVDB_H
#define HSE_IKVS_CN_KVDB_H

#include <hse/util/atomic.h>
#include <hse/error/merr.h>
#include <hse/util/workqueue.h>

/* MTF_MOCK_DECL(cn_kvdb) */

/**
 * Public portion of per kvdb cN object
 */
struct cn_kvdb {
    struct workqueue_struct *cn_maint_wq;
    struct workqueue_struct *cn_io_wq;
};

/* MTF_MOCK */
merr_t
cn_kvdb_create(uint cn_maint_threads, uint cn_io_threads, struct cn_kvdb **h);

/* MTF_MOCK */
void
cn_kvdb_destroy(struct cn_kvdb *h);

#if HSE_MOCKING
#include "cn_kvdb_ut.h"
#endif /* HSE_MOCKING */

#endif
