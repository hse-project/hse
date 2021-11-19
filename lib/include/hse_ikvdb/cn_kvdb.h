/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_KVDB_H
#define HSE_IKVS_CN_KVDB_H

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/workqueue.h>

/* MTF_MOCK_DECL(cn_kvdb) */

/**
 * struct cn_kvdb - public portion of per kvdb cN object
 * @cnd_kblk_cnt:  number of cn kblocks in kvdb
 * @cnd_vblk_cnt:  number of cn vblocks in kvdb
 * @cnd_kblk_size: sum of on-media sizes of all cn kblocks in kvdb (bytes)
 * @cnd_vblk_size: sum of on-media sizes of all cn vblocks in kvdb (bytes)
 */
struct cn_kvdb {
    atomic_ulong cnd_kblk_cnt;
    atomic_ulong cnd_vblk_cnt;
    atomic_ulong cnd_kblk_size;
    atomic_ulong cnd_vblk_size;

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
