/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_KVDB_H
#define HSE_IKVS_CN_KVDB_H

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>

/* MTF_MOCK_DECL(cn_kvdb) */

/**
 * struct cn_kvdb - public portion of per kvdb cN object
 * @cnd_kblk_cnt:  number of cn kblocks in kvdb
 * @cnd_vblk_cnt:  number of cn vblocks in kvdb
 * @cnd_kblk_size: sum of on-media sizes of all cn kblocks in kvdb (bytes)
 * @cnd_vblk_size: sum of on-media sizes of all cn vblocks in kvdb (bytes)
 */
struct cn_kvdb {
    atomic64_t cnd_kblk_cnt;
    atomic64_t cnd_vblk_cnt;
    atomic64_t cnd_kblk_size;
    atomic64_t cnd_vblk_size;
};

/* MTF_MOCK */
merr_t
cn_kvdb_create(struct cn_kvdb **h);

/* MTF_MOCK */
void
cn_kvdb_destroy(struct cn_kvdb *h);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_kvdb_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
