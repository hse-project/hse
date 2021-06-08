/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_H
#define MPOOL_MDC_H

#include <hse_util/mutex.h>
#include <hse_util/hse_err.h>

#define MDC_FILES_MAX  10

struct mpool;
struct mpool_mdc;

/**
 * mdc_mclass_get() - get mclass handle
 *
 * @mdc: MDC handle
 */
struct media_class *
mdc_mclass_get(struct mpool_mdc *mdc);

/**
 * mpool_mdc_root_init() - initialize the root MDC
 *
 * @mp: mpool handle
 */
merr_t
mpool_mdc_root_init(struct mpool *mp);

/**
 * mpool_mdc_sync() - sync the root MDC
 *
 * @mdc: mdc handle
 */
merr_t
mpool_mdc_sync(struct mpool_mdc *mdc);

#endif /* MPOOL_MDC_H */
