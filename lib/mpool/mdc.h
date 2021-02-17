/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_H
#define MPOOL_MDC_H

#include <hse_util/mutex.h>
#include <hse_util/hse_err.h>

#define MDC_ROOT_MAGIC (0xFACE0FFF)

struct mpool;
struct mpool_mdc;

struct media_class *
mdc_mclass_get(struct mpool_mdc *mdc);

merr_t
mpool_mdc_root_init(struct mpool *mp);

merr_t
mpool_mdc_root_destroy(struct mpool *mp);

#endif /* MPOOL_MDC_H */
