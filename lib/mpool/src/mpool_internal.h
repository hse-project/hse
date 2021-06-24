/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_INTERNAL_H
#define MPOOL_INTERNAL_H

#include <hse_util/hse_err.h>

#include <mpool/mpool_structs.h>

struct media_class;
struct mpool;

/**
 * mpool_mclass_handle - return media class handle
 *
 * @mp:     mpool handle
 * @mclass: media class
 */
struct media_class *
mpool_mclass_handle(struct mpool *mp, enum mpool_mclass mclass);

/**
 * mpool_mclass_dirfd - return media class directory fd
 *
 * @mp:     mpool handle
 * @mclass: media class
 */
merr_t
mpool_mclass_dirfd(struct mpool *mp, enum mpool_mclass mclass, int *dirfd);

#endif /* MPOOL_INTERNAL_H */
