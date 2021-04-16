/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_INTERNAL_H
#define MPOOL_INTERNAL_H

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

#endif /* MPOOL_INTERNAL_H */
