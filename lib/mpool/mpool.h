/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_H
#define MPOOL_H

#include <mpool/mpool_internal.h>

#include "mclass.h"

struct media_class;
struct mdc;

struct media_class *
mpool_mclass_handle(struct mpool *mp, enum mp_media_classp mclass);

#endif /* MPOOL_H */
