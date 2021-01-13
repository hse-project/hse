/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_H
#define MPOOL_H

#include <mpool/mpool2.h>

#include "mclass.h"

struct media_class;
struct mdc;

/**
 * struct mpool - mpool handle
 *
 * @mc:       media class handles
 * @mdc_root: root mdc handle (stored in the capacity mclass)
 * @name:     mpool/kvdb name
 */
struct mpool {
	struct media_class *mc[MCID_MAX];

	struct mdc         *mdc_root;

	char                name[64];
};

#endif /* MPOOL_H */

