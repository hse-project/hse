/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_WORK_H
#define CN_WORK_H

#include <hse/util/workqueue.h>

struct cn;
struct cn_work;

typedef void
cn_work_fn(struct cn_work *);

struct cn_work {
    struct cn *        cnw_cnref;
    cn_work_fn *       cnw_handler;
    struct work_struct cnw_work;
};

void
cn_work_submit(struct cn *cn, cn_work_fn *worker, struct cn_work *work);

#endif
