/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/*
 * CN performance counter family.
 *
 * There is one counter set per logical operation of CN.
 */
#ifndef CN_CN_PERFC_H
#define CN_CN_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse/ikvdb/cn_perfc.h>
#include <hse/util/perfc.h>

struct cn;

void
cn_perfc_alloc(struct cn *cn, uint prio);

void
cn_perfc_free(struct cn *cn);

#endif
