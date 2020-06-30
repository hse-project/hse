/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * CN performance counter family.
 *
 * There is one counter set per logical operation of CN.
 */
#ifndef CN_CN_PERFC_H
#define CN_CN_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse_util/perfc.h>
#include <hse_ikvdb/cn_perfc.h>

extern struct perfc_name cn_perfc_get[];
extern struct perfc_name cn_perfc_cmn[];
extern struct perfc_name cn_perfc_compact[];
extern struct perfc_name cn_perfc_shape[];
extern struct perfc_name cn_perfc_capped[];
extern struct perfc_name cn_perfc_mclass[];

#endif
