/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_PERFC_INTERNAL_H
#define CN_PERFC_INTERNAL_H

#include "cn_perfc.h"

void
cn_perfc_bkts_create(struct perfc_name *pcn, int edgec, u64 *edgev, uint sample_pct);

void
cn_perfc_bkts_destroy(struct perfc_name *pcn);

#endif
