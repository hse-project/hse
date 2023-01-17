/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_PERFC_INTERNAL_H
#define CN_PERFC_INTERNAL_H

#include <stdint.h>

#include "cn_perfc.h"

void
cn_perfc_bkts_create(struct perfc_name *pcn, int edgec, uint64_t *edgev, uint sample_pct);

void
cn_perfc_bkts_destroy(struct perfc_name *pcn);

#endif
