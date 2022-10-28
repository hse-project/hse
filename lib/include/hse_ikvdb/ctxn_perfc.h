/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Client transaction (CTXN) performance counter family.
 *
 */

#ifndef CTXN_PERFC_H
#define CTXN_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse/util/perfc.h>

extern struct perfc_name ctxn_perfc_op[];

void
ctxn_perfc_init(void);

void
ctxn_perfc_fini(void);

#endif
