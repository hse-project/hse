/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
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
