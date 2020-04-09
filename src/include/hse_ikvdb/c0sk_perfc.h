/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * C0SK performance counter family.
 *
 * There is one counter set per logical instance of c0sk
 */

#ifndef C0SK_PERFC_H
#define C0SK_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse_util/perfc.h>

extern struct perfc_name c0sk_perfc_op[];
extern struct perfc_name c0sk_perfc_ingest[];

void
c0sk_perfc_init(void);

void
c0sk_perfc_fini(void);

#endif
