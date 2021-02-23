/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef KVDB_PERFC_H
#define KVDB_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse_util/perfc.h>

/*
 * KVDB operation performance counter families.
 *
 * There is one counter set per globally
 */

extern struct perfc_name kvdb_perfc_op[];
extern struct perfc_name kvdb_perfc_pkvdbl_op[];
extern struct perfc_name csched_sp3_perfc[];

extern struct perfc_set kvdb_pc;
extern struct perfc_set kvdb_pkvdbl_pc; /* Public KVDB interface Latencies */

/*
 * c0 metrics performance counter family.
 *
 * There is one counter set per globally
 */

extern struct perfc_name c0_metrics_perfc[];
extern struct perfc_name kvdb_metrics_perfc[];

extern struct perfc_set c0_metrics_pc;

void
kvdb_perfc_init(void);

void
kvdb_perfc_fini(void);

#endif
