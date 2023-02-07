/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef KVDB_PERFC_H
#define KVDB_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse/util/perfc.h>

/*
 * KVDB operation performance counter families.
 *
 * There is one counter set per globally
 */
extern struct perfc_set kvdb_pc;
extern struct perfc_set kvdb_pkvdbl_pc; /* Public KVDB interface Latencies */
extern struct perfc_set kvdb_metrics_pc;

/*
 * c0 metrics performance counter family.
 *
 * There is one counter set per globally
 */
extern struct perfc_set c0_metrics_pc;

void
kvdb_perfc_init(void);

void
kvdb_perfc_fini(void);

#endif
