/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * C0SKM performance counter family.
 *
 * There is one counter set per c0skm instance.
 */

#ifndef C0SKM_PERFC_H
#define C0SKM_PERFC_H

#include <hse/kvdb_perfc.h>

#include <hse_util/perfc.h>

void
c0skm_perfc_init(void);

void
c0skm_perfc_fini(void);

#endif /* C0SKM_PERFC_H */
