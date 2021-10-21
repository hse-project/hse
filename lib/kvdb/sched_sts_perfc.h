/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_STS_PERFC_H
#define HSE_KVDB_STS_PERFC_H

#include <hse_util/platform.h>

/* MTF_MOCK_DECL(sched_sts_perfc) */

struct sts;

/* MTF_MOCK */
void
sts_perfc_alloc(uint prio, const char *name, const char *ctrname, struct perfc_set *setp);

/* MTF_MOCK */
void
sts_perfc_free(struct perfc_set *set);

#if HSE_MOCKING
#include "sched_sts_perfc_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVDB_STS_PERFC_H */
