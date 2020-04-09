/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_NOOP_H
#define HSE_KVDB_CN_CSCHED_NOOP_H

#include <hse_util/hse_err.h>

/* MTF_MOCK_DECL(csched_noop) */

struct kvdb_rparams;
struct csched_ops;

/* MTF_MOCK */
merr_t
sp_noop_create(struct kvdb_rparams *rp, const char *mp, struct csched_ops **handle);

struct noop_node {
};
struct noop_tree {
};

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_noop_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
