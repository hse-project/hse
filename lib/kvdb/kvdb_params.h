/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_KVDB_PARAMS_H
#define HSE_KVDB_KVDB_PARAMS_H

#include <hse_util/hse_err.h>

struct kvdb_rparams;
struct kvdb_cparams;

/**
 * kvdb_rparams_add_to_dt() -
 * @mp_name:   mpool name
 * @p: runtime parameters
 *
 * Add all kvdb run-time parameters to the config subtree of the data tree
 */
merr_t
kvdb_rparams_add_to_dt(const char *mp_name, struct kvdb_rparams *p);

merr_t
kvdb_rparams_remove_from_dt(const char *mpool);

#endif /* HSE_KVDB_KVDB_PARAMS_H */
