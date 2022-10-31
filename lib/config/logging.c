/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_logging

#include <hse/ikvdb/param.h>

#include "logging.h"

const char *
params_logging_context(const struct params *const p)
{
	switch (p->p_type) {
        case PARAMS_HSE_GP:
            return "HSE global param";
        case PARAMS_KVDB_CP:
            return "KVDB create-time param";
        case PARAMS_KVDB_RP:
            return "KVDB runtime param";
        case PARAMS_KVS_CP:
            return "KVS create-time param";
        case PARAMS_KVS_RP:
            return "KVS runtime param";
        case PARAMS_GEN:
            /* This should really be an assert(false), but for testing purposes... */
            return "(null) param";
        default:
            abort();
    }

    return NULL;
}
