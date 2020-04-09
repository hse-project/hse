/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_VBLOCK_BUILDER_EXT_H
#define HSE_KVS_CN_VBLOCK_BUILDER_EXT_H

/* MTF_MOCK_DECL(vblock_builder_ext) */

#include <hse_util/hse_err.h>
struct vblock_builder;
struct kvs_rparams;

/* MTF_MOCK */
merr_t
vbb_create_ext(struct vblock_builder *bldr, struct kvs_rparams *rp);

/* MTF_MOCK */
void
vbb_destroy_ext(struct vblock_builder *bld);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "vblock_builder_ext_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
