/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_KVCOMP_H
#define HSE_KVDB_CN_KVCOMP_H

#include <hse/error/merr.h>
#include <hse_util/inttypes.h>

struct cn_compaction_work;

merr_t
cn_kvcompact(struct cn_compaction_work *w);

#endif

