/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_KVCOMPACT_H
#define HSE_KVDB_CN_KVCOMPACT_H

#include <hse/error/merr.h>

struct cn_compaction_work;

merr_t
cn_kvcompact(struct cn_compaction_work *w);

#endif
