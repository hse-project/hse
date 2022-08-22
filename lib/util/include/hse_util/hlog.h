/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_HYPERLOGLOG_H
#define HSE_PLATFORM_HYPERLOGLOG_H

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(hlog) */

struct hlog;

/* Defaults use by HSE */
#define HLOG_PRECISION 14
#define HLOG_SIZE hlog_size(HLOG_PRECISION)
#define HLOG_PGC ((HLOG_SIZE + PAGE_SIZE - 1) / PAGE_SIZE)

#define HLOG_PRECISION_MIN 4
#define HLOG_PRECISION_MAX 18

#define hlog_size(p) (1 << (p))

/* MTF_MOCK */
merr_t
hlog_create(struct hlog **hlog_out, uint p);

/* MTF_MOCK */
void
hlog_destroy(struct hlog *hlog);

/* MTF_MOCK */
void
hlog_reset(struct hlog *hlog);

/* MTF_MOCK */
uint8_t *
hlog_data(struct hlog *hlog);

/* MTF_MOCK */
void
hlog_union(struct hlog *hlog, const uint8_t *new_regv);

/* MTF_MOCK */
uint
hlog_precision(struct hlog *hlog);

/* MTF_MOCK */
void
hlog_add(struct hlog *hlog, u64 hash);

/* MTF_MOCK */
u64
hlog_card(struct hlog *hlog);

#if HSE_MOCKING
#include "hlog_ut.h"
#endif /* HSE_MOCKING */

#endif
