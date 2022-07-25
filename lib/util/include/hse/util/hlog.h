/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_HYPERLOGLOG_H
#define HSE_PLATFORM_HYPERLOGLOG_H

#include <stdint.h>

#include <sys/types.h>

#include <hse/error/merr.h>

struct hlog;

/* Defaults use by HSE */
#define HLOG_PRECISION 14
#define HLOG_SIZE      hlog_size(HLOG_PRECISION)
#define HLOG_PGC       ((HLOG_SIZE + PAGE_SIZE - 1) / PAGE_SIZE)

#define HLOG_PRECISION_MIN 4
#define HLOG_PRECISION_MAX 18

#define hlog_size(p) (1 << (p))

merr_t
hlog_create(struct hlog **hlog_out, uint p) HSE_MOCK;

void
hlog_destroy(struct hlog *hlog) HSE_MOCK;

void
hlog_reset(struct hlog *hlog) HSE_MOCK;

const uint8_t *
hlog_data(const struct hlog *hlog) HSE_MOCK;

void
hlog_union(struct hlog *hlog, const uint8_t *new_regv) HSE_MOCK;

uint
hlog_precision(const struct hlog *hlog) HSE_MOCK;

void
hlog_add(struct hlog *hlog, uint64_t hash) HSE_MOCK;

uint64_t
hlog_card(const struct hlog *hlog) HSE_MOCK;

#if HSE_MOCKING
#include "hlog_ut.h"
#endif /* HSE_MOCKING */

#endif
