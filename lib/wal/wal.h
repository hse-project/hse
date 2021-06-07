/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef WAL_INTERNAL_H
#define WAL_INTERNAL_H

#include <hse_ikvdb/wal.h>

#define WAL_DUR_INTVL_MS   (100)
#define WAL_DUR_SZ_BYTES   (100 << 20)
#define WAL_MDC_CAPACITY   (1 << 30)
#define WAL_MDC_MAGIC      (0xabcdabcd)

#define MSEC_TO_NSEC(x)    ((x) * 1000UL * 1000)
#define NSEC_TO_MSEC(x)    ((x) / MSEC_TO_NSEC(1))

struct wal;
struct mpool;

void
wal_dur_params_get(struct wal *wal, uint32_t *dur_intvl, uint32_t *dur_sz);

void
wal_dur_params_set(struct wal *wal, uint32_t dur_intvl, uint32_t dur_sz);

uint64_t
wal_reclaim_dgen_get(struct wal *wal);

void
wal_reclaim_dgen_set(struct wal *wal, uint64_t rdgen);

uint32_t
wal_version_get(struct wal *wal);

void
wal_version_set(struct wal *wal, uint32_t version);

#endif /* WAL_INTERNAL_H */
