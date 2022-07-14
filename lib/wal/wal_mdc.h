/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_MDC_H
#define WAL_MDC_H

#include <error/merr.h>

struct wal;
struct wal_mdc;

merr_t
wal_mdc_create(
    struct mpool     *mp,
    enum hse_mclass mclass,
    size_t            capacity,
    uint64_t         *mdcid1,
    uint64_t         *mdcid2);

void
wal_mdc_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2);

merr_t
wal_mdc_open(
    struct mpool    *mp,
    uint64_t         mdcid1,
    uint64_t         mdcid2,
    bool             rdonly,
    struct wal_mdc **handle);

merr_t
wal_mdc_close(struct wal_mdc *mdc);

merr_t
wal_mdc_format(struct wal_mdc *mdc, uint32_t version);

merr_t
wal_mdc_compact(struct wal_mdc *mdc, struct wal *wal);

merr_t
wal_mdc_replay(struct wal_mdc *mdc, struct wal *wal);

merr_t
wal_mdc_close_write(struct wal_mdc *mdc);

#endif /* WAL_MDC_H */
