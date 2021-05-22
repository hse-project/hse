/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_MDC_H
#define WAL_MDC_H

#include <hse_util/hse_err.h>

struct wal;
struct wal_mdc;

merr_t
wal_mdc_create(
    struct mpool     *mp,
    enum mpool_mclass mclass,
    size_t            capacity,
    uint64_t         *mdcid1,
    uint64_t         *mdcid2);

merr_t
wal_mdc_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2);

merr_t
wal_mdc_open(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2, struct wal_mdc **handle);

merr_t
wal_mdc_close(struct wal_mdc *mdc);

merr_t
wal_mdc_sync(struct wal_mdc *mdc);

merr_t
wal_mdc_version_write(struct wal_mdc *mdc, struct wal *wal, bool sync);

merr_t
wal_mdc_config_write(struct wal_mdc *mdc, struct wal *wal, bool sync);

merr_t
wal_mdc_reclaim_write(struct wal_mdc *mdc, struct wal *wal, bool sync);

merr_t
wal_mdc_close_write(struct wal_mdc *mdc, bool sync);

merr_t
wal_mdc_format(struct wal_mdc *mdc, uint32_t version, uint32_t dur_intvl, uint32_t dur_sz);

merr_t
wal_mdc_compact(struct wal_mdc *mdc, struct wal *wal);

merr_t
wal_mdc_replay(struct wal_mdc *mdc, struct wal *wal);

#endif /* WAL_MDC_H */
