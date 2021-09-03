/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef WAL_INTERNAL_H
#define WAL_INTERNAL_H

#include <hse_ikvdb/wal.h>
#include <hse_ikvdb/limits.h>

/* clang-format off */

#define WAL_MDC_CAPACITY        (32u << MB_SHIFT)
#define WAL_MAGIC               (0xabcdabcd)
#define WAL_FILE_SIZE_BYTES     ((HSE_C0_CHEAP_SZ_DFLT * HSE_C0_INGEST_WIDTH_DFLT * 3) / 10)

#define MSEC_TO_NSEC(_ms)       (NSEC_PER_SEC / MSEC_PER_SEC * (_ms))
#define NSEC_TO_MSEC(_ns)       ((_ns) / (NSEC_PER_SEC / MSEC_PER_SEC))

#define WAL_NODE_MAX            (4)
#define WAL_BPN_MAX             (2)
#define WAL_BUF_MAX             (WAL_NODE_MAX * WAL_BPN_MAX)

#define WAL_ROFF_UNRECOV_ERR    (UINT64_MAX)
#define WAL_ROFF_RECOV_ERR      (UINT64_MAX - 1)

/* clang-format on */

struct wal_minmax_info {
    uint64_t min_seqno;
    uint64_t max_seqno;
    uint64_t min_gen;
    uint64_t max_gen;
    uint64_t min_txid;
    uint64_t max_txid;
};

struct wal_iocb {
    void *cbarg;
    void (*iocb)(void *cbarg, merr_t err);
};

struct wal;
struct mpool;

enum mpool_mclass
wal_dur_mclass_get(struct wal *wal);

void
wal_dur_mclass_set(struct wal *wal, enum mpool_mclass mclass);

uint64_t
wal_reclaim_gen_get(struct wal *wal);

void
wal_reclaim_gen_set(struct wal *wal, uint64_t rgen);

uint32_t
wal_version_get(struct wal *wal);

void
wal_version_set(struct wal *wal, uint32_t version);

struct mpool *
wal_mpool_get(struct wal *wal);

void
wal_clean_set(struct wal *wal);

bool
wal_is_read_only(struct wal *wal);

bool
wal_is_clean(struct wal *wal);

struct ikvdb *
wal_ikvdb(struct wal *wal);

struct wal_fileset *
wal_fset(struct wal *wal);

struct wal_mdc *
wal_mdc(struct wal *wal);

#endif /* WAL_INTERNAL_H */
