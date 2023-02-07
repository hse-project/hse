/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef WAL_INTERNAL_H
#define WAL_INTERNAL_H

#include <hse/ikvdb/wal.h>
#include <hse/ikvdb/limits.h>

/* clang-format off */

#define WAL_MDC_CAPACITY        (32u << MB_SHIFT)
#define WAL_MAGIC               (0xabcdabcdU)

#define WAL_FILE_SIZE_BYTES     (((HSE_C0_SPILL_MB_MAX * 3) / 8) << MB_SHIFT)

#define MSEC_TO_NSEC(_ms)       (NSEC_PER_SEC / MSEC_PER_SEC * (_ms))
#define NSEC_TO_MSEC(_ns)       ((_ns) / (NSEC_PER_SEC / MSEC_PER_SEC))

#define WAL_NODE_MAX            (4)
#define WAL_BPN_MAX             (2)
#define WAL_BUF_MAX             (WAL_NODE_MAX * WAL_BPN_MAX)

#define WAL_ROFF_UNRECOV_ERR    (UINT64_MAX)
#define WAL_ROFF_RECOV_ERR      (UINT64_MAX - 1)

#define WAL_FLUSH_WAIT_PCT      (25)

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

struct wal_flush_stats {
    uint32_t bufcnt;
    uint64_t bufsz;
    uint64_t max_buflen;
    uint64_t flush_soff[WAL_BUF_MAX];
    uint64_t flush_len[WAL_BUF_MAX];
    uint64_t flush_tlen;
};

struct wal;
struct mpool;

enum hse_mclass
wal_dur_mclass_get(struct wal *wal);

void
wal_dur_mclass_set(struct wal *wal, enum hse_mclass mclass);

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
wal_allows_write(const struct wal *wal);

bool
wal_ignores_replay(const struct wal *wal);

bool
wal_is_clean(const struct wal *wal);

struct ikvdb *
wal_ikvdb(const struct wal *wal);

struct wal_fileset *
wal_fset(const struct wal *wal);

struct wal_mdc *
wal_mdc(const struct wal *wal);

struct kvdb_health *
wal_health(const struct wal *wal);

#endif /* WAL_INTERNAL_H */
