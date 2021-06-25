/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_STRUCTS_H
#define MPOOL_STRUCTS_H

#include <hse_util/inttypes.h>

#define MPOOL_ROOT_LOG_CAP     (8 * 1024 * 1024)
#define MDC_ROOT_MAGIC         (0xFACE0FFF)
#define MDC_ROOT_FILE_NAME     "hse.meta"
#define WAL_FILE_PFX           "wal"

/**
 * mpool_mclass = Media classes
 *
 * @MP_MED_CAPACITY: Primary data storage, cold data, or similar.
 * @MP_MED_STAGING:  Initial data ingest, hot data storage, or similar.
 */
enum mpool_mclass {
    MP_MED_CAPACITY = 0,
    MP_MED_STAGING = 1,
};

#define MP_MED_BASE    MP_MED_CAPACITY
#define MP_MED_COUNT   (MP_MED_STAGING + 1)
#define MP_MED_INVALID U8_MAX


/**
 * struct mpool_cparams - mpool create params
 *
 * @fmaxsz:   max file size
 * @mblocksz: mblock size
 * @filecnt:  number of files in an mclass fileset
 * @path:     storage path
 */
struct mpool_cparams {
    struct {
        size_t  fmaxsz;
        size_t  mblocksz;
        uint8_t filecnt;
        char    path[PATH_MAX];
    } mclass[MP_MED_COUNT];
};

/**
 * struct mpool_rparams - mpool run params
 *
 * @path: storage path
 */
struct mpool_rparams {
    struct {
        char path[PATH_MAX];
    } mclass[MP_MED_COUNT];
};

/**
 * struct mpool_dparams - mpool destroy params
 *
 * @path: storage path
 */
struct mpool_dparams {
    struct {
        char path[PATH_MAX];
    } mclass[MP_MED_COUNT];
};

/**
 * struct mpool_props -
 *
 * @mp_vma_size_max:    max VMA map size (log2)
 * @mp_mblocksz:        mblock size by media class (MiB)
 */
struct mpool_props {
    uint32_t mp_vma_size_max;
    uint32_t mp_mblocksz[MP_MED_COUNT];
};

/**
 * struct mpool_stats - aggregated mpool stats across all configured media classes
 *
 * @mps_total:     total space in the filesystem(s) containing mclass data directories
 * @mps_available: available space in the filesystem(s) containing mclass data directories
 * @mps_allocated: allocated capacity
 * @mps_used:      used capacity
 * @mps_mblock_cnt: number of active mblocks
 * @mps_path:       storage path
 */
struct mpool_stats {
    uint64_t mps_total;
    uint64_t mps_available;
    uint64_t mps_allocated;
    uint64_t mps_used;
    uint32_t mps_mblock_cnt;
    char     mps_path[MP_MED_COUNT][PATH_MAX];
};

/**
 * mpool_mclass_props - props for a specific media class
 *
 * @mc_mblocksz: mblock size in MiB
 */
struct mpool_mclass_props {
    uint32_t mc_mblocksz;
};

/**
 * struct mpool_mclass_stats - stats for a specific media class
 *
 * @mcs_total:      total space in the filesystem containing this mclass data directory
 * @mcs_available:  available space in the filesystem containing this mclass data directory
 * @mcs_allocated:  allocated capacity
 * @mcs_used:       used capacity
 * @mcs_fsid:       fsid of the FS hosting this data directory
 * @mcs_mblock_cnt: number of active mblocks
 * @mcs_path:       media class storage path
 */
struct mpool_mclass_stats {
    uint64_t mcs_total;
    uint64_t mcs_available;
    uint64_t mcs_allocated;
    uint64_t mcs_used;
    uint64_t mcs_fsid;
    uint32_t mcs_mblock_cnt;
    char     mcs_path[PATH_MAX];
};

/*
 * struct mblock_props -
 *
 * @mpr_objid:        mblock identifier
 * @mpr_alloc_cap:    allocated capacity in bytes
 * @mpr_write_len:    written user-data in bytes
 * @mpr_optimal_wrsz: optimal write size(in bytes) for all but the last incremental mblock write
 * @mpr_mclass:       media class
 */
struct mblock_props {
    uint64_t mpr_objid;
    uint32_t mpr_alloc_cap;
    uint32_t mpr_write_len;
    uint32_t mpr_optimal_wrsz;
    uint32_t mpr_mclass;
};

#endif /* MPOOL_STRUCTS_H */
