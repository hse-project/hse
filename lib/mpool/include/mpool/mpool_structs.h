/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_STRUCTS_H
#define MPOOL_STRUCTS_H

#include <hse/types.h>

#include <hse_util/inttypes.h>
#include <hse_util/storage.h>

#define WAL_FILE_PFX           "wal"
#define WAL_FILE_PFX_LEN       (sizeof(WAL_FILE_PFX) - 1)

/**
 * mpool_mclass = Media classes
 *
 * @MP_MED_CAPACITY: Primary data storage, cold data, or similar.
 * @MP_MED_STAGING:  Initial data ingest, hot data storage, or similar.
 * @MP_MED_PMEM:     WAL, Initial data ingest, hot data storage, or similar.
 */
enum mpool_mclass {
    MP_MED_CAPACITY = 0,
    MP_MED_STAGING  = 1,
    MP_MED_PMEM     = 2,
};

#define MP_MED_BASE            MP_MED_CAPACITY
#define MP_MED_MAX             MP_MED_PMEM
#define MP_MED_COUNT           (MP_MED_MAX + 1)
#define MP_MED_INVALID         U8_MAX

#define MPOOL_CAPACITY_MCLASS_DEFAULT_PATH "capacity"
#define MPOOL_PMEM_MCLASS_DEFAULT_PATH     "pmem"

#define MPOOL_MBLOCK_SIZE_DEFAULT      (32ul << MB_SHIFT)
#define MPOOL_MBLOCK_FILECNT_DEFAULT   (32)
#define MPOOL_MBLOCK_FILESZ_DEFAULT    (2048ull << GB_SHIFT)

/**
 * struct mpool_cparams - mpool create params
 *
 * @fmaxsz:    max file size
 * @mblocksz:  mblock size
 * @filecnt:   number of files in an mclass fileset
 * @path:      storage path
 */
struct mpool_cparams {
    struct {
        uint64_t fmaxsz;
        uint32_t mblocksz;
        uint8_t  filecnt;
        char     path[PATH_MAX];
    } mclass[MP_MED_COUNT];
};

/**
 * struct mpool_rparams - mpool run params
 *
 * @path:      storage path
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
    uint64_t mc_fmaxsz;
    uint32_t mc_mblocksz;
    uint8_t  mc_filecnt;
    char     mc_path[PATH_MAX];
};

/**
 * struct mpool_props -
 *
 * @mclass: Array of media class properties.
 */
struct mpool_props {
    struct mpool_mclass_props mclass[MP_MED_COUNT];
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


struct mpool_file_cb {
    void *cbarg;
    void (*cbfunc)(void *cbarg, const char *path);
};

#endif /* MPOOL_STRUCTS_H */
