/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_STRUCTS_H
#define MPOOL_STRUCTS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <sys/types.h>

#define MPOOL_ROOT_LOG_CAP (8 * 1024 * 1024)

/**
 * mp_media_classp = Media classes
 *
 * @MP_MED_CAPACITY: Primary data storage, cold data, or similar.
 * @MP_MED_STAGING:  Initial data ingest, hot data storage, or similar.
 */
enum mp_media_classp {
    MP_MED_CAPACITY = 0,
    MP_MED_STAGING = 1,
};

#define MP_MED_BASE    MP_MED_CAPACITY
#define MP_MED_COUNT   (MP_MED_STAGING + 1)
#define MP_MED_INVALID U8_MAX

/**
 * struct mpool_props -
 * @mp_vma_size_max:    max VMA map size (log2)
 * @mp_mblocksz:        mblock size by media class (MiB)
 */
struct mpool_props {
    uint32_t mp_vma_size_max;
    uint32_t mp_mblocksz[MP_MED_COUNT];
};

/**
 * struct mpool_usage - in bytes
 * @mpu_total:   total capacity
 * @mpu_used:    used capacity
 *
 * @mpu_mblock_alen: mblock allocated length
 * @mpu_mblock_wlen: mblock written length
 * @mpu_mblock_cnt:  number of active mblocks
 */
struct mpool_usage {
    uint64_t mpu_total;
    uint64_t mpu_used;

    uint64_t mpu_mblock_alen;
    uint64_t mpu_mblock_wlen;
    uint32_t mpu_mblock_cnt;
};

/**
 * mpool_mclass_props -
 *
 * @mc_total:      total space in the media class
 * @mc_used:       used space
 * @mc_mblocksz:   mblock size in MiB
 */
struct mpool_mclass_props {
    uint64_t mc_total;
    uint64_t mc_used;
    uint32_t mc_mblocksz;
};

/*
 * struct mblock_props -
 *
 * @mpr_objid:        mblock identifier
 * @mpr_alloc_cap:    allocated capacity in bytes
 * @mpr_write_len:    written user-data in bytes
 * @mpr_optimal_wrsz: optimal write size(in bytes) for all but the last incremental mblock write
 * @mpr_mclassp:      media class
 */
struct mblock_props {
    uint64_t mpr_objid;
    uint32_t mpr_alloc_cap;
    uint32_t mpr_write_len;
    uint32_t mpr_optimal_wrsz;
    uint32_t mpr_mclassp; /* enum mp_media_classp */
};

#endif /* MPOOL_STRUCTS_H */
