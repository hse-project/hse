/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef MPOOL_STRUCTS_H
#define MPOOL_STRUCTS_H

#include <stdbool.h>
#include <stdint.h>

#include <hse/types.h>

#include <hse/mpool/limits.h>
#include <hse/util/page.h>
#include <hse/util/storage.h>

#define WAL_FILE_PFX     "wal"
#define WAL_FILE_PFX_LEN (sizeof(WAL_FILE_PFX) - 1)

/* [HSE_REVISIT]: The fact that this is necessary at all seems like a code
 * smell. Ideally, I think we remove this and properly propogate errors up the
 * stack, assert(), or abort(). This is a holdover from MP_MED_INVALID.
 */
#define HSE_MCLASS_INVALID   UINT8_MAX
#define HSE_MCLASS_AUTO      HSE_MCLASS_COUNT
#define HSE_MCLASS_AUTO_NAME "auto"

#define MPOOL_CAPACITY_MCLASS_DEFAULT_PATH "capacity"
#define MPOOL_PMEM_MCLASS_DEFAULT_PATH     "pmem"

/* Both prealloc and punch hole flags are mutually exclusive */
#define MPOOL_MBLOCK_PREALLOC   (1u << 0) /* advisory */
#define MPOOL_MBLOCK_PUNCH_HOLE (1u << 1)

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
        uint8_t filecnt;
        char path[PATH_MAX];
    } mclass[HSE_MCLASS_COUNT];
};

/**
 * struct mpool_rparams - mpool run params
 *
 * @path:      storage path
 */
struct mpool_rparams {
    struct {
        bool dio_disable;
        char path[PATH_MAX];
    } mclass[HSE_MCLASS_COUNT];
};

/**
 * struct mpool_dparams - mpool destroy params
 *
 * @path: storage path
 */
struct mpool_dparams {
    struct {
        char path[PATH_MAX];
    } mclass[HSE_MCLASS_COUNT];
};

/**
 * struct mpool_info - aggregated mpool stats across all configured media classes
 *
 * @mclass: Array of media class info objects.
 */
struct mpool_info {
    struct hse_mclass_info mclass[HSE_MCLASS_COUNT];
};

/**
 * mpool_mclass_props - props for a specific media class
 *
 * @mc_mblocksz: mblock size in MiB
 */
struct mpool_mclass_props {
    uint64_t mc_fmaxsz;
    uint32_t mc_mblocksz;
    uint16_t mc_ra_pages;
    uint8_t mc_filecnt;
    char mc_path[PATH_MAX];
};

/**
 * struct mpool_props -
 *
 * @mclass: Array of media class properties.
 */
struct mpool_props {
    struct mpool_mclass_props mclass[HSE_MCLASS_COUNT];
};

/*
 * struct mblock_props -
 *
 * @mpr_objid:        mblock identifier
 * @mpr_alloc_cap:    allocated capacity in bytes
 * @mpr_write_len:    written user-data in bytes
 * @mpr_mclass:       media class
 * @mpr_ra_pages:     read-ahead size in pages
 */
struct mblock_props {
    uint64_t mpr_objid;
    uint32_t mpr_alloc_cap;
    uint32_t mpr_write_len;
    uint32_t mpr_mclass;
    uint16_t mpr_ra_pages;
};

struct mpool_file_cb {
    void *cbarg;
    void (*cbfunc)(void *cbarg, const char *path);
};

#endif /* MPOOL_STRUCTS_H */
