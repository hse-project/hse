/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_INTERNAL_H
#define MPOOL_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sys/uio.h>
#include <sys/types.h>

#define MPOOL_NAMESZ_MAX            64

#define MPOOL_ROOT_LOG_CAP          (8 * 1024 * 1024)

#define MPOOL_MBSIZE_MB_DEFAULT     32

struct mdc_props;
struct mdc_capacity;

/**
 * mp_media_classp = Media classes
 *
 * @MP_MED_CAPACITY: Primary data storage, cold data, or similar.
 * @MP_MED_STAGING:  Initial data ingest, hot data storage, or similar.
 */
enum mp_media_classp {
	MP_MED_CAPACITY   = 0,
	MP_MED_STAGING    = 1,
};

#define MP_MED_BASE        MP_MED_CAPACITY
#define MP_MED_NUMBER      (MP_MED_STAGING + 1)
#define MP_MED_INVALID     U8_MAX

/**
 * struct mpool_params -
 * @mp_poolid:          UUID of mpool
 * @mp_type:            user-specified identifier
 * @mp_uid:
 * @mp_gid:
 * @mp_mode:
 * @mp_stat:            overall mpool status (enum mpool_status)
 * @mp_mdc_captgt:      user MDC capacity
 * @mp_oidv:            user MDC OIDs
 * @mp_ra_pages_max:    max VMA map readahead pages
 * @mp_vma_size_max:    max VMA map size (log2)
 * @mp_mblocksz:        mblock size by media class (MiB)
 * @mp_utype:           user-defined type
 * @mp_name:            mpool name (2x for planned expansion)
 */
struct mpool_params {
	uuid_t      mp_poolid;
	uid_t       mp_uid;
	gid_t       mp_gid;
	mode_t      mp_mode;
	uint8_t     mp_stat;
	uint8_t     mp_spare_cap;
	uint8_t     mp_spare_stg;
	uint8_t     mp_rsvd0;
	uint64_t    mp_mdc_captgt;
	uint64_t    mp_oidv[2];
	uint32_t    mp_ra_pages_max;
	uint32_t    mp_vma_size_max;
	uint32_t    mp_mblocksz[MP_MED_NUMBER];
	uint16_t    mp_mdc0cap;
	uint16_t    mp_mdcncap;
	uint16_t    mp_mdcnum;
	uint16_t    mp_rsvd1;
	uint32_t    mp_rsvd2;
	uint64_t    mp_rsvd3;
	uint64_t    mp_rsvd4;
	uuid_t      mp_utype;
	char        mp_name[MPOOL_NAMESZ_MAX * 2];
};

/**
 * struct mpool_usage - in bytes
 * @mpu_total:   raw capacity for all drives
 * @mpu_usable:  usable capacity for all drives
 * @mpu_fusable: free usable capacity for all drives
 * @mpu_used:    used capacity for all drives; possible for
 *               used > usable when fusable=0; see smap
 *               module for details
 * @mpu_spare:   total spare space
 * @mpu_fspare:  free spare space
 *
 * @mpu_mblock_alen: mblock allocated length
 * @mpu_mblock_wlen: mblock written length
 * @mpu_mlog_alen:   mlog allocated length
 * @mpu_mblock_cnt:  number of active mblocks
 * @mpu_mlog_cnt:    number of active mlogs
 */
struct mpool_usage {
	uint64_t   mpu_total;
	uint64_t   mpu_usable;
	uint64_t   mpu_fusable;
	uint64_t   mpu_used;
	uint64_t   mpu_spare;
	uint64_t   mpu_fspare;

	uint64_t   mpu_alen;
	uint64_t   mpu_wlen;
	uint64_t   mpu_mblock_alen;
	uint64_t   mpu_mblock_wlen;
	uint64_t   mpu_mlog_alen;
	uint32_t   mpu_mblock_cnt;
	uint32_t   mpu_mlog_cnt;
};

/**
 * mpool_mclass_xprops -
 * @mc_devtype: type of devices in the media class
 *                  (enum pd_devtype)
 * @mc_mclass: media class (enum mp_media_classp)
 * @mc_sectorsz: media class (enum mp_media_classp)
 * @mc_spare: percent spare zones for drives
 * @mc_uacnt: UNAVAIL status drive count
 * @mc_zonepg: pages per zone
 * @mc_features: feature bitmask
 * @mc_usage: feature bitmask
 */
struct mpool_mclass_xprops {
	uint8_t                    mc_devtype;
	uint8_t                    mc_mclass;
	uint8_t                    mc_sectorsz;
	uint8_t                    mc_rsvd1;
	uint32_t                   mc_spare;
	uint16_t                   mc_uacnt;
	uint16_t                   mc_rsvd2;
	uint32_t                   mc_zonepg;
	uint64_t                   mc_features;
	uint64_t                   mc_rsvd3;
	struct mpool_usage         mc_usage;
};

/**
 * mpool_mclass_props -
 *
 * @mc_mblocksz:   mblock size in MiB
 * @mc_rsvd:       reserved struct field (for future use)
 * @mc_total:      total space in the media class (mc_usable + mc_spare)
 * @mc_usable:     usable space in bytes
 * @mc_used:       bytes allocated from usable space
 * @mc_spare:      spare space in bytes
 * @mc_spare_used: bytes allocated from spare space
 */
struct mpool_mclass_props {
	uint32_t   mc_mblocksz;
	uint32_t   mc_rsvd;
	uint64_t   mc_total;
	uint64_t   mc_usable;
	uint64_t   mc_used;
	uint64_t   mc_spare;
	uint64_t   mc_spare_used;
};

/*
 * struct mblock_props -
 *
 * @mpr_objid:        mblock identifier
 * @mpr_alloc_cap:    allocated capacity in bytes
 * @mpr_write_len:    written user-data in bytes
 * @mpr_optimal_wrsz: optimal write size(in bytes) for all but the last incremental mblock write
 * @mpr_mclassp:      media class
 * @mpr_iscommitted:  Is this mblock committed?
 */
struct mblock_props {
	uint64_t                mpr_objid;
	uint32_t                mpr_alloc_cap;
	uint32_t                mpr_write_len;
	uint32_t                mpr_optimal_wrsz;
	uint32_t                mpr_mclassp; /* enum mp_media_classp */
	uint8_t                 mpr_iscommitted;
	uint8_t                 mpr_rsvd1[7];
	uint64_t                mpr_rsvd2;
};

struct mblock_props_ex {
	struct mblock_props     mbx_props;
	uint8_t                 mbx_zonecnt;      /* zone count per strip */
	uint8_t                 mbx_rsvd1[7];
	uint64_t                mbx_rsvd2;
};


/**
 * enum mpc_vma_advice -
 * @MPC_VMA_COLD:
 * @MPC_VMA_WARM:
 * @MPC_VMA_HOT:
 * @MPC_VMA_PINNED:
 */
enum mpc_vma_advice {
	MPC_VMA_COLD = 0,
	MPC_VMA_WARM,
	MPC_VMA_HOT,
	MPC_VMA_PINNED
};

#endif /* MPOOL_INTERNAL_H */
