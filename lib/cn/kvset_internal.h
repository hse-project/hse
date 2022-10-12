/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_INTERNAL_H
#define HSE_KVS_CN_KVSET_INTERNAL_H

#include <hse/error/merr.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/atomic.h>
#include <hse_util/workqueue.h>
#include <hse_util/key_util.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/omf_kmd.h>
#include <hse_ikvdb/kvset_view.h>

#include <mpool/mpool.h>

#include "cn_work.h"

#include "kblock_reader.h"
#include "bloom_reader.h"
#include "wbt_reader.h"
#include "blk_list.h"
#include "wbt_internal.h"
#include "cn_metrics.h"
#include "cn_tree.h"
#include "kvset.h"
#include "hblock_reader.h"

struct kvset_hblk {
    struct kvs_mblk_desc kh_hblk_desc;
    struct wbt_desc kh_ptree_desc;

    struct key_disc kh_pfx_max_disc;
    struct key_disc kh_pfx_min_disc;
    const void *kh_pfx_max;
    const void *kh_pfx_min;
    uint8_t kh_pfx_max_len;
    uint8_t kh_pfx_min_len;

    uint64_t kh_seqno_min; /* min seqno */
    uint64_t kh_seqno_max; /* max seqno */

    struct hblk_metrics kh_metrics;
};

struct kvset_kblk {
    struct kvs_mblk_desc kb_kblk_desc; /* kblock descriptor */
    struct wbt_desc      kb_wbt_desc;  /* wbtree descriptor */

    u8              kb_ksmall[64]; /* small key cache */
    struct key_disc kb_kdisc_max;  /* kdisc of largest key in kblk */
    struct key_disc kb_kdisc_min;  /* kdisc of smallest key */
    const uint8_t  *kb_hlog;       /* ptr to hlog region in kblk */
    const void     *kb_koff_max;   /* ptr to largest key in kblk */
    const void     *kb_koff_min;   /* ptr to smallest key in kblk */
    u16             kb_klen_max;   /* length of largest key */
    u16             kb_klen_min;   /* length of smallest key */

    struct bloom_desc kb_blm_desc;  /* Bloom descriptor */

    struct kblk_metrics kb_metrics; /* kblock metrics */
};

struct kvset {
    struct kvset_list_entry ks_entry; /* kvset list linkage */

    uint64_t      ks_dgen_hi; /* relative age of entries (hi) */
    uint64_t      ks_dgen_lo; /* relative age of entries (lo) */
    struct mpool *ks_mp;
    u32           ks_pfx_len; /* cn tree pfx_len */
    uint16_t      ks_rule;
    u64           ks_nodeid;
    u32           ks_vmin;
    u32           ks_vmax;
    uint64_t      ks_vra_len;
    uint32_t      ks_compc;

    struct kvs_rparams *ks_rp;
    u64                 ks_seqno_max;
    u64                 ks_cnid;
    struct cn_kvdb *    ks_cn_kvdb;
    struct cn_tree *    ks_tree;
    struct kvset_stats  ks_st;

    /* cndb - deferred delete */
    struct cndb        *ks_cndb;
    struct cndb_txn    *ks_delete_txn;
    void               *ks_delete_cookie;
    u64                 ks_kvsetid;

    /* new compaction metrics */
    u8 * ks_hlog;

    struct vgmap *ks_vgmap;
    bool          ks_use_vgmap; /* consult vgmap during query/compaction? */

    struct mbset_locator *ks_vblk2mbs;

    /* csched uses ks_work to mark busy all the kvsets within a compaction
     * operation (by stashing the address of the cn_compaction_work object
     * into ks_work).
     */
    const void * _Atomic ks_work;

    struct key_disc ks_kdisc_max; /* max key in kvset */
    struct key_disc ks_kdisc_min; /* min key in kvset */
    size_t          ks_lcp;       /* longest common prefix */

    struct kvset_hblk ks_hblk;

    const u8 *                ks_klarge; /* large key cache */
    struct mbset **           ks_vbsetv;
    uint                      ks_vbsetc;

    struct cn_work ks_kvset_cn_work;

    const void *ks_maxkey;  /* largest key in kvset */
    const void *ks_minkey;  /* smallest key in kvset */
    u16         ks_maxklen; /* length of largest key */
    u16         ks_minklen; /* length of smallest key */

    atomic_int ks_ref HSE_L1D_ALIGNED; /* reference count */
    u32        ks_deleted;             /* DEL_NONE, DEL_KEEPV, DEL_ALL */
    atomic_int ks_delete_error;
    atomic_int ks_mbset_callbacks;
    bool       ks_mbset_cb_pending;
    u64        ks_seqno_min;
    size_t     ks_kvset_sz;
    u64        ks_ctime;

    struct blk_list ks_purge; /* used by kvset split */

    struct kvset_kblk ks_kblks[] HSE_L1D_ALIGNED;
};

#endif /* HSE_KVS_CN_KVSET_INTERNAL_H */
