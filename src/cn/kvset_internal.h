/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_INTERNAL_H
#define HSE_KVS_CN_KVSET_INTERNAL_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/atomic.h>
#include <hse_util/workqueue.h>
#include <hse_util/key_util.h>

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

struct kvset_kblk {
    struct kvs_mblk_desc kb_kblk_desc; /* kblock descriptor */
    struct wbt_desc      kb_wbt_desc;  /* wbtree descriptor */
    struct wbt_desc      kb_pt_desc;   /* ptree descriptor */

    u8              kb_ksmall[64]; /* small key cache */
    struct key_disc kb_kdisc_max;  /* kdisc of largest key in kblk */
    struct key_disc kb_kdisc_min;  /* kdisc of smallest key */
    const void *    kb_koff_max;   /* ptr to largest key in kblk */
    const void *    kb_koff_min;   /* ptr to smallest key in kblk */
    u16             kb_klen_max;   /* length of largest key */
    u16             kb_klen_min;   /* length of smallest key */

    u16               kb_cn_bloom_lookup;
    struct bloom_desc kb_blm_desc;  /* Bloom descriptor */
    u8 *              kb_blm_pages; /* Bloom pages */

    u64 kb_seqno_min; /* min seqno */
    u64 kb_seqno_max; /* max seqno */

    struct kblk_metrics kb_metrics; /* kblock metrics */
    struct kvs_block    kb_kblk;    /* blkid and handle */
};

struct kvset {
    struct kvset_list_entry ks_entry; /* kvset list linkage */

    u64           ks_dgen; /* relative age of entries */
    struct mpool *ks_ds;
    u32           ks_pfx_len; /* cn tree pfx_len */
    u32           ks_sfx_len; /* cn tree pfx_len */
    u16           ks_node_level;
    u16           ks_vminlvl;
    u32           ks_vmin;
    u32           ks_vmax;
    u32           ks_vra_len;
    uint          ks_compc;

    struct kvs_rparams *ks_rp;
    u64                 ks_seqno_max;
    u64                 ks_cnid;
    struct cn_kvdb *    ks_cn_kvdb;
    struct cn_tree *    ks_tree;
    struct cndb *       ks_cndb;
    struct kvset_stats  ks_st;

    /* new compaction metrics */
    u8 * ks_hlog;
    uint ks_scatter;
    uint ks_scatter_pct;

    u32                   ks_vgroups;
    struct mbset_locator *ks_vblk2mbs;
    u64                   ks_workid;

    struct key_disc ks_kdisc_max; /* max key in kvset */
    struct key_disc ks_kdisc_min; /* min key in kvset */
    int             ks_lcp;       /* longest common prefix */

    const u8 *                ks_klarge; /* large key cache */
    struct mpool_mcache_map **ks_kmapv;
    struct mbset **           ks_vbsetv;
    uint                      ks_vbsetc;

    struct cn_work ks_kvset_cn_work;
    u64            ks_delete_txid;

    const void *ks_maxkey;  /* largest key in kvset */
    const void *ks_minkey;  /* smallest key in kvset */
    u16         ks_maxklen; /* length of largest key */
    u16         ks_minklen; /* length of smallest key */

    __aligned(SMP_CACHE_BYTES) atomic_t ks_ref; /* reference count */
    u32      ks_deleted;                        /* DEL_NONE, DEL_KEEPV, DEL_ALL */
    atomic_t ks_delete_error;
    atomic_t ks_mbset_callbacks;
    bool     ks_mbset_cb_pending;
    u64      ks_seqno_min;
    size_t   ks_kvset_sz;
    u64      ks_ctime;
    u64      ks_tag;

    __aligned(SMP_CACHE_BYTES) struct kvset_kblk ks_kblks[];
};

#endif /* HSE_KVS_CN_KVSET_INTERNAL_H */
