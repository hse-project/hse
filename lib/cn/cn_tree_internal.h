/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_INTERNAL_H
#define HSE_KVDB_CN_CN_TREE_INTERNAL_H

/* MTF_MOCK_DECL(cn_tree_internal) */

#include <hse_util/rmlock.h>
#include <hse_util/mutex.h>
#include <hse_util/spinlock.h>
#include <hse_util/list.h>

#include <hse/limits.h>

#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/mclass_policy.h>

#include "cn_tree.h"
#include "cn_tree_iter.h"
#include "cn_metrics.h"
#include "cn_work.h"
#include "omf.h"

#include "csched_sp3.h"

struct hlog;
struct route_map;

/* Each node in a cN tree contains a list of kvsets that must be protected
 * against concurrent update.  Since update of the list is relatively rare,
 * we optimize the read path to avoid contention on what would otherwise be
 * a per-list lock.  To protect a kvset list for read-only access, a thread
 * must acquire a read lock on any one of the locks in the vector of locks
 * in the cN tree (i.e., tree->ct_bktv[]).  To update/modify a kvset list,
 * a thread must acquire a write lock on each and every lock in ct_bktv[].
 */

/**
 * struct cn_kle_cache - kvset list entry cache
 * @kc_lock:    protects %ic_npages and %kc_pages
 * @kc_npages:  number of pages in cache
 * @kc_pages:   list of pages in cache
 *
 * The kvset list entry cache keeps the kvset list entry
 * nodes co-located to minimize pages faults during
 * cn tree traversals.  Each page in the cache contains
 * a header (cn_kle_hdr) followed by as many kvset list
 * entry objects as will fit into the page.
 */
struct cn_kle_cache {
    spinlock_t       kc_lock;
    int              kc_npages;
    struct list_head kc_pages;
};

struct cn_kle_hdr {
    struct list_head kh_link HSE_L1D_ALIGNED;
    struct list_head kh_entries;
    ulong            kh_nallocs;
    ulong            kh_nfrees;
};

/**
 * struct cn_tree - the cn tree (tree of nodes holding kvsets)
 * @ct_root:        root node of tree
 * @ct_fanout:      tree fanout
 * @ct_depth_max:   depth limit for this tree (not current depth)
 * @cn:    ptr to parent cn object
 * @ds:    dataset
 * @rp:    ptr to shared runtime parameters struct
 * @ct_cp:          cn create-time parameters
 * @cndb:  handle for cndb (the metadata journal/log)
 * @cnid:  cndb's identifier for this cn tree
 * @ct_dgen_init:
 * @ct_r_nodec:
 * @ct_l_nodec:
 * @ct_l_samp:
 * @ct_sched:
 * @ct_kvdb_health: for monitoring KDVB health
 * @ct_nospace:     set when "disk is full"
 * @ct_iter:        iterate over tree nodes for compaction
 * @ct_last_ptseq:
 * @ct_last_ptlen:  length of @ct_last_ptomb
 * @ct_last_ptomb:  if cn is a capped, this holds the last (largest) ptomb in cn
 * @ct_kle_cache:   kvset list entry cache
 * @ct_lock:        read-mostly lock to protect kvset list
 *
 * Note: The first fields are frequently accessed in the order listed
 * (e.g., by cn_tree_lookup) and are read-only after initialization.
 */
struct cn_tree {
    struct cn_tree_node *ct_root;
    u16                  ct_fanout;
    u16                  ct_depth_max;
    u16                  ct_pfx_len;
    u16                  ct_sfx_len;
    bool                 ct_nospace;
    struct cn *          cn;
    struct mpool *       ds;
    struct kvs_rparams * rp;

    struct route_map  *ct_route_map;

    struct cndb *       cndb;
    struct cn_kvdb *    cn_kvdb;
    struct kvs_cparams *ct_cp;
    u64                 cnid;
    u64                 ct_dgen_init;

    uint                 ct_i_nodec;
    uint                 ct_l_nodec;
    uint                 ct_lvl_max;
    struct cn_samp_stats ct_samp;

    union {
        struct sp3_tree sp3t HSE_L1D_ALIGNED;
    } ct_sched;

    u64                      ct_capped_ttl;
    u64                      ct_capped_dgen;
    struct kvset_list_entry *ct_capped_le;

    struct kvdb_health *ct_kvdb_health HSE_L1D_ALIGNED;

    u64 ct_last_ptseq;
    u32 ct_last_ptlen;
    u8  ct_last_ptomb[HSE_KVS_PFX_LEN_MAX];

    struct cn_kle_cache ct_kle_cache HSE_L1D_ALIGNED;

    struct rmlock ct_lock;
};

/**
 * struct cn_tree_node - A node in a k-way cn_tree
 * @tn_rspills_lock:  lock to protect @tn_rspills
 * @tn_rspills:       list of active spills from this node to its children
 * @tn_compacting:   true if node is being compacted
 * @tn_busycnt:      count of jobs and kvsets being compacted/spilled
 * @tn_destroy_work: used for async destroy
 * @tn_hlog:         hyperloglog structure
 * @tn_add_cntr:
 * @tn_rem_cntr:
 * @tn_stats_add_cntr:
 * @tn_stats_rem_cntr:
 * @tn_ns:           metrics about node to guide node compaction decisions
 * @tn_loc:          location of node within tree
 * @tn_pfx_spill:    true if spills/scans from this node use the prefix hash
 * @tn_cgen:         incremented each time the node changes
 * @tn_tree:         ptr to tree struct
 * @tn_parent:       parent node
 * @tn_child:        child nodes
 */
struct cn_tree_node {
    struct mutex     tn_rspills_lock;
    struct list_head tn_rspills;
    u64              tn_biggest_kvset; /* key count */
    bool             tn_rspills_wedged;
    uint16_t         tn_childc;
    atomic_int       tn_compacting;
    atomic_uint      tn_busycnt;

    union {
        struct sp3_node tn_sp3n;
        struct cn_work  tn_destroy_work;
    };

    struct hlog         *tn_hlog HSE_L1D_ALIGNED;
    struct cn_node_stats tn_ns;
    struct cn_samp_stats tn_samp;
    u64                  tn_size_max;
    u64                  tn_update_incr_dgen;

    struct cn_node_loc   tn_loc HSE_L1D_ALIGNED;
    bool                 tn_terminal_node_warning;
    uint                 tn_cgen;
    struct list_head     tn_kvset_list; /* head = newest kvset */
    struct cn_tree *     tn_tree;
    struct route_node   *tn_route_node;
    struct cn_tree_node *tn_parent;
    struct cn_tree_node *tn_childv[];
};

/* cn_tree_node to sp3_node */
#define tn2spn(_tn) (&(_tn)->tn_sp3n)
#define spn2tn(_spn) container_of(_spn, struct cn_tree_node, tn_sp3n)

/* MTF_MOCK */
void
cn_node_stats_get(const struct cn_tree_node *tn, struct cn_node_stats *stats);

/* MTF_MOCK */
bool
cn_node_isleaf(const struct cn_tree_node *node);

bool
cn_node_isroot(const struct cn_tree_node *node);

enum hse_mclass
cn_tree_node_mclass(struct cn_tree_node *tn, enum hse_mclass_policy_dtype dtype);

/* MTF_MOCK */
void
cn_comp_slice_cb(struct sts_job *job);

#if HSE_MOCKING
/**
 * cn_tree_find_node() - Map a node location to a node pointer.
 *
 * @tree: tree to search
 * @loc: (input) node location
 *
 * Returns NULL if tree @tree has no node at location @loc.
 */
struct cn_tree_node *
cn_tree_find_node(struct cn_tree *tree, const struct cn_node_loc *loc);

#include "cn_tree_internal_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVDB_CN_CN_TREE_INTERNAL_H */
