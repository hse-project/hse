/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_CN_TREE_INTERNAL_H
#define HSE_KVDB_CN_CN_TREE_INTERNAL_H

/* MTF_MOCK_DECL(cn_tree_internal) */

#include <stdint.h>

#include <hse/util/rmlock.h>
#include <hse/util/mutex.h>
#include <hse/util/spinlock.h>
#include <hse/util/list.h>

#include <hse/limits.h>

#include <hse/ikvdb/sched_sts.h>
#include <hse/ikvdb/mclass_policy.h>

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
 * @ct_nodes:       list of all tree nodes, including ct_root
 * @ct_fanout:      the number of leaf nodes on ct_nodes list
 * @cn:    ptr to parent cn object
 * @rp:    ptr to shared runtime parameters struct
 * @cndb:  handle for cndb (the metadata journal/log)
 * @ct_cp:          cn create-time parameters
 * @cnid:  cndb's identifier for this cn tree
 * @ct_rspill_dt:  running average time to spill a kvset (nanoseconds)
 * @ct_rspill_slp: number of rspill jobs waiting on a split to finish
 * @ct_split_cnt:  number of pending or running split jobs
 * @ct_split_dly:  time at which a new splits may be requested
 * @ct_sched:
 * @ct_kvdb_health: for monitoring KDVB health
 * @ct_last_ptseq:
 * @ct_last_ptlen:  length of @ct_last_ptomb
 * @ct_last_ptomb:  if cn is a capped, this holds the last (largest) ptomb in cn
 * @ct_kle_cache:   kvset list entry cache
 * @ct_lock:        read-mostly lock to protect tree updates
 *
 * Note: The first fields are frequently accessed in the order listed
 * (e.g., by cn_tree_lookup) and are read-only after initialization.
 */
struct cn_tree {
    struct cn_tree_node *ct_root;
    struct list_head     ct_nodes;
    uint16_t             ct_fanout;
    uint16_t             ct_pfx_len;
    bool                 ct_rspills_wedged;
    struct cn           *cn;
    struct mpool        *mp;
    struct kvs_rparams  *rp;
    struct route_map    *ct_route_map;

    struct cndb *       cndb;
    struct cn_kvdb *    cn_kvdb;
    struct kvs_cparams *ct_cp;
    uint64_t            cnid;

    struct cn_samp_stats ct_samp;

    struct mutex         ct_ss_lock HSE_L1D_ALIGNED;
    struct cv            ct_ss_cv;

    atomic_ulong         ct_rspill_dt;
    atomic_uint          ct_rspill_slp;
    atomic_uint          ct_split_cnt;
    uint64_t             ct_split_dly;
    uint64_t             ct_sgen;

    union {
        struct sp3_tree sp3t HSE_L1D_ALIGNED;
    } ct_sched;

    uint64_t                 ct_capped_ttl;
    uint64_t                 ct_capped_dgen;
    struct kvset_list_entry *ct_capped_le;

    struct kvdb_health *ct_kvdb_health HSE_L1D_ALIGNED;

    uint64_t ct_last_ptseq;
    uint32_t ct_last_ptlen;
    uint8_t  ct_last_ptomb[HSE_KVS_PFX_LEN_MAX];

    struct cn_kle_cache ct_kle_cache HSE_L1D_ALIGNED;

    struct rmlock ct_lock;
};

/**
 * struct cn_tree_node - A node in a cn_tree
 * @tn_nodeid:       0 if root node, otherwise unique within the kvdb
 * @tn_tree:         ptr to tree struct
 * @tn_split_size:   size in bytes at which the node should split
 * @tn_split_ns:     time beyond which a node may split again
 * @tn_readers:      non-zero if there have been readers in the node recently
 * @tn_hlog:         hyperloglog structure
 * @tn_ns:           metrics about node to guide node compaction decisions
 * @tn_compacting:   true if if an exclusive job is running on this node
 * @tn_busycnt:      count of jobs and kvsets being compacted/spilled
 * @tn_dnode_linkv:  dirty list linkage for csched
 * @tn_destroy_work: used for async destroy
 */
struct cn_tree_node {
    uint64_t             tn_nodeid;
    struct cn_tree      *tn_tree;
    struct route_node   *tn_route_node;
    struct list_head     tn_link;
    size_t               tn_split_size;
    uint64_t             tn_split_ns;
    atomic_uint          tn_readers;

    struct list_head     tn_kvset_list HSE_L1D_ALIGNED;
    uint64_t             tn_update_incr_dgen;
    struct hlog         *tn_hlog;
    struct cn_node_stats tn_ns;
    struct cn_samp_stats tn_samp;

    atomic_int           tn_compacting HSE_L1D_ALIGNED;
    atomic_uint          tn_busycnt;
    struct list_head     tn_dnode_linkv[2];

    union {
        struct sp3_node  tn_sp3n;
        struct cn_work   tn_destroy_work;
    };

    /* Subspill synchronization.
     */
    struct list_head     tn_ss_list HSE_L1D_ALIGNED;
    atomic_uint          tn_ss_spilling;
    bool                 tn_ss_splitting;
    int8_t               tn_ss_joining;
    uint8_t              tn_ss_visits;
    atomic_long          tn_sgen;      /* The last spill gen that was added to the node */
};

/* Iterate over all tree nodes, starting with the root node.
 */
#define cn_tree_foreach_node(_item, _tree)                                                      \
    for ((_item) = (_tree)->ct_root;                                                            \
         (_item);                                                                               \
         (_item) = list_next_entry_or_null((_item), tn_link, &(_tree)->ct_nodes))

/* Iterate over all leaf nodes (excluding root node).
 */
#define cn_tree_foreach_leaf(_item, _tree)                                                      \
    for ((_item) = list_next_entry_or_null((_tree)->ct_root, tn_link, &(_tree)->ct_nodes);      \
         (_item);                                                                               \
         (_item) = list_next_entry_or_null((_item), tn_link, &(_tree)->ct_nodes))

#define cn_tree_foreach_leaf_safe(_item, _next, _tree)                                          \
    for ((_item) = list_next_entry_or_null((_tree)->ct_root, tn_link, &(_tree)->ct_nodes),         \
             _next = (_item) ? list_next_entry_or_null((_item), tn_link, &(_tree)->ct_nodes) : NULL; \
         (_item);                                                                                  \
         _item = (_next), _next = (_item) ? list_next_entry_or_null((_item), tn_link, &(_tree)->ct_nodes) : NULL)

/* cn_tree_node to sp3_node */
#define tn2spn(_tn) (&(_tn)->tn_sp3n)
#define spn2tn(_spn) container_of(_spn, struct cn_tree_node, tn_sp3n)

/* MTF_MOCK */
void
cn_node_stats_get(const struct cn_tree_node *tn, struct cn_node_stats *stats);

static HSE_ALWAYS_INLINE bool
cn_node_isroot(const struct cn_tree_node *tn)
{
    return (tn->tn_nodeid == 0);
}

static HSE_ALWAYS_INLINE bool
cn_node_isleaf(const struct cn_tree_node *tn)
{
    return !cn_node_isroot(tn);
}

enum hse_mclass
cn_tree_node_mclass(struct cn_tree_node *tn, enum hse_mclass_policy_dtype dtype);

/**
 * cn_tree_node_scatter()
 * @tn: cn tree node pointer
 *
 * "Scatter" is a measurement of the contiguity in virtual memory of a kvset's
 * values relative to its keys.  For example, a kvset with (scatter == 1) means
 * that for every key (n), the value for key (n+1) will immediately follow the
 * value for key (n) in virtual memory.  The probability that the preceding is
 * true decreases as the scatter increases.  Similarly, the probability that
 * accessing a value will incur a TLB miss or a page fault is directionally
 * proportional to scatter.
 *
 * Scatter is a direct consequence of k-compaction, where each k-compaction
 * will typically amplify scatter by 4x or more.  Conversely, a kv-compaction
 * completely eliminates scatter, returning the measurement to 1.
 */
uint
cn_tree_node_scatter(const struct cn_tree_node *tn);

/* MTF_MOCK */
void
cn_compact(struct cn_compaction_work *w);

/* MTF_MOCK */
struct cn_tree_node *
cn_kvset_can_zspill(struct kvset *ks, struct route_map *map);

/**
 * cn_tree_find_node() - Find a cn tree node by node ID.
 *
 * @tree:   tree to search
 * @nodeid: node ID
 *
 * Return: Node that matches %nodeid or NULL.
 */
struct cn_tree_node *
cn_tree_find_node(struct cn_tree *tree, uint64_t nodeid);

#if HSE_MOCKING
#include "cn_tree_internal_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVDB_CN_CN_TREE_INTERNAL_H */
