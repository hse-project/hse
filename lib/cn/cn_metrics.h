/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_METRICS_H
#define HSE_KVDB_CN_METRICS_H

#include <stdint.h>
#include <sys/types.h>

/**
 * Kvset statistics.
 *
 * This struct is designed to be additive so it can be used for node and tree
 * stats as well as for kvset stats.
 *
 * Notes:
 * - h/k/v alen refers to allocated length on media.
 * - h/k/v wlen refers to written length on media.
 * - vulen refers to vblock used length and measures the amount of data in
 *   vblocks referenced by keys.  For a kvset, vulen equals vwlen after
 *   kv-compaction abd decreases after k-compaction).
 *
 * Assertions:
 * - ulen <= wlen
 * - wlen <= alen
 */
struct kvset_stats {
    uint64_t kst_keys;      //<! number of keys
    uint64_t kst_tombs;     //<! number of tombtones
    uint64_t kst_ptombs;    //<! number of prefix tombtones
    uint64_t kst_halen;     //<! sum of mpr_alloc_cap for all hblocks
    uint64_t kst_hwlen;     //<! sum of mpr_write_len for all hblocks
    uint64_t kst_kalen;     //<! sum of mpr_alloc_cap for all kblocks
    uint64_t kst_kwlen;     //<! sum of mpr_write_len for all kblocks
    uint64_t kst_valen;     //<! sum of mpr_alloc_cap for all vblocks
    uint64_t kst_vwlen;     //<! sum of mpr_write_len for all vblocks
    uint64_t kst_vulen;     //<! total referenced data in all vblocks
    uint64_t kst_vgarb;     //<! total unreferenced data in all vblocks
    uint32_t kst_kvsets;    //<! number of kvsets (for node-level)
    uint32_t kst_hblks;     //<! number of hblocks
    uint32_t kst_kblks;     //<! number of kblocks
    uint32_t kst_vblks;     //<! number of vblocks
};

/**
 * Sum of hblock, kblock and vblock alen
 */
static inline uint64_t
kvset_alen(const struct kvset_stats *kst)
{
    return kst->kst_halen + kst->kst_kalen + kst->kst_valen;
}

/**
 * Sum of hblock, kblock and vblock wlen
 */
static inline uint64_t
kvset_wlen(const struct kvset_stats *kst)
{
    return kst->kst_hwlen + kst->kst_kwlen + kst->kst_vwlen;
}

static inline uint64_t
kvset_vgarb(const struct kvset_stats *kst)
{
    return kst->kst_vgarb;
}

/**
 * Node metrics used by compaction scheduler
 */
struct cn_node_stats {
    struct kvset_stats ns_kst; //<! Sum of kvset stats for all kvsts in node
    uint64_t ns_keys_uniq;     //<! number of unique keys (estimated from HyperLogLog stats)
    uint64_t ns_hclen;         //<! estimated total hblock capacity (mpr_alloc_cap) after compaction
    uint64_t ns_kclen;         //<! estimated total kblock capacity (mpr_alloc_cap) after compaction
    uint64_t ns_vclen;         //<! estimated total vblock capacity (mpr_alloc_cap) after compaction
    uint16_t ns_pcap;          //<! current size / max size as a percentage (0 <= ns_pcap <= 100)
};

/**
 * Sum of "alen" for all mblocks in node.
 */
static inline uint64_t
cn_ns_alen(const struct cn_node_stats *ns)
{
    return kvset_alen(&ns->ns_kst);
}

/**
 * Sum of "wlen" for all mblocks in node.
 */
static inline uint64_t
cn_ns_wlen(const struct cn_node_stats *ns)
{
    return kvset_wlen(&ns->ns_kst);
}

static inline uint64_t
cn_ns_vgarb(const struct cn_node_stats *ns)
{
    return kvset_vgarb(&ns->ns_kst);
}

/**
 * Estimated mpool capacity used by node after kv-compaction.
 */
static inline uint64_t
cn_ns_clen(const struct cn_node_stats *ns)
{
    return ns->ns_hclen + ns->ns_kclen + ns->ns_vclen;
}

/**
 * Number of keys in node (counts duplicates).
 */
static inline uint64_t
cn_ns_keys(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_keys;
}

/**
 * An estimate of the number of unique keys in node.
 *
 * Not accurate unless HyperLogLog stats are enabled on the node (for example,
 * on the root node).
 */
static inline uint64_t
cn_ns_keys_uniq(const struct cn_node_stats *ns)
{
    return ns->ns_keys_uniq;
}

/**
 * Number of tombstones in node.
 */
static inline uint64_t
cn_ns_tombs(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_tombs;
}

/**
 * Number of prefix tombstones in node.
 */
static inline uint64_t
cn_ns_ptombs(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_ptombs;
}

/**
 * Number of hblocks in node.
 */
static inline uint32_t
cn_ns_hblks(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_hblks;
}

/**
 * Number of kblocks in node.
 */
static inline uint32_t
cn_ns_kblks(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_kblks;
}

/**
 * Number of vblocks in node.
 */
static inline uint32_t
cn_ns_vblks(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_vblks;
}

/**
 * Number of kvses in node.
 */
static inline uint32_t
cn_ns_kvsets(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_kvsets;
}

static inline uint
cn_ns_samp(const struct cn_node_stats *ns)
{
    uint64_t alen = cn_ns_alen(ns);
    uint64_t clen = cn_ns_clen(ns);

    /* clen will be zero if the node is empty, in which
     * case we return 100% (i.e., there's 0% garbage).
     */
    return clen ? 100 * alen / clen : 100;
}

struct cn_merge_stats_ops {
    uint64_t op_size;
    uint32_t op_cnt;
    uint32_t op_time;
};

static inline void
count_ops(struct cn_merge_stats_ops *op, uint32_t count, uint64_t size, uint64_t time)
{
    op->op_size += size;
    op->op_cnt += count;
    op->op_time += time / 1000000;
}

/**
 * Statistics related to kvset merge
 */
struct cn_merge_stats {
    uint32_t ms_jobs;           //<! number of jobs
    uint32_t ms_srcs;           //<! number of input kvsets
    uint64_t ms_keys_in;        //<! number of input keys
    uint64_t ms_keys_out;       //<! number of output keys
    uint64_t ms_key_bytes_in;   //<! total length of input keys
    uint64_t ms_key_bytes_out;  //<! total length of output keys
    uint64_t ms_val_bytes_out;  //<! total length of output values
    uint64_t ms_vblk_wasted_reads;

    struct cn_merge_stats_ops ms_hblk_alloc;
    struct cn_merge_stats_ops ms_hblk_write;

    struct cn_merge_stats_ops ms_kblk_alloc;
    struct cn_merge_stats_ops ms_kblk_write;

    struct cn_merge_stats_ops ms_vblk_alloc;
    struct cn_merge_stats_ops ms_vblk_write;

    struct cn_merge_stats_ops ms_vblk_read1;
    struct cn_merge_stats_ops ms_vblk_read1_wait;

    struct cn_merge_stats_ops ms_vblk_read2;
    struct cn_merge_stats_ops ms_vblk_read2_wait;

    struct cn_merge_stats_ops ms_kblk_read;
    struct cn_merge_stats_ops ms_kblk_read_wait;
};

static inline void
cn_merge_stats_ops_diff(
    struct cn_merge_stats_ops *      s,
    const struct cn_merge_stats_ops *a,
    const struct cn_merge_stats_ops *b)
{
    s->op_size = a->op_size - b->op_size;
    s->op_cnt = a->op_cnt - b->op_cnt;
    if (a->op_time >= b->op_time)
        s->op_time = a->op_time - b->op_time;
    else
        s->op_time = a->op_time + (UINT32_MAX - b->op_time);
}

static inline void
cn_merge_stats_ops_add(
    struct cn_merge_stats_ops *lhs,
    const struct cn_merge_stats_ops *rhs)
{
    lhs->op_cnt += rhs->op_cnt;
    lhs->op_size += rhs->op_size;
    lhs->op_time += rhs->op_time;
}

static inline void
cn_merge_stats_diff(
    struct cn_merge_stats *      s,
    const struct cn_merge_stats *a,
    const struct cn_merge_stats *b)
{
    s->ms_jobs     = a->ms_jobs     - b->ms_jobs;
    s->ms_srcs     = a->ms_srcs     - b->ms_srcs;
    s->ms_keys_in  = a->ms_keys_in  - b->ms_keys_in;
    s->ms_keys_out = a->ms_keys_out - b->ms_keys_out;

    s->ms_key_bytes_in  = a->ms_key_bytes_in  - b->ms_key_bytes_in;
    s->ms_key_bytes_out = a->ms_key_bytes_out - b->ms_key_bytes_out;
    s->ms_val_bytes_out = a->ms_val_bytes_out - b->ms_val_bytes_out;

    s->ms_vblk_wasted_reads = a->ms_vblk_wasted_reads - b->ms_vblk_wasted_reads;

    cn_merge_stats_ops_diff(&s->ms_hblk_alloc, &a->ms_hblk_alloc, &b->ms_hblk_alloc);
    cn_merge_stats_ops_diff(&s->ms_hblk_write, &a->ms_hblk_write, &b->ms_hblk_write);

    cn_merge_stats_ops_diff(&s->ms_kblk_alloc, &a->ms_kblk_alloc, &b->ms_kblk_alloc);
    cn_merge_stats_ops_diff(&s->ms_kblk_write, &a->ms_kblk_write, &b->ms_kblk_write);

    cn_merge_stats_ops_diff(&s->ms_vblk_alloc, &a->ms_vblk_alloc, &b->ms_vblk_alloc);
    cn_merge_stats_ops_diff(&s->ms_vblk_write, &a->ms_vblk_write, &b->ms_vblk_write);

    cn_merge_stats_ops_diff(&s->ms_vblk_read1,      &a->ms_vblk_read1,      &b->ms_vblk_read1);
    cn_merge_stats_ops_diff(&s->ms_vblk_read1_wait, &a->ms_vblk_read1_wait, &b->ms_vblk_read1_wait);

    cn_merge_stats_ops_diff(&s->ms_vblk_read2,      &a->ms_vblk_read2,      &b->ms_vblk_read2);
    cn_merge_stats_ops_diff(&s->ms_vblk_read2_wait, &a->ms_vblk_read2_wait, &b->ms_vblk_read2_wait);

    cn_merge_stats_ops_diff(&s->ms_kblk_read,      &a->ms_kblk_read,      &b->ms_kblk_read);
    cn_merge_stats_ops_diff(&s->ms_kblk_read_wait, &a->ms_kblk_read_wait, &b->ms_kblk_read_wait);
}

static inline void
cn_merge_stats_add(
    struct cn_merge_stats *lhs,
    const struct cn_merge_stats *rhs)
{
    lhs->ms_jobs += rhs->ms_jobs;
    lhs->ms_srcs += rhs->ms_srcs;
    lhs->ms_keys_in += rhs->ms_keys_in;
    lhs->ms_keys_out += rhs->ms_keys_out;

    lhs->ms_key_bytes_in += rhs->ms_key_bytes_in;
    lhs->ms_key_bytes_out += rhs->ms_key_bytes_out;
    lhs->ms_val_bytes_out += rhs->ms_val_bytes_out;

    lhs->ms_vblk_wasted_reads += rhs->ms_vblk_wasted_reads;

    cn_merge_stats_ops_add(&lhs->ms_hblk_alloc, &rhs->ms_hblk_alloc);
    cn_merge_stats_ops_add(&lhs->ms_hblk_write, &rhs->ms_hblk_write);

    cn_merge_stats_ops_add(&lhs->ms_kblk_alloc, &rhs->ms_kblk_alloc);
    cn_merge_stats_ops_add(&lhs->ms_kblk_write, &rhs->ms_kblk_write);

    cn_merge_stats_ops_add(&lhs->ms_vblk_alloc, &rhs->ms_vblk_alloc);
    cn_merge_stats_ops_add(&lhs->ms_vblk_write, &rhs->ms_vblk_write);

    cn_merge_stats_ops_add(&lhs->ms_vblk_read1,      &rhs->ms_vblk_read1);
    cn_merge_stats_ops_add(&lhs->ms_vblk_read1_wait, &rhs->ms_vblk_read1_wait);

    cn_merge_stats_ops_add(&lhs->ms_vblk_read2,      &rhs->ms_vblk_read2);
    cn_merge_stats_ops_add(&lhs->ms_vblk_read2_wait, &rhs->ms_vblk_read2_wait);

    cn_merge_stats_ops_add(&lhs->ms_kblk_read,      &rhs->ms_kblk_read);
    cn_merge_stats_ops_add(&lhs->ms_kblk_read_wait, &rhs->ms_kblk_read_wait);
}

/**
 * Metrics used to track space amp
 */
struct cn_samp_stats {
    int64_t r_alen; //<! allocated length of root node
    int64_t l_alen; //<! allocated length of leaf nodes
    int64_t l_good; //<! estimated "alen" of leaf nodes if each one were fully compacted
    int64_t l_vgarb; //<! length of vblock garbage in leaf nodes
};

static inline void
cn_samp_add(
    struct cn_samp_stats *lhs,
    const struct cn_samp_stats *rhs)
{
    lhs->r_alen += rhs->r_alen;
    lhs->l_alen += rhs->l_alen;
    lhs->l_good += rhs->l_good;
    lhs->l_vgarb += rhs->l_vgarb;
}

static inline void
cn_samp_sub(
    struct cn_samp_stats *lhs,
    const struct cn_samp_stats *rhs)
{
    lhs->r_alen -= rhs->r_alen;
    lhs->l_alen -= rhs->l_alen;
    lhs->l_good -= rhs->l_good;
    lhs->l_vgarb -= rhs->l_vgarb;
}

void
kvset_stats_add(const struct kvset_stats *add, struct kvset_stats *result);

#endif
