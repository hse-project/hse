/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_METRICS_H
#define HSE_KVDB_CN_METRICS_H

#include <hse_util/inttypes.h>

#include <hse_ikvdb/cn_node_loc.h>

/**
 * struct kvset_stats - kvset statistics
 * @kst_keys:  number of keys
 * @kst_kvsets: number of kvsets
 * @kst_kblks: number of kblocks
 * @kst_vblks: number of vblocks
 * @kst_kalen: sum mpr_alloc_cap for all kblocks
 * @kst_kwlen: sum mpr_write_len for all kblocks
 * @kst_valen: sum mpr_alloc_cap for all vblocks
 * @kst_vwlen: sum mpr_write_len for all vblocks
 * @kst_vulen: total referenced user data in all vblocks
 *
 */
struct kvset_stats {
    u64 kst_keys;
    u64 kst_kalen;
    u64 kst_kwlen;
    u64 kst_valen;
    u64 kst_vwlen;
    u64 kst_vulen;
    u32 kst_kvsets;
    u32 kst_kblks;
    u32 kst_vblks;
};

/**
 * Kvset derived stats:
 *   kvset_alen()  - sum of kblock and vblock alen
 *   kvset_wlen()  - sum of kblock and vblock wlen
 *   kvset_vulen() - sum of vblock ulen (n/a for kblocks)
 */
static inline u64
kvset_alen(const struct kvset_stats *kst)
{
    return kst->kst_kalen + kst->kst_valen;
}

static inline u64
kvset_wlen(const struct kvset_stats *kst)
{
    return kst->kst_kwlen + kst->kst_vwlen;
}

static inline u64
kvset_vulen(const struct kvset_stats *kst)
{
    return kst->kst_vulen;
}

/**
 * struct cn_node_stats - node metrics used by compacation scheduler
 * @ns_kclen:  estimated total kblock capacity (mpr_alloc_cap) after compaction
 * @ns_vclen:  estimated total vblock capacity (mpr_alloc_cap) after compaction
 * @ns_keys_uniq:  number of unique keys (estimated from hyperloglog)
 * @ns_scatter:   a measure of vblocks scatter
 * @ns_pcap:      current size / max size as a percentage
 * @ns_kst:       sum of kvset_stats for all kvsets in node
 */
struct cn_node_stats {
    struct kvset_stats ns_kst;
    u64                ns_keys_uniq;
    u64                ns_kclen;
    u64                ns_vclen;
    u32                ns_scatter;
    u16                ns_pcap;
};

/**
 * Node derived stats:
 *   cn_ns_clen()  - estimated mpool capacity used by node after kv-compaction
 *   cn_ns_alen()  - current capacity used by node (sum of kvset alen)
 *   cn_ns_wlen()  - sum of kvset wlen
 *   cn_ns_vulen() - sum of kvset vblocks ulen
 *   cn_ns_keys()  - number of keys in kvset
 *   cn_ns_kblks() - number of kblocks in node
 *   cn_ns_vblks() - number of vblocks in node
 */
static inline u64
cn_ns_alen(const struct cn_node_stats *ns)
{
    return kvset_alen(&ns->ns_kst);
}

static inline u64
cn_ns_wlen(const struct cn_node_stats *ns)
{
    return kvset_wlen(&ns->ns_kst);
}

static inline u64
cn_ns_vulen(const struct cn_node_stats *ns)
{
    return kvset_vulen(&ns->ns_kst);
}

static inline u64
cn_ns_clen(const struct cn_node_stats *ns)
{
    /* This is different than alen, wlen, and ulen because it depends
     * on HyperLogLog stats which are only computed at the node level.
     */
    return ns->ns_kclen + ns->ns_vclen;
}

static inline u64
cn_ns_keys(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_keys;
}

static inline u64
cn_ns_kblks(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_kblks;
}

static inline u64
cn_ns_vblks(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_vblks;
}

static inline uint
cn_ns_samp(const struct cn_node_stats *ns)
{
    u64 samp = cn_ns_alen(ns) * 100 / cn_ns_clen(ns);

    return (uint)samp;
}

static inline u64
cn_ns_kvsets(const struct cn_node_stats *ns)
{
    return ns->ns_kst.kst_kvsets;
}

struct cn_merge_stats_ops {
    u64 op_cnt;
    u64 op_size;
    u64 op_time;
};

static inline void
count_ops(struct cn_merge_stats_ops *op, u64 count, u64 size, u64 time)
{
    op->op_cnt += count;
    op->op_size += size;
    op->op_time += time;
}

static inline void
cn_merge_stats_ops_diff(
    struct cn_merge_stats_ops *      s,
    const struct cn_merge_stats_ops *a,
    const struct cn_merge_stats_ops *b)
{
    s->op_cnt = a->op_cnt - b->op_cnt;
    s->op_size = a->op_size - b->op_size;
    s->op_time = a->op_time - b->op_time;
}

/**
 * struct cn_merge_stats - statistics related to kvset merge
 * @ms_srcs:          number of input kvsets
 * @ms_keys_in:       number of input keys
 * @ms_key_bytes_in:  total length of input keys
 * @ms_keys_out:      number of output keys
 * @ms_key_bytes_out: total length of output keys
 * @ms_val_bytes_out: total length of output values
 * @ms_wbytes:        ptr to shared atomic for "realtime" I/O stats
 */
struct cn_merge_stats {
    u64 ms_srcs;
    u64 ms_keys_in;
    u64 ms_keys_out;
    u64 ms_key_bytes_in;
    u64 ms_key_bytes_out;
    u64 ms_val_bytes_out;
    u64 ms_vblk_wasted_reads;

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
cn_merge_stats_diff(
    struct cn_merge_stats *      s,
    const struct cn_merge_stats *a,
    const struct cn_merge_stats *b)
{
    s->ms_srcs = a->ms_srcs - b->ms_srcs;
    s->ms_keys_in = a->ms_keys_in - b->ms_keys_in;
    s->ms_keys_out = a->ms_keys_out - b->ms_keys_out;

    s->ms_key_bytes_in = a->ms_key_bytes_in - b->ms_key_bytes_in;
    s->ms_key_bytes_out = a->ms_key_bytes_out - b->ms_key_bytes_out;
    s->ms_val_bytes_out = a->ms_val_bytes_out - b->ms_val_bytes_out;

    s->ms_vblk_wasted_reads = a->ms_vblk_wasted_reads - b->ms_vblk_wasted_reads;

    cn_merge_stats_ops_diff(&s->ms_kblk_alloc, &a->ms_kblk_alloc, &b->ms_kblk_alloc);
    cn_merge_stats_ops_diff(&s->ms_kblk_write, &a->ms_kblk_write, &b->ms_kblk_write);

    cn_merge_stats_ops_diff(&s->ms_vblk_alloc, &a->ms_vblk_alloc, &b->ms_vblk_alloc);
    cn_merge_stats_ops_diff(&s->ms_vblk_write, &a->ms_vblk_write, &b->ms_vblk_write);

    cn_merge_stats_ops_diff(&s->ms_vblk_read1, &a->ms_vblk_read1, &b->ms_vblk_read1);
    cn_merge_stats_ops_diff(&s->ms_vblk_read1_wait, &a->ms_vblk_read1_wait, &b->ms_vblk_read1_wait);

    cn_merge_stats_ops_diff(&s->ms_vblk_read2, &a->ms_vblk_read2, &b->ms_vblk_read2);
    cn_merge_stats_ops_diff(&s->ms_vblk_read2_wait, &a->ms_vblk_read2_wait, &b->ms_vblk_read2_wait);

    cn_merge_stats_ops_diff(&s->ms_kblk_read, &a->ms_kblk_read, &b->ms_kblk_read);
    cn_merge_stats_ops_diff(&s->ms_kblk_read_wait, &a->ms_kblk_read_wait, &b->ms_kblk_read_wait);
}

/**
 * struct cn_samp_stats - metrics used to track space amp
 * @r_alen: allocated length of root node
 * @r_wlen: written length of root node
 * @i_alen: allocated length of internal nodes
 * @l_alen: allocated length of leaf nodes
 * @l_good: estimated "alen" of leaf nodes if each one were fully compacted
 *
 * Notes:
 * - The root node is always considered internal -- it is never a
 *   leaf.  So a single-node tree has one internal node and no leaves.
 *   The @i_alen metric includes the root node, so it is counted twice
 *   in this struct: once in @r_alen and once in @i_alen.
 * - [HSE_REVISIT] remove r_alen and r_wlen from this struct and just
 *   track them manually in sp3.
 * - [HSE_REVISIT] remove all alen/rlen from notify ingest and just
 *   look at node stats.
 */
struct cn_samp_stats {
    s64 r_alen;
    s64 r_wlen;
    s64 i_alen;
    s64 l_alen;
    s64 l_good;
};

static inline void
cn_samp_diff(
    struct cn_samp_stats *out,
    const struct cn_samp_stats *new,
    const struct cn_samp_stats *old)
{
    out->r_alen = new->r_alen - old->r_alen;
    out->r_wlen = new->r_wlen - old->r_wlen;
    out->i_alen = new->i_alen - old->i_alen;
    out->l_alen = new->l_alen - old->l_alen;
    out->l_good = new->l_good - old->l_good;
}

void
kvset_stats_add(const struct kvset_stats *add, struct kvset_stats *result);

#endif
