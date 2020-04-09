/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/logging.h>
#include <hse_util/bloom_filter.h>

static bool
fmt_bloom_stats(char **tgt_pos, char *tgt_end, void *obj)
{
    struct bloom_filter_stats stats = *(struct bloom_filter_stats *)obj;

    char *tgt = *tgt_pos;
    int   space = (int)(tgt_end - *tgt_pos);
    int   written;
    bool  res = false;

    written = snprintf(
        tgt,
        space,
        "[%u, %u](%lu, %lu, %lu, %lu)",
        stats.bfs_filter_hashes,
        stats.bfs_filter_bits,
        (ulong)stats.bfs_lookup_cnt,
        (ulong)stats.bfs_hit_cnt,
        (ulong)stats.bfs_no_hit_cnt,
        (ulong)stats.bfs_hit_failed_cnt);
    if (written >= 0) {
        tgt += (written > space) ? space : written;
        *tgt_pos = tgt;
        res = (written < space);
    }
    return res;
}

static bool
add_bloom_stats(struct hse_log_fmt_state *state, void *obj)
{
    struct bloom_filter_stats stats = *(struct bloom_filter_stats *)obj;

    static char *cat = "hse_%d_category";
    static char *cat_val = "bloom_stats";
    static char *ver = "hse_%d_version";
    static char *n_hashes = "hse_%d_hash_count";
    static char *filt_sz = "hse_%d_filter_size";
    static char *lkup_cnt = "hse_%d_lookup_count";
    static char *hit_cnt = "hse_%d_hit_count";
    static char *no_hit_cnt = "hse_%d_no_hit_count";
    static char *hit_failed_cnt = "hse_%d_hit_failed_count";
    char         tmp_str[24];

    if (!hse_log_push(state, true, cat, cat_val))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%u", stats.bfs_ver);
    if (!hse_log_push(state, true, ver, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%u", stats.bfs_filter_hashes);
    if (!hse_log_push(state, true, n_hashes, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%u", stats.bfs_filter_bits);
    if (!hse_log_push(state, true, filt_sz, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%lu", (ulong)stats.bfs_lookup_cnt);
    if (!hse_log_push(state, true, lkup_cnt, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%lu", (ulong)stats.bfs_hit_cnt);
    if (!hse_log_push(state, true, hit_cnt, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%lu", (ulong)stats.bfs_no_hit_cnt);
    if (!hse_log_push(state, true, no_hit_cnt, tmp_str))
        return false;

    snprintf(tmp_str, sizeof(tmp_str), "%lu", (ulong)stats.bfs_hit_failed_cnt);
    if (!hse_log_push(state, true, hit_failed_cnt, tmp_str))
        return false;

    return true;
}

static bool
fmt_wbtree_est(char **tgt_pos, char *tgt_end, void *obj)
{
    return false;
}

static bool
add_wbtree_est(struct hse_log_fmt_state *state, void *obj)
{
    return false;
}

static bool
fmt_compact(char **tgt_pos, char *tgt_end, void *obj)
{
    return false;
}

static bool
add_compact(struct hse_log_fmt_state *state, void *obj)
{
    return false;
}

static bool
fmt_candidate(char **tgt_pos, char *tgt_end, void *obj)
{
    return false;
}

static bool
add_candidate(struct hse_log_fmt_state *state, void *obj)
{
    return false;
}

/* --------------------------------------------------
 * Register these with hse_log().
 */

void
hse_log_reg_cn(void)
{
    hse_log_register('b', fmt_bloom_stats, add_bloom_stats);
    hse_log_register('w', fmt_wbtree_est, add_wbtree_est);
    hse_log_register('k', fmt_compact, add_compact);
    hse_log_register('K', fmt_candidate, add_candidate);
}
