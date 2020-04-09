/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_UTILS_H
#define HSE_C1_UTILS_H

struct c1;
struct c1_journal;
struct c1_tree;

enum {
    C1_REPLAY_INVALID,
    C1_REPLAY_METADATA,
    C1_REPLAY_DATA,
    C1_REPLAY_ALL,
};

struct c1_header {
    u32 c1h_type;
    u32 c1h_len;
};

struct c1_version {
    u32 c1v_magic;
    u32 c1v_version;
};

struct c1_complete {
    struct list_head c1c_list;
    u64              c1c_seqno;
    u32              c1c_gen;
    u64              c1c_kvseqno;
};

struct c1_info {
    struct list_head c1i_list;
    u64              c1i_seqno;
    u32              c1i_gen;
    u64              c1i_dtime;
    u64              c1i_dsize;
    u64              c1i_capacity;
};

struct c1_desc {
    struct list_head c1d_list;
    u64              c1d_oid;
    u64              c1d_seqno;
    u32              c1d_state;
    u32              c1d_gen;
};

struct c1_ingest {
    struct list_head c1ing_list;
    u64              c1ing_seqno;
    u64              c1ing_cnid;
    u64              c1ing_cntgen;
    u64              c1ing_status;
};

struct c1_reset {
    struct list_head c1reset_list;
    u64              c1reset_seqno;
    u64              c1reset_newseqno;
    u32              c1reset_gen;
    u32              c1reset_newgen;
};

struct c1_replay {
    bool             c1r_close;
    struct list_head c1r_info;
    struct list_head c1r_desc;
    struct list_head c1r_ingest;
    struct list_head c1r_reset;
    struct list_head c1r_complete;
};

merr_t
c1_replay_version(struct c1 *c1, char *omf);

merr_t
c1_replay_add_info(struct c1 *c1, char *omf);

merr_t
c1_replay_add_desc(struct c1 *c1, char *omf);

merr_t
c1_replay_add_ingest(struct c1 *c1, char *omf);

merr_t
c1_replay_add_reset(struct c1 *c1, char *omf);

merr_t
c1_replay_add_complete(struct c1 *c1, char *omf);

void
c1_replay_add_close(struct c1 *c1, char *omf);

merr_t
c1_parse_cparams(struct kvdb_cparams *cparams, u64 *capacity, u64 *ntrees);

merr_t
c1_replay(struct c1 *c1);

merr_t
c1_invalidate_tree(struct c1 *c1, u64 seqno, merr_t status, u64 cnid, const struct kvs_ktuple *kt);

merr_t
c1_mark_tree_complete(struct c1 *c1, struct c1_tree *tree);

merr_t
c1_next_tree(struct c1 *c1);

struct c1_tree *
c1_current_tree(struct c1 *c1);

merr_t
c1_new_tree(
    struct c1_journal *jrnl,
    u32                stripsize,
    u32                stripewidth,
    struct perfc_set * pcset,
    struct c1_tree **  out);

merr_t
c1_close_trees(struct c1 *c1);

merr_t
c1_destroy_tree(struct mpool *ds, u64 oid1, u64 oid2, struct c1 *c1);

merr_t
c1_replay_build_trees(struct mpool *ds, u64 oid1, u64 oid2, struct c1 *c1);

merr_t
c1_replay_remove_reset_trees(struct mpool *ds, struct c1 *c1);

void
c1_replay_sort_trees(struct c1 *c1);

#endif /* HSE_C1_UTILS_H */
