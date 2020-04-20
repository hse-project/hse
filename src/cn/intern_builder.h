/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_INTERN_BUILDER_H
#define HSE_KVS_INTERN_BUILDER_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

struct wbb;

/**
 * struct intern_node - node data
 *
 * @buf:  a PAGE_SIZE buffer that stores compressed keys (lcp elimiated keys)
 * @used: used bytes in @buf
 * @next: next node;
 */

struct intern_node {
    unsigned char          buf[PAGE_SIZE]; /* Must be the first member */
    uint                   used;
    uint                   x;
    struct intern_builder *ib_back;
    struct intern_node    *next;
    struct intern_node    *fnext; /* flattened list */
};

struct intern_key {
    uint          child_idx;
    uint          klen;
    unsigned char kdata[];
};

/**
 * struct intern_builder - metadata for each level of the wb tree with
 *                         internal nodes
 * @curr_rkeys_sum: Sum of all keys in the active node
 * @curr_rkeys_cnt: Number of keys in the active node. (Doesn't include the
 *                  entry about the mandatory right edge).
 * @full_node_cnt:  Number of 'full' nodes in the level. i.e. these nodes were
 *                  frozen because there wasn't any more space for more keys.
 * @level:          level in the tree. From bottom to top.
 * @parent:         pointer to parent. Null if root.
 * @sbuf:           staging area buffer
 * @sbuf_sz:        size of @sbuf
 * @sbuf_used:      used bytes in @sbuf
 */
struct intern_builder {
    uint                       curr_rkeys_sum;
    uint                       curr_rkeys_cnt;
    uint                       curr_child;
    uint                       full_node_cnt;
    uint                       level;
    struct intern_node        *node_head;
    struct intern_node        *node_curr;
    size_t                     node_lcp_len;
    unsigned char             *sbuf;
    size_t                     sbuf_sz;
    size_t                     sbuf_used;
    struct intern_builder     *parent;
};

int
ib_lcp_len(struct intern_builder *ib, const struct key_obj *ko);

merr_t
ib_key_add(struct wbb *wbb, struct key_obj *right_edge, uint *node_cnt, bool count_only);

void
ib_free(struct intern_builder *ibldr);

void
ib_child_update(struct intern_builder *ibldr, uint num_leaves);

merr_t
ib_flat_verify(
    struct intern_builder *ibldr);

struct intern_builder *
wbb_ibldr_get(struct wbb *wbb);

void
wbb_ibldr_set(
    struct wbb *wbb,
    struct intern_builder *ibldr);

merr_t
ib_init(void);

void
ib_fini(void);

#endif /* HSE_KVS_INTERN_BUILDER_H */
