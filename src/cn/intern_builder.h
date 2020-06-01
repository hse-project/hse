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
    unsigned char *        buf;
    uint                   used;
    struct intern_builder *ib_back;
    struct intern_node *   next;
};

struct intern_key {
    uint          child_idx;
    uint          klen;
    unsigned char kdata[];
};

struct intern_builder {
    struct intern_level *base;
    struct wbb *         wbb;
};

/**
 * struct intern_level - metadata for each level of the wb tree with
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
struct intern_level {
    uint                 curr_rkeys_sum;
    uint                 curr_rkeys_cnt;
    uint                 curr_child;
    uint                 full_node_cnt;
    uint                 level;
    struct intern_node * node_head;
    struct intern_node * node_curr;
    size_t               node_lcp_len;
    unsigned char *      sbuf;
    size_t               sbuf_sz;
    size_t               sbuf_used;
    struct intern_level *parent;
};

merr_t
ib_key_add(struct intern_builder *ib, struct key_obj *right_edge, uint *node_cnt, bool count_only);

struct intern_builder *
ib_create(struct wbb *wbb);

void
ib_destroy(struct intern_builder *ibldr);

void
ib_child_update(struct intern_builder *ibldr, uint num_leaves);

uint
ib_iovec_construct(struct intern_builder *ibldr, struct iovec *iov);

merr_t
ib_init(void);

void
ib_fini(void);

#endif /* HSE_KVS_INTERN_BUILDER_H */
