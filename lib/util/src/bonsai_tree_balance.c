/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "bonsai_tree_pvt.h"

static struct bonsai_node *
bn_single_left_rotate(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *newleft)
{
    struct bonsai_node *left = newleft;

    if (!left) {
        left = bn_node_dup(tree, node->bn_left);
        if (!left)
            return NULL;

        node->bn_left->bn_flags |= HSE_BNF_UNLINKED;
    }

    node->bn_left = left->bn_right;
    left->bn_right = node;

    bn_height_update(node);
    bn_height_update(left);

    return left;
}

static struct bonsai_node *
bn_single_right_rotate(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *newright)
{
    struct bonsai_node *right = newright;

    if (!right) {
        right = bn_node_dup(tree, node->bn_right);
        if (!right)
            return NULL;

        node->bn_right->bn_flags |= HSE_BNF_UNLINKED;
    }

    node->bn_right = right->bn_left;
    right->bn_left = node;

    bn_height_update(node);
    bn_height_update(right);

    return right;
}

static struct bonsai_node *
bn_double_left_rotate(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *left, *newleft, *out;

    left = bn_node_dup(tree, node->bn_left);
    if (!left)
        return NULL;

    newleft = bn_single_right_rotate(tree, left, NULL);
    if (!newleft) {
        left->bn_flags |= HSE_BNF_UNLINKED;
        return NULL;
    }

    node->bn_left->bn_flags |= HSE_BNF_UNLINKED;
    node->bn_left = newleft;

    out = bn_single_left_rotate(tree, node, newleft);

    return out;
}

static struct bonsai_node *
bn_double_right_rotate(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *right, *newright, *out;

    right = bn_node_dup(tree, node->bn_right);
    if (!right)
        return NULL;

    newright = bn_single_left_rotate(tree, right, NULL);
    if (!newright) {
        right->bn_flags |= HSE_BNF_UNLINKED;
        return NULL;
    }

    node->bn_right->bn_flags |= HSE_BNF_UNLINKED;
    node->bn_right = newright;

    out = bn_single_right_rotate(tree, node, newright);

    return out;
}

static struct bonsai_node *
bn_balance_left(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    const struct key_immediate *key_imm,
    const void *                key)
{
    struct bonsai_node *newnode;
    struct bonsai_node *out;

    s32 res;

    newnode = bn_node_dup_ext(tree, node, left, right);
    if (!newnode)
        return node;

    res = key_full_cmp(key_imm, key, &left->bn_key_imm, left->bn_kv->bkv_key);

    assert(res != 0);

    if (res < 0)
        out = bn_single_left_rotate(tree, newnode, NULL);
    else
        out = bn_double_left_rotate(tree, newnode);

    return out ? out : node;
}

static struct bonsai_node *
bn_balance_right(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    const struct key_immediate *key_imm,
    const void *                key)
{
    struct bonsai_node *newnode;
    struct bonsai_node *out;

    s32 res;

    newnode = bn_node_dup_ext(tree, node, left, right);
    if (!newnode)
        return node;

    res = key_full_cmp(key_imm, key, &right->bn_key_imm, right->bn_kv->bkv_key);

    assert(res != 0);

    if (res > 0)
        out = bn_single_right_rotate(tree, newnode, NULL);
    else
        out = bn_double_right_rotate(tree, newnode);

    return out ? out : node;
}

static inline struct bonsai_node *
bn_update_path(
    struct bonsai_root *  tree,
    struct bonsai_node *  parent,
    struct bonsai_node *  left,
    struct bonsai_node *  right,
    enum bonsai_update_lr lr)
{
    struct bonsai_node *myleft;
    struct bonsai_node *myright;

    if (lr == B_UPDATE_L) {
        assert(parent->bn_right == right);
        myleft = parent->bn_left;
        if (myleft != left) {
            rcu_assign_pointer(parent->bn_left, left);
        }
    } else {
        assert(parent->bn_left == left);
        myright = parent->bn_right;
        if (myright != right) {
            rcu_assign_pointer(parent->bn_right, right);
        }
    }

    bn_height_update(parent);

    return parent;
}

static HSE_ALWAYS_INLINE bool
bn_need_left_balance(int lh, int rh)
{
    return (lh - rh) >= BONSAI_TREE_BALANCE_THRESHOLD;
}

static HSE_ALWAYS_INLINE bool
bn_need_right_balance(int lh, int rh)
{
    return (rh - lh) >= BONSAI_TREE_BALANCE_THRESHOLD;
}

struct bonsai_node *
bn_balance_tree(
    struct bonsai_root *        tree,
    struct bonsai_node *        parent,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    const struct key_immediate *key_imm,
    const void *                key,
    enum bonsai_update_lr       lr)
{
    int lh;
    int rh;

    lh = bn_height_get(left);
    rh = bn_height_get(right);

    if (bn_need_left_balance(lh, rh))
        return bn_balance_left(tree, parent, left, right, key_imm, key);

    if (bn_need_right_balance(lh, rh))
        return bn_balance_right(tree, parent, left, right, key_imm, key);

    return bn_update_path(tree, parent, left, right, lr);
}
