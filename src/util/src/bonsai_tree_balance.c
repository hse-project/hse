/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>

#include "bonsai_tree_pvt.h"

static struct bonsai_node *
bn_single_left_rotate(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *newleft)
{
    struct bonsai_node *left;
    struct bonsai_node *oldleft;

    assert(node->bn_left);
    oldleft = node->bn_left;

    if (newleft)
        left = newleft;
    else
        left = bn_node_dup(tree, oldleft);

    if (!left) {
        ev(1);
        return NULL;
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
    struct bonsai_node *right;
    struct bonsai_node *oldright;

    assert(node->bn_right);
    oldright = node->bn_right;

    if (newright)
        right = newright;
    else
        right = bn_node_dup(tree, oldright);

    if (!right) {
        ev(1);
        return NULL;
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
    struct bonsai_node *left;
    struct bonsai_node *newleft;
    struct bonsai_node *oldleft;
    struct bonsai_node *out;

    assert(node->bn_left);
    oldleft = node->bn_left;

    left = bn_node_dup(tree, oldleft);
    if (!left) {
        ev(1);
        return NULL;
    }

    newleft = bn_single_right_rotate(tree, left, NULL);
    if (!newleft) {
        ev(1);
        bn_node_free(tree, left);
        return NULL;
    }

    node->bn_left = newleft;

    out = bn_single_left_rotate(tree, node, newleft);
    if (!out) {
        ev(1);
        bn_node_free(tree, left);
        bn_node_free(tree, newleft);
    }

    return out;
}

static struct bonsai_node *
bn_double_right_rotate(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *right;
    struct bonsai_node *newright;
    struct bonsai_node *oldright;
    struct bonsai_node *out;

    assert(node->bn_right);
    oldright = node->bn_right;

    right = bn_node_dup(tree, oldright);
    if (!right) {
        ev(1);
        return NULL;
    }

    newright = bn_single_left_rotate(tree, right, NULL);
    if (!newright) {
        ev(1);
        bn_node_free(tree, right);
        return NULL;
    }

    node->bn_right = newright;

    out = bn_single_right_rotate(tree, node, newright);
    if (!out) {
        ev(1);
        bn_node_free(tree, right);
        bn_node_free(tree, newright);
    }

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
    if (!newnode) {
        ev(1);
        return node;
    }

    res = key_immediate_cmp(key_imm, &left->bn_key_imm);
    if (res == S32_MIN)
        res = inner_key_cmp(
            key + key_imm->ki_dlen,
            key_imm->ki_klen - key_imm->ki_dlen,
            left->bn_kv->bkv_key + left->bn_key_imm.ki_dlen,
            left->bn_key_imm.ki_klen - left->bn_key_imm.ki_dlen);

    assert(res != 0);

    if (res < 0)
        out = bn_single_left_rotate(tree, newnode, NULL);
    else
        out = bn_double_left_rotate(tree, newnode);

    if (!out) {
        ev(1);
        bn_node_free(tree, newnode);
        return node;
    }

    if (res > 0)
        bn_node_free(tree, left->bn_right);

    bn_node_free(tree, left);

    return out;
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
    if (!newnode) {
        ev(1);
        return node;
    }

    res = key_immediate_cmp(key_imm, &right->bn_key_imm);
    if (res == S32_MIN)
        res = inner_key_cmp(
            key + key_imm->ki_dlen,
            key_imm->ki_klen - key_imm->ki_dlen,
            right->bn_kv->bkv_key + right->bn_key_imm.ki_dlen,
            right->bn_key_imm.ki_klen - right->bn_key_imm.ki_dlen);

    assert(res != 0);

    if (res > 0)
        out = bn_single_right_rotate(tree, newnode, NULL);
    else
        out = bn_double_right_rotate(tree, newnode);

    if (!out) {
        ev(1);
        bn_node_free(tree, newnode);
        return node;
    }

    if (res < 0)
        bn_node_free(tree, right->bn_left);

    bn_node_free(tree, right);

    return out;
}

static inline struct bonsai_node *
bn_update_path(
    struct bonsai_root *  tree,
    struct bonsai_node *  node,
    struct bonsai_node *  left,
    struct bonsai_node *  right,
    enum bonsai_update_lr lr)
{
    struct bonsai_node *myleft;
    struct bonsai_node *myright;

    if (lr == B_UPDATE_L) {
        assert(node->bn_right == right);
        myleft = node->bn_left;
        if (myleft != left) {
            rcu_assign_pointer(node->bn_left, left);
            bn_node_free(tree, myleft);
        }
    } else {
        assert(node->bn_left == left);
        myright = node->bn_right;
        if (myright != right) {
            rcu_assign_pointer(node->bn_right, right);
            bn_node_free(tree, myright);
        }
    }

    bn_height_update(node);

    return node;
}

static __always_inline bool
bn_need_left_balance(int lh, int rh)
{
    return (lh - rh) >= BONSAI_TREE_BALANCE_THRESHOLD;
}

static __always_inline bool
bn_need_right_balance(int lh, int rh)
{
    return (rh - lh) >= BONSAI_TREE_BALANCE_THRESHOLD;
}

struct bonsai_node *
bn_balance_tree(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
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
        return bn_balance_left(tree, node, left, right, key_imm, key);

    if (bn_need_right_balance(lh, rh))
        return bn_balance_right(tree, node, left, right, key_imm, key);

    return bn_update_path(tree, node, left, right, lr);
}
