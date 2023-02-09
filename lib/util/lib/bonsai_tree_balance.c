/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/util/event_counter.h>

#include "bonsai_tree_pvt.h"

static struct bonsai_node *
bn_right_rotate(struct bonsai_root *tree, struct bonsai_node *node, struct bonsai_node *newleft)
{
    struct bonsai_node *left = newleft;

    if (!left) {
        if (!node->bn_left) {
            bn_height_update(node);
            return node;
        }

        left = bn_node_dup(tree, node->bn_left);

        bn_node_rcufree(tree, node->bn_left);
    }

    node->bn_left = left->bn_right;
    left->bn_right = node;

    bn_height_update(node);
    bn_height_update(left);

    return left;
}

static struct bonsai_node *
bn_left_rotate(struct bonsai_root *tree, struct bonsai_node *node, struct bonsai_node *newright)
{
    struct bonsai_node *right = newright;

    if (!right) {
        if (!node->bn_right) {
            bn_height_update(node);
            return node;
        }

        right = bn_node_dup(tree, node->bn_right);

        bn_node_rcufree(tree, node->bn_right);
    }

    node->bn_right = right->bn_left;
    right->bn_left = node;

    bn_height_update(node);
    bn_height_update(right);

    return right;
}

static struct bonsai_node *
bn_left_right_rotate(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *left, *newleft;

    left = bn_node_dup(tree, node->bn_left);

    newleft = bn_left_rotate(tree, left, NULL);

    bn_node_rcufree(tree, node->bn_left);
    node->bn_left = newleft;

    return bn_right_rotate(tree, node, newleft);
}

static struct bonsai_node *
bn_right_left_rotate(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *right, *newright;

    right = bn_node_dup(tree, node->bn_right);

    newright = bn_right_rotate(tree, right, NULL);

    bn_node_rcufree(tree, node->bn_right);
    node->bn_right = newright;

    return bn_left_rotate(tree, node, newright);
}

static struct bonsai_node *
bn_balance_right(
    struct bonsai_root *tree,
    struct bonsai_node *parent,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    struct bonsai_node *newnode;

    newnode = bn_node_dup_ext(tree, parent, left, right);

    if (bn_height_get(left->bn_right) < bn_height_get(left->bn_left))
        return bn_right_rotate(tree, newnode, NULL);

    return bn_left_right_rotate(tree, newnode);
}

static struct bonsai_node *
bn_balance_left(
    struct bonsai_root *tree,
    struct bonsai_node *parent,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    struct bonsai_node *newnode;

    newnode = bn_node_dup_ext(tree, parent, left, right);

    if (bn_height_get(right->bn_left) < bn_height_get(right->bn_right))
        return bn_left_rotate(tree, newnode, NULL);

    return bn_right_left_rotate(tree, newnode);
}

static HSE_ALWAYS_INLINE struct bonsai_node *
bn_update_path(
    struct bonsai_root *tree,
    struct bonsai_node *parent,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    if (parent->bn_left != left) {
        assert(parent->bn_right == right);
        rcu_assign_pointer(parent->bn_left, left);
    } else if (parent->bn_right != right) {
        assert(parent->bn_left == left);
        rcu_assign_pointer(parent->bn_right, right);
    }

    bn_height_update(parent);

    return parent;
}

static HSE_ALWAYS_INLINE bool
bn_need_right_balance(int lh, int rh)
{
    return (lh - rh) >= HSE_BT_BALANCE_THRESHOLD;
}

static HSE_ALWAYS_INLINE bool
bn_need_left_balance(int lh, int rh)
{
    return (rh - lh) >= HSE_BT_BALANCE_THRESHOLD;
}

struct bonsai_node *
bn_balance(
    struct bonsai_root *tree,
    struct bonsai_node *parent,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    int lh, rh;

    lh = bn_height_get(left);
    rh = bn_height_get(right);

    if (bn_need_left_balance(lh, rh))
        return bn_balance_left(tree, parent, left, right);

    if (bn_need_right_balance(lh, rh))
        return bn_balance_right(tree, parent, left, right);

    return bn_update_path(tree, parent, left, right);
}
