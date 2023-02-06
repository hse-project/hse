/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_route

#include <hse/ikvdb/kvs_cparams.h>

#include <hse/util/platform.h>
#include <hse/util/alloc.h>
#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/keycmp.h>
#include <hse/util/xrand.h>
#include <hse/util/log2.h>
#include <hse/util/byteorder.h>
#include <hse/util/minmax.h>
#include <hse/util/assert.h>

#include "cn_tree_internal.h"
#include "route.h"

struct route_map {
    struct rb_root        rtm_root;
    uint                  rtm_nodec;
    struct route_node    *rtm_free;
    struct route_node     rtm_nodev[] HSE_L1D_ALIGNED;
};

static merr_t
route_node_keybuf_alloc(struct route_node *node, uint edge_klen)
{
    uint32_t kbufsz = node->rtn_keybufsz;

    /* 1. If the edge key fits the inline buffer then use the inline buffer.
     * 2. If the edge key doesn't fit the inline buffer but fits the previously allocated
     * buffer then use the previously allocated buffer.
     * 3. If the edge key doesn't fit both the inline and the previously allocated buffer
     * then allocate a new larger buffer.
     *
     * For cases (1) and (3), free the previously allocated buffer.
     */
    if ((edge_klen <= sizeof(node->rtn_keybuf)) || edge_klen > kbufsz) {
        if (kbufsz > 0) {
            assert(node->rtn_keybufp != node->rtn_keybuf);
            free(node->rtn_keybufp);
            node->rtn_keybufp = node->rtn_keybuf;
            node->rtn_keybufsz = 0;
        }

        if (edge_klen > sizeof(node->rtn_keybuf)) {
            size_t align = sizeof(uint64_t);

            assert(edge_klen > kbufsz);
            kbufsz = ALIGN(edge_klen, align);

            node->rtn_keybufp = aligned_alloc(align, kbufsz);
            if (!node->rtn_keybufp)
                return merr(ENOMEM);

            node->rtn_keybufsz = kbufsz;
        }
    }

    return 0;
}

static void
route_node_key_set(struct route_node *node, const void *edge_key, uint edge_klen)
{
    if (!edge_key || !edge_klen)
        return;

    INVARIANT(node);
    INVARIANT(node->rtn_keybufp);
    assert(node->rtn_keybufp != node->rtn_keybuf || edge_klen <= sizeof(node->rtn_keybuf));

    memcpy(node->rtn_keybufp, edge_key, edge_klen);
    node->rtn_keylen = edge_klen;
}

struct route_node *
route_node_alloc(struct route_map *map, void *tnode, const void *edge_key, uint edge_klen)
{
    struct route_node *node;
    merr_t err;

    node = map->rtm_free;
    if (!node)
        return NULL;

    err = route_node_keybuf_alloc(node, edge_klen);
    if (err)
        return NULL;

    map->rtm_free = node->rtn_next;

    route_node_key_set(node, edge_key, edge_klen);

    node->rtn_tnode = tnode;

    return node;
}

void
route_node_free(struct route_map *map, struct route_node *node)
{
    if (!map || !node)
        return;

    assert(node >= map->rtm_nodev && node < (map->rtm_nodev + map->rtm_nodec));

    node->rtn_tnode = NULL;
    node->rtn_keylen = 0;
    node->rtn_isfirst = node->rtn_islast = false;

    node->rtn_next = map->rtm_free;
    map->rtm_free = node;
}

merr_t HSE_MAYBE_UNUSED
route_node_key_modify(
    struct route_map  *map,
    struct route_node *node,
    const void        *edge_key,
    uint               edge_klen)
{
    merr_t err;

    if (!map || !node || !edge_key || !edge_klen)
        return merr(EINVAL);

    err = route_node_keybuf_alloc(node, edge_klen);
    if (err)
        return err;

    route_node_key_set(node, edge_key, edge_klen);

    return 0;
}

struct route_node *
route_map_insert_by_node(struct route_map *map, struct route_node *node)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *parent = NULL;
    struct rb_node *first = rb_first(root), *last = rb_last(root);

    INVARIANT(map && node);
    INVARIANT(node->rtn_tnode);

    node->rtn_isfirst = node->rtn_islast = false;

    while (*link) {
        struct route_node *this;
        int rc;

        this = rb_entry(*link, struct route_node, rtn_node);
        parent = *link;

        rc = keycmp(node->rtn_keybufp, node->rtn_keylen, this->rtn_keybufp, this->rtn_keylen);

        if (rc < 0) {
            link = &(*link)->rb_left;
        } else if (rc > 0) {
            link = &(*link)->rb_right;
        } else {
            return this;
        }
    }

    rb_link_node(&node->rtn_node, parent, link);
    rb_insert_color(&node->rtn_node, root);

    if (first != rb_first(root)) {
        assert(rb_first(root) == &node->rtn_node);
        node->rtn_isfirst = true;
        if (first) {
            struct route_node *this = rb_entry(first, struct route_node, rtn_node);
            this->rtn_isfirst = false;
        }
    }

    if (last != rb_last(root)) {
        assert(rb_last(root) == &node->rtn_node);
        node->rtn_islast = true;
        if (last) {
            struct route_node *this = rb_entry(last, struct route_node, rtn_node);
            this->rtn_islast = false;
        }
    }

    return NULL;
}

struct route_node *
route_map_insert(struct route_map *map, void *tnode, const void *edge_key, uint edge_klen)
{
    struct route_node *node, *dup;

    INVARIANT(map && tnode);

    node = route_node_alloc(map, tnode, edge_key, edge_klen);
    if (!node) {
        log_err("route node allocation failed");
        return NULL;
    }

    dup = route_map_insert_by_node(map, node);
    if (dup) {
        route_node_free(map, node);
        log_err("dup node detected (%u %p; %u %p)", edge_klen, tnode,
                dup->rtn_keylen, dup->rtn_tnode);
        return NULL;
    }

    return node;
}

void
route_map_delete(struct route_map *map, struct route_node *node)
{
    struct rb_root *root;
    struct rb_node *first, *last, *cur;

    if (!map || !node)
        return;

    root = &map->rtm_root;
    first = rb_first(root);
    last = rb_last(root);

    rb_erase(&node->rtn_node, root);
    route_node_free(map, node);

    assert(first && last);
    if (first != (cur = rb_first(root)) && cur) {
        struct route_node *this = rb_entry(cur, struct route_node, rtn_node);

        this->rtn_isfirst = true;
    }

    if (last != (cur = rb_last(root)) && cur) {
        struct route_node *this = rb_entry(cur, struct route_node, rtn_node);

        this->rtn_islast = true;
    }
}

static struct route_node *
route_map_find(struct route_map *map, const void *key, uint keylen, bool gt)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *node = *link;
    int dir = 0;

    /* The last node from which a left turn was taken in the traversal path is the
     * in-order successor of the search key.  If there was no left turn taken in
     * the traversal path then the in-order successor is the last parent node.
     */
    while (*link) {
        struct route_node *this;
        int rc;

        this = rb_entry(*link, struct route_node, rtn_node);

        rc = keycmp(key, keylen, this->rtn_keybufp, this->rtn_keylen);

        if (rc < 0) {
            dir = -1;
            node = *link;
            link = &(*link)->rb_left;
        } else if (rc > 0) {
            link = &(*link)->rb_right;
            if (dir >= 0 && *link)
                node = *link;
        } else {
            return gt ? rb_entry(rb_next(*link), struct route_node, rtn_node) : this;
        }
    }

    return rb_entry(node, struct route_node, rtn_node);
}

struct route_node *
route_map_last_node(struct route_map *map)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node *node = rb_last(root);
    struct route_node *last = NULL;

    if (node) {
        last = rb_entry(node, struct route_node, rtn_node);
        assert(last->rtn_islast);
    }

    return last;
}

struct route_node *
route_map_first_node(struct route_map *map)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node *node = rb_first(root);
    struct route_node *first = NULL;

    if (node) {
        first = rb_entry(node, struct route_node, rtn_node);
        assert(first->rtn_isfirst);
    }

    return first;
}

struct route_node *
route_map_lookup(struct route_map *map, const void *key, uint keylen)
{
    return map ? route_map_find(map, key, keylen, false) : NULL;
}

struct route_node *
route_map_lookupGT(struct route_map *map, const void *key, uint keylen)
{
    return map ? route_map_find(map, key, keylen, true) : NULL;
}

struct route_node *
route_node_next(struct route_node *node)
{
    struct rb_node *next;

    if (!node)
        return NULL;

    next = rb_next(&node->rtn_node);
    return next ? rb_entry(next, struct route_node, rtn_node) : NULL;
}

struct route_node *
route_node_prev(struct route_node *node)
{
    struct rb_node *prev;

    if (!node)
        return NULL;

    prev = rb_prev(&node->rtn_node);
    return prev ? rb_entry(prev, struct route_node, rtn_node) : NULL;
}

struct route_map *
route_map_create(uint nodec)
{
    struct route_map *map;
    size_t sz;

    if (nodec == 0)
        return NULL;

    sz = sizeof(*map) + sizeof(map->rtm_nodev[0]) * nodec;

    map = aligned_alloc(4096, roundup(sz, 4096));
    if (!map)
        return NULL;

    memset(map, 0, sz);
    map->rtm_nodec = nodec;

    /* Fill the route_node cache entries */
    for (uint i = nodec; i > 0; --i) {
        struct route_node *node = map->rtm_nodev + (i - 1);

        node->rtn_keybufp = node->rtn_keybuf;
        route_node_free(map, node);
    }

    return map;
}

void
route_map_destroy(struct route_map *map)
{
    struct rb_root *root;
    struct route_node *node;

    if (!map)
        return;

    root = &map->rtm_root;

    assert(!root->rb_node);
    if (root->rb_node) {
        struct route_node *node, *next;

        log_err("route node leak detected");

        rbtree_postorder_for_each_entry_safe(node, next, &map->rtm_root, rtn_node) {
            route_map_delete(map, node);
        }
    }

    node = map->rtm_free;
    while (node) {
        if (node->rtn_keybufp != node->rtn_keybuf) {
            assert(node->rtn_keybufsz > sizeof(node->rtn_keybuf));
            free(node->rtn_keybufp);
        }
        node = node->rtn_next;
    }

    free(map);
}

#if HSE_MOCKING
#include "route_ut_impl.i"
#endif
