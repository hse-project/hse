/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/kvs_cparams.h>

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/logging.h>
#include <hse_util/assert.h>
#include <hse_util/keycmp.h>
#include <hse_util/xrand.h>
#include <hse_util/log2.h>
#include <hse_util/byteorder.h>
#include <hse_util/minmax.h>
#include <hse_util/assert.h>

#include "cn_tree_internal.h"
#include "route.h"

/*
 * TODO: `rtm_skip' and `rtm_fmt' will be gone when we get rid of static routes
 */
struct route_map {
    struct rb_root        rtm_root;
    uint                  rtm_pfxlen;
    uint                  rtm_fanout;
    uint                  rtm_skip;
    char                 *rtm_fmt;
    struct route_node    *rtm_free;
    struct route_node     rtm_nodev[] HSE_L1D_ALIGNED;
};

static int
route_node_key_set(
    struct route_map  *map,
    struct route_node *node,
    const void        *edge_key,
    uint               edge_klen,
    uint32_t           nodeoff)
{
    INVARIANT(node);

    if (edge_key && edge_klen > 0) {
        INVARIANT(node->rtn_keybufp);
        assert(node->rtn_keybufp != node->rtn_keybuf || edge_klen <= sizeof(node->rtn_keybuf));

        memcpy(node->rtn_keybufp, edge_key, edge_klen);
        node->rtn_keylen = edge_klen;
    } else { /* TODO: This else path will be gone when we get rid of static routes */
        uint pfxlen = map->rtm_pfxlen;
        uint fmtarg = (nodeoff + 1) * map->rtm_skip - 1;

        if (map->rtm_fmt) {
            if (!strcmp(map->rtm_fmt, "MainKvs")) {
                uint64_t binkeybuf = cpu_to_be64(fmtarg);

                memset(node->rtn_keybuf, 0, 4);
                node->rtn_keybuf[3] = 0x0d;

                memcpy(node->rtn_keybuf + 4,
                       (char *)&binkeybuf + (sizeof(binkeybuf) - pfxlen),
                       pfxlen);
                pfxlen += 4;

                log_info("nodeoff %u, fmtarg %u, pfxlen %u, %02x %02x %02x %02x %02x %02x %02x %02x",
                         nodeoff, fmtarg, pfxlen,
                         ((uint8_t *)&binkeybuf)[0],
                         ((uint8_t *)&binkeybuf)[1],
                         ((uint8_t *)&binkeybuf)[2],
                         ((uint8_t *)&binkeybuf)[3],
                         ((uint8_t *)&binkeybuf)[4],
                         ((uint8_t *)&binkeybuf)[5],
                         ((uint8_t *)&binkeybuf)[6],
                         ((uint8_t *)&binkeybuf)[7]);
            } else {
                int n = snprintf((char *)node->rtn_keybuf, sizeof(node->rtn_keybuf),
                                 map->rtm_fmt, fmtarg);

                if (n < 1 || n >= sizeof(node->rtn_keybuf)) {
                    log_err("overflow %u: n %d, pfxlen %u, fmt [%s], fmtarg %u",
                            nodeoff, n, pfxlen, map->rtm_fmt, fmtarg);
                    abort();
                }

                if (n != pfxlen) {
                    log_err("skipping %u: n %d, pfxlen %u, fmt [%s], fmtarg %u",
                            nodeoff, n, pfxlen, map->rtm_fmt, fmtarg);
                    return -1;
                }
            }
        } else {
            uint64_t binkeybuf = cpu_to_be64(fmtarg);

            memcpy(node->rtn_keybuf, (char *)&binkeybuf + (sizeof(binkeybuf) - pfxlen), pfxlen);
        }

        node->rtn_keylen = pfxlen;
    }

    return 0;
}

static struct route_node *
route_node_alloc(struct route_map *map, uint edge_klen)
{
    struct route_node *node = map->rtm_free;
    size_t nodesz;

    if (node) {
        uint32_t kbufsz;

        map->rtm_free = node->rtn_next;
        kbufsz = node->rtn_keybufsz;

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
                    return NULL;
                node->rtn_keybufsz = kbufsz;
            }
        }

        return node;
    }

    /* The route_node cache is empty, allocate a new route_node.
     * These allocated route_node entries are never cached.
     */
    nodesz = sizeof(*node);
    if (edge_klen > sizeof(node->rtn_keybuf))
        nodesz += ALIGN(edge_klen, __alignof__(*node));

    node = aligned_alloc(__alignof__(*node), nodesz);
    if (node) {
        memset(node, 0, nodesz);
        node->rtn_keybufp = (nodesz > sizeof(*node)) ? (uint8_t *)(node + 1) : node->rtn_keybuf;
    }

    return node;
}

static void
route_node_free(struct route_map *map, struct route_node *node)
{
    bool freeme = (node < map->rtm_nodev || node >= (map->rtm_nodev + map->rtm_fanout));

    if (!freeme) {
        node->rtn_tnode = NULL;
        node->rtn_keylen = 0;
        node->rtn_isfirst = node->rtn_islast = false;

        node->rtn_next = map->rtm_free;
        map->rtm_free = node;
        return;
    }

    free(node);
}

/*
 * TODO: The `nodeoff' parameter will be gone when we get rid of static routes
 */
struct route_node *
route_map_insert(
    struct route_map *map,
    void             *tnode,
    const void       *edge_key,
    uint              edge_klen,
    uint32_t          nodeoff)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *parent = NULL;
    struct rb_node *first = rb_first(root), *last = rb_last(root);
    struct route_node *node;
    int rc;

    INVARIANT(map && tnode);

    node = route_node_alloc(map, edge_klen);
    if (!node) {
        log_err("route node allocation failed for %u", nodeoff);
        return NULL;
    }

    node->rtn_tnode = tnode;
    node->rtn_isfirst = node->rtn_islast = false;

    rc = route_node_key_set(map, node, edge_key, edge_klen, nodeoff);
    if (rc < 0) {
        route_node_free(map, node);
        return NULL;
    }

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
            log_err("dup route detected %u", nodeoff);
            route_node_free(map, node);
            return NULL;
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
    return rb_entry(next, struct route_node, rtn_node);
}

struct route_node *
route_node_prev(struct route_node *node)
{
    struct rb_node *prev;

    if (!node)
        return NULL;

    prev = rb_prev(&node->rtn_node);
    return rb_entry(prev, struct route_node, rtn_node);
}

struct route_map *
route_map_create(const struct kvs_cparams *cp, const char *kvsname)
{
    char path[128], buf[4096];
    uint fanout, pfxlen, skip;
    struct route_map *map;
    ssize_t cc;
    size_t sz;
    char *fmt;
    int n;

    if (!cp || !kvsname)
        return NULL;

    n = snprintf(path, sizeof(path), "/var/tmp/routemap-%s", kvsname);
    if (n < 1 || n >= sizeof(path))
        return NULL;

    cc = hse_readfile(-1, path, buf, sizeof(buf), O_RDONLY);
    if (cc < 1) {
        pfxlen = cp->pfx_len ? cp->pfx_len : 5;
        if (pfxlen > sizeof(uint64_t))
            return NULL;

        /* Create binary edge keys by default with user-specified pfxlen and fanout.
         */
        fanout = cp->fanout;
        skip = 1;
        fmt = NULL;
    } else {
        n = sscanf(buf, "%u%u%ms%u", &fanout, &pfxlen, &fmt, &skip);

        if (n < 3 || fanout != cp->fanout) {
            log_err("fanout (%u vs %u)", fanout, cp->fanout);
            return NULL;
        }

        if (n < 4 || skip < 1)
            skip = 1;

        if (!strcmp(fmt, "binary")) {
            if (pfxlen > sizeof(uint64_t)) {
                log_err("pfxlen %u > %zu", pfxlen, sizeof(uint64_t));
                return NULL;
            }

            free(fmt);
            fmt = NULL;
        }
        else if (!strcmp(fmt, "MainKvs")) {
            if (pfxlen > sizeof(uint64_t)) {
                log_err("pfxlen %u > %zu", pfxlen, sizeof(uint64_t));
                return NULL;
            }
        }
    }

    sz = sizeof(*map) + sizeof(map->rtm_nodev[0]) * fanout;

    map = aligned_alloc(4096, roundup(sz, 4096));
    if (!map) {
        free(fmt);
        return NULL;
    }

    memset(map, 0, sz);
    map->rtm_fanout = fanout;
    map->rtm_pfxlen = pfxlen;
    map->rtm_fmt = fmt;
    map->rtm_skip = skip;

    /* Fill the route_node cache entries */
    for (int i = fanout - 1; i >= 0; --i) {
        struct route_node *node = map->rtm_nodev + i;

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

    free(map->rtm_fmt);
    free(map);
}

#ifndef NDEBUG
/* Walk the generated tree to compute the depth of each child node and distribution
 * of nodes per level (for debugging).
 *
 * TODO: Leaving this function here so that it can be used in the future to peek at
 * the route map via REST.
 */
static void HSE_MAYBE_UNUSED
route_map_dump(struct route_map *map)
{
    struct rb_node *node;
    uint distv[64] = {}, nodeoff = 0;
    char buf[1024];
    int n;

    node = rb_first(&map->rtm_root);

    while (node) {
        struct route_node *this = rb_entry(node, struct route_node, rtn_node);
        struct rb_node *parent = node;
        uint depth = 0;

        while ((parent = rb_parent(parent)))
            ++depth;

        ++distv[depth];

        n = 0;
        for (uint i = 0; i < this->rtn_keylen; ++i)
            n += snprintf(buf + n, sizeof(buf) - n, " %02x", this->rtn_keybuf[i]);

        log_debug("%3u %2u %2u:%s", nodeoff++, this->rtn_keylen, depth, buf);

        node = rb_next(node);
    }

    n = 0;
    for (uint i = 0; i < NELEM(distv); ++i) {
        if (distv[i] > 0)
            n += snprintf(buf + n, sizeof(buf) - n, " %u,%u", distv[i], i);
    }

    log_info("distv:%s", buf);
}
#endif
