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

#include <rbtree.h>

#include "route.h"

struct route_node {
    union {
        struct rb_node rtn_node;
        struct route_node *rtn_next;
    };
    uint16_t       rtn_keylen;
    uint16_t       rtn_child;
    uint8_t        rtn_keybuf[28];
};

struct route_map {
    struct rb_root     rtm_root;
    uint               rtm_pfxlen;
    uint               rtm_fanout;
    struct route_node *rtm_free;
    struct route_node  rtm_nodev[] HSE_L1D_ALIGNED;
};

static struct route_node *
route_map_insert(struct route_map *map, struct route_node *node)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *parent = NULL;

    while (*link) {
        struct route_node *this;
        int rc;

        this = rb_entry(*link, struct route_node, rtn_node);
        parent = *link;

        rc = keycmp(node->rtn_keybuf, node->rtn_keylen, this->rtn_keybuf, this->rtn_keylen);

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

    return NULL;
}

static struct route_node *
route_map_find(struct route_map *map, const void *key, uint keylen)
{
    struct rb_root *root = &map->rtm_root;
    struct rb_node **link = &root->rb_node;
    struct rb_node *node = *link;
    uint len = keylen;
    int dir = 0;

    if (len > map->rtm_pfxlen)
        len = map->rtm_pfxlen;

    /* The last node from which a left turn was taken in the traversal path is the
     * in-order successor of the search key.  If there was no left turn taken in
     * the traversal path then the in-order successor is the last parent node.
     */
    while (*link) {
        struct route_node *this;
        int rc;

        this = rb_entry(*link, struct route_node, rtn_node);

        rc = memcmp(key, this->rtn_keybuf, len);

        if (rc < 0) {
            dir = -1;
            node = *link;
            link = &(*link)->rb_left;
        } else if (rc > 0) {
            link = &(*link)->rb_right;
            if (dir >= 0 && *link)
                node = *link;
        } else {
            return this;
        }
    }

    return rb_entry(node, struct route_node, rtn_node);
}

uint
route_map_lookup(struct route_map *map, const void *pfx, uint pfxlen)
{
    struct route_node *node;

    node = route_map_find(map, pfx, pfxlen);

    return node->rtn_child;
}

uint
route_map_get(
    struct route_map *map,
    const void       *pfx,
    uint              pfxlen,
    void             *edge_kbuf,
    size_t            edge_kbuf_sz,
    uint             *edge_klen)
{
    struct route_node *node;

    node = route_map_find(map, pfx, pfxlen);

    assert(edge_kbuf && edge_kbuf_sz >= node->rtn_keylen);
    if (edge_kbuf && edge_kbuf_sz >= node->rtn_keylen) {
        memcpy(edge_kbuf, node->rtn_keybuf, node->rtn_keylen);
        *edge_klen = node->rtn_keylen;
    }

    return node->rtn_child;
}

void
route_map_put(struct route_map *map, uint cnum)
{
}

struct route_map *
route_map_create(const struct kvs_cparams *cp, const char *kvsname)
{
    char path[128], buf[1024];
    uint fanout, pfxlen, skip;
    struct route_map *map;
    uint64_t binkeybuf;
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
    if (cc < 1)
        return NULL;

    n = sscanf(buf, "%u%u%ms%u", &fanout, &pfxlen, &fmt, &skip);

    if (n < 3 || fanout != cp->fanout || pfxlen != cp->pfx_len) {
        log_err("fanout (%u vs %u), pfxlen (%u vs %u)",
                fanout, cp->fanout, pfxlen, cp->pfx_len);
        return NULL;
    }

    if (n < 4 || skip < 1)
        skip = 1;

    if (!strcmp(fmt, "binary")) {
        if (pfxlen > sizeof(binkeybuf)) {
            log_err("pfxlen %u > binkeybuf %zu", pfxlen, sizeof(binkeybuf));
            return NULL;
        }

        free(fmt);
        fmt = NULL;
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

    uint childv[fanout];

    if (is_power_of_2(fanout)) {
        uint child = 0;

        /* Build a vector of child node indices in order of optimal
         * pivots per level for a perfectly balanced rb tree.
         */
        for (uint div = 2; div <= fanout; div *= 2) {
            for (uint i = 1; i < div; i += 2)
                childv[child++] = (i * fanout) / div;
        }

        assert(child == fanout - 1);
        childv[child] = 0;
    } else {
        for (uint i = 0; i < fanout; ++i)
            childv[i] = i;

        childv[0] = fanout / 2;
        childv[fanout / 2] = 0;

        /* Shuffle child node indices to prevent worst-case rb insertion...
         */
        for (uint i = 1; i < fanout; ++i) {
            uint r = (xrand64_tls() % (fanout - 1)) + 1;
            uint tmp = childv[i];

            childv[i] = childv[r];
            childv[r] = tmp;
        }
    }

    /* Iterate over the vector of child node indicies to generate an edge key
     * for each child node and then insert the node into the rb tree.
     */
    for (uint i = 0; i < fanout; ++i) {
        struct route_node *node = map->rtm_nodev + i;
        struct route_node *dup;
        uint child, fmtarg;
        int n;

        child = childv[i];
        fmtarg = (child + 1) * skip - 1;

        node->rtn_keylen = pfxlen;
        node->rtn_child = child;

        if (fmt) {
            n = snprintf((char *)node->rtn_keybuf, sizeof(node->rtn_keybuf), fmt, fmtarg);

            if (n < 1 || n >= sizeof(node->rtn_keybuf)) {
                log_err("overflow %u: n %d, pfxlen %u, fmt [%s], fmtarg %u",
                        child, n, pfxlen, fmt, fmtarg);
                abort();
            }

            if (n != pfxlen) {
                log_err("skipping %u: n %d, pfxlen %u, fmt [%s], fmtarg %u",
                        child, n, pfxlen, fmt, fmtarg);
                continue;
            }
        } else {
            binkeybuf = cpu_to_be64(fmtarg);

            memcpy(node->rtn_keybuf, (char *)&binkeybuf + (sizeof(binkeybuf) - pfxlen), pfxlen);
        }

        dup = route_map_insert(map, node);
        if (dup) {
            log_err("dup route %u: child %u, pfxlen %u, fmt [%s], fmtarg %u",
                    child, dup->rtn_child, pfxlen, fmt ?: "binary", fmtarg);

            node->rtn_next = map->rtm_free;
            map->rtm_free = node;
        }
    }

    free(fmt);

    if (!rb_first(&map->rtm_root)) {
        free(map);
        return NULL;
    }

    /* Walk the generated tree to compute the depth of each child node and distribution
     * of nodes per level (for debugging).
     */
    if (1) {
        struct route_node *root = rb_entry(map->rtm_root.rb_node, struct route_node, rtn_node);
        struct rb_node *node;
        uint distv[64] = {};
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

            log_debug("%3u %2u %2u:%s", this->rtn_child, this->rtn_keylen, depth, buf);

            node = rb_next(node);
        }

        n = 0;
        for (uint i = 0; i < NELEM(distv); ++i) {
            if (distv[i] > 0)
                n += snprintf(buf + n, sizeof(buf) - n, " %u,%u", distv[i], i);
        }

        log_info("pivot %3u, distv:%s", root->rtn_child, buf);
    }

    return map;
}

void
route_map_destroy(struct route_map *map)
{
    if (!map)
        return;

    free(map);
}
