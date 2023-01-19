/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <hse/limits.h>

#include <hse/test/support/ref_tree.h>
#include <hse/util/base.h>
#include <hse/util/keycmp.h>

/*
 * Reference Tree API
 */
struct ref_tree {
    struct rb_root rt_root;
};

/* Each ref_tree_node contains one key. */
struct ref_tree_node {
    struct rb_node rbnode;
    char *key;
    size_t klen;
    uint64_t seqno;
};

struct ref_tree_iter {
    struct ref_tree_node *curr;
    struct ref_tree *rt;

    unsigned char pfx[HSE_KVS_KEY_LEN_MAX];
    size_t pfxlen;
    uint64_t view_seq;
    bool reverse;
    bool eof;
};

enum query_type {
    QTYPE_GET,
    QTYPE_SEEK_FWD,
    QTYPE_SEEK_REV,
};

static struct ref_tree_node *
rt_lookup(struct ref_tree *rt, char *kdata, size_t klen, enum query_type qtype)
{
    struct rb_node *rbnode;
    struct rb_node *last_smaller = rb_first(&rt->rt_root);
    struct rb_node *last_larger = rb_last(&rt->rt_root);
    struct ref_tree_node *rtn = NULL;

    rbnode = rt->rt_root.rb_node;

    while (rbnode) {
        int rc;

        rtn = container_of(rbnode, struct ref_tree_node, rbnode);

        rc = keycmp(kdata, klen, rtn->key, rtn->klen);
        if (rc < 0) {
            last_larger = rbnode;
            rbnode = rbnode->rb_left;
        } else if (rc > 0) {
            last_smaller = rbnode;
            rbnode = rbnode->rb_right;
        } else {
            last_smaller = last_larger = rbnode;
            break;
        }
    }

    switch (qtype) {
    case QTYPE_GET:
        rtn = NULL;
        if (rbnode)
            rtn = container_of(rbnode, struct ref_tree_node, rbnode);

        break;
    case QTYPE_SEEK_FWD:
        rtn = container_of(last_larger, struct ref_tree_node, rbnode);
        if (keycmp(rtn->key, rtn->klen, kdata, klen) < 0)
            rtn = NULL;

        break;
    case QTYPE_SEEK_REV:
        rtn = container_of(last_smaller, struct ref_tree_node, rbnode);
        if (keycmp(rtn->key, rtn->klen, kdata, klen) > 0)
            rtn = NULL;

        break;
    }

    return rtn;
}

struct ref_tree *
ref_tree_create(void)
{
    struct ref_tree *rt;

    rt = malloc(sizeof(struct ref_tree));
    if (!rt)
        return NULL;

    rt->rt_root = RB_ROOT;
    return rt;
}

void
ref_tree_destroy(struct ref_tree *rt)
{
    struct rb_node *rbnode = rb_first(&rt->rt_root);

    while (rbnode) {
        struct ref_tree_node *rtn = rb_entry(rbnode, typeof(*rtn), rbnode);
        struct rb_node *next = rb_next(rbnode);

        rb_erase(rbnode, &rt->rt_root);
        free(rtn);

        rbnode = next;
    }

    free(rt);
}

bool
ref_tree_insert(struct ref_tree *rt, char *key, size_t klen, uint64_t seqno)
{
    struct rb_node **link;
    struct rb_node *parent;
    struct rb_root *root;
    struct ref_tree_node *rtn;

    root = &rt->rt_root;
    link = &root->rb_node;
    parent = 0;

    while (*link) {
        int rc;

        parent = *link;
        rtn = container_of(parent, struct ref_tree_node, rbnode);

        rc = keycmp(key, klen, rtn->key, rtn->klen);
        if (rc < 0)
            link = &(*link)->rb_left;
        else if (rc > 0)
            link = &(*link)->rb_right;
        else
            return false;
    }

    rtn = malloc(sizeof(*rtn) + klen);
    if (!rtn)
        return false;

    rtn->seqno = seqno;
    rtn->klen = klen;
    rtn->key = (char *)(rtn + 1);
    memcpy(rtn->key, key, klen);

    rb_link_node(&rtn->rbnode, parent, link);
    rb_insert_color(&rtn->rbnode, root);

    return true;
}

bool
ref_tree_get(struct ref_tree *rt, char *key, size_t klen)
{
    struct ref_tree_node *rtn;

    rtn = rt_lookup(rt, key, klen, QTYPE_GET);
    if (!rtn)
        return false;

    assert(klen == rtn->klen && memcmp(rtn->key, key, klen) == 0);
    return true;
}

struct ref_tree_iter *
ref_tree_iter_create(struct ref_tree *rt, char *pfx, size_t pfxlen, bool reverse, uint64_t view_seq)
{
    struct ref_tree_iter *it = malloc(sizeof(*it));

    if (!it)
        return NULL;

    it->rt = rt;
    it->view_seq = view_seq;
    it->reverse = reverse;
    it->pfxlen = pfxlen;

    if (pfxlen)
        memcpy(it->pfx, pfx, pfxlen);

    it->curr = NULL;
    it->eof = false;

    return it;
}

void
ref_tree_iter_destroy(struct ref_tree_iter *rt_iter)
{
    free(rt_iter);
}

void
ref_tree_iter_seek(struct ref_tree_iter *rt_iter, char *key, size_t klen, bool *eof)
{
    struct ref_tree_node *rtn;
    enum query_type qtype = rt_iter->reverse ? QTYPE_SEEK_REV : QTYPE_SEEK_FWD;

    rtn = rt_lookup(rt_iter->rt, key, klen, qtype);
    if (!rtn) {
        *eof = rt_iter->eof = true;
        return;
    }

    rt_iter->curr = rtn;
    *eof = rt_iter->eof = false;
}

bool
ref_tree_iter_read(struct ref_tree_iter *rt_iter, char **key, size_t *klen)
{
    struct ref_tree_node *rtn = rt_iter->curr;
    struct rb_node *rbnode;

    if (rt_iter->eof)
        return false;

    rbnode = &rtn->rbnode;
    while (rbnode) {
        rtn = rb_entry(rbnode, typeof(*rtn), rbnode);

        rbnode = rt_iter->reverse ? rb_prev(rbnode) : rb_next(rbnode);
        rt_iter->curr = rb_entry(rbnode, typeof(*rtn), rbnode);

        if (rtn->seqno <= rt_iter->view_seq)
            break;
    }

    rt_iter->eof = !rtn;

    if (!rt_iter->eof) {
        *key = rtn->key;
        *klen = rtn->klen;
    }

    return !rt_iter->eof;
}
