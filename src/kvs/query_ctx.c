/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/keycmp.h>
#include <hse_util/byteorder.h>
#include <hse_util/assert.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/query_ctx.h>

pthread_key_t tomb_thread_key;

/**
 * struct te_mem - Memory for tomb elems
 * @pglist:  list of all pages that constitute this memory.
 * @curr_pg: current page in use.
 */
struct te_mem {
    void *pglist;
    void *curr_pg;
};

/**
 * struct te_page_hdr - Header at the beginning of each page in the memory
 *                      region's page list
 * @next: pointer to the next page header.
 */
struct te_page_hdr {
    struct te_page_hdr *next;
};

void
qctx_thread_dtor(void *mem)
{
    struct te_mem *     tem = mem;
    struct te_page_hdr *hdr;

    hdr = tem->pglist;
    while (hdr) {
        struct te_page_hdr *next = hdr->next;

        free_page((unsigned long)hdr);
        hdr = next;
    }

    free(tem);
}

static struct tomb_elem *
alloc_tomb_mem(struct query_ctx *qctx, size_t bytes)
{
    struct tomb_elem *  te;
    size_t              sz = sizeof(*te) + bytes;
    struct te_mem *     ptr;
    struct te_page_hdr *hdr;
    unsigned int        min_offset = (sizeof(*hdr) + 0x0f) & (~0x0e);

    ptr = pthread_getspecific(tomb_thread_key);

    if (qctx->pos < min_offset)
        qctx->pos = min_offset;

    if (!ptr) {
        int rc;

        ptr = malloc(sizeof(*ptr));
        if (!ptr)
            return 0;

        ptr->pglist = (void *)__get_free_page(GFP_KERNEL);
        if (!ptr->pglist) {
            free(ptr);
            return 0;
        }

        ptr->curr_pg = ptr->pglist;
        hdr = ptr->curr_pg;
        hdr->next = 0;
        qctx->pos = min_offset;

        rc = pthread_setspecific(tomb_thread_key, ptr);
        if (ev(rc)) {
            free_page((unsigned long)ptr->pglist);
            free(ptr);
            return 0;
        }

    } else if (qctx->pos + sz > PAGE_SIZE) {
        hdr = ptr->curr_pg;
        if (hdr->next) {
            /* The there is a cached page that can be used */
            hdr = hdr->next;
        } else {
            /* No more cached pages. Allocate and use a new page */
            void *mem;

            mem = (void *)__get_free_page(GFP_KERNEL);
            if (!mem)
                return 0;

            hdr->next = mem;
            hdr = mem;
            hdr->next = 0;
        }

        ptr->curr_pg = hdr;
        qctx->pos = min_offset;
    }

    te = (void *)(ptr->curr_pg + qctx->pos);
    qctx->pos += (sz + 0x08) & ~0x07;

    return te;
}

static __always_inline int
qctx_tomb_cmp(const void *lhs, size_t len1, const void *rhs, size_t len2)
{
    const uint64_t *l, *r;
    uint64_t        ll, rr;

    if (unlikely(len1 != sizeof(uint64_t) || len2 != sizeof(uint64_t)))
        return keycmp(lhs, len1, rhs, len2);

    l = lhs;
    r = rhs;
    ll = be64_to_cpu(*l);
    rr = be64_to_cpu(*r);

    if (rr > ll)
        return 1;

    if (rr < ll)
        return -1;

    return 0;
}

merr_t
qctx_tomb_insert(struct query_ctx *qctx, const void *sfx, size_t sfx_len)
{
    struct rb_node * parent;
    int              bkt;
    struct rb_root * root;
    struct rb_node **link;

    bkt = *(uint64_t *)sfx % TT_WIDTH;
    root = &qctx->tomb_tree[bkt];
    link = &root->rb_node;

    parent = 0;
    while (*link) {
        struct tomb_elem *p;
        int               rc;

        __builtin_prefetch(*link);

        parent = *link;
        p = rb_entry(*link, struct tomb_elem, node);

        rc = qctx_tomb_cmp(sfx, sfx_len, p->tomb, p->tomblen);
        if (rc > 0)
            link = &(*link)->rb_right;
        else if (rc < 0)
            link = &(*link)->rb_left;
        else
            break;
    }

    if (*link) {
        /* duplicate. Do nothing */
    } else {
        struct tomb_elem *te;

        te = alloc_tomb_mem(qctx, sfx_len);
        if (ev(!te))
            return merr(ENOMEM);

        te->tomblen = sfx_len;
        te->tomb = te + 1;
        memcpy(te->tomb, sfx, sfx_len);

        rb_link_node(&te->node, parent, link);
        rb_insert_color(&te->node, root);
        ++qctx->ntombs;
    }

    return 0;
}

bool
qctx_tomb_seen(struct query_ctx *qctx, const void *sfx, size_t sfx_len)
{
    struct tomb_elem *p = 0;
    int               bkt;
    struct rb_node *  n;

    bkt = *(uint64_t *)sfx % TT_WIDTH;
    n = qctx->tomb_tree[bkt].rb_node;

    if (!qctx->ntombs)
        return false;

    while (n) {
        int rc;

        __builtin_prefetch(n);

        p = rb_entry(n, struct tomb_elem, node);

        rc = qctx_tomb_cmp(sfx, sfx_len, p->tomb, p->tomblen);
        if (rc > 0)
            n = n->rb_right;
        else if (rc < 0)
            n = n->rb_left;
        else
            break;
    }

    if (n)
        return true;

    return false;
}

merr_t
qctx_te_mem_init(void)
{
    int rc;

    rc = pthread_key_create(&tomb_thread_key, &qctx_thread_dtor);
    return merr(ev(rc));
}

void
qctx_te_mem_reset(void)
{
    struct te_mem *ptr;

    /* reset current page pointer for use by the next call */
    ptr = pthread_getspecific(tomb_thread_key);
    if (ptr)
        ptr->curr_pg = ptr->pglist;
}
