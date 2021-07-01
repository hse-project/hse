/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/limits.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>
#include <hse_util/key_util.h>

#include "omf.h"
#include "intern_builder.h"
#include "wbt_builder.h"

/**
 * struct intern_node - node data
 *
 * @buf:  a PAGE_SIZE buffer that stores compressed keys (lcp elimiated keys)
 * @next: next node;
 */
struct intern_node {
    unsigned char      *buf;
    struct intern_node *next;
};

struct intern_key {
    uint          child_idx;
    uint          klen;
    unsigned char kdata[];
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
    uint                    curr_rkeys_sum;
    uint                    curr_rkeys_cnt;
    uint                    curr_child;
    uint                    full_node_cnt;
    uint                    level;
    uint                    node_lcp_len;
    struct intern_node     *node_head;
    struct intern_node     *node_curr;
    unsigned char          *sbuf;
    uint                    sbuf_sz;
    uint                    sbuf_used;
    struct intern_level    *parent;
    struct intern_builder  *ibldr;
};

/* Max sizes of objects embedded into struct intern_builder.
 */
#define IB_ENODEV_MAX       NELEM(((struct intern_builder *)0)->nodev)
#define IB_ELEVELV_MAX      NELEM(((struct intern_builder *)0)->levelv)
#define IB_ESBUFSZ_MAX                                                  \
    roundup(                                                            \
        ((8192 - sizeof(struct intern_builder) - 16) / IB_ELEVELV_MAX), \
        alignof(struct intern_key))

/**
 * struct intern_buiilder -
 * @base:       pointer to the first allocated level object
 * @wbb:        pointer to owning the wt builder
 * @nodec:      number of nodes allocated from nodev[]
 * @sbufs:      head of a singly-linked list of free sbufs
 * @levelc:     number of levels allocated from levelv[]
 * @levelv:     private cache of level objects
 * @nodev:      private cache of node objects
 * @sbufv:      IB_ESBUFSZ_MAX scratch bytes per embedded level
 *
 * %intern_builder embeds several small but sufficiently large caches
 * (node, level, and sbuf) so as to maintain a very high locality
 * of reference when accessing any part of the builder.
 */
struct intern_builder {
    struct intern_level    *base;
    struct wbb             *wbb;
    u_char                 *sbufs;
    uint                    nodec;
    uint                    levelc;
    struct intern_level     levelv[5];
    struct intern_node      nodev[48];
    u_char                  sbufv[];
};

/* If you increase the size of IB_ESBUFSZ_MAX or HSE_KVS_KEY_LEN_MAX then
 * you probably need to increase the buffer grow size in ib_sbuf_key_add().
 */
_Static_assert(IB_ESBUFSZ_MAX < 4096, "adjust grow size in ib_sbuf_key_add()");
_Static_assert(HSE_KVS_KEY_LEN_MAX < 4096, "adjust grow size in ib_sbuf_key_add()");


static struct kmem_cache *ib_node_cache HSE_READ_MOSTLY;
static struct kmem_cache *ib_cache HSE_READ_MOSTLY;
static atomic_t           ib_init_ref;

merr_t
ib_init(void)
{
    size_t sz;

    if (atomic_inc_return(&ib_init_ref) > 1)
        return 0;

    sz = sizeof(struct intern_node);

    ib_node_cache = kmem_cache_create("ibnode", sz, 0, 0, NULL);
    if (ev(!ib_node_cache)) {
        atomic_dec(&ib_init_ref);
        return merr(ENOMEM);
    }

    sz = sizeof(struct intern_builder);
    sz += IB_ESBUFSZ_MAX * IB_ELEVELV_MAX;

    ib_cache = kmem_cache_create("ibldr", sz, 0, 0, NULL);
    if (ev(!ib_cache)) {
        kmem_cache_destroy(ib_node_cache);
        ib_node_cache = NULL;
        atomic_dec(&ib_init_ref);
        return merr(ENOMEM);
    }

    return 0;
}

void
ib_fini(void)
{
    if (atomic_dec_return(&ib_init_ref) > 0)
        return;

    kmem_cache_destroy(ib_node_cache);
    ib_node_cache = NULL;
}

static HSE_ALWAYS_INLINE bool
ib_node_free(struct intern_builder *ib, struct intern_node *n)
{
    if (!(n >= ib->nodev && n < ib->nodev + NELEM(ib->nodev))) {
        kmem_cache_free(ib_node_cache, n);
        return true;
    }

    return false;
}

static HSE_ALWAYS_INLINE void
ib_level_free(struct intern_builder *ib, struct intern_level *l)
{
    if (l->sbuf_sz > IB_ESBUFSZ_MAX) {
        *(void **)l->sbuf = ib->sbufs;
        ib->sbufs = l->sbuf;
    }

    if (!(l >= ib->levelv && l < ib->levelv + NELEM(ib->levelv)))
        free(l);
}

/*
 * Compute the current node's lcp length if the key, ko is added.
 */
static int
ib_lcp_len(struct intern_level *ib, const struct key_obj *ko)
{
    struct intern_key *k;
    uint               new_pfxlen, old_pfxlen;

    if (ib->curr_rkeys_cnt == 0)
        return key_obj_len(ko);

    k = (void *)ib->sbuf; /* Point to first key in the scratch space. */
    old_pfxlen = ib->node_lcp_len;
    assert(old_pfxlen <= k->klen);

    if (old_pfxlen < ko->ko_pfx_len)
        return memlcp(k->kdata, ko->ko_pfx, old_pfxlen);

    /* old_pfxlen >= ko->ko_pfx_len */
    new_pfxlen = memlcp(k->kdata, ko->ko_pfx, ko->ko_pfx_len);
    if (new_pfxlen == ko->ko_pfx_len) {
        void *p = k->kdata + new_pfxlen;
        uint  cmplen = old_pfxlen - new_pfxlen;

        assert(old_pfxlen >= new_pfxlen);
        new_pfxlen += memlcp(p, ko->ko_sfx, cmplen);
    }

    return new_pfxlen;
}

static merr_t
ib_sbuf_key_add(struct intern_level *l, uint child_idx, struct key_obj *kobj)
{
    struct intern_key *k;
    uint klen = key_obj_len(kobj);
    uint newsz;

    /* Grow scratch buffer, if necessary.  On entry l->sbuf is almost always
     * pointing to an embedded scratch buffer, it might be NULL if the level
     * object is not an embeedded object, otherwise it will be pointing at a
     * buffer previously allocated in this block.
     */
    newsz = l->sbuf_used + klen + sizeof(*k);

    if (HSE_UNLIKELY(newsz > l->sbuf_sz)) {
        void *sbuf = NULL;

        newsz = roundup(newsz, 4096) * 2;

        if (l->sbuf_sz > IB_ESBUFSZ_MAX)
            sbuf = l->sbuf;

        if (!sbuf && l->ibldr->sbufs) {
            sbuf = l->ibldr->sbufs;
            l->ibldr->sbufs = *(void **)sbuf;
        } else {
            sbuf = realloc(sbuf, newsz);
            if (!sbuf)
                return merr(ENOMEM);
        }

        if (l->sbuf_sz == IB_ESBUFSZ_MAX)
            memcpy(sbuf, l->sbuf, l->sbuf_used);

        l->sbuf_sz = newsz;
        l->sbuf = sbuf;
    }

    l->node_lcp_len = ib_lcp_len(l, kobj);

    k = (void *)(l->sbuf + l->sbuf_used);
    k->child_idx = child_idx;
    key_obj_copy(k->kdata, l->sbuf_sz - l->sbuf_used, &k->klen, kobj);

    l->sbuf_used += sizeof(*k) + roundup(k->klen, alignof(*k));

    return 0;
}

static void
ib_node_publish(struct intern_level *ib, uint last_child)
{
    void *                   cnode;
    struct wbt_node_hdr_omf *node_hdr;

    size_t              lcp_len = ib->node_lcp_len;
    struct wbt_ine_omf *entry; /* (out) current key entry ptr */
    void *              sfxp;  /* (out) current suffix ptr */
    int                 i;
    uint                nkey = ib->curr_rkeys_cnt;

    struct intern_key *k = (void *)ib->sbuf;

    cnode = ib->node_curr->buf;
    node_hdr = cnode;

    omf_set_wbn_magic(node_hdr, WBT_INE_NODE_MAGIC);
    omf_set_wbn_num_keys(node_hdr, nkey);
    omf_set_wbn_kmd(node_hdr, 0);
    omf_set_wbn_pfx_len(node_hdr, lcp_len);

    /* Use the first key to write out the prefix. */
    if (lcp_len) {
        void *pfxp = cnode + sizeof(*node_hdr);

        assert(lcp_len <= k->klen);
        memcpy(pfxp, k->kdata, lcp_len);
    }

    entry = cnode + sizeof(*node_hdr) + lcp_len;
    sfxp = cnode + PAGE_SIZE;

    for (i = 0; i < nkey; i++) {
        u16 sfx_len = k->klen - lcp_len;

        sfxp -= sfx_len;
        memcpy(sfxp, k->kdata + lcp_len, sfx_len);
        omf_set_ine_koff(entry, sfxp - cnode);
        omf_set_ine_left_child(entry, k->child_idx);

        assert((void *)k >= (void *)ib->sbuf);
        assert((void *)k < (void *)(ib->sbuf + ib->sbuf_used));
        assert((void *)entry < sfxp);

        entry++;
        k = (void *)k + sizeof(*k) + roundup(k->klen, alignof(*k));
    }

    /* should have space for this last entry */
    assert((void *)(entry) <= sfxp);

    /* Create rightmost edge entry -- yes, it uses 'ine_left_child' member.
     */
    omf_set_ine_koff(entry, 0);
    omf_set_ine_left_child(entry, last_child);
}

static merr_t
ib_new_node(struct wbb *wbb, struct intern_level *l)
{
    struct intern_builder *ib = l->ibldr;
    struct intern_node *n;

    if (ib->nodec < NELEM(ib->nodev)) {
        n = ib->nodev + ib->nodec;
    } else {
        n = kmem_cache_alloc(ib_node_cache);
        if (!n)
            return merr(ENOMEM);
    }

    n->next = NULL;

    n->buf = wbb_inode_get_page(wbb);
    if (!n->buf) {
        ib_node_free(ib, n);
        return merr(ENOMEM);
    }

    ++ib->nodec;

    if (l->node_curr)
        l->node_curr->next = n;
    else
        l->node_head = n;

    l->node_curr = n;
    l->sbuf_used = 0;

    return 0;
}

struct intern_level *
ib_level_create(struct intern_builder *ib, uint level)
{
    struct intern_level *l;
    merr_t err;

    if (ib->levelc < NELEM(ib->levelv)) {
        l = ib->levelv + ib->levelc;

        memset(l, 0, sizeof(*l));
        l->sbuf = ib->sbufv + IB_ESBUFSZ_MAX * ib->levelc;
        l->sbuf_sz = IB_ESBUFSZ_MAX;
    } else {
        l = calloc(1, sizeof(*l));
        if (!l)
            return NULL;
    }

    l->level = level;
    l->ibldr = ib;

    err = ib_new_node(ib->wbb, l);
    if (err) {
        ib_level_free(ib, l);
        return NULL;
    }

    ++ib->levelc;

    return l;
}

void
ib_level_destroy(struct intern_level *l)
{
    struct intern_builder *ib = l->ibldr;
    struct intern_node *n;

    while (ib->nodec > NELEM(ib->nodev) && (n = l->node_head)) {
        l->node_head = n->next;
        if (ib_node_free(ib, n))
            --ib->nodec;
    }

    ib_level_free(ib, l);
}

struct intern_builder *
ib_create(struct wbb *wbb)
{
    struct intern_builder *ib;

    ib = kmem_cache_alloc(ib_cache);
    if (ib) {
        ib->base = NULL;
        ib->wbb = wbb;
        ib->sbufs = NULL;
        ib->nodec = 0;
        ib->levelc = 0;
    }

    return ib;
}

void
ib_reset(struct intern_builder *ib)
{
    struct intern_level *l;

    if (!ib)
        return;

    while ((l = ib->base)) {
        ib->base = l->parent;
        ib_level_destroy(l);
    }

    ib->nodec  = 0;
    ib->levelc  = 0;
}

void
ib_destroy(struct intern_builder *ib)
{
    u_char *sbuf;

    if (!ib)
        return;

    ib_reset(ib);

    while ((sbuf = ib->sbufs)) {
        ib->sbufs = *(void **)sbuf;
        free(sbuf);
    }

    kmem_cache_free(ib_cache, ib);
}

static merr_t
key_add(
    struct intern_builder *ibldr,
    struct key_obj *       right_edge,
    uint *                 node_cnt,
    bool                   count_only)
{
    struct intern_level *l;
    int                  cnt = 0;
    merr_t               err;
    uint                 right_edge_klen = right_edge ? key_obj_len(right_edge) : 0;

    /* As long as there's just one leaf node, the tree needs exactly one
     * internal node (root). This happens when creating the first leaf node.
     */
    if (!right_edge_klen) {
        *node_cnt = 0;
        return 0;
    }

    if (!ibldr->base) {
        ibldr->base = ib_level_create(ibldr, 0);
        if (ev(!ibldr->base))
            return merr(ENOMEM);
    }

    l = ibldr->base;

    /* On adding a new key from the leaf node to its parent, its ancestors
     * further up might need to be updated too. The following loop does
     * this.
     */
    while (l) {
        uint used;
        uint ine_sz = sizeof(struct wbt_ine_omf);
        uint hdr_sz = sizeof(struct wbt_node_hdr_omf);
        uint lcp_len = ib_lcp_len(l, right_edge); /* new lcp len if key is added */

        /* All internal nodes must have a right edge. Adding one to
         * the level's l->curr_rkeys_cnt accounts for this.
         *
         * used = hdr_sz + lcp_len + tot_klen - lcp_savings + ines
         */
        used = hdr_sz + lcp_len + l->curr_rkeys_sum - (l->curr_rkeys_cnt * lcp_len) +
               ((1 + l->curr_rkeys_cnt) * ine_sz);

        /* Check if this key will prompt a new node at this level */
        if (used + ine_sz + right_edge_klen - lcp_len > PAGE_SIZE) {

            /* Count this key as the right edge of the current node
             * and finish the node.
             * Reset stats for the current node in anticipation of
             * a new node, and bump up the number of 'full' nodes
             * at this level.
             */

            cnt += l->full_node_cnt + 1;
            if (!count_only) {
                ib_node_publish(l, l->curr_child++);
                err = ib_new_node(ibldr->wbb, l);
                if (err)
                    goto err_exit;
                l->curr_rkeys_sum = l->curr_rkeys_cnt = 0;
                l->full_node_cnt++;
                l->node_lcp_len = 0;
            }

            /* The number of nodes at this level has grown beyond 1.
             * This level needs a parent. If one doesn't exist, create it.
             */
            if (!l->parent) {
                cnt += 1;

                if (!count_only) {
                    assert(l->full_node_cnt == 1);
                    l->parent = ib_level_create(ibldr, l->level + 1);
                    if (!l->parent) {
                        err = merr(ENOMEM);
                        goto err_exit;
                    }
                }
            }

        } else {

            /* There is enough space in the current node for this
             * key. Add the key and stop proceeding up the tree.
             */
            if (!count_only) {
                err = ib_sbuf_key_add(l, l->curr_child++, right_edge);
                if (err)
                    goto err_exit;

                l->curr_rkeys_sum += right_edge_klen;
                l->curr_rkeys_cnt++;
            }

            break;
        }

        cnt += 1; /* +1 for active node */

        l = l->parent;
    }

    /* Rest of the list doesn't need any updates. Simply count nodes at
     * each level up to the root.
     */
    while (l) {
        cnt += l->full_node_cnt + 1; /* +1 for active node */

        l = l->parent;
    }

    if (node_cnt)
        *node_cnt = cnt;

    return 0;

err_exit:
    return err;
}

/**
 * ib_key_add() - Update internal nodes with a new key. If the count_only flag
 *                is set, just get the number of internal nodes if the key
 *                were to be added.
 *
 * @ibldr:             intern_builder handle
 * @right_edge:        rightmost key of the finished leaf node.
 * @node_cnt (output): number of internal nodes.
 * @count_only:        only count nodes, do not add key
 */
merr_t
ib_key_add(
    struct intern_builder *ibldr,
    struct key_obj *       right_edge,
    uint *                 node_cnt,
    bool                   count_only)
{
    uint   max_inodec = 0;
    merr_t err;

    err = key_add(ibldr, right_edge, &max_inodec, true);
    if (ev(err))
        return err;

    if (right_edge) {
        if (!wbb_inode_has_space(ibldr->wbb, max_inodec))
            return merr(ENOSPC);

        err = key_add(ibldr, right_edge, NULL, false);
        if (ev(err))
            return err;
    }

    *node_cnt = max_inodec;

    return 0;
}

void
ib_child_update(struct intern_builder *ibldr, uint num_leaves)
{
    struct intern_level *l;
    uint                 prev[2];

    uint dbg_lvl_cnt HSE_MAYBE_UNUSED;
    uint dbg_tot_cnt HSE_MAYBE_UNUSED;

    prev[0] = 0;
    prev[1] = num_leaves;

    dbg_lvl_cnt = dbg_tot_cnt = 0;

    l = ibldr->base;
    while (l) {
        struct intern_node *n = l->node_head;

        /* Close out current node under construction. The last leaf node
         * that was closed did not initiate any internal node creations.
         */
        ib_node_publish(l, prev[1] - 1);

        l->curr_rkeys_sum = l->curr_rkeys_cnt = 0;
        l->full_node_cnt++;

        while (n) {
            struct wbt_node_hdr_omf *node_hdr = (void *)n->buf;
            size_t                   pfxlen;
            struct wbt_ine_omf *     k;
            uint                     nkey, max;
            int                      i;

            pfxlen = omf_wbn_pfx_len(node_hdr);
            nkey = omf_wbn_num_keys(node_hdr);
            k = (void *)n->buf + sizeof(*node_hdr) + pfxlen;

            max = n->next ? nkey + 1 : nkey;
            max = nkey + 1;
            for (i = 0; i < max; i++) {
                uint child = omf_ine_left_child(k);
                omf_set_ine_left_child(k, child + prev[0]);
                k++;
            }
            n = n->next;
            dbg_lvl_cnt++;
            dbg_tot_cnt++;
        }

        dbg_lvl_cnt = 0;
        prev[0] += prev[1];
        prev[1] = l->full_node_cnt;
        l = l->parent;
    }
}

uint
ib_iovec_construct(struct intern_builder *ibldr, struct iovec *iov)
{
    int                  i;
    struct intern_node * n;
    struct intern_level *l = ibldr->base;

    if (!ibldr->base)
        return 0;

    n = l->node_head;
    i = 0;
    while (n) {
        iov[i].iov_base = n->buf;
        iov[i].iov_len = PAGE_SIZE;
        if (n->next) {
            n = n->next;
        } else if (l->parent) {
            l = l->parent;
            n = l->node_head;
        } else {
            n = 0;
        }

        i++;
    }

    return i;
}
