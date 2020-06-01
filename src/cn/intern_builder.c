/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/key_util.h>

#include "omf.h"
#include "intern_builder.h"
#include "wbt_builder.h"

static struct kmem_cache *ib_node_cache;
static atomic_t           ib_init_ref;

merr_t
ib_init(void)
{
    struct kmem_cache *zone;

    if (atomic_inc_return(&ib_init_ref) > 1)
        return 0;

    zone = kmem_cache_create("ibldr", sizeof(struct intern_node), PAGE_SIZE, 0, NULL);
    if (ev(!zone)) {
        atomic_dec(&ib_init_ref);
        return merr(ENOMEM);
    }

    ib_node_cache = zone;

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

#define SCRATCH_BUFSZ (1 << 20)

static merr_t
ib_sbuf_key_add(struct intern_level *ib, uint child_idx, struct key_obj *kobj)
{
    uint               klen = key_obj_len(kobj);
    struct intern_key *k;

    if (!ib->sbuf) {
        ib->sbuf_sz = SCRATCH_BUFSZ;
        ib->sbuf = malloc(ib->sbuf_sz * sizeof(*ib->sbuf));
        if (!ib->sbuf)
            return merr(ENOMEM);
    }

    /* Grow scratch space if necessary */
    if (ib->sbuf_used + klen + sizeof(*k) > ib->sbuf_sz) {
        ib->sbuf_sz += SCRATCH_BUFSZ;
        ib->sbuf = realloc(ib->sbuf, ib->sbuf_sz * sizeof(*ib->sbuf));
        if (!ib->sbuf)
            return merr(ENOMEM);
    }

    ib->node_lcp_len = ib_lcp_len(ib, kobj);

    k = (void *)(ib->sbuf + ib->sbuf_used);
    k->child_idx = child_idx;
    key_obj_copy(k->kdata, ib->sbuf_sz - ib->sbuf_used, &k->klen, kobj);

    ib->sbuf_used += k->klen + sizeof(*k);

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
        k = (void *)k + sizeof(*k) + k->klen;
    }

    /* should have space for this last entry */
    assert((void *)(entry) <= sfxp);

    /* Create rightmost edge entry -- yes, it uses 'ine_left_child' member.
     */
    omf_set_ine_koff(entry, 0);
    omf_set_ine_left_child(entry, last_child);
}

static merr_t
ib_new_node(struct wbb *wbb, struct intern_level *ib)
{
    struct intern_node *n;

    n = kmem_cache_alloc(ib_node_cache, GFP_KERNEL);
    if (!n)
        return merr(ENOMEM);

    n->buf = wbb_inode_get_page(wbb);
    if (!n->buf) {
        kmem_cache_free(ib_node_cache, n);
        return merr(ENOMEM);
    }

    n->next = 0;
    ib->sbuf_used = 0;

    if (ib->node_curr)
        ib->node_curr->next = n;
    else
        ib->node_head = n;

    ib->node_curr = n;

    return 0;
}

struct intern_level *
ib_level_create(struct intern_builder *ibldr, uint level)
{
    struct intern_level *l;
    merr_t               err;

    l = calloc(1, sizeof(*l));
    if (ev(!l))
        return 0;

    err = ib_new_node(ibldr->wbb, l);
    if (err) {
        free(l);
        return 0;
    }

    l->level = level;

    return l;
}

void
ib_level_destroy(struct intern_level *l)
{
    struct intern_node *n = l->node_head;

    while (n) {
        struct intern_node *curr = n;

        n = n->next;
        kmem_cache_free(ib_node_cache, curr);
    }

    free(l->sbuf);
    free(l);
}

struct intern_builder *
ib_create(struct wbb *wbb)
{
    struct intern_builder *ib;

    ib = malloc(sizeof(*ib));
    if (!ib)
        return NULL;

    ib->base = NULL;
    ib->wbb = wbb;

    return ib;
}

void
ib_destroy(struct intern_builder *ibldr)
{
    struct intern_level *l;

    if (!ibldr)
        return;

    l = ibldr->base;
    while (l) {
        struct intern_level *parent = l->parent;

        ib_level_destroy(l);
        l = parent;
    }

    free(ibldr);
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
    uint   max_inodec;
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

    uint dbg_lvl_cnt __maybe_unused;
    uint dbg_tot_cnt __maybe_unused;

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
