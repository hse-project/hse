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
int
ib_lcp_len(struct intern_builder *ib, const struct key_obj *ko)
{
    struct intern_key     *k;
    uint                   new_pfxlen, old_pfxlen;

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
ib_sbuf_key_add(struct intern_builder *ib, uint child_idx, struct key_obj *kobj)
{
    uint klen = key_obj_len(kobj);
    struct intern_key *k;

    if (!ib->sbuf) {
        ib->sbuf_sz = SCRATCH_BUFSZ;
        ib->sbuf = malloc(ib->sbuf_sz * sizeof(*ib->sbuf));
        if (!ib->sbuf)
            return merr(ENOMEM);
    }

    /* Grow scratch space if necessary */
    if (ib->sbuf_used + klen  + sizeof(*k) > ib->sbuf_sz) {
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
ib_node_publish(struct intern_builder *ib, uint last_child)
{
    void *cnode = ib->node_curr->buf;
    struct wbt_node_hdr_omf *node_hdr = (void *)ib->node_curr->buf;

    size_t              lcp_len = ib->node_lcp_len;
    struct wbt_ine_omf *entry; /* (out) current key entry ptr */
    void *              sfxp;  /* (out) current suffix ptr */
    int                 i;
    uint                nkey = ib->curr_rkeys_cnt;

    struct intern_key *k = (void *)ib->sbuf;

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
ib_new_node(struct intern_builder *ib)
{
    struct intern_node *n;

    n = kmem_cache_alloc(ib_node_cache, GFP_KERNEL);
    if (!n)
        return merr(ENOMEM);

    n->next = 0;
    ib->sbuf_used = 0;

    if (ib->node_curr)
        ib->node_curr->next = n;
    else
        ib->node_head = n;

    ib->node_curr = n;

    return 0;
}

static struct intern_builder *
ib_create(uint level)
{
    struct intern_builder *b;
    merr_t err;

    b = calloc(1, sizeof(*b));
    if (ev(!b))
        return 0;

    err = ib_new_node(b);
    if (err) {
        free(b);
        return 0;
    }

    b->node_curr->next = 0;
    b->level = level;

    return b;
}

/**
 * ib_key_add() - Update internal nodes with a new key. If the count_only flag
 *                is set, just get the number of internal nodes if the key
 *                were to be added.
 *
 * @wbb:               wbt builder handle
 * @right_edge:        rightmost key of the finished leaf node.
 * @node_cnt (output): number of internal nodes.
 * @count_only:        only count nodes, do not add key
 */
merr_t
ib_key_add(struct wbb *wbb, struct key_obj *right_edge, uint *node_cnt, bool count_only)
{
    struct intern_builder     *ibldr;
    int                        cnt = 0;
    merr_t                     err;
    uint                       right_edge_klen = right_edge ? key_obj_len(right_edge) : 0;

    if (!wbb_ibldr_get(wbb)) {
        ibldr = ib_create(0);
        if (!ibldr)
            return merr(ENOMEM);

        wbb_ibldr_set(wbb, ibldr);
    }

    /* As long as there's just one leaf node, the tree needs exactly one
     * internal node (root). This happens when creating the first leaf node.
     */
    if (!right_edge_klen) {
        *node_cnt = 1;
        return 0;
    }

    ibldr = wbb_ibldr_get(wbb);

    /* On adding a new key from the leaf node to its parent, its ancestors
     * further up might need to be updated too. The following loop does
     * this.
     */
    while (ibldr) {
        uint used;
        uint ine_sz = sizeof(struct wbt_ine_omf);
        uint hdr_sz = sizeof(struct wbt_node_hdr_omf);
        uint lcp_len = ib_lcp_len(ibldr, right_edge); /* new lcp len if key is added */

        /* All internal nodes must have a right edge. Adding one to
         * the level's ibldr->curr_rkeys_cnt accounts for this.
         *
         * used = hdr_sz + lcp_len + tot_klen - lcp_savings + ines
         */
        used = hdr_sz + lcp_len + ibldr->curr_rkeys_sum -
                (ibldr->curr_rkeys_cnt * lcp_len) +
                ((1 + ibldr->curr_rkeys_cnt) * ine_sz);

        /* Check if this key will prompt a new node at this level */
        if (used + ine_sz + right_edge_klen - lcp_len > PAGE_SIZE) {

            /* Count this key as the right edge of the current node
             * and finish the node.
             * Reset stats for the current node in anticipation of
             * a new node, and bump up the number of 'full' nodes
             * at this level.
             */

            cnt += ibldr->full_node_cnt + 1;
            if (!count_only) {
                ib_node_publish(ibldr, ibldr->curr_child++);
                err = ib_new_node(ibldr);
                if (err)
                    goto err_exit;
                ibldr->curr_rkeys_sum = ibldr->curr_rkeys_cnt = 0;
                ibldr->full_node_cnt++;
                ibldr->node_lcp_len = 0;
            }

            /* The number of nodes at this level has grown beyond 1.
             * This level needs a parent. If one doesn't exist, create it.
             */
            if (!ibldr->parent) {
                cnt += 1;

                if (!count_only) {
                    assert(ibldr->full_node_cnt == 1);
                    ibldr->parent = ib_create(ibldr->level + 1);
                    if (!ibldr->parent) {
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
                err = ib_sbuf_key_add(ibldr, ibldr->curr_child++, right_edge);
                if (err)
                    goto err_exit;

                ibldr->curr_rkeys_sum += right_edge_klen;
                ibldr->curr_rkeys_cnt++;
            }

            break;
        }

        cnt += 1; /* +1 for active node */

        ibldr = ibldr->parent;
    }

    /* Rest of the list doesn't need any updates. Simply count nodes at
     * each level up to the root.
     */
    while (ibldr) {
        cnt += ibldr->full_node_cnt + 1; /* +1 for active node */

        ibldr = ibldr->parent;
    }

    if (node_cnt)
        *node_cnt = cnt;

    return 0;

err_exit:
    ibldr = wbb_ibldr_get(wbb);

    ib_free(ibldr);
    wbb_ibldr_set(wbb, 0);

    return err;
}

void
ib_free(struct intern_builder *ibldr)
{
    while (ibldr) {
        struct intern_builder *parent = ibldr->parent;
        struct intern_node *n;

        n = ibldr->node_head;
        while (n) {
            struct intern_node *curr = n;

            n = n->next;
            kmem_cache_free(ib_node_cache, curr);
        }

        free(ibldr->sbuf);
        free(ibldr);

        ibldr = parent;
    }
}

void
ib_child_update(struct intern_builder *ibldr, uint num_leaves)
{
    uint prev[2];

    uint dbg_lvl_cnt __maybe_unused;
    uint dbg_tot_cnt __maybe_unused;

    prev[0] = 0;
    prev[1] = num_leaves;

    dbg_lvl_cnt = dbg_tot_cnt = 0;

    while (ibldr) {
        struct intern_node *n = ibldr->node_head;

        /* Close out current node under construction. The last leaf node
         * that was closed did not initiate any internal node creations.
         */
        ib_node_publish(ibldr, prev[1] - 1);

        ibldr->curr_rkeys_sum = ibldr->curr_rkeys_cnt = 0;
        ibldr->full_node_cnt++;

        while (n) {
            struct wbt_node_hdr_omf *node_hdr = (void *)n->buf;
            size_t pfxlen;
            struct wbt_ine_omf  *k;
            uint   nkey, max;
            int i;

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
        prev[1] = ibldr->full_node_cnt;
        ibldr = ibldr->parent;
    }
}

static struct intern_node *
ib_flatten(struct intern_builder *ibldr)
{
    struct intern_builder *ib = ibldr;
    struct intern_node *k = 0;

    if (!ib)
        return 0;

    while (ib) {
        struct intern_node *n = ib->node_head;

        if (k)
            k->fnext = n;

        while (n) {
            k = n;
            n->fnext = n->next;
            n = n->next;
        }

        ib = ib->parent;
    }

    if (k)
        k->fnext = 0;

    return ibldr->node_head;
}

merr_t
ib_flat_verify(
    struct intern_builder *ibldr)
{
    struct intern_node *n = ib_flatten(ibldr);
    uint last_child = -1;

    while (n) {
        struct wbt_node_hdr_omf *hdr = (void *)n->buf;
        uint nkey = omf_wbn_num_keys(hdr);
        struct wbt_ine_omf *entry;
        int i;

        entry = (void *)(n->buf + sizeof(*hdr) + omf_wbn_pfx_len(hdr));
        for (i = 0; i <= nkey; i++, entry++) {
            uint child = omf_ine_left_child(entry);
            assert(child == last_child + 1);
            last_child = child;
            if (child != last_child + 1)
                return merr(EBUG);
        }

        n = n->fnext;
    }

    return 0;
}

