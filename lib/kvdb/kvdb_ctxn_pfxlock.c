/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 *
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>

#include <rbtree/rbtree.h>

#include "kvdb_ctxn_pfxlock.h"

struct kvdb_ctxn_pfxlock_entry {
    struct rb_node ktpe_node;
    u64            ktpe_hash : 63;
    u64            ktpe_excl : 1;
    void *         ktpe_cookie;
};

struct kvdb_ctxn_pfxlock {
    struct rb_root       ktp_tree;
    struct kvdb_pfxlock *ktp_pfxlock;
    u64                  ktp_view_seqno;
};

static struct kmem_cache *ctxn_pfxlock_cache;
static struct kmem_cache *ctxn_pfxlock_entry_cache;

merr_t
kvdb_ctxn_pfxlock_create(
    struct kvdb_pfxlock *      pfxlock,
    u64                        view_seqno,
    struct kvdb_ctxn_pfxlock **ktp_out)
{
    struct kvdb_ctxn_pfxlock *ktp;

    ktp = kmem_cache_alloc(ctxn_pfxlock_cache);
    if (ev(!ktp))
        return merr(ENOMEM);

    ktp->ktp_pfxlock = pfxlock;
    ktp->ktp_tree = RB_ROOT;
    ktp->ktp_view_seqno = view_seqno;

    *ktp_out = ktp;
    return 0;
}

void
kvdb_ctxn_pfxlock_destroy(struct kvdb_ctxn_pfxlock *ktp)
{
    struct kvdb_ctxn_pfxlock_entry *entry, *next;

    rbtree_postorder_for_each_entry_safe(entry, next, &ktp->ktp_tree, ktpe_node) {
        kmem_cache_free(ctxn_pfxlock_entry_cache, entry);
    }

    kmem_cache_free(ctxn_pfxlock_cache, ktp);
}

static struct rb_node **
kvdb_ctxn_pfxlock_lookup(
    struct kvdb_ctxn_pfxlock        *ktp,
    u64                              hash,
    struct rb_node                 **parent_out,
    struct kvdb_ctxn_pfxlock_entry **entry_out)
{
    struct rb_node **               link = &ktp->ktp_tree.rb_node;
    struct rb_node                 *parent = NULL;
    struct kvdb_ctxn_pfxlock_entry *entry = NULL;

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), ktpe_node);

        if (HSE_UNLIKELY(hash == entry->ktpe_hash))
            break;

        link = (hash < entry->ktpe_hash) ? &parent->rb_left : &parent->rb_right;
    }

    *parent_out = parent;
    *entry_out = entry;
    return link;
}

merr_t
kvdb_ctxn_pfxlock_shared(struct kvdb_ctxn_pfxlock *ktp, u64 hash)
{
    struct rb_node **               link, *parent;
    struct kvdb_ctxn_pfxlock_entry *entry;
    merr_t                          err;
    void *                          cookie;
    u64                             ctxn_hash;

    ctxn_hash = hash >> 1;

    link = kvdb_ctxn_pfxlock_lookup(ktp, ctxn_hash, &parent, &entry);
    if (*link)
        return 0;

    cookie = NULL;
    err = kvdb_pfxlock_shared(ktp->ktp_pfxlock, hash, ktp->ktp_view_seqno, &cookie);
    if (err)
        return err;

    entry = kmem_cache_alloc(ctxn_pfxlock_entry_cache);
    if (ev(!entry))
        return merr(ENOMEM);

    entry->ktpe_hash = ctxn_hash;
    entry->ktpe_cookie = cookie;
    entry->ktpe_excl = 0;

    rb_link_node(&entry->ktpe_node, parent, link);
    rb_insert_color(&entry->ktpe_node, &ktp->ktp_tree);

    return 0;
}

merr_t
kvdb_ctxn_pfxlock_excl(struct kvdb_ctxn_pfxlock *ktp, u64 hash)
{
    struct rb_node **               link, *parent;
    struct kvdb_ctxn_pfxlock_entry *entry;
    merr_t                          err;
    void *                          cookie;
    bool                            insert;
    u64                             ctxn_hash;

    ctxn_hash = hash >> 1;

    link = kvdb_ctxn_pfxlock_lookup(ktp, ctxn_hash, &parent, &entry);
    if (*link && entry->ktpe_excl)
        return 0; /* Nothing to do, we already own an exclusive lock */

    cookie = *link ? entry->ktpe_cookie : NULL;
    err = kvdb_pfxlock_excl(ktp->ktp_pfxlock, hash, ktp->ktp_view_seqno, &cookie);
    if (err)
        return err;

    insert = *link ? false : true;
    if (insert) {
        entry = kmem_cache_alloc(ctxn_pfxlock_entry_cache);
        if (ev(!entry))
            return merr(ENOMEM);
    }

    entry->ktpe_hash = ctxn_hash;
    entry->ktpe_cookie = cookie;
    entry->ktpe_excl = 1;

    if (insert) {
        rb_link_node(&entry->ktpe_node, parent, link);
        rb_insert_color(&entry->ktpe_node, &ktp->ktp_tree);
    }

    return 0;
}

void
kvdb_ctxn_pfxlock_seqno_pub(struct kvdb_ctxn_pfxlock *ktp, u64 end_seqno)
{
    struct rb_node *node, *next;

    for (node = rb_first(&ktp->ktp_tree); node; node = next) {
        struct kvdb_ctxn_pfxlock_entry *entry = rb_entry(node, typeof(*entry), ktpe_node);

        next = rb_next(node);
        kvdb_pfxlock_seqno_pub(ktp->ktp_pfxlock, end_seqno, entry->ktpe_cookie);
    }
}

HSE_COLD merr_t
kvdb_ctxn_pfxlock_init(void)
{
    if (ctxn_pfxlock_cache && ctxn_pfxlock_entry_cache)
        return 0;

    ctxn_pfxlock_cache = kmem_cache_create("ctxn_pfxlock",
                                           sizeof(struct kvdb_ctxn_pfxlock),
                                           2 * SMP_CACHE_BYTES, 0, NULL);

    ctxn_pfxlock_entry_cache = kmem_cache_create("ctxn_pfxlock_entry",
                                                 sizeof(struct kvdb_ctxn_pfxlock_entry),
                                                 2 * SMP_CACHE_BYTES, 0, NULL);

    if (!ctxn_pfxlock_cache || !ctxn_pfxlock_entry_cache) {
        kvdb_ctxn_pfxlock_fini();
        return merr(ENOMEM);
    }

    return 0;
}

HSE_COLD void
kvdb_ctxn_pfxlock_fini(void)
{
    kmem_cache_destroy(ctxn_pfxlock_entry_cache);
    ctxn_pfxlock_entry_cache = NULL;

    kmem_cache_destroy(ctxn_pfxlock_cache);
    ctxn_pfxlock_cache = NULL;
}
