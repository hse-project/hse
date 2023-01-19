/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MOCKS_MOCK_KVSET_H
#define MOCKS_MOCK_KVSET_H

#include <stdint.h>

#include <cn/cn_metrics.h>
#include <cn/kv_iterator.h>
#include <cn/kvset.h>

#include <hse/util/page.h>

/**
 * struct mock_kvset - test harness
 * @tripwire:   deliberately inaccessible pages, must be first field
 * @len:        size of mock_kvset
 * @mk_entry:   mock_kvset list linkage
 * @iter_data: kvdata from mock_make_kvi, passed as ds in kvset_open() (opt)
 * @nk:    number of kblk / vblk ids
 * @nv:
 * @dgen:  increments from 1 each call (first call is oldest kvset)
 * @ids[]: initd by mock_make_kvi
 */
struct mock_kvset {
    char tripwire[PAGE_SIZE * 7];
    struct kvset_list_entry entry;
    struct kvset_stats stats;
    size_t alloc_sz;
    void *iter_data;
    int start;
    int ref;
    uint64_t dgen_hi;
    uint64_t dgen_lo;
    uint64_t kvsetid;
    uint64_t nodeid;
    const void *work;
    uint32_t compc;
    uint64_t ids[];
};

enum val_mix { VMX_S32 = 1, VMX_BUF = 2, VMX_MIXED = 3 };

/*
 * struct nkv_tab - number of keys/values to generate
 */
struct nkv_tab {
    int nkeys;
    int key1;
    int val1;
    enum val_mix vmix;
    int be;
    uint64_t dgen;
};

/* Values for 'int be` member of struct nkv_tab */
#define KVDATA_BE_KEY  true
#define KVDATA_INT_KEY false

/*
 * We cannot use the real kv_iterator, it is private in a .c file.
 * kv_iterator MUST be the first element in this struct.
 * This iterator traverses an array per kvset.
 */

struct mock_kv_iterator {
    struct kv_iterator kvi;
    char tripwire[1024]; /* not an mprotect enforced tripwire */
    struct mock_kvset *kvset;
    int src;
    int nextkey;
};

void
mock_kvset_set(void);
void
mock_kvset_unset(void);

void *
mock_vref_to_vdata(struct kv_iterator *kvi, uint vboff);

/*
 * These mock apis exist to faciliate test data creation.
 */
struct kvset_meta;

merr_t
mock_make_kvi(struct kv_iterator **kvi, int src, struct kvs_rparams *rp, struct nkv_tab *nkv);

merr_t
mock_make_vblocks(struct kv_iterator **kvi, struct kvs_rparams *rp, int nv);

#endif
