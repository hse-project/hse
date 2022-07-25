/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CREATE_H
#define HSE_KVDB_CN_CN_TREE_CREATE_H

#include <stdint.h>

#include <hse/util/platform.h>

struct cn;
struct cn_tree;
struct cn_kvdb;
struct cndb;
struct kvdb_health;
struct kvs_rparams;
struct kvset;
struct mpool;
struct kvs_cparams;
struct cn_tree_node;

/**
 * cn_tree_create() - Create a CN_TREE and associate it with
 *                 a KBLOCK and some VBLOCKs.
 * @cn_tree: (output) newly constructed cn_tree object
 * @cn_clags:    create-time flags for the cn tree
 * @cp:          ptr to kvs cparams
 * @health:      reference to kvdb health struct
 * @rp:          ptr to kvs rparams
 */
merr_t
cn_tree_create(
    struct cn_tree **tree,
    uint32_t cn_cflags,
    struct kvs_cparams *cp,
    struct kvdb_health *health,
    struct kvs_rparams *rp) HSE_MOCK;

/**
 * cn_tree_destroy() - Destroy a CN_TREE object.
 * @cn_tree: cn_tree object to destroy
 *
 * This function invokes kvset_class.destroy on each
 * kvset in the tree.
 */
void
cn_tree_destroy(struct cn_tree *tree) HSE_MOCK;

/**
 * cn_tree_setup() - Initialize cn tree with resources.
 * @tree: tree created with cn_tree_create()
 * @mp:   mpool
 * @cn:   cn handle
 * @rp:   runtime parameters
 * @cndb: cndb handle
 * @cnid: cndb's identifier for this tree
 */
void
cn_tree_setup(
    struct cn_tree *tree,
    struct mpool *mp,
    struct cn *cn,
    struct kvs_rparams *rp,
    struct cndb *cndb,
    uint64_t cnid,
    struct cn_kvdb *cn_kvdb) HSE_MOCK;

/**
 * cn_tree_insert_kvset() - Add kvset to a tree node during tree initialization
 * @tree:   cn tree structure
 * @kvset:  kvset to add
 * @nodeid: node ID
 *
 * Add @kvset to @tree into given node ID, creating a new node if necessary.
 * Insert @kvset into node in correct dgen order.  This function
 * should only be used by cn_open() -- it should not used to add kvsets to
 * nodes after ingest or compaction operations.
 */
merr_t
cn_tree_insert_kvset(struct cn_tree *tree, struct kvset *kvset, uint64_t nodeid) HSE_MOCK;

merr_t
cn_node_insert_kvset(struct cn_tree_node *node, struct kvset *kvset);

struct cn_tree_node *
cn_node_alloc(struct cn_tree *tree, uint64_t nodeid);

void
cn_tree_samp_init(struct cn_tree *tree) HSE_MOCK;

#if HSE_MOCKING
#include "cn_tree_create_ut.h"
#endif /* HSE_MOCKING */

#endif
