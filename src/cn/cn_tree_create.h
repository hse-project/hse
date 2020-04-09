/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CREATE_H
#define HSE_KVDB_CN_CN_TREE_CREATE_H

#include <hse_util/platform.h>

/* MTF_MOCK_DECL(cn_tree_create) */

struct cn;
struct cn_tree;
struct cn_tstate;
struct cn_kvdb;
struct cndb;
struct kvdb_health;
struct kvs_rparams;
struct kvset;
struct mpool;
struct kvs_cparams;

/**
 * cn_tree_create() - Create a CN_TREE and associate it with
 *                 a KBLOCK and some VBLOCKs.
 * @cn_tree: (output) newly constructed cn_tree object
 * @cn_tstate:   ptr to per-kvs dynamic state object
 * @cn_clags:    create-time flags for the cn tree
 * @cp:          ptr to kvs cparams
 * @health:      reference to kvdb health struct
 * @rp:          ptr to kvs rparams
 */
/* MTF_MOCK */
merr_t
cn_tree_create(
    struct cn_tree **   tree,
    struct cn_tstate *  tstate,
    u32                 cn_cflags,
    struct kvs_cparams *cp,
    struct kvdb_health *health,
    struct kvs_rparams *rp);

/**
 * cn_tree_destroy() - Destroy a CN_TREE object.
 * @cn_tree: cn_tree object to destroy
 *
 * This function invokes kvset_class.destroy on each
 * kvset in the tree.
 */
/* MTF_MOCK */
void
cn_tree_destroy(struct cn_tree *tree);

/**
 * cn_tree_setup() - Initialize cn tree with resources.
 * @tree: tree created with cn_tree_create()
 * @ds:   dataset
 * @cn:   cn handle
 * @rp:   runtime parameters
 * @cndb: cndb handle
 * @cnid: cndb's identifier for this tree
 */
/* MTF_MOCK */
void
cn_tree_setup(
    struct cn_tree *    tree,
    struct mpool *      ds,
    struct cn *         cn,
    struct kvs_rparams *rp,
    struct cndb *       cndb,
    u64                 cnid,
    struct cn_kvdb *    cn_kvdb);

/**
 * cn_tree_set_initial_dgen() - set most current dgen in tree
 * @tree: tree to update
 * @dgen: new dgen
 *
 * This sets dgen in the cn_tree, used to initialize cn_ingest_dgen.
 */
/* MTF_MOCK */
void
cn_tree_set_initial_dgen(struct cn_tree *tree, u64 dgen);

/**
 * cn_tree_insert_kvset() - Add kvset to a tree node during tree initialization
 * @tree:  cn tree structure
 * @kvset: kvset to add
 * @level: node level
 * @offset:  node offset
 *
 * Add @kvset to @tree at give node @level and @offset, creating a new node if
 * necessary.  Insert @kvset into node in correct dgen order.  This function
 * should only be used by cn_open() -- it should not used to add kvsets to
 * nodes after ingest or compaction operations.
 */
/* MTF_MOCK */
merr_t
cn_tree_insert_kvset(struct cn_tree *tree, struct kvset *kvset, uint level, uint offset);

/* MTF_MOCK */
void
cn_tree_samp_init(struct cn_tree *tree);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_tree_create_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
