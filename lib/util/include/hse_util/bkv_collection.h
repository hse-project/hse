/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_BKVCOL_H
#define HSE_CORE_BKVCOL_H

#include <hse_util/bonsai_tree.h>

struct bkv_collection;

typedef merr_t
bkv_collection_cb(void *rock, struct bonsai_kv *bkv, struct bonsai_val *vlist);

void *
bkv_collection_rock_get(struct bkv_collection *bkvc);

merr_t
bkv_collection_create(struct bkv_collection **collection, size_t cnt, bkv_collection_cb *cb, void *cbarg);

void
bkv_collection_destroy(struct bkv_collection *bkvc);

size_t
bkv_collection_count(struct bkv_collection *bkvc);

merr_t
bkv_collection_add(struct bkv_collection *bkvc, struct bonsai_kv *bkv, struct bonsai_val *val_list);

merr_t
bkv_collection_finish(struct bkv_collection *bkvc);

merr_t
bkv_collection_init(void);

void
bkv_collection_fini(void);

#endif
