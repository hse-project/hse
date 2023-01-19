/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef SUPPORT_REF_TREE_H
#define SUPPORT_REF_TREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct ref_tree;
struct ref_tree_iter;

struct ref_tree *
ref_tree_create(void);

void
ref_tree_destroy(struct ref_tree *rt);

bool
ref_tree_insert(struct ref_tree *rt, char *key, size_t klen, uint64_t seqno);

bool
ref_tree_get(struct ref_tree *rt, char *key, size_t klen);

struct ref_tree_iter *
ref_tree_iter_create(
    struct ref_tree *rt,
    char *pfx,
    size_t pfxlen,
    bool reverse,
    uint64_t view_seq);

void
ref_tree_iter_seek(struct ref_tree_iter *rt_iter, char *key, size_t klen, bool *eof);

bool
ref_tree_iter_read(struct ref_tree_iter *rt_iter, char **key, size_t *klen);

void
ref_tree_iter_destroy(struct ref_tree_iter *rt_iter);

#endif
