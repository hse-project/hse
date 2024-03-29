/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_INTERN_BUILDER_H
#define HSE_KVS_INTERN_BUILDER_H

#include <stdbool.h>

#include <sys/types.h>

#include <hse/error/merr.h>

struct intern_builder;
struct iovec;
struct key_obj;
struct wbb;

merr_t
ib_key_add(struct intern_builder *ib, struct key_obj *right_edge, uint *node_cnt, bool count_only);

struct intern_builder *
ib_create(struct wbb *wbb);

void
ib_reset(struct intern_builder *ibldr);

void
ib_destroy(struct intern_builder *ibldr);

void
ib_child_update(struct intern_builder *ibldr, uint num_leaves);

uint
ib_iovec_construct(struct intern_builder *ibldr, struct iovec *iov);

merr_t
ib_init(void) HSE_COLD;

void
ib_fini(void) HSE_COLD;

#endif /* HSE_KVS_INTERN_BUILDER_H */
