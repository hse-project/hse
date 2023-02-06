/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_CN_WBT_BUILDER_H
#define HSE_KVS_CN_WBT_BUILDER_H

/* MTF_MOCK_DECL(wbt_builder) */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <hse/error/merr.h>

struct iovec;
struct key_obj;
struct wbb;
struct wbt_hdr_omf;
struct wbt_desc;

/* Create a wbtree builder
 *
 * Parameters:
 * - wbb_out: (output) builder handle
 * - max_pgc: (in) max allowable size of wbtree in pages
 * - wbt_pgc: (in/out) actual size (in pages) of wbtree creation
 */
/* MTF_MOCK */
merr_t
wbb_create(struct wbb **wbb_out, uint max_pgc, uint *wbt_pgc);

/* Reset a wbtree builder so it can be reused for a new wbtree
 */
/* MTF_MOCK */
void
wbb_reset(struct wbb *wbb, uint *wbt_pgc);

/* Destroy a wbtree builder
 */
/* MTF_MOCK */
void
wbb_destroy(struct wbb *wbb);

/* Get the number of keys stored in a wbtree under construction.
 */
uint
wbb_entries(const struct wbb *wbb);

/* Get the current "kvlen" of a finalized wbtree.
 */
uint64_t
wbb_kvlen(const struct wbb *wbb);

/* Add a key and its metadata to a wbtree.
 *
 * Parameters:
 * - wbb: builder handle
 * - kobj: key to add
 * - kmd: buffer containing omf-encoded key metadata
 * - kmd_len: length of omf-encoded key metadata
 * - kmd_entries: number of key metadata entries
 * - vblk_om_vlen: on-media length of vblock values referenced by key
 * - max_pgc: max allowable size of wbtree in pages
 * - wbt_pgc: (in/out) current size of wbtree in pages
 * - added: (out) set to true if entry was added
 *
 * Return:
 * - (rc == 0 && added == true)  ==> success
 * - (rc == 0 && added == false) ==> not enough space for new entry
 * - (rc != 0)                   ==> error
 */
/* MTF_MOCK */
merr_t
wbb_add_entry(
    struct wbb *          wbb,
    const struct key_obj *kobj,
    uint                  kmd_entries,
    uint64_t              vblk_om_vlen,
    const void *          key_kmd,
    uint                  key_kmd_len,
    uint                  max_pgc,
    uint *                wbt_pgc,
    bool *                added);

void
wbb_hdr_init(struct wbt_hdr_omf *hdr);

void
wbb_hdr_set(struct wbt_hdr_omf *hdr, struct wbt_desc *desc);

/**
 * wbb_freeze() - finalize a wbtree
 */
/* MTF_MOCK */
merr_t
wbb_freeze(
    struct wbb *        wbb,
    struct wbt_hdr_omf *hdr,
    uint                max_pgc,
    uint *              wbt_pgc,
    struct iovec *      iov,
    uint                iov_max,
    uint *              iov_cnt);

/**
 * wbb_min_max_keys() - get min/max keys from a finalized or non-finalized wbtree
 */
/* MTF_MOCK */
void
wbb_min_max_keys(struct wbb *wbb, struct key_obj *first_kobj, struct key_obj *last_kobj);

/**
 * wbb_page_cnt() - Get total number of pages consumed by wbtree and the
 *                  associated kmd region.
 * @wbb: wbtree builder
 */
/* MTF_MOCK */
uint
wbb_page_cnt_get(struct wbb *wbb);

uint
wbb_max_inodec_get(struct wbb *wbb);

uint
wbb_kmd_pgc_get(struct wbb *wbb);

struct intern_builder *
wbb_ibldr_get(struct wbb *wbb);

struct intern_builder *
wbb_ibldr_get(struct wbb *wbb);

void
wbb_ibldr_set(struct wbb *wbb, struct intern_builder *ibldr);

void *
wbb_inode_get_page(struct wbb *wbb);

bool
wbb_inode_has_space(struct wbb *wbb, uint inode_cnt);

#if HSE_MOCKING
#include "wbt_builder_ut.h"
#endif /* HSE_MOCKING */

#endif
