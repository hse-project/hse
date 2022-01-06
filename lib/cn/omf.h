/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_OMF_H
#define HSE_KVDB_CN_OMF_H

#include <hse_util/omf.h>
#include <hse_ikvdb/omf_version.h>

/*****************************************************************
 *
 * Kblock header OMF
 *
 ****************************************************************/

#define KBLOCK_HDR_MAGIC ((u32)0xfadedfad)

/* This is currently set to 1350 which is the max key size supported. However,
 * with the current header sizes, this can grow up to (3972-7*2)/2 i.e. 1979
 * bytes (to fit min/max keys in the kblock header with 8-byte alignment).
 */
#define HSE_KBLOCK_OMF_KLEN_MAX ((u32)1350)

struct kblock_hdr_omf {

    /* integrity check, version and type */
    uint32_t kbh_magic;
    uint32_t kbh_version;

    /* Hyperloglog data */
    uint32_t kbh_hlog_doff_pg;
    uint32_t kbh_hlog_dlen_pg;

    /* metrics */
    uint32_t kbh_entries;
    uint32_t kbh_tombs;
    uint32_t kbh_key_bytes;
    uint32_t kbh_val_bytes;

    /* easily accessible copies of min and max keys */
    uint32_t kbh_min_koff;
    uint32_t kbh_min_klen;
    uint32_t kbh_max_koff;
    uint32_t kbh_max_klen;

    /* WBT header */
    uint32_t kbh_wbt_hoff;
    uint32_t kbh_wbt_hlen;
    uint32_t kbh_wbt_doff_pg;
    uint32_t kbh_wbt_dlen_pg;

    /* Bloom header and data */
    uint32_t kbh_blm_hoff;
    uint32_t kbh_blm_hlen;
    uint32_t kbh_blm_doff_pg;
    uint32_t kbh_blm_dlen_pg;

    /* ptomb WBT header */
    uint32_t kbh_pt_hoff;
    uint32_t kbh_pt_hlen;
    uint32_t kbh_pt_doff_pg;
    uint32_t kbh_pt_dlen_pg;

    /* min and max seqno */
    uint64_t kbh_min_seqno;
    uint64_t kbh_max_seqno;

} HSE_PACKED;

/* Define set/get methods for kblock_hdr_omf */
OMF_SETGET(struct kblock_hdr_omf, kbh_magic, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_version, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_entries, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_tombs, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_key_bytes, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_val_bytes, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_min_koff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_min_klen, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_max_koff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_max_klen, 32)

OMF_SETGET(struct kblock_hdr_omf, kbh_hlog_doff_pg, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_hlog_dlen_pg, 32)

OMF_SETGET(struct kblock_hdr_omf, kbh_wbt_hoff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_wbt_hlen, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_wbt_doff_pg, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_wbt_dlen_pg, 32)

OMF_SETGET(struct kblock_hdr_omf, kbh_blm_hoff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_blm_hlen, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_blm_doff_pg, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_blm_dlen_pg, 32)

OMF_SETGET(struct kblock_hdr_omf, kbh_pt_hoff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_pt_hlen, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_pt_doff_pg, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_pt_dlen_pg, 32)

OMF_SETGET(struct kblock_hdr_omf, kbh_min_seqno, 64)
OMF_SETGET(struct kblock_hdr_omf, kbh_max_seqno, 64)

/*****************************************************************
 *
 * Bloom filter header OMF (part of the kblock)
 *
 ****************************************************************/

#define BLOOM_OMF_MAGIC ((u32)('b' << 24 | 'l' << 16 | 'm' << 8 | 'h'))

/**
 * struct bloom_hdr_omf -
 * @bh_magic:           BLOOM_OMF_MAGIC
 * @bh_version:         BLOOM_OMF_VERSION
 * @bh_bktsz:           number of bytes per bucket
 * @bh_rotl:            hash rotate left amount
 * @bh_n_hashes:        number of hashes per bucket
 * @bh_bitmapsz:        size of bitmap in bytes
 * @bh_modulus:         modulus used to convert first hash to bucket
 */
struct bloom_hdr_omf {
    uint32_t bh_magic;
    uint32_t bh_version;
    uint32_t bh_bitmapsz;
    uint32_t bh_modulus;
    uint32_t bh_bktshift;
    uint16_t bh_rsvd1;
    uint8_t  bh_rotl;
    uint8_t  bh_n_hashes;
    uint32_t bh_rsvd2;
    uint32_t bh_rsvd3;
} HSE_PACKED;

/* Define set/get methods for bloom_hdr_omf */
OMF_SETGET(struct bloom_hdr_omf, bh_magic, 32)
OMF_SETGET(struct bloom_hdr_omf, bh_version, 32)
OMF_SETGET(struct bloom_hdr_omf, bh_bitmapsz, 32)
OMF_SETGET(struct bloom_hdr_omf, bh_modulus, 32)
OMF_SETGET(struct bloom_hdr_omf, bh_bktshift, 32)
OMF_SETGET(struct bloom_hdr_omf, bh_rotl, 8)
OMF_SETGET(struct bloom_hdr_omf, bh_n_hashes, 8)

/*****************************************************************
 *
 * Wanna B-Tree (WBT) On-Media-Format
 *
 * Supported versions:
 *     v6: Added support for compressed values. Uses a new value type
 *         (vtype_cval) which affects KMD format. Unfortunately,
 *         there is no version field for KMD, so we bump the WBTree
 *         version even though the actual WBTree header, leaf and
 *         internal nodes are no different from OMF v5.
 *
 * Deprecated versions:
 *     v5: Added longest common prefix elimination for keys in WBTree nodes
 *     v4: Added new value, "immediate", for short values
 */
#define WBT_NODE_SIZE 4096 /* must equal system page size */

#define WBT_TREE_MAGIC ((u32)0x4a3a2a1a)

/* WBT header (v6) */
struct wbt_hdr_omf {
    uint32_t wbt_magic;
    uint32_t wbt_version;
    uint16_t wbt_root;     /* index of wbtree root node */
    uint16_t wbt_leaf;     /* index of first wbtree leaf node */
    uint16_t wbt_leaf_cnt; /* number of wbtree leaf nodes */
    uint16_t wbt_kmd_pgc;  /* size of kmd region in pages */
    uint32_t wbt_reserved1;
    uint32_t wbt_reserved2;
} HSE_PACKED;

OMF_SETGET(struct wbt_hdr_omf, wbt_magic, 32)
OMF_SETGET(struct wbt_hdr_omf, wbt_version, 32)
OMF_SETGET(struct wbt_hdr_omf, wbt_root, 16);
OMF_SETGET(struct wbt_hdr_omf, wbt_leaf, 16);
OMF_SETGET(struct wbt_hdr_omf, wbt_leaf_cnt, 16);
OMF_SETGET(struct wbt_hdr_omf, wbt_kmd_pgc, 16);

static inline int
wbt_hdr_version(void *omf)
{
    return omf_wbt_magic(omf) == WBT_TREE_MAGIC ? omf_wbt_version(omf) : -1;
}

#define WBT_LFE_NODE_MAGIC ((u16)0xabc0)
#define WBT_INE_NODE_MAGIC ((u16)0xabc1)

/* WBT node header (v6) */
struct wbt_node_hdr_omf {
    uint16_t wbn_magic;    /* magic number, distinguishes INEs from LFEs */
    uint16_t wbn_num_keys; /* number of keys in node */
    uint32_t wbn_kmd;      /* offset in kmd region to this node's kmd */
    uint16_t wbn_pfx_len;  /* length of the longest common prefix */
    uint16_t wbn_padding;  /* unused padding */
} HSE_PACKED;

OMF_SETGET(struct wbt_node_hdr_omf, wbn_magic, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_num_keys, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_kmd, 32)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_pfx_len, 16)

/* WBT internal node entry (v6) */
struct wbt_ine_omf {
    uint16_t ine_koff;       /* byte offset from start of node to key */
    uint16_t ine_left_child; /* node number of left child */
} HSE_PACKED;

OMF_SETGET(struct wbt_ine_omf, ine_koff, 16)
OMF_SETGET(struct wbt_ine_omf, ine_left_child, 16)

/* WBT leaf node entry (v6)
 * Note, if lfe_kmd == U16_MAX, then the actual kmd offset is stored as a LE32
 * value at lfe_koff, and the actual key is stored at lfe_koff + 4.
 */
struct wbt_lfe_omf {
    uint16_t lfe_koff;
    uint16_t lfe_kmd;
} HSE_PACKED;

OMF_SETGET(struct wbt_lfe_omf, lfe_koff, 16)
OMF_SETGET(struct wbt_lfe_omf, lfe_kmd, 16)

/* GCOV_EXCL_STOP */

/*****************************************************************
 *
 * Vblock header OMF
 *
 ****************************************************************/

#define VBLOCK_HDR_MAGIC ((u32)0xea73feed)

/* Version 2 header */
struct vblock_hdr_omf {
    uint32_t vbh_magic;
    uint32_t vbh_version;
    uint64_t vbh_vgroup;
} HSE_PACKED;

OMF_SETGET(struct vblock_hdr_omf, vbh_magic, 32)
OMF_SETGET(struct vblock_hdr_omf, vbh_version, 32)
OMF_SETGET(struct vblock_hdr_omf, vbh_vgroup, 64)

/* cn dynamic state
 */
#define CN_TSTATE_MAGIC (u32)('c' << 24 | 't' << 16 | 's' << 8 | 'm')
#define CN_TSTATE_KHM_SZ (1024)

struct cn_tstate_omf {
    uint32_t ts_magic;
    uint32_t ts_version;

    uint64_t ts_rsvd[14];

    uint32_t ts_khm_gen;
    uint32_t ts_khm_rsvd;
    uint8_t  ts_khm_mapv[CN_TSTATE_KHM_SZ];
} HSE_PACKED;

OMF_SETGET(struct cn_tstate_omf, ts_magic, 32)
OMF_SETGET(struct cn_tstate_omf, ts_version, 32)

OMF_SETGET(struct cn_tstate_omf, ts_khm_gen, 32)
OMF_SETGET_CHBUF(struct cn_tstate_omf, ts_khm_mapv);

#endif
