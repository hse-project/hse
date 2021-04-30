/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_OMF_H
#define HSE_KVDB_CN_OMF_H

#include <hse_util/omf.h>
#include <hse_util/inttypes.h>

/*****************************************************************
 *
 * Kblock header OMF
 *
 ****************************************************************/

#define KBLOCK_HDR_VERSION ((u32)5)
#define KBLOCK_HDR_MAGIC ((u32)0xfadedfad)

/* This is currently set to 1350 which is the max key size supported. However,
 * with the current header sizes, this can grow up to (3972-7*2)/2 i.e. 1979
 * bytes (to fit min/max keys in the kblock header with 8-byte alignment).
 */
#define HSE_KBLOCK_OMF_KLEN_MAX ((u32)1350)

/* older versions that are still supported */
#define KBLOCK_HDR_VERSION4 ((u32)4)
#define KBLOCK_HDR_VERSION3 ((u32)3)
#define KBLOCK_HDR_VERSION2 ((u32)2)

struct kblock_hdr_omf {

    /* integrity check, version and type */
    __le32 kbh_magic;
    __le32 kbh_version;

    /* Hyperloglog data */
    __le32 kbh_hlog_doff_pg;
    __le32 kbh_hlog_dlen_pg;

    /* metrics */
    __le32 kbh_entries;
    __le32 kbh_tombs;
    __le32 kbh_key_bytes;
    __le32 kbh_val_bytes;

    /* easily accessible copies of min and max keys */
    __le32 kbh_min_koff;
    __le32 kbh_min_klen;
    __le32 kbh_max_koff;
    __le32 kbh_max_klen;

    /* WBT header */
    __le32 kbh_wbt_hoff;
    __le32 kbh_wbt_hlen;
    __le32 kbh_wbt_doff_pg;
    __le32 kbh_wbt_dlen_pg;

    /* Bloom header and data */
    __le32 kbh_blm_hoff;
    __le32 kbh_blm_hlen;
    __le32 kbh_blm_doff_pg;
    __le32 kbh_blm_dlen_pg;

    /* ptomb WBT header */
    __le32 kbh_pt_hoff;
    __le32 kbh_pt_hlen;
    __le32 kbh_pt_doff_pg;
    __le32 kbh_pt_dlen_pg;

    /* min and max seqno */
    __le64 kbh_min_seqno;
    __le64 kbh_max_seqno;

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
#define BLOOM_OMF_VERSION ((u32)4)

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
    __le32 bh_magic;
    __le32 bh_version;
    __le32 bh_bitmapsz;
    __le32 bh_modulus;
    __le32 bh_bktshift;
    __le16 bh_rsvd1;
    u8     bh_rotl;
    u8     bh_n_hashes;
    __le32 bh_rsvd2;
    __le32 bh_rsvd3;
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
 * OMF v6: Added support for compressed values. Uses a new value type
 *         (vtype_cval) which affects KMD format. Unfortunately,
 *         there is no version field for KMD, so we bump the WBTree
 *         version even though the actual WBTree header, leaf and
 *         internal nodes are no different from OMF v5.
 *
 * OMF v5: Added longest common prefix elimination for keys in WBTree nodes.
 *
 * OMF v4: Added new value, "immediate", for short values.
 *
 * OMF v3 and below: Ancient history. Nobody cares. Should remove support.
 */
#define WBT_NODE_SIZE 4096 /* must equal system page size */

#define WBT_TREE_MAGIC ((u32)0x4a3a2a1a)
#define WBT_TREE_VERSION  WBT_TREE_VERSION6
#define WBT_TREE_VERSION6 ((u32)6)
#define WBT_TREE_VERSION5 ((u32)5)
#define WBT_TREE_VERSION4 ((u32)4)
#define WBT_TREE_VERSION3 ((u32)3)
#define WBT_TREE_VERSION2 ((u32)2)

/* WBT header (OMF v4-v6) */
struct wbt_hdr_omf {
    __le32 wbt_magic;
    __le32 wbt_version;
    __le16 wbt_root;     /* index of wbtree root node */
    __le16 wbt_leaf;     /* index of first wbtree leaf node */
    __le16 wbt_leaf_cnt; /* number of wbtree leaf nodes */
    __le16 wbt_kmd_pgc;  /* size of kmd region in pages */
    __le32 wbt_reserved1;
    __le32 wbt_reserved2;
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

/* WBT node header (OMF v5-v6) */
struct wbt_node_hdr_omf {
    __le16 wbn_magic;    /* magic number, distinguishes INEs from LFEs */
    __le16 wbn_num_keys; /* number of keys in node */
    __le32 wbn_kmd;      /* offset in kmd region to this node's kmd */
    __le16 wbn_pfx_len;  /* length of the longest common prefix */
    __le16 wbn_padding;  /* unused padding */
} HSE_PACKED;

OMF_SETGET(struct wbt_node_hdr_omf, wbn_magic, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_num_keys, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_kmd, 32)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_pfx_len, 16)

/* WBT node header (OMF v4) */
struct wbt4_node_hdr_omf {
    __le16 wbn4_magic;    /* node magic , distinguishes INEs from LFEs */
    __le16 wbn4_num_keys; /* number of keys in node */
    __le32 wbn4_kmd;      /* offset in kmd region to this node's kmd */
} HSE_PACKED;

OMF_SETGET(struct wbt4_node_hdr_omf, wbn4_magic, 16)
OMF_SETGET(struct wbt4_node_hdr_omf, wbn4_num_keys, 16)
OMF_SETGET(struct wbt4_node_hdr_omf, wbn4_kmd, 32)

/* WBT internal node entry (OMF v4-v6) */
struct wbt_ine_omf {
    __le16 ine_koff;       /* byte offset from start of node to key */
    __le16 ine_left_child; /* node number of left child */
} HSE_PACKED;

OMF_SETGET(struct wbt_ine_omf, ine_koff, 16)
OMF_SETGET(struct wbt_ine_omf, ine_left_child, 16)

/* WBT leaf node entry (OMF v4-v6)
 * Note, if lfe_kmd == U16_MAX, then the actual kmd offset is stored as a LE32
 * value at lfe_koff, and the actual key is stored at lfe_koff + 4.
 */
struct wbt_lfe_omf {
    __le16 lfe_koff;
    __le16 lfe_kmd;
} HSE_PACKED;

OMF_SETGET(struct wbt_lfe_omf, lfe_koff, 16)
OMF_SETGET(struct wbt_lfe_omf, lfe_kmd, 16)

/******** WB tree Version 3 ********/

/* GCOV_EXCL_START */

/* WB tree version 3 header */
struct wbt3_hdr_omf {
    __le32 wbt3_magic;
    __le32 wbt3_version;
    __le16 wbt3_root;     /* index of wbtree root node */
    __le16 wbt3_leaf;     /* index of first wbtree leaf node */
    __le16 wbt3_leaf_cnt; /* number of wbtree leaf nodes */
    __le16 wbt3_kmd_pgc;  /* size of kmd region in pages */
    __le32 wbt3_reserved1;
    __le32 wbt3_reserved2;
} HSE_PACKED;

OMF_SETGET(struct wbt3_hdr_omf, wbt3_magic, 32)
OMF_SETGET(struct wbt3_hdr_omf, wbt3_version, 32)
OMF_SETGET(struct wbt3_hdr_omf, wbt3_root, 16);
OMF_SETGET(struct wbt3_hdr_omf, wbt3_leaf, 16);
OMF_SETGET(struct wbt3_hdr_omf, wbt3_leaf_cnt, 16);
OMF_SETGET(struct wbt3_hdr_omf, wbt3_kmd_pgc, 16);

/* WB tree version 3 node header */

struct wbt3_node_hdr_omf {
    __le16 wbn3_magic;    /* magic number, distinguishes INEs from LFEs */
    __le16 wbn3_num_keys; /* number of keys in node */
    __le32 wbn3_kmd;      /* offset in kmd region to node's kmd data */
} HSE_PACKED;

OMF_SETGET(struct wbt3_node_hdr_omf, wbn3_magic, 16)
OMF_SETGET(struct wbt3_node_hdr_omf, wbn3_num_keys, 16)
OMF_SETGET(struct wbt3_node_hdr_omf, wbn3_kmd, 32)

/* WB tree version 3 internal node entry (ine) */
struct wbt3_ine_omf {
    __le16 ine3_koff;       /* byte offset from start of node to key */
    __le16 ine3_left_child; /* node number of left child */
} HSE_PACKED;

OMF_SETGET(struct wbt3_ine_omf, ine3_koff, 16)
OMF_SETGET(struct wbt3_ine_omf, ine3_left_child, 16)

/* WB tree version 3 leaf node entry (lfe).
 * Note, if lfe_kmd == U16_MAX, then the actual kmd offset is stored as a LE32
 * value at lfe_koff, and the actual key is stored at lfe_koff + 4.
 */
struct wbt3_lfe_omf {
    __le16 lfe3_koff;
    __le16 lfe3_kmd;
} HSE_PACKED;

OMF_SETGET(struct wbt3_lfe_omf, lfe3_koff, 16)
OMF_SETGET(struct wbt3_lfe_omf, lfe3_kmd, 16)

/* GCOV_EXCL_STOP */

/*****************************************************************
 *
 * Vblock header OMF
 *
 ****************************************************************/

#define VBLOCK_HDR_MAGIC ((u32)0xea73feed)
#define VBLOCK_HDR_VERSION1 ((u32)1)
#define VBLOCK_HDR_VERSION2 ((u32)2)

/* Version 2 header */
struct vblock_hdr_omf {
    __le32 vbh_magic;
    __le32 vbh_version;
    __le64 vbh_vgroup;
} HSE_PACKED;

OMF_SETGET(struct vblock_hdr_omf, vbh_magic, 32)
OMF_SETGET(struct vblock_hdr_omf, vbh_version, 32)
OMF_SETGET(struct vblock_hdr_omf, vbh_vgroup, 64)

/* Version 1 header */
struct vblock_hdr1_omf {
    __le32 vbh1_magic;
    __le32 vbh1_version;
    __le32 vbh1_entries;
    __le32 vbh1_data_off; /* offset from start of vblock to values */
    __le64 vbh1_data_len; /* length of value region */
} HSE_PACKED;

/* cn dynamic state
 */
#define CN_TSTATE_MAGIC (u32)('c' << 24 | 't' << 16 | 's' << 8 | 'm')
#define CN_TSTATE_VERSION (u32)1
#define CN_TSTATE_KHM_SZ (1024)

struct cn_tstate_omf {
    __le32 ts_magic;
    __le32 ts_version;

    __le64 ts_rsvd[14];

    __le32 ts_khm_gen;
    __le32 ts_khm_rsvd;
    u8     ts_khm_mapv[CN_TSTATE_KHM_SZ];
} HSE_PACKED;

OMF_SETGET(struct cn_tstate_omf, ts_magic, 32)
OMF_SETGET(struct cn_tstate_omf, ts_version, 32)

OMF_SETGET(struct cn_tstate_omf, ts_khm_gen, 32)
OMF_SETGET_CHBUF(struct cn_tstate_omf, ts_khm_mapv);

#endif
