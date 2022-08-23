/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_OMF_H
#define HSE_KVDB_CN_OMF_H

#include <stdint.h>
#include <sys/param.h>

#include <hse/limits.h>

#include <hse_ikvdb/omf_version.h>
#include <hse_util/omf.h>
#include <hse_util/page.h>

/*****************************************************************
 *
 * Wanna B-Tree (WBT) On-Media-Format
 *
 * Supported versions:
 *     v6: Added support for compressed values. Uses a new value type
 *         (VTYPE_CVAL) which affects KMD format. Unfortunately,
 *         there is no version field for KMD, so we bump the WBTree
 *         version even though the actual WBTree header, leaf and
 *         internal nodes are no different from OMF v5.
 *
 * Deprecated versions:
 *     v5: Added longest common prefix elimination for keys in WBTree nodes
 *     v4: Added new value, "immediate", for short values
 */
#define WBT_NODE_SIZE PAGE_SIZE /* must equal system page size */

#define WBT_TREE_MAGIC ((uint32_t)0x4a3a2a1a)

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

#define WBT_LFE_NODE_MAGIC ((uint16_t)0xabc0)
#define WBT_INE_NODE_MAGIC ((uint16_t)0xabc1)

/* WBT node header (v6) */
struct wbt_node_hdr_omf {
    uint16_t wbn_magic;    /* magic number, distinguishes INEs from LFEs */
    uint16_t wbn_num_keys; /* number of keys in node */
    uint32_t wbn_kmd;      /* offset in kmd region to this node's kmd */
    uint64_t wbn_kvlen;    /* total key and value data referenced by this node */
    uint16_t wbn_pfx_len;  /* length of the longest common prefix */
    uint16_t wbn_rsvd1;    /* unused padding */
    uint32_t wbn_rsvd2;    /* unused padding */
} HSE_PACKED;

OMF_SETGET(struct wbt_node_hdr_omf, wbn_magic, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_num_keys, 16)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_kmd, 32)
OMF_SETGET(struct wbt_node_hdr_omf, wbn_kvlen, 64)
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

/*****************************************************************
 *
 * Hblock header OMF
 *
 ****************************************************************/

#define HBLOCK_HDR_MAGIC ((uint32_t)0xcafedead)

struct hblock_hdr_omf {
    /* integrity check, version and type */
    uint32_t hbh_magic;
    uint32_t hbh_version;

    uint64_t hbh_min_seqno;
    uint64_t hbh_max_seqno;

    uint32_t hbh_num_ptombs;
    uint32_t hbh_num_kblocks;
    uint32_t hbh_num_vblocks;

    /* vgroup map */
    uint32_t hbh_vgmap_off_pg;
    uint32_t hbh_vgmap_len_pg;

    /* HyperLogLog */
    uint32_t hbh_hlog_off_pg;
    uint32_t hbh_hlog_len_pg;

    /* prefix tombstone tree */
    struct wbt_hdr_omf hbh_ptree_hdr;
    uint32_t hbh_ptree_data_off_pg;
    uint32_t hbh_ptree_data_len_pg;

    /* max prefix */
    uint32_t hbh_max_pfx_off;
    uint8_t hbh_max_pfx_len;
    uint8_t hbh_rsvd1[3];

    /* min prefix */
    uint32_t hbh_min_pfx_off;
    uint8_t hbh_min_pfx_len;
    uint8_t hbh_rsvd2[3];
} HSE_PACKED;

OMF_SETGET(struct hblock_hdr_omf, hbh_magic, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_version, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_min_seqno, 64)
OMF_SETGET(struct hblock_hdr_omf, hbh_max_seqno, 64)
OMF_SETGET(struct hblock_hdr_omf, hbh_num_ptombs, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_num_kblocks, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_num_vblocks, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_vgmap_off_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_vgmap_len_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_hlog_off_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_hlog_len_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_ptree_data_off_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_ptree_data_len_pg, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_max_pfx_off, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_max_pfx_len, 8)
OMF_SETGET(struct hblock_hdr_omf, hbh_min_pfx_off, 32)
OMF_SETGET(struct hblock_hdr_omf, hbh_min_pfx_len, 8)

static_assert(HSE_KVS_PFX_LEN_MAX <= UINT8_MAX,
    "uint8_t is not enough to hold HSE_KVS_PFX_LEN_MAX");

#define HBLOCK_HDR_PAGES \
    (roundup(sizeof(struct hblock_hdr_omf) + 2 * HSE_KVS_PFX_LEN_MAX, PAGE_SIZE) / PAGE_SIZE)
#define HBLOCK_HDR_LEN (HBLOCK_HDR_PAGES * PAGE_SIZE)

static_assert(HBLOCK_HDR_PAGES == 1, "Hblock header spanning more than 1 page has not been tested");


/*****************************************************************
 *
 * Vgroup Map OMF
 *
 ****************************************************************/

#define VGROUP_MAP_MAGIC   ((uint32_t)('v' << 24 | 'g' << 16 | 'p' << 8 | 'm'))

struct vgroup_map_entry_omf {
    uint16_t vgme_vbidx;
    uint16_t vgme_vbadj;
} HSE_PACKED;

OMF_SETGET(struct vgroup_map_entry_omf, vgme_vbidx, 16)
OMF_SETGET(struct vgroup_map_entry_omf, vgme_vbadj, 16)


struct vgroup_map_omf {
    uint32_t                    vgm_magic;
    uint32_t                    vgm_version;
    uint32_t                    vgm_count;
    uint32_t                    vgm_rsvd;
    struct vgroup_map_entry_omf vgm_entries[0];
} HSE_PACKED;

OMF_SETGET(struct vgroup_map_omf, vgm_magic, 32)
OMF_SETGET(struct vgroup_map_omf, vgm_version, 32)
OMF_SETGET(struct vgroup_map_omf, vgm_count, 32)
OMF_SETGET(struct vgroup_map_omf, vgm_rsvd, 32)


/*****************************************************************
 *
 * Kblock header OMF
 *
 ****************************************************************/

#define KBLOCK_HDR_MAGIC ((uint32_t)0xfadedfad)

/* This is currently set to 1350 which is the max key size supported. However,
 * with the current header sizes, this can grow up to (3972-7*2)/2 i.e. 1979
 * bytes (to fit min/max keys in the kblock header with 8-byte alignment).
 */
#define HSE_KBLOCK_OMF_KLEN_MAX ((uint32_t)1350)

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
    uint32_t kbh_rsvd1;
    uint32_t kbh_key_bytes;
    uint64_t kbh_val_bytes;
    uint64_t kbh_vused_bytes;

    /* easily accessible copies of min and max keys */
    uint32_t kbh_min_koff;
    uint32_t kbh_max_koff;
    uint16_t kbh_min_klen;
    uint16_t kbh_max_klen;
    uint32_t kbh_rsvd2;

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
} HSE_PACKED;

/* Define set/get methods for kblock_hdr_omf */
OMF_SETGET(struct kblock_hdr_omf, kbh_magic, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_version, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_entries, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_tombs, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_key_bytes, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_val_bytes, 64)
OMF_SETGET(struct kblock_hdr_omf, kbh_vused_bytes, 64)
OMF_SETGET(struct kblock_hdr_omf, kbh_min_koff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_min_klen, 16)
OMF_SETGET(struct kblock_hdr_omf, kbh_max_koff, 32)
OMF_SETGET(struct kblock_hdr_omf, kbh_max_klen, 16)

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

/* Storing 2 keys in the header: min and max. */
#define KBLOCK_HDR_PAGES \
    (roundup(sizeof(struct kblock_hdr_omf) + 2 * HSE_KVS_KEY_LEN_MAX, PAGE_SIZE) / PAGE_SIZE)
#define KBLOCK_HDR_LEN (KBLOCK_HDR_PAGES * PAGE_SIZE)

static_assert(KBLOCK_HDR_PAGES == 1, "Kblock header spanning more than 1 page has not been tested");

/*****************************************************************
 *
 * Bloom filter header OMF (part of the kblock)
 *
 ****************************************************************/

#define BLOOM_OMF_MAGIC ((uint32_t)('b' << 24 | 'l' << 16 | 'm' << 8 | 'h'))

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
 * Vblock footer OMF
 *
 ****************************************************************/

#define VBLOCK_FOOTER_MAGIC ((uint32_t)0xea73feed)

/*
 * min_key is stored at offset VBLOCK_FOOTER_LEN - (2 * HSE_KVS_KEY_LEN_MAX)
 * min key is inclusive in all the vblocks
 *
 * max_key is stored at offset VBLOCK_FOOTER_LEN - HSE_KVS_KEY_LEN_MAX
 * max key is exclusive in all but the last vblock
 */
struct vblock_footer_omf {
    uint32_t vbf_magic;
    uint32_t vbf_version;
    uint64_t vbf_vgroup;
    uint16_t vbf_min_klen;
    uint16_t vbf_max_klen;
    uint32_t vbf_rsvd;
} HSE_PACKED;

/* Storing 2 keys in the footer: min and max. */
#define VBLOCK_FOOTER_PAGES \
    (roundup(sizeof(struct vblock_footer_omf) + 2 * HSE_KVS_KEY_LEN_MAX, PAGE_SIZE) / PAGE_SIZE)
#define VBLOCK_FOOTER_LEN (VBLOCK_FOOTER_PAGES * PAGE_SIZE)

static_assert(VBLOCK_FOOTER_PAGES == 1, "Vblock footer cannot span multiple pages");

OMF_SETGET(struct vblock_footer_omf, vbf_magic, 32)
OMF_SETGET(struct vblock_footer_omf, vbf_version, 32)
OMF_SETGET(struct vblock_footer_omf, vbf_vgroup, 64)
OMF_SETGET(struct vblock_footer_omf, vbf_min_klen, 16)
OMF_SETGET(struct vblock_footer_omf, vbf_max_klen, 16)
OMF_SETGET(struct vblock_footer_omf, vbf_rsvd, 32)

#endif
