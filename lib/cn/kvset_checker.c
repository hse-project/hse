/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/table.h>
#include <hse_util/keycmp.h>
#include <hse_util/hash.h>
#include <hse_util/bitmap.h>
#include <hse_util/log2.h>
#include <hse_util/logging.h>

#include <mpool/mpool.h>

/* [HSE_REVISIT] - why are these includes not </>? */

#include "hse_ikvdb/kvs_cparams.h"

#include "hse_ikvdb/omf_kmd.h"
#include "hse_ikvdb/limits.h"

#include "kvset.h"
#include "omf.h"
#include "wbt_internal.h"
#include "blk_list.h"
#include "bloom_reader.h"
#include "cn_tree_internal.h"

/*
 * All static functions that return an int, return a non-zero value if an error
 * was encountered
 */

#define pgoff(x) ((x)*PAGE_SIZE)

struct wbt_ops {
    struct wbt_lfe_omf *(*wops_lfe)(void *node, int nth);

    void (*wops_node_pfx)(void *node, const void **pfx, uint *pfx_len);

    void (*wops_lfe_key)(void *node, struct wbt_lfe_omf *lfe, const void **kdata, uint *klen);

    uint (*wops_lfe_kmd)(void *node, struct wbt_lfe_omf *lfe);

    struct wbt_ine_omf *(*wops_ine)(void *node, int nth);

    void (*wops_ine_key)(void *node, struct wbt_ine_omf *ine, const void **kdata, uint *klen);
};

struct kb_info {
    /* kblock contents */
    void *blk;

    /* position of current entity */
    u64 blkid;
    u32 dgen;
    u32 level;
    u32 offset;

    uint           wbt_version;
    u32            wbt_page;
    u32            wbt_entry;
    struct wbt_ops wbt_ops;

    int kmd_idx; /* index into list of vals for a key*/

    /* tree shape info */
    struct kvs_cparams *cp;
    struct cn_tree     *tree;

    /* other kb data */
    u8 *              kmd;
    struct bloom_desc blm_desc;
    u8 *              blm_data;

    bool is_kvset;
};

struct kb_metrics {
    u32 entries;
    u32 tombs;
    u32 key_bytes;
    u32 val_bytes;
};

struct vb_meta {
    struct blk_list *    blk_list;
    struct mblock_props *props;
};

struct node_info {
    const void *maxkey;
    size_t      maxlen;
    u32         vboff;
    u32         vbidx;
};

/* Map of all nodes pointed to directly.
 * i.e. if a node is visited because its parent is being checked, the entry in
 * this map is relevant.
 * It's not relevant if the node is visited as part of a recursive call to get
 * to a leaf node. Hence, such visits do not update the map.
 */
struct nodemap {
    u8 *   map;
    size_t len;
};

struct print_info {
    bool      verbose;
    print_cb *print_func;
};

#define print_dbg(fmt, ...)                              \
    do {                                                 \
        if (print_info.verbose)                          \
            print_info.print_func((fmt), ##__VA_ARGS__); \
    } while (0)

#define print_err(fmt, ...) print_info.print_func((fmt), ##__VA_ARGS__)

#define print_merr(err, fmt, ...)                     \
    do {                                              \
        char errbuf[300];                             \
        merr_strinfo(err, errbuf, sizeof(errbuf), 0); \
        print_err(fmt ": %s", ##__VA_ARGS__, errbuf); \
    } while (0)

#define kb_err(k, fmt, ...) print_err("kblock 0x%08lx: " fmt, (k)->blkid, ##__VA_ARGS__)

#define lfe_err(k, fmt, ...)                       \
    print_err(                                     \
        "kblock 0x%08lx wbt_page %u lfe %u: " fmt, \
        (k)->blkid,                                \
        (k)->wbt_page,                             \
        (k)->wbt_entry,                            \
        ##__VA_ARGS__)

#define ine_err(k, fmt, ...)                       \
    print_err(                                     \
        "kblock 0x%08lx wbt_page %u ine %u: " fmt, \
        (k)->blkid,                                \
        (k)->wbt_page,                             \
        (k)->wbt_entry,                            \
        ##__VA_ARGS__)

#define kmd_err(k, fmt, ...)                              \
    print_err(                                            \
        "kblock 0x%08lx wbt_page %u lfe %u kmd %u: " fmt, \
        (k)->blkid,                                       \
        (k)->wbt_page,                                    \
        (k)->wbt_entry,                                   \
        (k)->kmd_idx,                                     \
        ##__VA_ARGS__)

static void
default_print(char *fmt, ...)
{
    va_list ap;
    char    buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    log_debug("%s", buf);
}

static struct print_info print_info = { false, default_print };

void
kc_print_reg(bool verbose, print_cb *print_func)
{
    print_info.verbose = verbose;

    if (print_func)
        print_info.print_func = print_func;
}

static int
kc_loc_check(struct kb_info *kb, struct key_obj *kobj, u64 *hash_out)
{
    u64  fullhash;
    int  hashlen;
    bool err = false;

    u8   key[HSE_KVS_KEY_LEN_MAX];
    uint klen;

    key_obj_copy(key, sizeof(key), &klen, kobj);

    fullhash = 0;
    if (klen >= kb->cp->pfx_len + kb->cp->sfx_len) {
        hashlen = klen - kb->cp->sfx_len;
        fullhash = hse_hash64(key, hashlen);
        *hash_out = fullhash;
    }

    if (kb->cp->pfx_len && kb->cp->pfx_len <= klen) {
        hashlen = kb->cp->pfx_len;
    }

    /* [HSE_REVISIT] The kvck tool would like to verify the route of
     * the given hash, but it does not have access to the cn tree.
     * Perhaps we can pass it in by cnid and look it up?
     */
    if (!kb->tree)
        return 0;

    return err ? 1 : 0;
}

static int
rightmost_key(struct kb_info *kb, int idx, struct key_obj *kobj, struct nodemap *map)
{
    void *node;
    int   num_keys;

    node = kb->blk + pgoff(1 + idx);
    num_keys = omf_wbn_num_keys(node);

    if (omf_wbn_magic(node) == WBT_LFE_NODE_MAGIC) {
        struct wbt_lfe_omf *lfe;

        lfe = kb->wbt_ops.wops_lfe(node, 0);
        lfe += (num_keys - 1);

        kb->wbt_ops.wops_lfe_key(node, lfe, &kobj->ko_sfx, &kobj->ko_sfx_len);
        kb->wbt_ops.wops_node_pfx(node, &kobj->ko_pfx, &kobj->ko_pfx_len);

        return 0;
    }

    if (omf_wbn_magic(node) == WBT_INE_NODE_MAGIC) {
        struct wbt_ine_omf *ine;
        u32                 left;

        ine = kb->wbt_ops.wops_ine(node, 0);

        if (map->map[idx] == 0)
            ine_err(kb, "rightmost_key: node %d not visited", idx);

        ine += num_keys;
        left = omf_ine_left_child(ine);

        if (left >= idx)
            ine_err(
                kb,
                "rightmost_key: "
                "node idx (%d) < child idx (%d)",
                idx,
                left);

        /* recurse till lfe */
        return rightmost_key(kb, left, kobj, map);
    }

    return 1;
}

static int
check_vref(
    struct kb_info *   kb_info,
    size_t *           off,
    struct kb_metrics *metrics,
    struct vb_meta *   vb_meta,
    u32 *              last_vbidx,
    u32 *              last_vboff)
{
    u64  vbid;
    u32  vbidx, vlen, vboff;
    bool err = false;

    kmd_val(kb_info->kmd, off, &vbid, &vbidx, &vboff, &vlen);

    if (*last_vboff > 0 && vbidx == *last_vbidx && vboff < *last_vboff) {
        err = true;
        kmd_err(kb_info, "vb %u off %u len %u: overlaps with previous", vbidx, vboff, vlen);
    }

    *last_vbidx = vbidx;
    *last_vboff = vboff + vlen;

    if (vboff + vlen > VBLOCK_MAX_SIZE) {
        err = true;
        kmd_err(
            kb_info,
            "vb %u off %u len %u: extends beyond "
            "VBLOCK_MAX_SIZE",
            vbidx,
            vboff,
            vlen);
    }

    /* vblock list wasn't provided. So we do not have a way to verify kmd's
     * contents regarding the key's value
     */
    if (!vb_meta)
        goto done;

    if (vbidx > vb_meta->blk_list->n_blks) {
        err = true;
        kmd_err(
            kb_info,
            "vb %u off %u len %u: vbidx beyond total "
            "vblocks (%u)",
            vbidx,
            vboff,
            vlen,
            vb_meta->blk_list->n_blks);
    }

    if (vboff + vlen > vb_meta->props[vbidx].mpr_write_len) {
        err = true;
        kmd_err(
            kb_info,
            "vb %u off %u len %u: extends beyond "
            "vblock size (%u)",
            vbidx,
            vboff,
            vlen,
            vb_meta->props[vbidx].mpr_write_len);
    }

done:
    metrics->val_bytes += vlen;

    return err ? 1 : 0;
}

static int
wbn_leaf_check(
    void *             hdr,
    struct kb_info *   kb_info,
    struct vb_meta *   vb_meta,
    int                idx,
    struct nodemap *   map,
    struct node_info * prev,
    struct kb_metrics *kb_metrics)
{
    int                 i, j;
    struct wbt_lfe_omf *lfe;

    const void *key = 0;
    const void *pfx = 0;
    u32         klen = 0;
    u32         pfx_len = 0;

    const void *prev_key = prev->maxkey;
    u32         prev_klen = prev->maxlen;
    u32         last_vbidx = prev->vbidx;
    u32         last_vboff = prev->vboff;

    u32    kmd_cnt, kcnt;
    size_t lfe_kmd, off;
    u64    last_seq;
    bool   err = false;

    kcnt = omf_wbn_num_keys(hdr);
    if (kcnt == 0) {
        lfe_err(kb_info, "no keys");
        return 1;
    }

    lfe = kb_info->wbt_ops.wops_lfe(hdr, 0);

    kb_info->wbt_ops.wops_node_pfx(hdr, &pfx, &pfx_len);
    for (i = 0; i < kcnt; i++) {
        struct key_obj    kobj;
        struct kvs_ktuple kt;

        kb_info->wbt_ops.wops_lfe_key(hdr, lfe, &key, &klen);
        kt.kt_data = key;
        kt.kt_len = klen;

        kb_info->wbt_entry = i;

        /* Check key */
        if (prev_key && keycmp(key, klen, prev_key, prev_klen) <= 0) {
            err = true;
            lfe_err(kb_info, "keys out of order");
        }

        kobj.ko_pfx = pfx;
        kobj.ko_pfx_len = pfx_len;
        kobj.ko_sfx = key;
        kobj.ko_sfx_len = klen;

        if (kb_info->is_kvset && kc_loc_check(kb_info, &kobj, &kt.kt_hash)) {
            err = true;
            break;
        }

        if (!bloom_reader_buffer_lookup(&kb_info->blm_desc, kb_info->blm_data, &kt)) {
            err = true;
            lfe_err(kb_info, "bloom cannot find this key");
        }

        prev_key = key;
        prev_klen = klen;

        /* Check key's kmd region */
        lfe_kmd = kb_info->wbt_ops.wops_lfe_kmd(hdr, lfe);
        kmd_cnt = kmd_count(kb_info->kmd, &lfe_kmd);
        off = lfe_kmd;
        last_seq = 0;

        if (kmd_cnt == 0) {
            err = true;
            lfe_err(kb_info, "key has no kmd data");
        }

        for (j = 0; j < kmd_cnt; j++) {
            enum kmd_vtype vtype;
            u64            seq;
            const void *   ival;
            u32            ivlen;

            kb_info->kmd_idx = j;

            kmd_type_seq(kb_info->kmd, &off, &vtype, &seq);
            if (last_seq && seq < last_seq) {
                kmd_err(kb_info, "seqno out of order");
                last_seq = seq;
                err = true;
            }

            switch (vtype) {
                case vtype_val:
                    if (check_vref(kb_info, &off, kb_metrics, vb_meta, &last_vbidx, &last_vboff) !=
                        0)
                        err = true;
                    break;
                case vtype_tomb:
                    kb_metrics->tombs++;
                    break;
                case vtype_ival:
                    kmd_ival(kb_info->kmd, &off, &ival, &ivlen);
                    if (ivlen > CN_SMALL_VALUE_THRESHOLD) {
                        err = true;
                        kmd_err(
                            kb_info,
                            "ival larger than "
                            "CN_SMALL_VALUE_THRESHOLD");
                    }
                    kb_metrics->val_bytes += ivlen;
                    break;
                default:
                    break;
            }
        }

        lfe++;

        kb_metrics->entries++;
        kb_metrics->key_bytes += key_obj_len(&kobj);
    }

    prev->maxkey = key;
    prev->maxlen = klen;
    prev->vbidx = last_vbidx;
    prev->vboff = last_vboff;

    return err ? 1 : 0;
}

static int
wbn_int_check(struct kb_info *kb, void *hdr, struct nodemap *map, int idx)
{
    struct wbt_ine_omf *ine;
    int                 i;
    bool                err = false;
    u32                 edge_cnt; /* number of edge keys in this node */

    ine = kb->wbt_ops.wops_ine(hdr, 0);

    edge_cnt = omf_wbn_num_keys(hdr);

    for (i = 0; i < edge_cnt + 1; i++) {
        struct key_obj ref, key;
        u32            left;

        kb->wbt_entry = i;

        left = omf_ine_left_child(ine);

        if (map->map[left] > 0) {
            err = true;
            ine_err(kb, "node already visited");
        }

        map->map[left]++;

        if (left >= idx) {
            err = true;
            ine_err(kb, "node idx (%d) < child idx (%d)", idx, left);
            continue;
        }

        kb->wbt_ops.wops_ine_key(hdr, ine, &key.ko_sfx, &key.ko_sfx_len);
        kb->wbt_ops.wops_node_pfx(hdr, &key.ko_pfx, &key.ko_pfx_len);

        if (rightmost_key(kb, left, &ref, map) != 0)
            err = true;

        if (i == edge_cnt)
            break;

        if (key_obj_cmp(&ref, &key) != 0) {
            err = true;
            ine_err(kb, "key does not match right child's key");
        }

        ine++;
    }

    return err ? 1 : 0;
}

struct vb_meta *
kc_vblock_meta(struct mpool *ds, struct blk_list *list)
{
    struct vb_meta *vb;
    u32             num_blks = list->n_blks;
    merr_t          err;
    int             i;

    vb = calloc(1, sizeof(*vb) + num_blks * sizeof(struct mblock_props));
    if (!vb)
        return 0;

    vb->blk_list = list;
    vb->props = (struct mblock_props *)(vb + 1);

    for (i = 0; i < num_blks; i++) {
        struct iovec iov;
        char *       vb_buf;
        u64          vbid = list->blks[i].bk_blkid;

        struct vblock_hdr_omf *vb_hdr;

        err = mpool_mblock_props_get(ds, vbid, &vb->props[i]);
        if (ev(err)) {
            print_merr(err, "vblock 0x%08lx", vbid);
            break;
        }

        /* Verify correctness of vblocks' headers */
        vb_buf = alloc_page_aligned(PAGE_SIZE);
        iov.iov_base = vb_buf;
        iov.iov_len = PAGE_SIZE;

        err = mpool_mblock_read(ds, vbid, &iov, 1, 0);
        if (ev(err)) {
            print_merr(err, "vblock 0x%08lx: cannot read mblock", vbid);
            free_aligned(vb_buf);
            break;
        }

        vb_hdr = (struct vblock_hdr_omf *)vb_buf;
        if (omf_vbh_magic(vb_hdr) != VBLOCK_HDR_MAGIC)
            print_err("vblock 0x%08lx: incorrect magic", vbid);

        if (omf_vbh_version(vb_hdr) > VBLOCK_HDR_VERSION)
            print_err("vblock 0x%08lx: invalid version", vbid);

        free_aligned(vb_buf);
    }

    if (i < num_blks) {
        free(vb);
        vb = 0;
    }

    return vb;
}

/* Read contents of an mblock in a page aligned buffer */
static int
read_mblock(struct mpool *ds, u64 blkid, void **buf)
{
    merr_t       err;
    int          rc = 0;
    struct iovec iov;
    char *       mem;
    int          meg_bits = 20;
    int          i, nmegs, meg = 1 << meg_bits;
    u32          len;
    size_t       off, remainder;

    struct mblock_props props;

    err = mpool_mblock_props_get(ds, blkid, &props);
    if (ev(err)) {
        print_merr(err, "mblock 0x%08lx: cannot find mblock", blkid);
        return 1;
    }

    len = props.mpr_write_len;
    mem = alloc_page_aligned(len);
    if (ev(!mem)) {
        print_err("mblock 0x%08lx: cannot allocate memory (%lu bytes)", blkid, len);
        return 1;
    }

    off = 0;
    nmegs = len >> meg_bits;
    iov.iov_len = meg;
    for (i = 0; i < nmegs; ++i) {
        iov.iov_base = mem + off;
        err = mpool_mblock_read(ds, blkid, &iov, 1, off);
        if (err) {
            rc = 1;
            print_merr(err, "mblock 0x%08lx: cannot read meg %d", blkid, i);
        }
        off += iov.iov_len;
    }

    /* residual */
    remainder = len & (meg - 1);
    if (remainder) {
        iov.iov_base = mem + off;
        iov.iov_len = remainder;
        err = mpool_mblock_read(ds, blkid, &iov, 1, off);
        if (ev(err)) {
            rc = 1;
            print_merr(err, "mblock 0x%08lx: cannot read meg %d", blkid, i);
        }
    }

    if (ev(rc != 0)) {
        free_aligned(mem);
        return rc;
    }

    *buf = mem;

    return 0;
}

static int
verify_minmax(struct kb_info *kb)
{
    bool                   err = false;
    struct kblock_hdr_omf *kb_hdr = kb->blk;

    struct key_obj ref, key;

    void *minkey = kb->blk + omf_kbh_min_koff(kb_hdr);
    u32   minklen = omf_kbh_min_klen(kb_hdr);
    void *maxkey = kb->blk + omf_kbh_max_koff(kb_hdr);
    u32   maxklen = omf_kbh_max_klen(kb_hdr);

    struct wbt_hdr_omf *wbt_hdr = kb->blk + omf_kbh_wbt_hoff(kb_hdr);
    void *              node_hdr = kb->blk + pgoff(omf_wbt_leaf(wbt_hdr) + 1);

    u16 leaf_cnt = omf_wbt_leaf_cnt(wbt_hdr);

    struct wbt_lfe_omf *lfe;

    /* smallest key */
    lfe = kb->wbt_ops.wops_lfe(node_hdr, 0);

    key2kobj(&ref, minkey, minklen);
    kb->wbt_ops.wops_node_pfx(node_hdr, &key.ko_pfx, &key.ko_pfx_len);
    kb->wbt_ops.wops_lfe_key(node_hdr, lfe, &key.ko_sfx, &key.ko_sfx_len);
    if (key_obj_cmp(&key, &ref) != 0) {
        err = true;
        kb_err(kb, "incorrect min key in hdr");
    }

    /* largest key */
    node_hdr = node_hdr + pgoff(leaf_cnt - 1);
    lfe = kb->wbt_ops.wops_lfe(node_hdr, 0);
    lfe += omf_wbn_num_keys(node_hdr) - 1;

    key2kobj(&ref, maxkey, maxklen);
    kb->wbt_ops.wops_node_pfx(node_hdr, &key.ko_pfx, &key.ko_pfx_len);
    kb->wbt_ops.wops_lfe_key(node_hdr, lfe, &key.ko_sfx, &key.ko_sfx_len);
    if (key_obj_cmp(&key, &ref) != 0) {
        err = true;
        kb_err(kb, "incorrect max key in hdr");
    }

    return err ? 1 : 0;
}

/* If 'is_kvset' is false, the arguments following it will be ignored since
 * the information of the kblock (i.e. info regarding its location in the
 * cn tree) is missing.
 */
static merr_t
_kblock_check(struct kb_info *kb_info, struct vb_meta *vb_meta)
{
    struct kblock_hdr_omf *kb_hdr;
    struct wbt_hdr_omf *   wbt_hdr;
    void *                 node_hdr;
    struct bloom_hdr_omf * blm_hdr;
    struct kb_metrics      kb_metrics = { 0 };

    struct nodemap kb_map;

    int  i, errcnt = 0;
    int  root_idx;
    u32  leaf_cnt;
    uint wbt_ver;

    if (!kb_info->blk)
        return merr(ev(EINVAL));

    kb_hdr = kb_info->blk;

    if (omf_kbh_magic(kb_hdr) != KBLOCK_HDR_MAGIC && (++errcnt))
        kb_err(kb_info, "Incorrect kblock hdr magic");

    if (omf_kbh_version(kb_hdr) > KBLOCK_HDR_VERSION && (++errcnt))
        kb_err(kb_info, "Invalid kblock hdr version");

    if (errcnt)
        return merr(ev(EILSEQ));

    wbt_hdr = kb_info->blk + omf_kbh_wbt_hoff(kb_hdr);

    if (omf_wbt_magic(wbt_hdr) != WBT_TREE_MAGIC && (++errcnt))
        kb_err(kb_info, "Incorrect wbt hdr magic");

    if (omf_wbt_version(wbt_hdr) > WBT_TREE_VERSION && (++errcnt))
        kb_err(kb_info, "Invalid wbt hdr version");

    if (errcnt)
        return merr(ev(EILSEQ));

    wbt_ver = omf_wbt_version(wbt_hdr);
    switch (wbt_ver) {
        case WBT_TREE_VERSION:
            kb_info->wbt_ops.wops_lfe = wbt_lfe;
            kb_info->wbt_ops.wops_node_pfx = wbt_node_pfx;
            kb_info->wbt_ops.wops_lfe_key = wbt_lfe_key;
            kb_info->wbt_ops.wops_lfe_kmd = wbt_lfe_kmd;
            kb_info->wbt_ops.wops_ine = wbt_ine;
            kb_info->wbt_ops.wops_ine_key = wbt_ine_key;
            break;
        default:
            return merr(EINVAL);
    }

    blm_hdr = kb_info->blk + omf_kbh_blm_hoff(kb_hdr);

    if (omf_bh_magic(blm_hdr) != BLOOM_OMF_MAGIC && (++errcnt))
        kb_err(kb_info, "Incorrect bloom hdr magic");

    if (omf_bh_version(blm_hdr) > BLOOM_OMF_VERSION && (++errcnt))
        kb_err(kb_info, "Invalid bloom hdr version");

    if (errcnt)
        return merr(ev(EILSEQ));

    leaf_cnt = omf_wbt_leaf_cnt(wbt_hdr);

    node_hdr = (void *)kb_hdr + pgoff(omf_wbt_leaf(wbt_hdr) + 1);

    kb_map.len = omf_wbt_root(wbt_hdr) + 1;
    kb_map.map = calloc(kb_map.len, sizeof(*kb_map.map));
    if (!kb_map.map) {
        kb_err(kb_info, "cannot allocate memory (%lu bytes)", kb_map.len * sizeof(*kb_map.map));
        return merr(ev(ENOMEM));
    }

    kb_info->blm_desc.bd_first_page = omf_kbh_blm_doff_pg(kb_hdr);
    kb_info->blm_desc.bd_n_pages = omf_kbh_blm_dlen_pg(kb_hdr);

    kb_info->blm_desc.bd_modulus = omf_bh_modulus(blm_hdr);
    kb_info->blm_desc.bd_bktshift = omf_bh_bktshift(blm_hdr);
    kb_info->blm_desc.bd_n_hashes = omf_bh_n_hashes(blm_hdr);
    kb_info->blm_desc.bd_rotl = omf_bh_rotl(blm_hdr);
    kb_info->blm_desc.bd_bktmask = (1u << kb_info->blm_desc.bd_bktshift) - 1;

    kb_info->blm_data = (void *)kb_hdr + pgoff(kb_info->blm_desc.bd_first_page);

    kb_info->kmd = (void *)kb_hdr + pgoff(omf_kbh_wbt_doff_pg(kb_hdr) + omf_wbt_root(wbt_hdr) + 1);

    for (i = 0; i < leaf_cnt; i++) {
        struct node_info last = { 0 };

        kb_info->wbt_page = i;
        kb_info->wbt_entry = 0;

        if (omf_wbn_magic(node_hdr) != WBT_LFE_NODE_MAGIC)
            lfe_err(kb_info, "not a leaf node");

        errcnt += wbn_leaf_check(node_hdr, kb_info, vb_meta, i, &kb_map, &last, &kb_metrics);

        node_hdr = node_hdr + PAGE_SIZE;
    }

    errcnt += verify_minmax(kb_info);

    root_idx = omf_wbt_root(wbt_hdr);
    for (i = omf_wbt_leaf_cnt(wbt_hdr); i <= root_idx; i++) {
        kb_info->wbt_page = i;
        kb_info->wbt_entry = 0;

        if (omf_wbn_magic(node_hdr) != WBT_INE_NODE_MAGIC)
            ine_err(kb_info, "not an internal node");

        errcnt += wbn_int_check(kb_info, node_hdr, &kb_map, i);

        node_hdr = node_hdr + PAGE_SIZE;
    }

    /* do not include root node in the following check, because we mark only
     * those nodes that are pointed to by others
     */
    for (i = 0; i < kb_map.len - 1; i++) {
        if (kb_map.map[i] != 1)
            kb_err(kb_info, "node %d visited %u times. Expected 1", i, kb_map.map[i]);
    }

    free(kb_map.map);

    /* Check correctness of metrics */
    if (kb_metrics.entries != omf_kbh_entries(kb_hdr))
        kb_err(
            kb_info,
            "Incorrect number of keys. "
            "Expected %u Found %u",
            omf_kbh_entries(kb_hdr),
            kb_metrics.entries);

    if (kb_metrics.key_bytes != omf_kbh_key_bytes(kb_hdr))
        kb_err(
            kb_info,
            "Incorrect total key len. "
            "Expected %u Found %u",
            omf_kbh_key_bytes(kb_hdr),
            kb_metrics.key_bytes);

    if (!vb_meta)
        goto done;

    if (kb_metrics.tombs != omf_kbh_tombs(kb_hdr))
        kb_err(
            kb_info,
            "Incorrect number of tombstones. "
            "Expected %u Found %u",
            omf_kbh_tombs(kb_hdr),
            kb_metrics.tombs);

    if (kb_metrics.val_bytes != omf_kbh_val_bytes(kb_hdr))
        kb_err(
            kb_info,
            "Incorrect total value len. "
            "Expected %u Found %u",
            omf_kbh_val_bytes(kb_hdr),
            kb_metrics.val_bytes);

done:
    return errcnt ? merr(EILSEQ) : 0;
}

merr_t
kc_kblock_check(struct mpool *ds, u64 kblkid, struct vb_meta *vb_meta)
{
    int            ret;
    void *         kb_buf;
    merr_t         err;
    struct kb_info kb;

    ret = read_mblock(ds, kblkid, &kb_buf);
    if (ret)
        return merr(ev(EIO));

    kb.is_kvset = false, kb.blkid = kblkid, kb.blk = kb_buf;

    print_dbg("kblock 0x%08lx", kblkid);

    err = _kblock_check(&kb, vb_meta);
    free_aligned(kb_buf);

    return err;
}

merr_t
kc_kvset_check(struct mpool *ds, struct kvs_cparams *cp, struct kvset_meta *km, struct cn_tree *tree)
{
    int             i, kblk_cnt;
    bool            rc = false;
    struct vb_meta *vb_meta = 0;

    struct blk_list *kblk_list = &km->km_kblk_list;
    struct blk_list *vblk_list = &km->km_vblk_list;

    if (vblk_list) {
        vb_meta = kc_vblock_meta(ds, vblk_list);
        if (!vb_meta)
            return merr(ev(ENOMEM));
    }

    kblk_cnt = kblk_list->n_blks;

    print_dbg("kvset %u,%u,%u", km->km_node_level, km->km_node_offset, km->km_dgen);

    for (i = 0; i < kblk_cnt; i++) {
        void * kb_buf = 0;
        u64    id = kblk_list->blks[i].bk_blkid;
        merr_t err;
        int    errcnt = 0;

        struct kb_info kb_info;

        print_dbg("kblock 0x%08lx", id);

        err = read_mblock(ds, id, &kb_buf);
        if (err) {
            rc = true;
            errcnt++;
        }

        kb_info.blkid = id;
        kb_info.blk = kb_buf;
        kb_info.is_kvset = true;
        kb_info.dgen = km->km_dgen;
        kb_info.level = km->km_node_level;
        kb_info.offset = km->km_node_offset;
        kb_info.cp = cp;
        kb_info.tree = tree;

        err = _kblock_check(&kb_info, vb_meta);
        if (err) {
            rc = true;
            errcnt++;
        }

        free_aligned(kb_buf);

        if (ev(err)) {
            free(vb_meta);
            return err;
        }
    }

    free(vb_meta);

    return rc ? merr(EILSEQ) : 0;
}
