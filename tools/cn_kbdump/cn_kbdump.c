/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * cn_kbdump - print internal structure of a kblock
 */

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/minmax.h>
#include <hse_util/table.h>
#include <hse_util/string.h>
#include <hse_util/fmt.h>
#include <hse_util/event_counter.h>
#include <hse_util/bloom_filter.h>

#include <mpool/mpool.h>

#include <hse/hse.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/omf_kmd.h>

#include <cn/omf.h>
#include <cn/wbt_internal.h>

#include <libgen.h>
#include <sysexits.h>

#define ERROR_BUF_SIZE 256

char *progname;

struct {
    int   pct_enc;
    int   klen;
    int   vlen;
    int   verbose;
    int   read;
    int   mmap;
    int   style;
    char *write;
} opt;

struct blk {
    void *buf;
    char *id;
    int   len;
    bool  is_kblock;
};

struct table *ktab, *vtab;
size_t        bh_bktsz;

#define pgoff(x)         ((x)*PAGE_SIZE)
#define off2addr(x, off) (void *)(((char *)(x)) + (off))

/* --------------------------------------------------
 * formatters
 */

void
fatal(hse_err_t err, char *fmt, ...)
{
    char    msg[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    char buf[ERROR_BUF_SIZE];
    hse_err_to_string(err, buf, sizeof(buf), NULL);
    fprintf(stderr, "%s: %s: %s\n", progname, msg, buf);
    exit(1);
}

void
syntax(const char *fmt, ...)
{
    char    msg[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

/*
 * fmt_data - format the data as ascii or hex
 *
 * use two static buffers, allows 2 simultaneous uses per printf
 * and buffer management is hidden from users
 *
 * NOT THREAD SAFE!
 */
char *
fmt_data(const void *off, int len, int max)
{
    static char *buf[2];
    static int   curbuf;
    size_t       buflen = 4096;

    const unsigned char *data = off;
    char *               bp;

    if (max == 0)
        return "";

    if (!buf[0]) {
        int n;

        n = abs(opt.vlen);
        if (n < abs(opt.klen))
            n = abs(opt.klen);
        if (n == 0)
            n = max;
        buf[0] = malloc(buflen); /* 1k max, 3n hex/byte, round up */
        buf[1] = malloc(buflen);
        if (!buf[0] || !buf[1])
            fatal(ENOMEM, "cannot malloc fmt data");
    }

    if (len >= abs(max) && max < 0)
        data = data + len + max;
    if (len < abs(max))
        max = len;

    bp = buf[++curbuf & 1];
    if (opt.pct_enc)
        fmt_pe(bp, buflen, data, abs(max));
    else
        fmt_hex(bp, buflen, data, abs(max));

    return bp;
}

char *
fmt_key(const void *v, int off, int len)
{
    return fmt_data(v + off, len, opt.klen);
}

char *
fmt_val(int idx, int off, int len)
{
    struct blk *blk;

    blk = table_at(vtab, idx);
    if (!blk || !blk->buf)
        return opt.verbose ? "not-mapped" : "";
    return fmt_data(blk->buf + off, len, opt.vlen);
}

char
fmt_wtype_v2(int t, int isroot)
{
    return t == 1 ? (isroot ? 'r' : 'i') : 'L';
}

char
fmt_wtype(uint magic, int isroot)
{
    return (
        isroot ? 'r'
               : (magic == WBT_LFE_NODE_MAGIC ? 'L' : (magic == WBT_INE_NODE_MAGIC ? 'i' : '?')));
}

/* --------------------------------------------------
 * struct interpretation
 */

void
print_kblk(struct blk *blk)
{
    struct kblock_hdr_omf *p = blk->buf;
    char *                 base = blk->buf;
    struct wbt_hdr_omf *   wbt_hdr = off2addr(p, omf_kbh_wbt_hoff(p));

    printf(
        "%s: K magic 0x%08x  ver %d  nkey %d  ntomb %d\n",
        blk->id,
        omf_kbh_magic(p),
        omf_kbh_version(p),
        omf_kbh_entries(p),
        omf_kbh_tombs(p));
    printf(
        "    metrics: keys %u tombs %u key_bytes %u val_bytes %u\n",
        omf_kbh_entries(p),
        omf_kbh_tombs(p),
        omf_kbh_key_bytes(p),
        omf_kbh_val_bytes(p));
    printf(
        "    wbt: hdr %d %d  data_pg %d %d\n",
        omf_kbh_wbt_hoff(p),
        omf_kbh_wbt_hlen(p),
        omf_kbh_wbt_doff_pg(p),
        omf_kbh_wbt_dlen_pg(p));
    printf(
        "    pt: hdr %d %d  data_pg %d %d\n",
        omf_kbh_pt_hoff(p),
        omf_kbh_pt_hlen(p),
        omf_kbh_pt_doff_pg(p),
        omf_kbh_pt_dlen_pg(p));
    printf(
        "    blm: hdr %d %d  data_pg %d %d\n",
        omf_kbh_blm_hoff(p),
        omf_kbh_blm_hlen(p),
        omf_kbh_blm_doff_pg(p),
        omf_kbh_blm_dlen_pg(p));
    printf("    kmd: start_pg %u\n", omf_kbh_wbt_doff_pg(p) + omf_wbt_root(wbt_hdr) + 1);
    printf(
        "    keymin: off %u len %u key %s\n",
        omf_kbh_min_koff(p),
        omf_kbh_min_klen(p),
        fmt_data(omf_kbh_min_koff(p) + base, omf_kbh_min_klen(p), 1024));
    printf(
        "    keymax: off %u len %u key %s\n",
        omf_kbh_max_koff(p),
        omf_kbh_max_klen(p),
        fmt_data(omf_kbh_max_koff(p) + base, omf_kbh_max_klen(p), 1024));
}

void
print_vblk(struct blk *blk)
{
    struct vblock_hdr_omf *p = blk->buf;

    printf("%s: V magic 0x%08x  ver %d\n", blk->id, omf_vbh_magic(p), omf_vbh_version(p));
}

int
bits_in_block(const void *mem, size_t blksz)
{
    const long *p = mem;
    const long *end = p + blksz / sizeof(*p);
    int         cnt = 0;

    while (p < end)
        cnt += __builtin_popcountl(*p++);

    return cnt;
}

int
bkt_cmp(const void *lhs, const void *rhs)
{
    const uint *l = lhs;
    const uint *r = rhs;

    if (*l < *r)
        return -1;
    if (*l > *r)
        return 1;
    return 0;
}

void
print_blm(struct blk *blk)
{
    struct kblock_hdr_omf *kblk = blk->buf;
    struct bloom_hdr_omf * hdr;
    const uint8_t *        bitmap;
    size_t                 bitmapsz;
    size_t                 bktsz, bitsperbkt;
    size_t                 doff, dlen;
    uint *                 cntv, cntmin, cntmax;
    uint                   cntsum, cntempty, cntfull;
    uint                   bktmax;
    uint                   i, j;

    hdr = off2addr(blk->buf, omf_kbh_blm_hoff(kblk));

    bktsz = (1u << omf_bh_bktshift(hdr)) >> BYTE_SHIFT;
    if (bh_bktsz > 0)
        bktsz = bh_bktsz;
    bitsperbkt = bktsz * CHAR_BIT;

    printf(
        "    blmhdr: magic 0x%08x  ver %u"
        "  bktsz %lu  rotl %u  hashes %u  bitmapsz %u  modulus %u\n",
        omf_bh_magic(hdr),
        omf_bh_version(hdr),
        bktsz,
        omf_bh_rotl(hdr),
        omf_bh_n_hashes(hdr),
        omf_bh_bitmapsz(hdr),
        omf_bh_modulus(hdr));

    doff = omf_kbh_blm_doff_pg(kblk) * PAGE_SIZE;
    dlen = omf_kbh_blm_dlen_pg(kblk) * PAGE_SIZE;

    if (blk->len < doff + dlen)
        return;

    bitmap = blk->buf + doff;
    bitmapsz = omf_bh_bitmapsz(hdr);

    if (!bitmapsz || !bktsz)
        return;

    bktmax = bitmapsz / bktsz;

    cntv = calloc(bktmax, sizeof(*cntv));
    if (ev(!cntv))
        return;

    cntmax = cntsum = cntempty = cntfull = 0;
    cntmin = UINT_MAX;

    for (i = 0; i < bktmax; ++i) {
        cntv[i] = bits_in_block(bitmap, bktsz);
        if (cntv[i] > cntmax)
            cntmax = cntv[i];
        if (cntv[i] < cntmin)
            cntmin = cntv[i];
        if (cntv[i] == 0)
            ++cntempty;
        if (cntv[i] == bitsperbkt)
            ++cntfull;
        cntsum += cntv[i];
        bitmap += bktsz;
    }

    if (opt.verbose > 0) {
        if (opt.verbose > 1)
            qsort(cntv, bktmax, sizeof(*cntv), bkt_cmp);

        printf("    blm distributions %s:\n", opt.verbose > 1 ? "(sorted)" : "(by bucket)");

        for (i = 0; i < bktmax; i += 8) {
            printf("    %8u  ", i);
            for (j = 0; j < 8; ++j) {
                if (i + j >= bktmax)
                    break;

                printf("  %5.3lf", (double)cntv[i + j] / bitsperbkt);
            }
            printf("\n");
        }
    }

    qsort(cntv, bktmax, sizeof(*cntv), bkt_cmp);

    printf(
        "    blm dist    min:  %6.3lf (%u / %zu)\n",
        (double)cntv[0] / bitsperbkt,
        cntv[0],
        bitsperbkt);

    printf(
        "    blm dist    .3%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 3 / 1000] / bitsperbkt,
        cntv[bktmax * 3 / 1000],
        bitsperbkt);
    printf(
        "    blm dist   2.1%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 21 / 1000] / bitsperbkt,
        cntv[bktmax * 21 / 1000],
        bitsperbkt);

    printf(
        "    blm dist median:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax / 2] / bitsperbkt,
        cntv[bktmax / 2],
        bitsperbkt);
    printf(
        "    blm dist   mean:  %6.3lf (%u / %zu)\n",
        (double)(cntsum / bktmax) / bitsperbkt,
        (cntsum / bktmax),
        bitsperbkt);

    printf(
        "    blm dist  97.9%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 979 / 1000] / bitsperbkt,
        cntv[bktmax * 979 / 1000],
        bitsperbkt);

    printf(
        "    blm dist  99.7%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 997 / 1000] / bitsperbkt,
        cntv[bktmax * 997 / 1000],
        bitsperbkt);

    printf(
        "    blm dist    max:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax - 1] / bitsperbkt,
        cntv[bktmax - 1],
        bitsperbkt);

    printf("    blm bucket size: %4lu (%lu bits)\n", bktsz, bitsperbkt);
    if (cntempty > 0)
        printf("    blm empty buckets: %5u\n", cntempty);
    if (cntfull > 0)
        printf("    blm full buckets:  %5u\n", cntfull);

    free(cntv);
}

/* Version 3/4 wbtree
 *
 * Version 4 is identical to version 3 except for the version field and the
 * fact that a version 4 WBT may have "immediate values". These are values
 * (small) that are directly encoded in the WBT LNE instead of being denoted
 * as a location in a Vblock.
 */

struct kmd_vref {
    enum kmd_vtype vtype;
    size_t         vtype_off;
    uint           vbidx;
    uint           vboff;
    uint           vlen;
    u64            seq;
    int            cnt;
    char           vinfo[64];
};

static bool
val_get_next(void *kmd, size_t *off, struct kmd_vref *vref)
{
    const void *vdata;
    u32         vlen;

    vref->vbidx = vref->vboff = vref->vlen = 0;

    if (vref->cnt-- == 0)
        return false;

    vref->vtype_off = *off;

    kmd_type_seq(kmd, off, &vref->vtype, &vref->seq);

    switch (vref->vtype) {
        case vtype_val:
            kmd_val(kmd, off, &vref->vbidx, &vref->vboff, &vref->vlen);
            snprintf(
                vref->vinfo,
                sizeof(vref->vinfo),
                "type=v %u/%u/%u",
                vref->vbidx,
                vref->vboff,
                vref->vlen);
            break;
        case vtype_ival:
            kmd_ival(kmd, off, &vdata, &vlen);
            snprintf(vref->vinfo, sizeof(vref->vinfo), "type=iv %u", vlen);
            break;
        case vtype_zval:
            strlcpy(vref->vinfo, "type=zv", sizeof(vref->vinfo));
            break;
        case vtype_tomb:
            strlcpy(vref->vinfo, "type=t", sizeof(vref->vinfo));
            break;
        case vtype_ptomb:
            strlcpy(vref->vinfo, "type=pt", sizeof(vref->vinfo));
            break;
        default:
            snprintf(
                vref->vinfo,
                sizeof(vref->vinfo),
                "type=unknown vtype 0x%02x doff 0x%lx",
                vref->vtype,
                *off);

            /* set vref->cnt to 0 so the next call returns false forcing
         * the caller to skip to the next key
         */
            vref->cnt = 0;
    }

    return true;
}

/* Handles versions 3 & 4 */

void
print_wbt_node(void *h, uint version, void *kmd, int pgno, int root)
{
    struct wbt_ine_omf *ie;
    struct wbt_lfe_omf *le;
    uint                i, nkeys, klen, pfx_len;
    const void *        kdata, *pfx;
    bool                internal_node;
    uint                hdr_sz;

    internal_node = omf_wbn_magic(h) == WBT_INE_NODE_MAGIC;
    hdr_sz = version < WBT_TREE_VERSION5 ? sizeof(struct wbt4_node_hdr_omf)
                                         : sizeof(struct wbt_node_hdr_omf);
    pfx_len = version < WBT_TREE_VERSION5 ? 0 : omf_wbn_pfx_len(h);
    pfx = h + hdr_sz;

    ie = (struct wbt_ine_omf *)(h + hdr_sz + pfx_len);
    le = (struct wbt_lfe_omf *)(h + hdr_sz + pfx_len);

    printf(
        "w: pg %d  magic 0x%04x nkeys %u kmdoff %u pfx_len %u "
        "pfx %s # type %c\n",
        pgno,
        omf_wbn_magic(h),
        omf_wbn_num_keys(h),
        omf_wbn_kmd(h),
        pfx_len,
        fmt_data(pfx, pfx_len, opt.klen),
        fmt_wtype(omf_wbn_magic(h), pgno == root));

    if (!opt.klen)
        return;

    nkeys = omf_wbn_num_keys(h);
    for (i = 0; i < nkeys; ++i, ++ie, ++le) {
        if (internal_node) {
            version < WBT_TREE_VERSION5 ? wbt4_ine_key(h, ie, &kdata, &klen)
                                        : wbt_ine_key(h, ie, &kdata, &klen);

            printf(
                "    ie %-4d left %d  key %d,%d %s\n",
                (int)((void *)ie - h),
                omf_ine_left_child(ie),
                omf_ine_koff(ie),
                klen,
                fmt_data(kdata, klen, opt.klen));
        } else {
            size_t off;
            uint   j, cnt, lfe_kmd, koff, klen;

            struct kmd_vref vref;

            version < WBT_TREE_VERSION5 ? wbt4_lfe_key(h, le, &kdata, &klen)
                                        : wbt_lfe_key(h, le, &kdata, &klen);

            koff = omf_lfe_koff(le);
            lfe_kmd = wbt_lfe_kmd(h, le);
            off = lfe_kmd;
            cnt = kmd_count(kmd, &off);
            vref.cnt = cnt;

            switch (opt.style) {
                default:
                    j = 1;
                    while (val_get_next(kmd, &off, &vref)) {
                        printf(
                            "    key: %u/%u lfe %-4u "
                            "koff %-4u klen %-2u kmd %u "
                            "key %s val: %u/%u kmd %lu "
                            "seq %lu %s%s%s\n",
                            i,
                            nkeys,
                            (uint)((void *)le - h),
                            koff,
                            klen,
                            lfe_kmd,
                            fmt_data(kdata, klen, opt.klen),
                            j,
                            cnt,
                            (ulong)off,
                            vref.seq,
                            vref.vinfo,
                            vref.vlen ? " " : "",
                            (vref.vlen ? fmt_val(vref.vbidx, vref.vboff, vref.vlen) : ""));
                        if (!opt.verbose)
                            break;
                        ++j;
                    }
                    break;
                case 1:
                    printf(
                        "    key: %u/%u lfe %-4u koff %-4u "
                        "klen %-2u kmd %u nvals %-2u key %s\n",
                        i,
                        nkeys,
                        (uint)((void *)le - h),
                        koff,
                        klen,
                        lfe_kmd,
                        cnt,
                        fmt_data(kdata, klen, opt.klen));
                    if (!opt.verbose)
                        break;
                    j = 1;
                    while (val_get_next(kmd, &off, &vref)) {
                        printf(
                            "    val: %u/%u kmd %lu "
                            "seq %lu %s%s%s\n",
                            j,
                            cnt,
                            (ulong)off,
                            vref.seq,
                            vref.vinfo,
                            vref.vlen ? " " : "",
                            (vref.vlen ? fmt_val(vref.vbidx, vref.vboff, vref.vlen) : ""));
                        ++j;
                    }
                    break;
            }
        }
    }
    if (internal_node) {
        printf("    ie %-4d right %d\n", (int)((void *)ie - h), omf_ine_left_child(ie));
    }
}

void
print_wbt_nodes(void *kblk, void *kmd, int root, bool ptomb)
{
    struct wbt_node_hdr_omf *wbn;
    struct wbt_hdr_omf *     wbt_hdr = off2addr(kblk, omf_kbh_wbt_hoff(kblk));
    int                      terse = !opt.klen;
    int                      i, pgno;
    uint                     magic, omagic = 0;

    if (terse)
        printf("wbt node list:");

    for (i = pgno = 0; pgno <= root; ++pgno, ++i) {
        if (ptomb)
            wbn = kblk + pgoff(pgno + omf_kbh_pt_doff_pg(kblk));
        else
            wbn = kblk + pgoff(pgno + omf_kbh_wbt_doff_pg(kblk));

        if (!terse) {
            print_wbt_node(wbn, omf_wbt_version(wbt_hdr), kmd, pgno, root);
            continue;
        }

        magic = omf_wbn_magic(wbn);
        if (pgno == root)
            omagic = 0; /* force line break */
        if (magic != omagic || i == 8) {
            i = 0;
            printf("\n");
        }
        printf("%c %3d %3d  ", fmt_wtype(magic, pgno == root), pgno, omf_wbn_num_keys(wbn));
        omagic = magic;
    }
    if (terse)
        printf("\n");
}

void
print_wbt_impl(void *wbt_hdr, void *kblk, bool ptomb)
{
    u32 wbt_doff;
    u8 *kmd;

    wbt_doff = ptomb ? omf_kbh_pt_doff_pg(kblk) : omf_kbh_wbt_doff_pg(kblk);
    kmd = kblk + pgoff(wbt_doff + omf_wbt_root(wbt_hdr) + 1);

    printf(
        "    wbthdr: magic 0x%08x  ver %d  root %d  leaf1 %d  nleaf %d "
        "kmdpgc %d\n",
        omf_wbt_magic(wbt_hdr),
        omf_wbt_version(wbt_hdr),
        omf_wbt_root(wbt_hdr),
        omf_wbt_leaf(wbt_hdr),
        omf_wbt_leaf_cnt(wbt_hdr),
        omf_wbt_kmd_pgc(wbt_hdr));

    if ((opt.verbose || opt.klen) && omf_wbt_kmd_pgc(wbt_hdr) > 0)
        print_wbt_nodes(kblk, kmd, omf_wbt_root(wbt_hdr), ptomb);
}

void
print_wbt(void *wbt_hdr, void *kblk, bool ptomb)
{
    switch (wbt_hdr_version(wbt_hdr)) {
        case WBT_TREE_VERSION6:
        case WBT_TREE_VERSION5:
        case WBT_TREE_VERSION4:
        case WBT_TREE_VERSION3:
            print_wbt_impl(wbt_hdr, kblk, ptomb);
            break;
        default:
            printf("Invalid wbtree magic and/or version\n");
            break;
    }
}

/* --------------------------------------------------
 * mpool / dataset readers
 */

void
eread_mblock(struct mpool *ds, struct blk *blk)
{
    struct mblock_props props;
    struct iovec        iov;
    char *              mem;
    hse_err_t           err;
    int                 rc, i, nmegs, meg = 1024 * 1024;
    u64                 id;
    u32                 len;

    id = strtoull(blk->id, 0, 0);
    err = merr_to_hse_err(mpool_mblock_props_get(ds, id, &props));
    if (err)
        fatal(err, "mblookup 0x%lx", id);

    len = blk->len = props.mpr_write_len;
    rc = posix_memalign(&blk->buf, PAGE_SIZE, len);
    if (rc)
        fatal(errno, "alloc for mblk 0x%lx, len %d", id, len);

    mem = blk->buf;

    /*
     * read in 1 meg increments until final part, then residual
     * discussions with jgrove suggest 1 meg as a "good citizen"
     * approach to kmalloc in the underlying - more is possible,
     * but puts undesirable stress on memory subsytem
     */
    nmegs = len / meg;
    for (i = 0; i < nmegs; ++i) {
        iov.iov_base = mem + i * meg;
        iov.iov_len = meg;
        err = merr_to_hse_err(mpool_mblock_read(ds, id, &iov, 1, i * meg));
        if (err)
            fatal(err, "mblkread 0x%lx, meg %d", id, i);
    }

    /* residual */
    if (nmegs * meg < len) {
        iov.iov_base = mem + i * meg;
        iov.iov_len = len - nmegs * meg;
        err = merr_to_hse_err(mpool_mblock_read(ds, id, &iov, 1, i * meg));
        if (err)
            fatal(err, "mblkread 0x%lx, meg %d", id, i);
    }
}

void
eread_ds(int argc, char **argv)
{
    struct mpool *ds;
    struct blk *  blk;
    char *        mpname, *junk;
    char **       kbids, **vbids;
    int           i, nk, nv;
    hse_err_t     err;

    mpname = argv[0];

    argc -= 2;
    argv += 2;

    strtol(*argv, &junk, 0);
    if (junk[0] != 0) {
        argc--;
        argv++;
    }

    /*
     * The arguments here follow the presentation:
     *  kbid kbid / vbid vbid vbid vbid
     * so there is a vector of kblock ids, and a vector of vblock ids.
     * We communicate the number of elements by writing 0 as last element.
     */

    kbids = argv;
    nk = nv = 0;
    for (i = 0; i < argc; ++i)
        if (argv[i][0] == '/' && argv[i][1] == 0) {
            nk = i;
            nv = (argc - nk) - 1;
            vbids = argv + nk + 1;
            break;
        }

    if (nk == 0) {
        /* assume old style: one kblock, zero or more vblocks */
        nk = 1;
        nv = argc - 1;
        vbids = argv + 1;
    }

    /* O_EXCL not required since mblocks are immutable by definition
     * and we are reading them directly. */
    /* TODO: fix this */
    err = merr_to_hse_err(mpool_open(mpname, NULL, O_RDONLY, &ds));
    if (err)
        fatal(err, "mpool_open");

    /* kblocks */
    for (i = 0; i < nk; ++i) {
        blk = table_insert(ktab, i);
        blk->id = kbids[i];
        eread_mblock(ds, blk);
    }

    /* vblocks */
    for (i = 0; i < nv; ++i) {
        blk = table_insert(vtab, i);
        blk->id = vbids[i];
        eread_mblock(ds, blk);
    }

    mpool_close(ds);
}

/* --------------------------------------------------
 * saved file i/o
 */

void
egzip(char *dirname, int i, char type, struct blk *blk)
{
    char  cmd[BUFSIZ];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "gzip > %s/%c%03d.%s.gz", dirname, type, i, blk->id);

    fp = popen(cmd, "w");
    if (!fp)
        fatal(errno, "cannot write to %s", cmd + 7);
    if (!fwrite(blk->buf, 1, blk->len, fp))
        fatal(errno, "writing to %s", cmd + 7);
    pclose(fp);
}

void
ereadfp(FILE *fp, struct blk *blk)
{
    struct kblock_hdr_omf *kblk;
    ssize_t                cc;
    void *                 cur;
    int                    rc;
    int                    remain = VBLOCK_MAX_SIZE;

    /*
     * we don't know the uncompressed size of the mblocks
     * so use a max-sized buffer
     */
    rc = posix_memalign(&blk->buf, PAGE_SIZE, VBLOCK_MAX_SIZE);
    if (rc)
        fatal(rc, "cannot alloc mblock for io");
    cur = blk->buf;
    cc = fread(cur, 1, 512, fp);
    kblk = (struct kblock_hdr_omf *)cur;
    if (cc != 512 ||
        (omf_kbh_magic(kblk) != KBLOCK_HDR_MAGIC && omf_kbh_magic(kblk) != VBLOCK_HDR_MAGIC))
        fatal(EPROTO, "%s not a kblock or vblock", blk->id);
    blk->is_kblock = omf_kbh_magic(kblk) == KBLOCK_HDR_MAGIC;
    /* read up to a max sized block */
    do {
        cur += cc;
        remain -= cc;
    } while (remain > 0 && (cc = fread(cur, 1, remain, fp)) > 0);
    clearerr(fp);
    blk->len = (int)(cur - blk->buf);
}

void
eread_pipe(struct blk *blk, char *fmt, ...)
{
    va_list ap;
    FILE *  fp;
    char    cmd[BUFSIZ];
    int     rc;

    va_start(ap, fmt);
    rc = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    if (rc >= sizeof(cmd))
        fatal(EINVAL, "cannot format command: %s\n", fmt);

    fp = popen(cmd, "r");
    if (!fp)
        fatal(errno, "cannot read pipe: %s", cmd);
    ereadfp(fp, blk);
    pclose(fp);
}

void
eread_file(char *file, struct blk *blk)
{
    FILE *fp;
    int   len;

    len = strlen(file);
    if (len > 3 && strcmp(file + len - 3, ".gz") == 0) {
        eread_pipe(blk, "zcat %s", file);
    } else if (len > 3 && strcmp(file + len - 3, ".xz") == 0) {
        eread_pipe(blk, "xzcat %s", file);
    } else {
        fp = fopen(file, "r");
        if (!fp)
            fatal(errno, "cannot open %s", file);
        ereadfp(fp, blk);
        fclose(fp);
    }
}

int
eread_mmap(int argc, char **argv)
{
    int i;

    for (i = 0; i < argc; ++i) {
        struct blk tmp = {};

        tmp.id = argv[i];
        eread_file(argv[i], &tmp);
        if (!table_append_object(tmp.is_kblock ? ktab : vtab, &tmp))
            fatal(ENOMEM, "cannot insert new block");
    }

    if (table_len(vtab))
        fprintf(stderr, "\n*** WARNING: values may not be coordinated with keys! ***\n\n");
    return 0;
}

int
eread_files(int argc, char **argv)
{
    /*
     * each kvdbet should be in a dir,
     * with sets of files:
     *  K0.0x0010210b.gz
     *  K1.0x0010210c.gz
     *  V0.0x0010410e.gz
     *  V1.0x0010410f.gz
     *  V2.0x00104110.gz
     */
    int i;

    for (i = 0; i < argc; ++i) {

        char *     file = argv[i];
        struct blk tmp = {};

        if (file[0] == '/' && file[1] == 0)
            continue;

        eread_file(file, &tmp);
        tmp.id = file;
        if (!table_append_object(tmp.is_kblock ? ktab : vtab, &tmp))
            fatal(ENOMEM, "cannot insert new block");
    }

    if (table_len(ktab) < 1)
        fatal(ENOENT, "no kblocks found");

    return 0;
}

void
ewrite_files(char *dirname)
{
    struct stat st;
    int         i, j;

    if (stat(dirname, &st) || !S_ISDIR(st.st_mode))
        fatal(ENOTDIR, dirname);

    j = table_len(ktab);
    for (i = 0; i < j; ++i)
        egzip(dirname, i, 'K', table_at(ktab, i));

    j = table_len(vtab);
    for (i = 0; i < j; ++i)
        egzip(dirname, i, 'V', table_at(vtab, i));
}

/* --------------------------------------------------
 * main
 */

void
usage(void)
{
    static const char usage1[] = "usage: %s [options] mpool kvdb kbid ... [/ vbid ...]\n";
    static const char usage2[] = "usage: %s -r [options] file ...\n";
    static const char usage3[] = "usage: %s -m [options] file ...\n";

    printf(usage1, progname);
    printf(usage2, progname);
    printf(usage3, progname);

    printf("-b bktsz  bloom block/bucket size\n"
           "-h        print this help list\n"
           "-K N      show keys and values, limit to first (last) N bytes\n"
           "-m        read mblock data from mmap path\n"
           "-o STYLE  outut format (0=default, 1=one value per line)\n"
           "-r        read mblock data from named files\n"
           "-V N      limit values to first (last) N bytes, implies -K\n"
           "-v        show wbt node headers and all values\n"
           "-w dir    write raw mblocks into $dir\n"
           "-x        show binary data in hex form\n"
           "-p        show binary data in percent-encoded form\n");
}

int
main(int argc, char **argv)
{
    struct kblock_hdr_omf *kblk;
    struct blk *           blk;
    int                    i, c, nk, nv;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    while (-1 != (c = getopt(argc, argv, ":b:hK:mo:prV:vw:x"))) {
        char *endptr = NULL;

        errno = 0;

        switch (c) {
            case 'b':
                bh_bktsz = strtoul(optarg, &endptr, 0);
                bh_bktsz = clamp_t(size_t, 64, PAGE_SIZE, bh_bktsz);
                break;

            case 'h':
                usage();
                exit(0);

            case 'K':
                opt.klen = strtol(optarg, &endptr, 0);
                break;

            case 'm':
                opt.mmap = 1;
                break;

            case 'o':
                opt.style = strtol(optarg, &endptr, 0);
                break;

            case 'r':
                opt.read = 1;
                break;

            case 'V':
                opt.vlen = strtol(optarg, &endptr, 0);
                break;

            case 'v':
                opt.verbose++;
                break;

            case 'w':
                opt.write = optarg;
                break;

            case 'x':
                opt.pct_enc = 0;
                break;

            case 'p':
                opt.pct_enc = 1;
                break;

            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                fatal(EINVAL, "unhandled option -%c\n", c);
                break;
        }

        if (errno || (endptr && *endptr)) {
            syntax("unable to convert option '-%c %s'", c, optarg);
            exit(EX_USAGE);
        }
    }

    argc -= optind;
    argv += optind;

    /* showing values implies showing keys */
    if (opt.vlen && !opt.klen)
        opt.klen = opt.vlen;

    if (opt.read && opt.mmap) {
        syntax("options -r and -m are mutually exclusive");
        exit(EX_USAGE);
    }

    ktab = table_create(0, sizeof(struct blk), true);
    vtab = table_create(0, sizeof(struct blk), true);

    if (!ktab || !vtab)
        fatal(ENOMEM, "cannot alloc blk vectors");

    if (opt.read) {
        if (argc < 1) {
            syntax("insufficient arguments for mandatory parameters");
            exit(EX_USAGE);
        }
        eread_files(argc, argv);
    } else if (opt.mmap) {
        if (argc < 1) {
            syntax("insufficient arguments for mandatory parameters");
            exit(EX_USAGE);
        }
        eread_mmap(argc, argv);
    } else {
        if (argc < 3) {
            syntax("insufficient arguments for mandatory parameters");
            exit(EX_USAGE);
        }
        eread_ds(argc, argv);
    }

    if (opt.write) {
        ewrite_files(opt.write);
        return 0;
    }

    /* interpret the data */

    /* print vblock headers and adjust offsets */
    nv = table_len(vtab);
    for (i = 0; i < nv; ++i) {
        blk = table_at(vtab, i);
        print_vblk(blk);
        blk->buf += PAGE_SIZE; /* adjust so offsets are ordinal 0 */
    }

    /* print the kblocks, and perhaps the keys + values */
    nk = table_len(ktab);
    for (i = 0; i < nk; ++i) {
        blk = table_at(ktab, i);
        kblk = blk->buf;

        /* print the headers - always */
        print_kblk(blk);
        /* [HSE_REVISIT] Print blm only if there are keys in the main
         * wbtree
         */
        print_blm(blk);
        print_wbt(off2addr(kblk, omf_kbh_wbt_hoff(kblk)), kblk, false);
        printf("ptombs\n");
        print_wbt(off2addr(kblk, omf_kbh_pt_hoff(kblk)), kblk, true);
    }

    return 0;
}
