/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hse/cli/program.h>
#include <hse/hse.h>
#include <hse/ikvdb/diag_kvdb.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/omf_kmd.h>
#include <hse/mpool/mpool_structs.h>
#include <hse/mpool/mpool.h>
#include <hse/util/parse_num.h>
#include <hse/util/fmt.h>

#include "cn/omf.h"
#include "cn/wbt_internal.h"

#include "cndb_reader.h"
#include "cndb_record.h"
#include "fatal.h"
#include "globals.h"
#include "commands.h"

bool dumping_mblock;

/* command line options for kvset sub-command */
struct opts {
    uint64_t kvset_id;          // CNDB ID of kvset to dump
    uint32_t klen;
    uint32_t min_max_klen;
    uint32_t wbt_detail;
    bool bloom_detail;
    bool penc;
    const char *home;           // KVDB home dir
};

static struct opts opts;

struct dump_mblock {
    struct mblock_props props;
    const void         *data;
};

struct dump_kvset {
    struct cndb_rec     rec;
    struct dump_mblock  hblk;
    struct dump_mblock *kblkv;
    struct dump_mblock *vblkv;
};

static void
help(void)
{
    if (dumping_mblock)
        printf("usage: %s %s [options] <kvdb_home> <mblock_id>\n", progname, MBLOCK_COMMAND_NAME);
    else
        printf("usage: %s %s [options] <kvdb_home> <kvset_id>\n", progname, KVSET_COMMAND_NAME);

    printf(
        "  -h            print help\n"
        "  -b            show bloom filter details\n"
        "  -k N          show at most N bytes of wbt keys\n"
        "  -K N          show at most N bytes of kblock min/max keys\n"
        "  -p            show keys/values in percent encoded format\n"
        "  -v            verbose\n"
        "  -w N          set wbtree detail (0 <= N <= 3)\n"
        "  <kvdb_home>   KVDB home directory\n");
    if (dumping_mblock)
        printf("  <mblock_id>   mblock ID (from the CNDB log)\n");
    else
        printf("  <kvset_id>    kvset ID (from the CNDB log)\n");

    if (!global_opts.verbose) {
        printf("use '-hv' for more detail\n");
        return;
    }

    if (dumping_mblock)
        printf("\nDump an mblock on standard output. The type of mblock (hblock, kblock,\n"
            "or vblock) is determined automatically.  Mblock IDs can be seen in the\n"
            "output of '%s %s'.\n", progname, CNDB_COMMAND_NAME);
    else
        printf("\nDump a KVSET on standard output. Kvset IDs can be seen in the\n"
            "output of '%s %s'.\n", progname, CNDB_COMMAND_NAME);
}

static void
parse_args(int argc, char **argv)
{
    const char *arg;
    int c;

    while ((c = getopt(argc, argv, "+:hbk:K:pvw:")) != -1) {
        switch (c) {
        case 'h':
            global_opts.help = true;
            break;
        case 'b':
            opts.bloom_detail = true;
            break;
        case 'k':
            if (parse_u32(optarg, &opts.klen))
                syntax("invalid value for -%c: '%s'", c, optarg);
            break;
        case 'K':
            if (parse_u32(optarg, &opts.min_max_klen))
                syntax("invalid value for -%c: '%s'", c, optarg);
            break;
        case 'p':
            opts.penc = true;
            break;
        case 'v':
            global_opts.verbose = true;
            break;
        case 'w':
            if (parse_u32(optarg, &opts.wbt_detail))
                syntax("invalid value for -%c: '%s'", c, optarg);
            break;
        case ':':
            syntax("option -%c requires a parameter", optopt);
            break;
        default:
            syntax("invalid %s option: -%c", KVSET_COMMAND_NAME, optopt);
            break;
        }
    }

    if (global_opts.help) {
        help();
        exit(0);
    }

    if (optind == argc)
        syntax("missing <kvdb_home> parameter");

    opts.home = argv[optind++];

    if (optind == argc) {
        if (dumping_mblock)
            syntax("missing <mblock_id> parameter");
        else
            syntax("missing <kvset_id> parameter");
    }

    arg = argv[optind++];
    if (parse_u64(arg, &opts.kvset_id)) {
        if (dumping_mblock)
            syntax("invalid mblock ID: '%s' (cannot convert to uint64_t)", arg);
        else
            syntax("invalid kvset ID: '%s' (cannot convert to uint64_t)", arg);
    }

    if (optind != argc)
        syntax("unexpected parameter: '%s'", argv[optind]);
}

static char *
fmt_data(void **buf_ptr, size_t *bufsz_ptr, const void *data, size_t data_len,
    size_t limit, bool pct_encode)
{
    char *buf = *buf_ptr;
    size_t bufsz = *bufsz_ptr;
    size_t len = (limit && limit < data_len) ? limit : data_len;
    size_t output_len = pct_encode ? fmt_pe_buf_size(len) : fmt_hex_buf_size(len);

    if (bufsz < output_len) {
        void *p = realloc(buf, output_len);
        if (!p)
            fatal("realloc", merr(ENOMEM));
        buf = *buf_ptr = p;
        bufsz = *bufsz_ptr = output_len;
    }

    if (pct_encode)
        fmt_pe(buf, bufsz, data, len);
    else
        fmt_hex(buf, bufsz, data, len);

    return buf;
}

static void
dump_props(const struct mblock_props *p)
{
    printf("mbid 0x%lx alen %9u wlen %9u mclass %u\n",
        p->mpr_objid, p->mpr_alloc_cap, p->mpr_write_len, p->mpr_mclass);
}

static void
dump_kvset_props(struct dump_kvset *kvset)
{

    struct cndb_rec_kvset_add *rec = &kvset->rec.rec.kvset_add;

    printf("\n## mblock properties\n");
    printf("hblk %2u : ", 0);
    dump_props(&kvset->hblk.props);

    for (uint i = 0; i < rec->kblkc; i++) {
        printf("kblk %2u : ", i);
        dump_props(&kvset->kblkv[i].props);
    }

    for (uint i = 0; i < rec->vblkc; i++) {
        printf("vblk %2u : ", i);
        dump_props(&kvset->vblkv[i].props);
    }
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
    uint64_t       seq;
    uint           cnt;
    char           vinfo[128];
};

#define pgoff(x)         ((x)*PAGE_SIZE)

static bool
val_get_next(const void *kmd, size_t *off, struct kmd_vref *vref)
{
    const void *vdata;
    uint32_t    vlen;

    vref->vbidx = vref->vboff = vref->vlen = 0;

    if (vref->cnt-- == 0)
        return false;

    vref->vtype_off = *off;

    kmd_type_seq(kmd, off, &vref->vtype, &vref->seq);

    switch (vref->vtype) {
    case VTYPE_UCVAL:
        kmd_val(kmd, off, &vref->vbidx, &vref->vboff, &vref->vlen);
        snprintf( vref->vinfo, sizeof(vref->vinfo), "UCVAL clen %u vbidx %u vboff %u",
            vref->vlen, vref->vbidx, vref->vboff);
        break;
    case VTYPE_IVAL:
        kmd_ival(kmd, off, &vdata, &vlen);
        snprintf(vref->vinfo, sizeof(vref->vinfo), "IVAL len %u", vlen);
        break;
    case VTYPE_ZVAL:
        snprintf(vref->vinfo, sizeof(vref->vinfo), "ZVAL");
        break;
    case VTYPE_TOMB:
        snprintf(vref->vinfo, sizeof(vref->vinfo), "TOMB");
        break;
    case VTYPE_PTOMB:
        snprintf(vref->vinfo, sizeof(vref->vinfo), "PTOMB");
        break;
    default:
        snprintf(vref->vinfo, sizeof(vref->vinfo), "unknown %d", vref->vtype);
        vref->cnt = 0; /* force caller to next key */
    }

    return true;
}

/* Handles versions 3 & 4 */

char
fmt_wtype(uint magic, int isroot)
{
    return (
        isroot ? 'r'
               : (magic == WBT_LFE_NODE_MAGIC ? 'L' : (magic == WBT_INE_NODE_MAGIC ? 'i' : '?')));
}

static void
wbt_dump_node(const struct wbt_node_hdr_omf *wbn, uint version, const void *kmd, int pgno, int root)
{
    const struct wbt_ine_omf *ine;
    const struct wbt_lfe_omf *lfe;
    const void *kdata, *pfx;
    uint i, nkeys, klen, pfx_len;
    bool internal_node;
    uint hdr_sz;
    void *buf = NULL;
    size_t bufsz = 0;

    internal_node = omf_wbn_magic(wbn) == WBT_INE_NODE_MAGIC;
    hdr_sz = sizeof(struct wbt_node_hdr_omf);
    pfx_len = omf_wbn_pfx_len(wbn);
    pfx = ((void*)wbn) + hdr_sz;

    ine = (struct wbt_ine_omf *)(((void*)wbn) + hdr_sz + pfx_len);
    lfe = (struct wbt_lfe_omf *)(((void*)wbn) + hdr_sz + pfx_len);

    printf("    %c: pg %d  magic 0x%04x  nkeys %u  kmdoff %u  pfx_len %u  pfx %s\n",
        fmt_wtype(omf_wbn_magic(wbn), pgno == root), pgno, omf_wbn_magic(wbn),
        omf_wbn_num_keys(wbn), omf_wbn_kmd(wbn), pfx_len,
        fmt_data(&buf, &bufsz, pfx, pfx_len, opts.klen, opts.penc));

    if (opts.wbt_detail <= 2)
        goto out;

    nkeys = omf_wbn_num_keys(wbn);
    for (i = 0; i < nkeys; ++i, ++ine, ++lfe) {
        if (internal_node) {
            wbt_ine_key(wbn, ine, &kdata, &klen);

            printf(
                "      ine %-4d left %d  key %d,%d %s\n",
                (int)((void *)ine - (void*)wbn),
                omf_ine_left_child(ine),
                omf_ine_koff(ine),
                klen,
                fmt_data(&buf, &bufsz, kdata, klen, opts.klen, opts.penc));
        } else {
            size_t off;
            uint   j, cnt, lfe_kmd, koff, klen;

            struct kmd_vref vref;

            wbt_lfe_key(wbn, lfe, &kdata, &klen);

            koff = omf_lfe_koff(lfe);
            lfe_kmd = wbt_lfe_kmd(wbn, lfe);
            off = lfe_kmd;
            cnt = kmd_count(kmd, &off);
            vref.cnt = cnt;

            j = 1;
            while (val_get_next(kmd, &off, &vref)) {
                if (j == 1)
                    printf("      key: %u/%u lfe %-4u koff %-4u klen %-2u kmd %u key %s",
                        i, nkeys, (uint)((void *)lfe - (void*)wbn), koff, klen, lfe_kmd,
                        fmt_data(&buf, &bufsz, kdata, klen, opts.klen, opts.penc));
                if (j > 1)
                    printf("\n        ");
                else
                    printf(" ");
                printf("val: %u/%u kmd %lu seq %lu %s\n",
                    j, cnt, (ulong)off, vref.seq, vref.vinfo);
                j++;
            }
        }
    }
    if (internal_node) {
        printf("      ine %-4d right %d\n", (int)((void *)ine - (void*)wbn), omf_ine_left_child(ine));
    }

  out:
    free(buf);
}

static void
wbt_dump_nodes(const struct dump_mblock *mblk, const void *kmd, uint root)
{
    const void *p = mblk->data;
    const struct kblock_hdr_omf *kbh = p;
    const struct wbt_hdr_omf *wbt = p + omf_kbh_wbt_hoff(kbh);
    const struct wbt_node_hdr_omf *wbn;
    int pgno, column, indent;
    uint magic, omagic = 0;
    const char *sep;

    printf("  wbt node list:\n");

    column = 0;
    for (pgno = 0; pgno <= root; pgno++) {
        wbn = p + pgoff(pgno + omf_kbh_wbt_doff_pg(kbh));

        if (opts.wbt_detail > 1) {

            wbt_dump_node(wbn, omf_wbt_version(wbt), kmd, pgno, root);

        } else {

            magic = omf_wbn_magic(wbn);
            if (pgno == root)
                omagic = 0; /* force line break */
            if (magic != omagic || column == 8) {
                column = 0;
                printf("\n");
                indent = 4;
            }

            indent = column == 0 ? 4 : 0;
            sep = column == 0 ? "" : " ";
            printf("%*s%s%c %4d %3d", indent, "", sep,
                fmt_wtype(magic, pgno == root), pgno, omf_wbn_num_keys(wbn));
            omagic = magic;
            column++;
        }
    }

    printf("\n");
}

static void
wbt_dump_impl(struct dump_mblock *mblk, const struct wbt_hdr_omf *wbt)
{
    const void *p = mblk->data;
    const struct kblock_hdr_omf *kbh = p;
    uint wbt_doff = omf_kbh_wbt_doff_pg(kbh);
    const uint8_t *kmd = p + pgoff(wbt_doff + omf_wbt_root(wbt) + 1);

    printf("  wbthdr: magic 0x%08x  ver %d  root %d  leaf %d  leaf_cnt %d kmd_pgc %d\n",
        omf_wbt_magic(wbt), omf_wbt_version(wbt), omf_wbt_root(wbt),
        omf_wbt_leaf(wbt), omf_wbt_leaf_cnt(wbt), omf_wbt_kmd_pgc(wbt));

    if (opts.wbt_detail > 0)
        wbt_dump_nodes(mblk, kmd, omf_wbt_root(wbt));
}

static void
wbt_dump(struct dump_mblock *mblk)
{
    const struct wbt_hdr_omf *wbt = mblk->data + omf_kbh_wbt_hoff(mblk->data);

    switch (omf_wbt_version(wbt)) {
    case WBT_TREE_VERSION:
        wbt_dump_impl(mblk, wbt);
        break;
    default:
        printf("Invalid wbtree magic and/or version\n");
        break;
    }
}

static int
bloom_bits_in_block(const void *mem, size_t blksz)
{
    const long *p = mem;
    const long *end = p + blksz / sizeof(*p);
    int         cnt = 0;

    while (p < end)
        cnt += __builtin_popcountl(*p++);

    return cnt;
}

static int
bloom_bkt_cmp(const void *lhs, const void *rhs)
{
    const uint *l = lhs;
    const uint *r = rhs;

    if (*l < *r)
        return -1;
    if (*l > *r)
        return 1;
    return 0;
}

static void
bloom_dump(struct dump_mblock *mblk)
{
    const void *p = mblk->data;
    const struct kblock_hdr_omf *kbh = p;
    const struct bloom_hdr_omf  *bh = p + omf_kbh_blm_hoff(kbh);
    const uint8_t *bitmap;
    size_t bitmapsz;
    size_t bktsz, bitsperbkt;
    size_t doff, dlen;
    uint *cntv, cntmin, cntmax;
    uint cntsum, cntempty, cntfull;
    uint bktmax;
    uint i, j;

    bktsz = (1u << omf_bh_bktshift(bh)) / 8;
    bitsperbkt = bktsz * CHAR_BIT;

    printf(
        "  bloom hdr: magic 0x%08x  ver %u bktsz %lu  rotl %u  "
        "hashes %u  bitmapsz %u  modulus %u\n",
        omf_bh_magic(bh),
        omf_bh_version(bh),
        bktsz,
        omf_bh_rotl(bh),
        omf_bh_n_hashes(bh),
        omf_bh_bitmapsz(bh),
        omf_bh_modulus(bh));

    doff = omf_kbh_blm_doff_pg(kbh) * PAGE_SIZE;
    dlen = omf_kbh_blm_dlen_pg(kbh) * PAGE_SIZE;

    if (mblk->props.mpr_write_len < doff + dlen)
        return;

    bitmap = p + doff;
    bitmapsz = omf_bh_bitmapsz(bh);

    if (!bitmapsz || !bktsz)
        return;

    bktmax = bitmapsz / bktsz;

    cntv = calloc(bktmax, sizeof(*cntv));
    if (!cntv)
        fatal("calloc", merr(ENOMEM));

    cntmax = cntsum = cntempty = cntfull = 0;
    cntmin = UINT_MAX;

    for (i = 0; i < bktmax; ++i) {
        cntv[i] = bloom_bits_in_block(bitmap, bktsz);
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

    qsort(cntv, bktmax, sizeof(*cntv), bloom_bkt_cmp);

    printf("  bloom bucket size:   %5lu (%lu bits)\n", bktsz, bitsperbkt);
    printf("  bloom empty buckets: %5u\n", cntempty);
    printf("  bloom full buckets:  %5u\n", cntfull);

    printf("  bloom dist    min:  %6.3lf (%u / %zu)\n",
        (double)cntv[0] / bitsperbkt, cntv[0], bitsperbkt);

    printf("  bloom dist    .3%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 3 / 1000] / bitsperbkt, cntv[bktmax * 3 / 1000], bitsperbkt);

    printf("  bloom dist   2.1%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 21 / 1000] / bitsperbkt, cntv[bktmax * 21 / 1000], bitsperbkt);

    printf("  bloom dist median:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax / 2] / bitsperbkt, cntv[bktmax / 2], bitsperbkt);

    printf("  bloom dist   mean:  %6.3lf (%u / %zu)\n",
        (double)(cntsum / bktmax) / bitsperbkt, (cntsum / bktmax), bitsperbkt);

    printf("  bloom dist  97.9%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 979 / 1000] / bitsperbkt, cntv[bktmax * 979 / 1000], bitsperbkt);

    printf("  bloom dist  99.7%%:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax * 997 / 1000] / bitsperbkt, cntv[bktmax * 997 / 1000], bitsperbkt);

    printf("  bloom dist    max:  %6.3lf (%u / %zu)\n",
        (double)cntv[bktmax - 1] / bitsperbkt, cntv[bktmax - 1], bitsperbkt);

    if (opts.bloom_detail) {
        printf("  bloom buckets sorted by bit pop:\n");
        for (i = 0; i < bktmax; i += 8) {
            printf("    %8u  ", i);
            for (j = 0; j < 8; j++) {
                if (i + j >= bktmax)
                    break;
                printf("  %5.3lf", (double)cntv[i + j] / bitsperbkt);
            }
            printf("\n");
        }
    }

    free(cntv);
}

static void
hblock_dump(struct dump_mblock *mblk)
{
    const void *p = mblk->data;
    const struct hblock_hdr_omf *hbh = p;
    uint pg, pgc;

    printf("\nhblock: ");

    dump_props(&mblk->props);

    printf("  magic 0x%08x  ver %d  minseq %lu  maxseq  %lu  ptombs %u  kblocks %u  vblocks %u\n",
        omf_hbh_magic(hbh), omf_hbh_version(hbh),
        omf_hbh_min_seqno(hbh), omf_hbh_min_seqno(hbh),
        omf_hbh_num_ptombs(hbh), omf_hbh_num_kblocks(hbh), omf_hbh_num_vblocks(hbh));

    pg  = omf_hbh_vgmap_off_pg(hbh);
    pgc = omf_hbh_vgmap_len_pg(hbh);
    printf("  vgmap pages [%u..%u], pgc %u\n", pg, pg + pgc - 1, pgc);

    pg  = omf_hbh_hlog_off_pg(hbh);
    pgc = omf_hbh_hlog_len_pg(hbh);
    printf("  hlog  pages [%u..%u], pgc %u\n", pg, pg + pgc - 1, pgc);

    pg  = omf_hbh_ptree_data_off_pg(hbh);
    pgc = omf_hbh_ptree_data_len_pg(hbh);
    printf("  ptree pages [%u..%u], pgc %u\n", pg, pg + pgc - 1, pgc);

    printf("  max_ptomb byte off/len %u %u, min_ptomb off/len %u %u\n",
        omf_hbh_max_pfx_off(hbh),
        omf_hbh_max_pfx_len(hbh),
        omf_hbh_min_pfx_off(hbh),
        omf_hbh_min_pfx_len(hbh));

    /* TODO: dump the ptomb tree */
}

static void
kblock_dump(struct dump_mblock *mblk)
{
    const void *p = mblk->data;
    const struct kblock_hdr_omf *kbh = p;
    const struct wbt_hdr_omf *   wbt = p + omf_kbh_wbt_hoff(kbh);
    const struct bloom_hdr_omf  *bh = p + omf_kbh_blm_hoff(kbh);

    void *buf = NULL;
    size_t bufsz = 0;

    printf("\nkblock: ");
    dump_props(&mblk->props);
    printf("  magic 0x%08x  ver %d  nkey %d  ntomb %d\n",
        omf_kbh_magic(kbh), omf_kbh_version(kbh), omf_kbh_entries(kbh), omf_kbh_tombs(kbh));

    printf("  metrics: keys %u tombs %u key_bytes %u val_bytes %lu\n",
        omf_kbh_entries(kbh),
        omf_kbh_tombs(kbh),
        omf_kbh_key_bytes(kbh),
        omf_kbh_val_bytes(kbh));

    printf("  wbt: hdr %d %d  data_pg %d %d  ver %u\n",
        omf_kbh_wbt_hoff(kbh),
        omf_kbh_wbt_hlen(kbh),
        omf_kbh_wbt_doff_pg(kbh),
        omf_kbh_wbt_dlen_pg(kbh),
        omf_wbt_version(wbt));

    printf("  bloom: hdr %d %d  data_pg %d %d  ver %u\n",
        omf_kbh_blm_hoff(kbh),
        omf_kbh_blm_hlen(kbh),
        omf_kbh_blm_doff_pg(kbh),
        omf_kbh_blm_dlen_pg(kbh),
        omf_bh_version(bh));

    printf("  kmd: start_pg %u\n",
        omf_kbh_wbt_doff_pg(kbh) + omf_wbt_root(wbt) + 1);

    printf("  keymin: off %u len %u key %s\n",
        omf_kbh_min_koff(kbh),
        omf_kbh_min_klen(kbh),
        fmt_data(&buf, &bufsz, p + omf_kbh_min_koff(kbh), omf_kbh_min_klen(kbh),
            opts.min_max_klen, opts.penc));

    printf("  keymax: off %u len %u key %s\n",
        omf_kbh_max_koff(kbh),
        omf_kbh_max_klen(kbh),
        fmt_data(&buf, &bufsz, p + omf_kbh_max_koff(kbh), omf_kbh_max_klen(kbh),
            opts.min_max_klen, opts.penc));

    bloom_dump(mblk);
    wbt_dump(mblk);
    free(buf);
}

static void
vblock_dump(struct dump_mblock *mblk)
{
    const struct vblock_footer_omf *vbf;
    uint min_koff, min_klen, max_koff, max_klen;
    uint32_t magic, version;
    uint64_t vgroup;
    void *buf = NULL;
    size_t bufsz = 0;

    vbf = mblk->data + mblk->props.mpr_write_len - VBLOCK_FOOTER_LEN;

    printf("vblock: ");
    dump_props(&mblk->props);

    magic = omf_vbf_magic(vbf);
    version = omf_vbf_version(vbf);
    printf("  magic 0x%x vers %u\n", magic, version);

    if (magic != VBLOCK_FOOTER_MAGIC) {
        printf("  BAD MAGIC: found 0x%x, expected 0x%x\n", magic, VBLOCK_FOOTER_MAGIC);
        return;
    }

    if (version != VBLOCK_FOOTER_VERSION) {
        printf("  UNSUPPORTED VERSION: found %u, expected %u\n", version, VBLOCK_FOOTER_VERSION);
        return;
    }

    min_koff = mblk->props.mpr_write_len - (2 * HSE_KVS_KEY_LEN_MAX);
    max_koff = mblk->props.mpr_write_len - HSE_KVS_KEY_LEN_MAX;

    min_klen = omf_vbf_min_klen(vbf);
    max_klen = omf_vbf_max_klen(vbf);

    vgroup = omf_vbf_vgroup(vbf);

    printf("  vgroup: %lu\n", vgroup);

    printf("  min_key: off %u len %u key %s\n",
        min_koff, min_klen,
        fmt_data(&buf, &bufsz, mblk->data + min_koff, min_klen, opts.klen, opts.penc));

    printf("  max_key: off %u len %u key %s\n",
        max_koff, max_klen,
        fmt_data(&buf, &bufsz, mblk->data + max_koff, max_klen, opts.klen, opts.penc));

    free(buf);
}

static void
mblock_dump(struct dump_mblock *mblk)
{
    const struct kblock_hdr_omf *kbh = mblk->data;
    const struct hblock_hdr_omf *hbh = mblk->data;

    if (hbh->hbh_magic == HBLOCK_HDR_MAGIC) {
        hblock_dump(mblk);
        return;
    }

    if (kbh->kbh_magic == KBLOCK_HDR_MAGIC) {
        kblock_dump(mblk);
        return;
    }

    vblock_dump(mblk);
}

static void
dump_kvset_mblocks(struct dump_kvset *kvset)
{
    struct cndb_rec_kvset_add *rec = &kvset->rec.rec.kvset_add;

    printf("\n## Header Block\n");
    mblock_dump(&kvset->hblk);

    printf("\n## Key Blocks\n");
    for (uint i = 0; i < rec->kblkc; i++)
        mblock_dump(&kvset->kblkv[i]);

    printf("\n## Value Blocks\n");
    for (uint i = 0; i < rec->vblkc; i++)
        mblock_dump(&kvset->vblkv[i]);
}

static void
dkvset_init(struct dump_kvset *kvset, struct cndb_rec *rec)
{
    memset(kvset, 0, sizeof(*kvset));
    cndb_rec_clone(rec, &kvset->rec);
}

static void
get_props(struct mpool *mp, uint64_t mbid, struct mblock_props *props)
{
    merr_t err;

    err = mpool_mblock_props_get(mp, mbid, props);
    if (err)
        fatal("mpool_mblock_props_get", err);
}

static void
read_mblock(struct mpool *mp, struct dump_mblock *mblk)
{
    struct iovec iov;
    size_t wlen;
    merr_t err;
    void *data;

    wlen = mblk->props.mpr_write_len;

    data = aligned_alloc(PAGE_SIZE, ALIGN(wlen, PAGE_SIZE));
    if (!data)
        fatal("aligned_alloc", merr(errno));

    memset(data, 0xbe, wlen);

    iov.iov_base = data;
    iov.iov_len = wlen;

    err = mpool_mblock_read(mp, mblk->props.mpr_objid, &iov, 1, 0);
    if (err)
        fatal("mpool_mblock_read", err);

    mblk->data = data;
}

static void
dkvset_read_props(struct mpool *mp, struct dump_kvset *kvset)
{
    struct cndb_rec_kvset_add *rec = &kvset->rec.rec.kvset_add;

    kvset->kblkv = calloc(rec->kblkc, sizeof(kvset->kblkv[0]));
    kvset->vblkv = calloc(rec->vblkc, sizeof(kvset->vblkv[0]));
    if (!kvset->kblkv || !kvset->vblkv)
        fatal("calloc", merr(ENOMEM));

    get_props(mp, rec->hblkid, &kvset->hblk.props);

    for (uint i = 0; i < rec->kblkc; i++)
        get_props(mp, rec->kblkv[i], &kvset->kblkv[i].props);

    for (uint i = 0; i < rec->vblkc; i++)
        get_props(mp, rec->vblkv[i], &kvset->vblkv[i].props);
}

static void
dkvset_read_mblocks(struct mpool *mp, struct dump_kvset *kvset)
{
    struct cndb_rec_kvset_add *rec = &kvset->rec.rec.kvset_add;

    read_mblock(mp, &kvset->hblk);

    for (uint i = 0; i < rec->kblkc; i++)
        read_mblock(mp, &kvset->kblkv[i]);

    for (uint i = 0; i < rec->vblkc; i++)
        read_mblock(mp, &kvset->vblkv[i]);
}

static void
dkvset_fini(struct dump_kvset *kvset)
{
    struct cndb_rec_kvset_add *rec = &kvset->rec.rec.kvset_add;

    free((void *)kvset->hblk.data);

    if (kvset->kblkv) {
        for (uint i = 0; i < rec->kblkc; i++)
            free((void *)kvset->kblkv[i].data);
        free(kvset->kblkv);
    }

    if (kvset->vblkv) {
        for (uint i = 0; i < rec->vblkc; i++)
            free((void *)kvset->vblkv[i].data);
        free(kvset->vblkv);
    }

    cndb_rec_fini(&kvset->rec);

}

void
kvset_cmd(int argc, char **argv)
{
    const char *paramv[] = { "rest.enabled=false" };
    struct cndb_dump_reader reader;
    struct cndb_rec rec;
    struct dump_kvset kvset;
    struct hse_kvdb *kvdb;
    struct mpool *mp;
    bool found = false;
    merr_t err;

    dumping_mblock = false;

    parse_args(argc, argv);

    err = hse_init(0, NELEM(paramv), paramv);
    if (err)
        fatal("hse_init", err);

    err = diag_kvdb_open(opts.home, 0, 0, &kvdb);
    if (err)
        fatal("diag_kvdb_open", err);

    printf("# Kvset ID %lu\n", opts.kvset_id);

    cndb_rec_init(&rec);
    cndb_iter_init(kvdb, &reader);

    while (cndb_iter_next(&reader, &rec)) {

        if (rec.type == CNDB_TYPE_KVSET_ADD) {

            if (rec.rec.kvset_add.kvsetid != opts.kvset_id)
                continue;

            if (found)
                fatal("CDNB log has two kvsets with same ID", merr(EPROTO));

            found = true;
            dkvset_init(&kvset, &rec);

        } else if (rec.type == CNDB_TYPE_KVSET_DEL) {

            if (rec.rec.kvset_del.kvsetid == opts.kvset_id)
                fatal("kvset no longer exists", merr(EINVAL));
        }
    }

    if (!found)
        fatal("no such kvset", merr(EINVAL));

    cndb_rec_fini(&rec);

    printf("\n## CDNB record:\n");
    cndb_rec_print(&kvset.rec, false);

    mp = ikvdb_mpool_get((struct ikvdb *)kvdb);

    dkvset_read_props(mp, &kvset);
    dump_kvset_props(&kvset);

    dkvset_read_mblocks(mp, &kvset);
    dump_kvset_mblocks(&kvset);

    dkvset_fini(&kvset);

    err = diag_kvdb_close(kvdb);
    if (err)
        fatal("diag_kvdb_close", err);

    hse_fini();
}

void
mblock_cmd(int argc, char **argv)
{
    const char *paramv[] = { "rest.enabled=false" };
    struct hse_kvdb *kvdb;
    struct mpool *mp;
    struct dump_mblock mblk = { 0 };
    uint64_t mbid;
    merr_t err;

    dumping_mblock = true;

    parse_args(argc, argv);

    mbid = opts.kvset_id;

    err = hse_init(0, NELEM(paramv), paramv);
    if (err)
        fatal("hse_init", err);

    err = diag_kvdb_open(opts.home, 0, 0, &kvdb);
    if (err)
        fatal("diag_kvdb_open", err);

    mp = ikvdb_mpool_get((struct ikvdb *)kvdb);

    get_props(mp, mbid, &mblk.props);
    read_mblock(mp, &mblk);
    mblock_dump(&mblk);

    free((void *)mblk.data);

    err = diag_kvdb_close(kvdb);
    if (err)
        fatal("diag_kvdb_close", err);

    hse_fini();
}
