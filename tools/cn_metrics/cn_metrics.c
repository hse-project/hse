/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>

#include <cn/cn_metrics.h>
#include <cn/cn_tree.h>
#include <cn/cn_tree_internal.h>
#include <cn/cn_tree_iter.h>
#include <cn/kvset.h>

#include <hse/hse.h>

#include <hse_util/parse_num.h>

#include <tools/parm_groups.h>
#include <tools/common.h>

#include <mpool/mpool.h>

#include <sysexits.h>

const char *progname;

void
usage(void)
{
    printf("usage: %s [options] kvdb_home kvs\n", progname);

    printf("-b      show all kblock/vblock IDs\n"
           "-f FMT  set output format\n"
           "-h      show this help list\n"
           "-l      use alternate node loc format\n"
           "-n      show node-level data only (skip kvsets)\n"
           "-y      output tree shape in yaml\n"
           "FMT  h=human(default), s=scalar, x=hex, e=exp\n"
           "\n");

    printf("%s shows detailed cn tree metrics such as tree structure,\n"
        "number of kvsets/kblocks/vblocks per node, number of keys/kblocks/vblocks\n"
        "per kvset, and kblock/vblock untilization.\n", progname);
}

void
syntax(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

/* Big enough for s64 min/max, u64 max, etc */
#define BIGNUM_WIDTH_MAX 21 /* max width for signed 64-bit */

#define BIGNUM_BUFSZ (BIGNUM_WIDTH_MAX + 1)

enum bn_fmt {
    BN_HUMAN = 0, /* 123.45m   */
    BN_EXP,       /* 123.45e06 */
    BN_SCALAR,    /* 123456789 */
    BN_HEX1,      /* 0x75bcd15 */
    BN_HEX2       /* 75bcd15   */
};

int
bn_width(enum bn_fmt fmt)
{
    switch (fmt) {
        case BN_HEX1:
            return 12;
        case BN_HEX2:
            return 12;
        case BN_SCALAR:
            return 14;
        case BN_HUMAN:
            return 7;
        case BN_EXP:
            return 9;
    }
    return 12;
}

int
bn_width_max(enum bn_fmt fmt)
{
    switch (fmt) {
        case BN_HEX1:
            return 18;
        case BN_HEX2:
            return 16;
        case BN_SCALAR:
            return BIGNUM_WIDTH_MAX;
        case BN_HUMAN:
            return 7;
        case BN_EXP:
            return 9;
    }
    return 12;
}

char
bn_human_sfx(uint exp)
{
    char sfx;

    switch (exp) {
        case 3:
            sfx = 'k';
            break;
        case 6:
            sfx = 'm';
            break;
        case 9:
            sfx = 'g';
            break;
        case 12:
            sfx = 't';
            break;
        case 15:
            sfx = 'p';
            break;
        case 18:
            sfx = 'e';
            break;
        case 21:
            sfx = 'z';
            break;
        case 24:
            sfx = 'y';
            break;
        default:
            sfx = '?';
            break;
    }

    return sfx;
}

char *
bn64(char *buf, size_t buf_sz, enum bn_fmt fmt, u64 value)
{
    unsigned exp = 0;
    u64      pv = 0;

    int n HSE_MAYBE_UNUSED;

    switch (fmt) {
        case BN_HEX1:
            n = snprintf(buf, buf_sz, "0x%lx", value);
            break;

        case BN_HEX2:
            n = snprintf(buf, buf_sz, "%lx", value);
            break;

        case BN_SCALAR:
            n = snprintf(buf, buf_sz, "%lu", value);
            break;

        default:
            while (value >= 1000) {
                exp += 3;
                pv = value;
                value /= 1000;
            }

            if (exp == 0) {

                n = snprintf(buf, buf_sz, "%*lu", bn_width_max(fmt), value);

            } else {
                /* In human readable and exponential form,
             * We use format printf("%3lu.%02lu",v,pv)
             * to show 2 places after decimal.
             * To get that, we do:
             *    pv = (pv % 1000) / 10;
             * Example:
             *   Original value:    1,234,567
             *   After above loop:  v=1; pv=1234; exp=3;
             *   Want to print:     1.23k
             *   After:  pv = (pv % 1000)/10,
             *   Then:   pv = 23
             *   So:     printf(v,pv,"%3lu.%02lu")
             *   Ouput:  "1.23"
             */

                pv = (pv % 1000) / 10;

                if (fmt == BN_HUMAN) {
                    n = snprintf(buf, buf_sz, "%3lu.%02lu%c", value, pv, bn_human_sfx(exp));

                } else {
                    n = snprintf(buf, buf_sz, "%3lu.%02lue%02u", value, pv, exp);
                }
            }
            break;
    }

    assert(n > 0 && n < buf_sz);

    return buf;
}

struct options {
    const char *kvdb_home;
    const char *kvs;

    uint bnfmt; /* big number format */
    int  nodes_only;
    int  all_blocks;
    int  yaml_output;
    int  alternate_loc;

    /* derived */
    char *loc_hdr;
    char *loc_fmt;
    int   bnfw; /* big number field width */
};

struct options opt;

void
process_options(int argc, char *argv[])
{
    int c;

    while ((c = getopt(argc, argv, ":bf:hlny")) != -1) {
        switch (c) {
            case 'h':
                usage();
                exit(0);
            case 'b':
                opt.all_blocks = 1;
                break;
            case 'l':
                opt.alternate_loc = 1;
                break;
            case 'n':
                opt.nodes_only = 1;
                break;
            case 'f':
                switch (optarg[0]) {
                    case 'h':
                        opt.bnfmt = BN_HUMAN;
                        break;
                    case 'x':
                        opt.bnfmt = BN_HEX1;
                        break;
                    case 's':
                        opt.bnfmt = BN_SCALAR;
                        break;
                    case 'e':
                        opt.bnfmt = BN_EXP;
                        break;
                }
                break;

            case 'y':
                opt.yaml_output = 1;
                break;
            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                syntax("option -%c ignored\n", c);
                break;
        }
    }

    if (argc - optind < 2) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    opt.kvdb_home = argv[optind++];
    opt.kvs = argv[optind++];
}

struct rollup {
    struct kvset_metrics km;
    struct kvset_stats   ks;
    struct cn_node_loc   loc;
    u64                  dgen;
};

void
rollup(struct rollup *from, struct rollup *to)
{
    kvset_stats_add(&from->ks, &to->ks);

    to->km.num_keys += from->km.num_keys;
    to->km.num_tombstones += from->km.num_tombstones;
    to->km.num_kblocks += from->km.num_kblocks;
    to->km.num_vblocks += from->km.num_vblocks;
    to->km.tot_key_bytes += from->km.tot_key_bytes;
    to->km.tot_val_bytes += from->km.tot_val_bytes;
    to->km.tot_wbt_pages += from->km.tot_wbt_pages;
    to->km.tot_blm_pages += from->km.tot_blm_pages;
    to->km.tot_blm_pages += from->km.tot_blm_pages;

    to->loc.node_level = max(to->loc.node_level, from->loc.node_level);
    to->loc.node_offset = max(to->loc.node_offset, from->loc.node_offset);

    to->dgen = max(to->dgen, from->dgen);
}

struct ctx {

    struct rollup rtotal;
    struct rollup rnode;
    struct rollup rkvset;

    uint node_kvsets;

    uint tree_kvsets;
    uint tree_nodes;

    bool header_done;
};

static void
print_ids(
    struct kvset *kvset,
    u32 (*get_count)(struct kvset *),
    u64 (*get_nth)(struct kvset *, u32),
    int max)
{
    int i, n = get_count(kvset);

    if (max == 0 || n < max)
        max = n;

    for (i = 0; i < max; ++i)
        printf(" 0x%08lx", get_nth(kvset, i));
    if (n > max)
        printf(" ...");
}

const char *hdrv[] = { "H",       "Loc",     "Dgen",   "Keys",   "Tombs",
                       "AvgKlen", "AvgVlen", "KbAlen", "VbAlen", "KbWlen%",
                       "VbWlen%", "VbUlen%", "Comps",  "Kbs",    "Vbs" };

#define FMT_HDR                \
    "%s %-12s %5s "            \
    "%*s %*s %*s %*s %*s %*s " \
    "%7s %7s %7s "             \
    "%5s %4s %4s"

#define FMT_ROW                \
    "%s %-12s %5lu "           \
    "%*s %*s %*s %*s %*s %*s " \
    "%7.1f %7.1f %7.1f "       \
    "%5u %4u %4u%s"

#define BN(_buf, _val) bn64((_buf), sizeof((_buf)), opt.bnfmt, (_val))

#define DIVZ(_a, _b) ((_b) ? (_a) / (_b) : 0)

static void
print_row(char *tag, struct rollup *r, uint index, char *sep)
{
    char locbuf[33]; /* 3 integers + 2 commas + NUL */

    char nkeys[BIGNUM_BUFSZ];
    char ntombs[BIGNUM_BUFSZ];

    char kalen[BIGNUM_BUFSZ];
    char valen[BIGNUM_BUFSZ];

    char avg_klen[BIGNUM_BUFSZ];
    char avg_vlen[BIGNUM_BUFSZ];

    sprintf(locbuf, opt.loc_fmt, r->loc.node_level, r->loc.node_offset, index);

    BN(nkeys, r->ks.kst_keys);
    BN(ntombs, r->km.num_tombstones);

    BN(kalen, r->ks.kst_kalen);
    BN(valen, r->ks.kst_valen);

    BN(avg_klen, DIVZ(r->km.tot_key_bytes, r->km.num_keys));
    BN(avg_vlen, DIVZ(r->km.tot_val_bytes, r->km.num_keys));

    printf(
        FMT_ROW,
        tag,
        locbuf,
        r->dgen,
        opt.bnfw,
        nkeys,
        opt.bnfw,
        ntombs,
        opt.bnfw,
        avg_klen,
        opt.bnfw,
        avg_vlen,
        opt.bnfw,
        kalen,
        opt.bnfw,
        valen,
        DIVZ(100.0 * r->ks.kst_kwlen, r->ks.kst_kalen),
        DIVZ(100.0 * r->ks.kst_vwlen, r->ks.kst_valen),
        DIVZ(100.0 * r->ks.kst_vulen, r->ks.kst_valen),
        r->km.compc,
        r->ks.kst_kblks,
        r->ks.kst_vblks,
        sep);
}

static void
print_hdr(void)
{
    printf(
        FMT_HDR "%s\n",
        hdrv[0],
        opt.loc_hdr,
        hdrv[2],
        opt.bnfw,
        hdrv[3],
        opt.bnfw,
        hdrv[4],
        opt.bnfw,
        hdrv[5],
        opt.bnfw,
        hdrv[6],
        opt.bnfw,
        hdrv[7],
        opt.bnfw,
        hdrv[8],
        hdrv[9],
        hdrv[10],
        hdrv[11],
        hdrv[12],
        hdrv[13],
        hdrv[14],
        (opt.nodes_only ? "" : " KblockIDs  / VblockIDs"));
}

static int
tree_walk_callback(
    void *               rock,
    struct cn_tree *     tree,
    struct cn_tree_node *node,
    struct cn_node_loc * loc,
    struct kvset *       kvset)
{
    struct ctx *   c = (struct ctx *)rock;
    struct rollup *k = &c->rkvset;
    struct rollup *n = &c->rnode;
    struct rollup *t = &c->rtotal;

    if (!node) {
        /* Finish current tree */
        t->loc.node_level = c->tree_nodes;
        printf("\n");
        print_hdr();
        print_row("t", t, c->tree_kvsets, "\n");
        memset(t, 0, sizeof(*t));
        return 0;
    }

    if (!kvset) {
        /* Finish current node */
        struct cn_node_stats ns;

        c->tree_nodes++;
        rollup(n, t);
        if (opt.nodes_only && c->tree_nodes == 1)
            print_hdr();
        print_row("n", n, c->node_kvsets, "\n");

        cn_node_stats_get(node, &ns);

        printf(
            "#Node pcap%% %u scatter %u kuniq%% %6.1f "
            "KbClen%% %6.1f VbClen%% %6.1f samp %6.1f\n",
            ns.ns_pcap,
            ns.ns_scatter,
            DIVZ(1e2 * ns.ns_keys_uniq, cn_ns_keys(&ns)),
            DIVZ(1e2 * ns.ns_kclen, n->ks.kst_kalen),
            DIVZ(1e2 * ns.ns_vclen, n->ks.kst_valen),
            cn_ns_samp(&ns) / 1e2);

        memset(n, 0, sizeof(*n));
        c->node_kvsets = 0;
        return 0;
    }

    /* New Kvset */
    memset(k, 0, sizeof(*k));
    kvset_get_metrics(kvset, &k->km);
    kvset_stats(kvset, &k->ks);
    k->dgen = kvset_get_dgen(kvset);
    k->loc = *loc;
    rollup(k, n);

    c->tree_kvsets++;
    c->node_kvsets++;

    if (!opt.nodes_only) {
        int limit = opt.all_blocks ? 0 : 2;

        if (c->node_kvsets == 1) {
            if (c->tree_kvsets > 1)
                printf("\n");
            print_hdr();
        }

        print_row("k", k, c->node_kvsets - 1, "");
        print_ids(kvset, kvset_get_num_kblocks, kvset_get_nth_kblock_id, limit);
        printf(" /");
        print_ids(kvset, kvset_get_num_vblocks, kvset_get_nth_vblock_id, limit);
        printf("\n");
    }

    return 0;
}

int
main(int argc, char **argv)
{
    const char *       errmsg = NULL;
    struct ctx         ctx;
    struct cn *        cn = NULL;
    struct hse_kvdb *  kd = NULL;
    struct hse_kvs *   kvs = NULL;
    hse_err_t          rc;

    struct parm_groups *pg = NULL;
    struct svec         hse_gparm = { 0 };
    struct svec         db_oparm = { 0 };
    struct svec         kv_oparm = { 0 };

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "pg_create");

    memset(&opt, 0, sizeof(opt));
    opt.bnfmt = BN_HUMAN;
    process_options(argc, argv);

    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
        case 0:
            if (optind < argc)
                fatal(0, "unknown parameter: %s", argv[optind]);
            break;
        case EINVAL:
            fatal(0, "missing group name (e.g. %s) before parameter %s\n",
                PG_KVDB_OPEN, argv[optind]);
            break;
        default:
            fatal(rc, "error processing parameter %s\n", argv[optind]);
            break;
    }

    rc = rc ?: svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ?: svec_append_pg(&db_oparm, pg, "perfc_enable=0", PG_KVDB_OPEN, "read_only=true", NULL);
    rc = rc ?: svec_append_pg(&kv_oparm, pg, PG_KVS_OPEN, "cn_diag_mode=true", "cn_maint_disable=true", NULL);
    if (rc)
        fatal(rc, "svec_apppend_pg failed");

    rc = hse_init(opt.kvdb_home, hse_gparm.strc, hse_gparm.strv);
    if (rc) {
        errmsg = "kvdb_init";
        goto done;
    }

    rc = hse_kvdb_open(opt.kvdb_home, db_oparm.strc, db_oparm.strv, &kd);
    if (rc) {
        errmsg = "kvdb_open";
        goto done;
    }

    rc = hse_kvdb_kvs_open(kd, opt.kvs, kv_oparm.strc, kv_oparm.strv, &kvs);
    if (rc) {
        errmsg = "kvs_open";
        goto done;
    }

    if (opt.yaml_output) {
        char                yaml_buf[4096]; /* Meant to fit one line of the yaml output */
        struct yaml_context yc = {
            .yaml_indent = 0,
            .yaml_offset = 0,
            .yaml_buf = yaml_buf,
            .yaml_buf_sz = sizeof(yaml_buf),
            .yaml_emit = NULL,
        };

        rc = ikvdb_kvs_query_tree(kvs, &yc, STDOUT_FILENO, opt.all_blocks);
    } else {
        /* derived options */
        opt.bnfw = bn_width(opt.bnfmt);
        if (opt.alternate_loc) {
            opt.loc_hdr = "Lvl Off Idx";
            opt.loc_fmt = "%3d %3d %3d";
        } else {
            opt.loc_hdr = "Loc";
            opt.loc_fmt = "%d,%d,%d";
        }

        cn = ikvdb_kvs_get_cn(kvs);
        if (!cn) {
            errmsg = "cn_open";
            rc = EBUG;
            goto done;
        }

        struct cn_tree *tree = cn_get_tree(cn);

        memset(&ctx, 0, sizeof(ctx));
        cn_tree_preorder_walk(tree, KVSET_ORDER_NEWEST_FIRST, tree_walk_callback, &ctx);
    }

done:
    if (errmsg) {
        char errbuf[1000];
        hse_strerror(rc, errbuf, sizeof(errbuf));
        fprintf(stderr, "Error: %s failed: %s\n", errmsg, errbuf);
    }

    if (kvs)
        hse_kvdb_kvs_close(kvs);

    if (kd)
        hse_kvdb_close(kd);

    hse_fini();
    pg_destroy(pg);
    svec_reset(&hse_gparm);
    svec_reset(&kv_oparm);
    svec_reset(&db_oparm);

    return rc ? EX_SOFTWARE : 0;
}
