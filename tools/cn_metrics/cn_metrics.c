/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>

#include <cn/cn_metrics.h>
#include <cn/cn_tree.h>
#include <cn/cn_tree_internal.h>
#include <cn/cn_tree_iter.h>
#include <cn/kvset.h>

#include <hse/cli/program.h>
#include <hse/hse.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/csched.h>
#include <hse/util/parse_num.h>

#include <tools/parm_groups.h>
#include <tools/common.h>

#include <hse/mpool/mpool.h>

#include <sysexits.h>

void
usage(void)
{
    printf("usage: %s [options] kvdb_home kvs\n", progname);

    printf("-b         show all kblock/vblock IDs\n"
           "-f fmt     set output format\n"
           "-h         show this help list\n"
           "-n         show node-level data only (skip kvsets)\n"
           "-v         increase verbosity\n"
           "-y         output tree shape in yaml\n"
           "-Z config  path to global config file\n"
           "fmt  h=human(default), s=scalar, x=hex, e=exp\n"
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

/* Minimum column widths for hex and scalar output modes.
 */
static int col2width[] = {
    0, 5, 4, 5, 5, 5, 5, 6, 6, 6, 6, 6, 4, 4, 5, 7, 5, 5
};

int
bn_width(enum bn_fmt fmt, uint col)
{
    switch (fmt) {
    case BN_HUMAN:
        return 8;

    case BN_EXP:
        return 9;

    case BN_HEX1:
    case BN_HEX2:
    case BN_SCALAR:
        return col2width[col];
    }

    return 12;
}

char *
bn64(char *buf, size_t buf_sz, enum bn_fmt fmt, u64 value)
{
    const char *suffix = "\0kmgtpezy";
    unsigned exp = 0;
    u64      pv = 0;
    int n;

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
            suffix++;
        }

        if (exp == 0) {
            n = snprintf(buf, buf_sz, "%*lu", bn_width(fmt, 0), value);
            break;
        }

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
            n = snprintf(buf, buf_sz, "%3lu.%02lu%c", value, pv, *suffix);
        } else {
            n = snprintf(buf, buf_sz, "%3lu.%02lue%02u", value, pv, exp);
        }
        break;
    }

    if (n < 1 || n >= buf_sz)
        abort();

    return buf;
}

struct options {
    const char *config;
    const char *kvdb_home;
    const char *kvs;

    uint bnfmt; /* big number format */
    int  nodes_only;
    int  all_blocks;
    int  verbosity;
};

struct options opt;

void
process_options(int argc, char *argv[])
{
    int c;

    while ((c = getopt(argc, argv, ":bf:hnvyZ:")) != -1) {
        switch (c) {
        case 'b':
            opt.all_blocks = 1;
            if (!opt.verbosity)
                opt.verbosity++;
            break;

        case 'f':
            switch (optarg[0]) {
            case 'e':
                opt.bnfmt = BN_EXP;
                break;

            case 'h':
                opt.bnfmt = BN_HUMAN;
                break;

            case 's':
                opt.bnfmt = BN_SCALAR;
                break;

            case 'x':
                opt.bnfmt = BN_HEX1;

                if (optarg[1] == 'x')
                    opt.bnfmt = BN_HEX2;
                break;
            }
            break;

        case 'h':
            usage();
            exit(0);

        case 'n':
            opt.nodes_only = 1;
            break;

        case 'v':
            opt.verbosity++;
            break;

        case 'Z':
            opt.config = optarg;
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
    u64                  dgen;
    u64                  nodeid;
};

void
rollup(struct rollup *from, struct rollup *to)
{
    kvset_stats_add(&from->ks, &to->ks);

    to->km.num_keys += from->km.num_keys;
    to->km.num_tombstones += from->km.num_tombstones;
    to->km.nptombs += from->km.nptombs;
    to->km.num_kblocks += from->km.num_kblocks;
    to->km.num_vblocks += from->km.num_vblocks;
    to->km.tot_key_bytes += from->km.tot_key_bytes;
    to->km.tot_val_bytes += from->km.tot_val_bytes;
    to->km.tot_wbt_pages += from->km.tot_wbt_pages;
    to->km.tot_blm_pages += from->km.tot_blm_pages;
    to->km.tot_blm_pages += from->km.tot_blm_pages;
    to->km.vgarb_bytes += from->km.vgarb_bytes;
    to->km.vgroups += from->km.vgroups;
    to->km.compc = max(to->km.compc, from->km.compc);

    to->dgen = max(to->dgen, from->dgen);
    to->nodeid = from->nodeid;
}

struct ctx {
    int (*print)(const char *restrict format, ...);

    struct rollup rtotal;
    struct rollup rnode;
    struct rollup rkvset;

    uint node_kvsets;

    uint tree_kvsets;
    uint tree_nodes;

    bool header_done;
};

static int
noprint(const char *restrict format, ...)
{
    return 0;
}

void
col2width_update(struct ctx *ctx)
{
    const char *fmt = "%lu";

    ulong valv[] = {
        ctx->rtotal.dgen,
        ctx->rtotal.km.compc,
        ctx->rtotal.km.num_keys,
        ctx->rtotal.km.num_tombstones,
        ctx->rtotal.km.nptombs,
        ctx->rtotal.ks.kst_halen,
        ctx->rtotal.ks.kst_kalen,
        ctx->rtotal.ks.kst_valen,
        ctx->rtotal.ks.kst_vgarb,
        ctx->rtotal.ks.kst_kblks,
        ctx->rtotal.ks.kst_vblks,
    };
    int n, i;

    if (opt.bnfmt == BN_HEX1)
        fmt = "0x%lx";
    else if (opt.bnfmt == BN_HEX2)
        fmt = "%lx";

    for (i = 0; i < NELEM(valv); ++i) {
        n = snprintf(NULL, 0, fmt, valv[i]);
        if (n > col2width[i + 3])
            col2width[i + 3] = n;
    }
}

static void
print_ids(
    struct ctx *ctx,
    struct kvset *kvset,
    u32 (*get_count)(struct kvset *),
    u64 (*get_nth)(struct kvset *, u32),
    int max)
{
    int i, n;

    if (ctx->print == noprint)
        return;

    n = get_count(kvset);

    if (max == 0 || n < max)
        max = n;

    for (i = 0; i < max; ++i)
        ctx->print(" 0x%08lx", get_nth(kvset, i));
    if (n > max)
        ctx->print(" ...");
}

const char *hdrv[] = {
    "T", "Node", "Idx",
    "Dgen", "Comp", "Keys", "Tombs", "Ptombs", "HbAlen", "KbAlen", "VbAlen", "VbGarb",
    "Kbs", "Vbs", "Vgrp", "Rule", "Kavg", "Vavg",
};

#define FMT_HDR                                    \
    "%s %5s %4s "                                  \
    "%*s %*s %*s %*s %*s %*s %*s %*s %*s "         \
    "%*s %*s %5s %7s %*s %*s"

#define FMT_ROW                                         \
    "%s %5u %4u "                                       \
    "%*lu %*u %*s %*s %*s %*s %*s %*s %*s "             \
    "%*u %*u %5u %7s %*s %*s"

#define BN(_buf, _val) bn64((_buf), sizeof((_buf)), opt.bnfmt, (_val))

#define DIVZ(_a, _b) ((_b) ? (_a) / (_b) : 0)

static void
print_row(struct ctx *ctx, char *tag, struct rollup *r, uint index, char *sep)
{
    char nkeys[BIGNUM_BUFSZ];
    char ntombs[BIGNUM_BUFSZ];
    char nptombs[BIGNUM_BUFSZ];

    char halen[BIGNUM_BUFSZ];
    char kalen[BIGNUM_BUFSZ];
    char valen[BIGNUM_BUFSZ];
    char vgarb[BIGNUM_BUFSZ];

    char avg_klen[BIGNUM_BUFSZ];
    char avg_vlen[BIGNUM_BUFSZ];

    if (ctx->print == noprint)
        return;

    BN(nkeys, r->ks.kst_keys);
    BN(ntombs, r->km.num_tombstones);
    BN(nptombs, r->km.nptombs);

    BN(halen, r->ks.kst_halen);
    BN(kalen, r->ks.kst_kalen);
    BN(valen, r->ks.kst_valen);
    BN(vgarb, r->ks.kst_vgarb);

    BN(avg_klen, DIVZ(r->km.tot_key_bytes, r->km.num_keys));
    BN(avg_vlen, DIVZ(r->km.tot_val_bytes, r->km.num_keys));

    ctx->print(
        FMT_ROW,
        tag, r->nodeid, index,
        bn_width(opt.bnfmt, 3), r->dgen,
        bn_width(opt.bnfmt, 4), r->km.compc,
        bn_width(opt.bnfmt, 5), nkeys,
        bn_width(opt.bnfmt, 6), ntombs,
        bn_width(opt.bnfmt, 7), nptombs,
        bn_width(opt.bnfmt, 8), halen,
        bn_width(opt.bnfmt, 9), kalen,
        bn_width(opt.bnfmt, 10), valen,
        bn_width(opt.bnfmt, 11), vgarb,
        bn_width(opt.bnfmt, 12), r->ks.kst_kblks,
        bn_width(opt.bnfmt, 13), r->ks.kst_vblks,
        r->km.vgroups,
        (tag[0] == 'k') ? cn_rule2str(r->km.rule) : "-",
        bn_width(opt.bnfmt, 16), avg_klen,
        bn_width(opt.bnfmt, 17), avg_vlen);

    if (opt.verbosity > 0) {
        ctx->print(" %7.1f %7.1f %7.1f %7.1f ",
                   DIVZ(100.0 * r->ks.kst_hwlen, r->ks.kst_halen),
                   DIVZ(100.0 * r->ks.kst_kwlen, r->ks.kst_kalen),
                   DIVZ(100.0 * r->ks.kst_vwlen, r->ks.kst_valen),
                   DIVZ(100.0 * r->ks.kst_vulen, r->ks.kst_valen));
    }

    if (sep)
        ctx->print(sep);
}

static void
print_hdr(struct ctx *ctx)
{
    ctx->print(
        FMT_HDR,
        hdrv[0], hdrv[1], hdrv[2],
        bn_width(opt.bnfmt, 3), hdrv[3],
        bn_width(opt.bnfmt, 4), hdrv[4],
        bn_width(opt.bnfmt, 5), hdrv[5],
        bn_width(opt.bnfmt, 6), hdrv[6],
        bn_width(opt.bnfmt, 7), hdrv[7],
        bn_width(opt.bnfmt, 8), hdrv[8],
        bn_width(opt.bnfmt, 9), hdrv[9],
        bn_width(opt.bnfmt, 10), hdrv[10],
        bn_width(opt.bnfmt, 11), hdrv[11],
        bn_width(opt.bnfmt, 12), hdrv[12],
        bn_width(opt.bnfmt, 13), hdrv[13],
        hdrv[14],
        hdrv[15],
        bn_width(opt.bnfmt, 16), hdrv[16],
        bn_width(opt.bnfmt, 17), hdrv[17]);

    if (opt.verbosity > 0) {
        ctx->print(" %7s %7s %7s %7s  %s",
                   "VbUlen%", "HbWlen%", "KbWlen%", "VbWlen%",
                   (opt.nodes_only ? "" : "HblockID / KblockIDs / VblockIDs"));
    }

    ctx->print("\n");
}

static int
tree_walk_callback(
    void *               rock,
    struct cn_tree *     tree,
    struct cn_tree_node *node,
    struct kvset *       kvset)
{
    struct ctx *   c = (struct ctx *)rock;
    struct rollup *k = &c->rkvset;
    struct rollup *n = &c->rnode;
    struct rollup *t = &c->rtotal;

    if (!node) {
        /* Finish current tree */
        c->print("\n");
        print_hdr(c);
        t->nodeid = c->tree_nodes;
        print_row(c, "t", t, c->tree_kvsets, "\n");
        return 0;
    }

    if (!kvset) {
        /* Finish current node */
        struct cn_node_stats ns;

        c->tree_nodes++;
        rollup(n, t);
        if (opt.nodes_only && c->tree_nodes == 1)
            print_hdr(c);
        print_row(c, "n", n, c->node_kvsets, "\n");

        cn_node_stats_get(node, &ns);

        if (opt.verbosity > 0) {
            c->print(
                "#Node pcap%% %u kuniq%% %6.1f "
                "HbClen%% %6.1f KbClen%% %6.1f VbClen%% %6.1f samp %6.1f\n",
                ns.ns_pcap,
                DIVZ(1e2 * ns.ns_keys_uniq, cn_ns_keys(&ns)),
                DIVZ(1e2 * ns.ns_hclen, n->ks.kst_halen),
                DIVZ(1e2 * ns.ns_kclen, n->ks.kst_kalen),
                DIVZ(1e2 * ns.ns_vclen, n->ks.kst_valen),
                cn_ns_samp(&ns) / 1e2);
        }

        memset(n, 0, sizeof(*n));
        c->node_kvsets = 0;
        return 0;
    }

    /* New Kvset */
    memset(k, 0, sizeof(*k));
    kvset_get_metrics(kvset, &k->km);
    kvset_stats(kvset, &k->ks);
    k->dgen = kvset_get_dgen(kvset);
    k->nodeid = kvset_get_nodeid(kvset);
    rollup(k, n);

    c->tree_kvsets++;
    c->node_kvsets++;

    if (c->print == noprint)
        return 0;

    if (!opt.nodes_only) {
        int limit = opt.all_blocks ? 0 : 2;

        if (c->node_kvsets == 1) {
            if (c->tree_kvsets > 1)
                c->print("\n");
            print_hdr(c);
        }

        print_row(c, "k", k, c->node_kvsets - 1, "");

        if (opt.verbosity > 0) {
            c->print(" 0x%08lx /", kvset_get_hblock_id(kvset));
            print_ids(c, kvset, kvset_get_num_kblocks, kvset_get_nth_kblock_id, limit);
            c->print(" /");
            print_ids(c, kvset, kvset_get_num_vblocks, kvset_get_nth_vblock_id, limit);
        }
        c->print("\n");
    }

    return 0;
}

int
main(int argc, char **argv)
{
    const char *       errmsg = NULL;
    struct ctx         ctx;
    struct cn *        cn = NULL;
    struct cn_tree *   tree;
    struct hse_kvdb *  kd = NULL;
    struct hse_kvs *   kvs = NULL;
    hse_err_t          rc;

    struct parm_groups *pg = NULL;
    struct svec         hse_gparm = { 0 };
    struct svec         db_oparm = { 0 };
    struct svec         kv_oparm = { 0 };

    progname_set(argv[0]);

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

    rc = rc ? rc : svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ? rc : svec_append_pg(&db_oparm, pg, PG_KVDB_OPEN, "mode=diag", NULL);
    rc = rc ? rc : svec_append_pg(&kv_oparm, pg, PG_KVS_OPEN, "cn_maint_disable=true", NULL);
    if (rc)
        fatal(rc, "svec_apppend_pg failed");

    rc = hse_init(opt.config, hse_gparm.strc, hse_gparm.strv);
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

    cn = ikvdb_kvs_get_cn(kvs);
    if (!cn) {
        errmsg = "cn_open";
        rc = EBUG;
        goto done;
    }

    tree = cn_get_tree(cn);

    /* In scalar and hex modes we must walk the tree twice:  The first time
        * to gather totals in order to determine minimum column widths, and the
        * second time to actually dump the tree.
        */
    if (opt.bnfmt == BN_SCALAR || opt.bnfmt == BN_HEX1 || opt.bnfmt == BN_HEX2) {
        memset(&ctx, 0, sizeof(ctx));
        ctx.print = noprint;
        cn_tree_preorder_walk(tree, KVSET_ORDER_NEWEST_FIRST, tree_walk_callback, &ctx);
        col2width_update(&ctx);
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.print = printf;
    cn_tree_preorder_walk(tree, KVSET_ORDER_NEWEST_FIRST, tree_walk_callback, &ctx);

done:
    if (errmsg) {
        char errbuf[1024];

        hse_strerror(rc, errbuf, sizeof(errbuf));
        fprintf(stderr, "%s: %s failed: %s\n", progname, errmsg, errbuf);
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
