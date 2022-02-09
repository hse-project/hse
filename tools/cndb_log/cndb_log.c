/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

/*
 * cndb_log - read and interpret a cndb log
 */

#include <stdio.h>

#include <hse/hse.h>

#include <hse_util/slab.h>
#include <hse_util/assert.h>
#include <hse_util/log2.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/omf_version.h>

#include <mpool/mpool.h>

#include "cn/cndb_omf.h"
#include "cn/cndb_internal.h"

#include <sysexits.h>
#include <libgen.h>

#define ERROR_BUF_SIZE 256
#define BUF_SZ         ((25 * 1024)) /* Initial buffer size */

const char *progname;

static int fileoff;
static int ignore;
static int check;
static int status;

struct tool_info {
    const char *  config;
    const char *  kvdb_home;
    char *        buf;
    size_t        bufsz;
    struct mpool *ds;

    char *           rpath;
    char *           wpath;
    FILE *           fp; /* only for writing */
    int              fd; /* only for reading */
    struct cndb *    cndb;
    struct hse_kvdb *kvdbh;
};

void
fatal(char *who, hse_err_t err)
{
    char buf[ERROR_BUF_SIZE];
    hse_strerror(err, buf, sizeof(buf));

    log_err("cndb_log: %s: %s", who, buf);
    exit(1);
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

void
usage(void)
{
    static const char msg[] = "usage: %s [-r file]\n"
                              "usage: %s [-w file] kvdb\n"
                              "-c         check integrity\n"
                              "-i         ignore errors\n"
                              "-r file    read from file\n"
                              "-w file    write raw data from input to file\n"
                              "-Z config  path to global config file\n"
                              "<kvdb_home> kvdb home dir\n"
                              "\n";

    printf(msg, progname, progname);
}

/* get a pointer to cndb */
void
open_kvdb_and_cndb(struct tool_info *ti)
{
    u64 rc;

    rc = diag_kvdb_open(ti->kvdb_home, 0, NULL, &ti->kvdbh);
    if (rc)
        fatal("diag_kvdb_open", rc);

    rc = diag_kvdb_get_cndb(ti->kvdbh, &ti->cndb);
    if (rc)
        fatal("diag_kvdb_cndb", rc);
}

/* Functions to interpret the cndb log ------------- */

static void
print_ver(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_ver *mtv = &(mtu->v);

    printf("%04x: ", fileoff);
    printf(
        "%-6s magic 0x%08x version %u captgt %lu\n",
        "ver",
        mtv->mtv_magic,
        mtv->mtv_version,
        (ulong)mtv->mtv_captgt);
}

static void
print_meta(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_meta *mte = &(mtu->e);

    printf("%04x: ", fileoff);
    printf("%-6s seqno %lu\n", "meta", mte->mte_seqno_max);
}

static void
print_info(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_info *mti = &(mtu->i);
    int               i;

    printf("%04x: ", fileoff);
    printf(
        "%-6s cnid %lu fanout %u prefix %u sfx_len %u pivot %u"
        " flags 0x%x metasz %lu name %s meta",
        "info",
        mti->mti_cnid,
        mti->mti_fanout,
        mti->mti_prefix_len,
        mti->mti_sfx_len,
        mti->mti_prefix_pivot,
        mti->mti_flags,
        (ulong)mti->mti_metasz,
        mti->mti_name);

    for (i = 0; i < mti->mti_metasz; i++)
        printf(" 0x%02x", (unsigned char)mti->mti_meta[i]);

    printf("\n");
}

static void
print_infod(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_info *mti = &(mtu->i);

    printf("%04x: ", fileoff);
    printf(
        "%-6s cnid %lu fanout %u prefix %u pivot %u"
        " flags 0x%x name %s\n",
        "infod",
        mti->mti_cnid,
        mti->mti_fanout,
        mti->mti_prefix_len,
        mti->mti_prefix_pivot,
        mti->mti_flags,
        mti->mti_name);
}

static void
print_tx(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_tx *mtx = &(mtu->x);

    printf("%04x: ", fileoff);
    printf(
        "%-6s %lu nc %u nd %u seq %lu ingestid %lu txhorizon %lu ",
        "tx",
        mtx->mtx_id,
        mtx->mtx_nc,
        mtx->mtx_nd,
        mtx->mtx_seqno,
        mtx->mtx_ingestid,
        mtx->mtx_txhorizon);
    printf("\n");
}

static void
print_txc(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_txc *mtc = &(mtu->c);
    u64 *            mblk;
    int              i;

    printf("%04x: ", fileoff);
    printf("%-6s %lu ", "txc", mtc->mtc_id);
    /* [HSE_REVISIT] either remove so-called meta-blocks (nm)
     * or implement them.  Until then, print 0 for nm so that
     * this output matches what cndblog2c.awk expects
     */
    printf(
        "tag %lu cnid %lu keepvbc %u nk %d nv %d nm %d ids ",
        mtc->mtc_tag,
        mtc->mtc_cnid,
        mtc->mtc_keepvbc,
        mtc->mtc_kcnt,
        mtc->mtc_vcnt,
        0);

    mblk = (void *)(mtc + 1); /* beginning of kblk list */
    for (i = 0; i < mtc->mtc_kcnt; i++)
        printf("0x%08lx ", mblk[i]);
    printf("/ ");

    mblk = &mblk[mtc->mtc_kcnt]; /* beginning of vblk list */
    for (i = 0; i < mtc->mtc_vcnt; i++)
        printf("0x%08lx ", mblk[i]);

    printf("\n");
}

static void
print_txm(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_txm *mtm = &(mtu->m);

    printf("%04x: ", fileoff);
    printf("%-6s %lu ", "txm", mtm->mtm_id);
    printf(
        "tag %lu cnid %lu dgen %lu loc %u,%u vused %lu compc %u "
        "scatter %u",
        mtm->mtm_tag,
        mtm->mtm_cnid,
        mtm->mtm_dgen,
        mtm->mtm_level,
        mtm->mtm_offset,
        mtm->mtm_vused,
        mtm->mtm_compc,
        mtm->mtm_scatter);
    printf("\n");
}

static void
print_txd(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_txd *mtd = &(mtu->d);
    u64 *            mblk;
    int              i;

    printf("%04x: ", fileoff);
    printf("%-6s %lu ", "txd", mtd->mtd_id);
    printf("tag %lu cnid %lu nb %d ids ", mtd->mtd_tag, mtd->mtd_cnid, mtd->mtd_n_oids);
    mblk = (void *)(mtd + 1); /* start of mblock list */
    for (i = 0; i < mtd->mtd_n_oids; i++)
        printf("0x%08lx ", mblk[i]);
    printf("\n");
}

static void
print_ack(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_ack *mta = &(mtu->a);
    const char *     a;

    printf("%04x: ", fileoff);
    a = mta->mta_type == CNDB_ACK_TYPE_C ? "ack-C" : "ack-D";
    printf("%-6s %lu tag %lu cnid %lu\n", a, mta->mta_txid, mta->mta_tag, mta->mta_cnid);
}

static void
print_nak(struct tool_info *ti, union cndb_mtu *mtu)
{
    struct cndb_nak *mtn = &(mtu->n);

    printf("%04x: ", fileoff);
    printf("%-6s %lu\n", "nak", mtn->mtn_txid);
}

int
eread(int fd, char *buf, int len)
{
    int rc;

    rc = read(fd, buf, len);
    if (rc < 0)
        fatal("read", ev(errno));
    if (rc && rc != len)
        fatal("read", ev(EIO));

    return rc;
}

hse_err_t
read_rec(struct tool_info *ti, size_t *len)
{
    int                  rc1, rc2;
    hse_err_t            err;
    struct cndb_hdr_omf *h = (void *)ti->buf;

    /* If a read path has NOT been provided, read from the cndb mdc, else
     * read from file
     */
    if (!ti->rpath) {
        err = mpool_mdc_read(ti->cndb->cndb_mdc, ti->buf, ti->bufsz, len);
        if (hse_err_to_errno(err) == EOVERFLOW) {
            log_info("bufsz:%lu, reclen:%lu\n", ti->bufsz, *len);
            ti->bufsz = *len;
            ti->buf = realloc(ti->buf, ti->bufsz);
            if (!ti->buf)
                return ENOMEM;

            memset(ti->buf, 0, ti->bufsz);
            err = mpool_mdc_read(ti->cndb->cndb_mdc, ti->buf, ti->bufsz, len);
        }
        return err;
    }

    /* Read one record from the file */
    rc1 = eread(ti->fd, ti->buf, sizeof(*h));

    if (ti->bufsz < omf_cnhdr_len(h) + sizeof(*h)) {
        /* Resize buffer if it's not sufficiently sized */
        ti->bufsz = omf_cnhdr_len(h) + sizeof(*h);
        ti->buf = realloc(ti->buf, ti->bufsz);
        if (!ti->buf)
            return ENOMEM;
    }

    rc2 = eread(ti->fd, ti->buf + sizeof(h), omf_cnhdr_len(h));

    *len = rc1 + rc2;

    return 0;
}

void
printbuf(struct tool_info *ti, u32 cndb_version, struct cndb_hdr_omf *hdr)
{
    hse_err_t       err;
    union cndb_mtu *mtu;
    u32             type;

    type = omf_cnhdr_type(hdr);
    err = cndb_record_unpack(cndb_version, hdr, &mtu);
    if (err) {
        char errbuf[300];

        hse_strerror(err, errbuf, sizeof(errbuf));

        printf("%04x: ", fileoff);
        printf("error unpacking record type %d: %s\n", type, errbuf);

        free(mtu);
        return;
    }

    switch (type) {
        case CNDB_TYPE_VERSION:
            print_ver(ti, mtu);
            break;
        case CNDB_TYPE_META:
            print_meta(ti, mtu);
            break;
        case CNDB_TYPE_INFO:
            print_info(ti, mtu);
            break;
        case CNDB_TYPE_INFOD:
            print_infod(ti, mtu);
            break;
        case CNDB_TYPE_TX:
            print_tx(ti, mtu);
            break;
        case CNDB_TYPE_ACK:
            print_ack(ti, mtu);
            break;
        case CNDB_TYPE_NAK:
            print_nak(ti, mtu);
            break;
        case CNDB_TYPE_TXC:
            print_txc(ti, mtu);
            break;
        case CNDB_TYPE_TXM:
            print_txm(ti, mtu);
            break;
        case CNDB_TYPE_TXD:
            print_txd(ti, mtu);
            break;
        default:
            printf("%04x: ", fileoff);
            printf("unknown type 0x%08x len %d\n", omf_cnhdr_type(hdr), omf_cnhdr_len(hdr));
            status = 1;
    }
    free(mtu);
}

hse_err_t
print_cndb_log(struct tool_info *ti)
{
    hse_err_t err;
    u32       cndb_version = 0;

    while (1) {
        struct cndb_hdr_omf *hdr;
        size_t               len = 0;

        /* Read from source(file or mdc) */
        err = read_rec(ti, &len);
        if (!len || err)
            break;

        if (ti->fp) {
            /* write to file instead of stdout */
            fwrite(ti->buf, 1, len, ti->fp);
            continue;
        }

        hdr = (void *)ti->buf;

        assert(omf_cnhdr_len(hdr) + sizeof(*hdr) == len);

        if (omf_cnhdr_type(hdr) == CNDB_TYPE_VERSION)
            cndb_version = omf_cnver_version((struct cndb_ver_omf *)ti->buf);

        printbuf(ti, cndb_version, hdr);

        fileoff += sizeof(*hdr) + omf_cnhdr_len(hdr);
    }

    return err;
}

void
close_all(struct tool_info *ti)
{
    if (ti->kvdbh)
        diag_kvdb_close(ti->kvdbh);
    if (ti->fp)
        fclose(ti->fp);
    if (ti->rpath)
        close(ti->fd);

    free(ti->buf);
}

static hse_err_t
replay_log(struct tool_info *ti)
{
    hse_err_t            err = 0;
    struct cndb_hdr_omf *hdr = NULL;
    size_t               hdrsz = 65536;
    size_t               len;
    int                  i;
    u64                  seqno;
    u64                  ingestid, txhorizon;
    u32                  cndb_version;
    union cndb_mtu *     mtu;

    /* [HSE_REVISIT] consider implementing replay from file via mock_mpool */
    if (ti->rpath)
        fatal(ti->rpath, EUNATCH);

    if (ti->wpath)
        fatal(ti->wpath, EUNATCH);

    ti->cndb->cndb_read_only = true;

    /* read the version record, then rewind. */
    err = mpool_mdc_read(ti->cndb->cndb_mdc, ti->cndb->cndb_cbuf, ti->cndb->cndb_cbufsz, &len);
    if (ev(err))
        return err;

    cndb_version = omf_cnver_version((void *)ti->cndb->cndb_cbuf);
    if (cndb_version > CNDB_VERSION)
        return ev(EPROTO);

    err = mpool_mdc_rewind(ti->cndb->cndb_mdc);
    if (ev(err))
        return err;

    err = ev(cndb_replay(ti->cndb, &seqno, &ingestid, &txhorizon));

    fileoff = 0;
    err = cndb_record_unpack(cndb_version, ti->cndb->cndb_cbuf, &mtu);
    if (err) {
        printf("error unpacking version record %d\n", hse_err_to_errno(err));
        free(mtu);
        return err;
    }
    print_ver(ti, mtu);
    free(mtu);
    fileoff += len;

    hdr = malloc(hdrsz);

    for (i = 0; i < ti->cndb->cndb_cnc; i++) {
        struct cndb_cn *      cn;
        struct cndb_info_omf *inf;
        size_t                sz = 0;

        cn = ti->cndb->cndb_cnv[i];
        inf = cn->cn_cbuf;

        cndb_set_hdr(&inf->hdr, CNDB_TYPE_INFO, cn->cn_cbufsz);
        omf_set_cninfo_fanout(inf, cn->cn_cp.fanout);
        omf_set_cninfo_prefix_len(inf, cn->cn_cp.pfx_len);
        omf_set_cninfo_cnid(inf, cn->cn_cnid);
        omf_set_cninfo_flags(inf, cn->cn_flags);
        omf_set_cninfo_name(inf, (unsigned char *)cn->cn_name, strlen(cn->cn_name));

        if (cn->cn_cbufsz > sizeof(*inf))
            sz = cn->cn_cbufsz - sizeof(*inf);

        omf_set_cninfo_metasz(inf, sz);

        err = cndb_record_unpack(CNDB_VERSION, &inf->hdr, &mtu);
        if (err) {
            printf("error unpacking info record %d\n", hse_err_to_errno(err));
            free(mtu);
            free(hdr);
            return err;
        }

        print_info(ti, mtu);
        free(mtu);

        fileoff += cn->cn_cbufsz;
    }

    for (i = 0; i < ti->cndb->cndb_keepc; i++) {
        err = mtx2omf(ti->cndb, hdr, ti->cndb->cndb_keepv[i]);
        if (ev(err))
            break;

        printbuf(ti, CNDB_VERSION, hdr);
        fileoff += sizeof(*hdr) + omf_cnhdr_len(hdr);
        memset(hdr, 0, hdrsz);
    }

    printf("------ unrecoverable txns:\n");

    for (i = 0; !err && i < ti->cndb->cndb_workc; i++) {
        if (ti->cndb->cndb_workv[i] == NULL) {
            printf("work item %d/%lu is NULL!\n", i, (ulong)ti->cndb->cndb_workc);
            continue;
        }
        err = mtx2omf(ti->cndb, hdr, ti->cndb->cndb_workv[i]);
        if (ev(err))
            break;

        printbuf(ti, CNDB_VERSION, hdr);
        fileoff += sizeof(*hdr) + omf_cnhdr_len(hdr);
        memset(hdr, 0, hdrsz);
    }

    free(hdr);

    return err;
}

int
main(int argc, char **argv)
{
    hse_err_t        err;
    int              c;
    struct tool_info ti = { 0 };
    const char *paramv[] = { "logging.level=7" };

    progname = basename(argv[0]);

    while ((c = getopt(argc, argv, ":chir:w:Z:")) != -1) {
        switch (c) {
            case 'c':
                check = 1;
                break;

            case 'Z':
                ti.config = optarg;
                break;

            case 'h':
                usage();
                exit(0);

            case 'i':
                ignore = 1;
                break;

            case 'r':
                ti.rpath = optarg;
                break;

            case 'w':
                ti.wpath = optarg;
                break;

            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                syntax("uknown option: -%c\n", c);
                exit(EX_USAGE);
                break;
        }
    }

    argc -= optind;
    argv += optind;


    /* Output: if wpath was provided, write raw data to file instead of
     * formatting to stdout
     */
    if (ti.wpath) {
        ti.fp = fopen(ti.wpath, "w");
        if (!ti.fp)
            fatal(ti.wpath, errno);
    }

    if (ti.rpath && check)
        fatal("compacting from file images is not yet supported", EINVAL);

    /* Input: if rpath was provided, read from file, else get an mdc hdl */
    if (ti.rpath) {
        ti.fd = open(ti.rpath, O_RDONLY, 0);
        if (ti.fd < 0)
            fatal(ti.rpath, errno);

        err = hse_init(NULL, NELEM(paramv), paramv);
        if (err)
            fatal("hse_init", err);
    } else {
        if (argc < 1) {
            syntax("insufficient arguments for mandatory parameters");
            exit(EX_USAGE);
        } else if (argc > 1) {
            syntax("extraneous parameter: %s", argv[0]);
            exit(EX_USAGE);
        }

        ti.kvdb_home = argv[0];

        err = hse_init(ti.config, NELEM(paramv), paramv);
        if (err)
            fatal("hse_init", err);

        open_kvdb_and_cndb(&ti);
    }

    ti.bufsz = BUF_SZ;
    ti.buf = malloc(ti.bufsz);
    if (!ti.buf) {
        err = ENOMEM;
        goto done;
    }

    if (check) {
        free(ti.cndb->cndb_cbuf);
        ti.cndb->cndb_cbuf = ti.buf;
        ti.cndb->cndb_cbufsz = ti.bufsz;

        err = replay_log(&ti);

        ti.buf = NULL; /* avoid double-free */
    } else {
        err = print_cndb_log(&ti);
    }

done:
    close_all(&ti);

    if (err)
        fatal("mpool_mdc_read", err);

    hse_fini();

    return status;
}
