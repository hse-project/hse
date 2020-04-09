/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * mdc_tool - dump or manipulate an MDC or file
 */

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/ikvdb.h>

#include <hse/hse.h>

#include <mpool/mpool.h>

#include "../kvdb/kvdb_log.h"
#include "../kvdb/kvdb_kvs.h"
#include "../cn/cndb_omf.h"

#include <sysexits.h>
#include <libgen.h>

const char *progname;

/*
 * MDC logs will never exceed a few MB
 * and I/O is always page sized.
 */
char buf[8192];

void
fatal(char *who, merr_t err)
{
    struct merr_info info;

    hse_log(HSE_ERR "mdc_tool: %s: %s", who, merr_info(err, &info));
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

int
dump(char *buf, size_t sz)
{
    hse_log(HSE_ERR "mdc_tool: record dumps not yet supported");
    return 0;
}

/*
 * MDC open and close dance
 */
static struct mpool *ds;

void
eopen_mdc(struct mpool *ds, u64 oid1, u64 oid2, struct mpool_mdc **mdc)
{
    merr_t err;

    if (oid1 && oid2)
        err = mpool_mdc_open(ds, oid1, oid2, 0, mdc);
    else {
        err = mpool_mdc_get_root(ds, &oid1, &oid2);
        if (err)
            fatal("mpool_mdc_get_root", err);

        err = mpool_mdc_open(ds, oid1, oid2, 0, mdc);
    }

    if (err)
        fatal("mpool_mdc_open", err);

    err = mpool_mdc_rewind(*mdc);
    if (err)
        fatal("mpool_mdc_rewind", err);
}

void
close_mdc(void *mdc)
{
    /* NB: failure to close is not fatal -- must exit anyway */
    mpool_mdc_close(mdc);
    mpool_close(ds);
}

void
usage(void)
{
    static const char msg[] = "usage: %s [options] mpool dataset [oid1 oid2]\n"
                              "-h       this help list\n"
                              "-i       ignore errors\n"
                              "-w file  write raw MDC data to file\n"
                              "mpool    name of the mpool\n"
                              "dataset  name of the dataset\n";

    printf(msg, progname);
}

int
main(int argc, char **argv)
{
    struct mpool_mdc *mdc;
    char *            wpath;
    FILE *            fp;
    merr_t            err;
    int               ignore;
    int               c;

    u64 oid1 = 0, oid2 = 0;

    struct mpool *ds;

    err = hse_kvdb_init();
    if (err)
        fatal("kvdb_init", err);

    progname = basename(argv[0]);
    hse_openlog(progname, 1);

    wpath = 0;
    ignore = 0;

    while ((c = getopt(argc, argv, ":hiw:")) != -1) {
        switch (c) {
            case 'h':
                usage();
                exit(0);

            case 'i':
                ignore = 1;
                break;

            case 'w':
                wpath = optarg;
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

    argc -= optind;
    argv += optind;

    if (argc != 2 && argc != 4) {
        syntax("expected 2 or 4 positional parameters, %d given", argc);
        exit(EX_USAGE);
    }

    /* [HSE_REVISIT] usage() says nothing about these additional params...
     * Also, the code below could check for conversion errors...
     */
    if (argc == 4) {
        oid1 = strtoull(argv[2], NULL, 0);
        if (!oid1)
            fatal(argv[2], merr(EINVAL));
        oid2 = strtoull(argv[3], NULL, 0);
        if (!oid2)
            fatal(argv[3], merr(EINVAL));
    }

    fp = 0;
    if (wpath) {
        fp = fopen(wpath, "w");
        if (!fp)
            fatal(wpath, merr(errno));
    }

    /* open root mdc, read entries for match to argv[2] */
    err = mpool_open(argv[0], 0, &ds, NULL);
    if (err)
        fatal("mpool_open", err);

    eopen_mdc(ds, oid1, oid2, &mdc);

    for (;;) {
        size_t len;

        err = mpool_mdc_read(mdc, buf, sizeof(buf), &len);
        if (len == 0 || err)
            break;
        if (fp)
            (void)fwrite(buf, 1, len, fp);
        else if (dump(buf, len) && !ignore)
            goto fini;
    }

fini:
    /* always close mdc, even if read error */
    close_mdc(mdc);
    if (fp)
        fclose(fp);

    if (err)
        fatal("mpool_mdc_read", err);

    hse_kvdb_fini();

    return 0;
}
