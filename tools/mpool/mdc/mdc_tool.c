/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/*
 * mdc_tool - dump or manipulate an MDC or file
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <sysexits.h>

#include <bsd/string.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/ikvdb/kvdb_meta.h>
#include <hse/logging/logging.h>
#include <hse/mpool/mpool.h>

#define ERROR_BUF_SIZE 256

/*
 * MDC logs will never exceed a few MB
 * and I/O is always page sized.
 */
static char buf[8192];

void
fatal(char *who, hse_err_t err)
{
    char buf[ERROR_BUF_SIZE];

    hse_strerror(err, buf, sizeof(buf));
    log_err("mdc_tool: %s: %s", who, buf);
    exit(1);
}

void
syntax(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

int
dump(char *buf, size_t sz)
{
    log_err("mdc_tool: record dumps not yet supported");
    return 0;
}

/*
 * MDC open and close dance
 */
void
eopen_mdc(struct mpool * const mp, const struct kvdb_meta * const meta, struct mpool_mdc **mdc)
{
    merr_t err;

    assert(mp);
    assert(mdc);

    err = mpool_mdc_open(mp, meta->km_cndb.oid1, meta->km_cndb.oid2, false, mdc);
    if (err)
        fatal("mpool_mdc_open", err);

    err = mpool_mdc_rewind(*mdc);
    if (err)
        fatal("mpool_mdc_rewind", err);
}

void
close_mdc(void *mdc)
{
    mpool_mdc_close(mdc);
}

void
usage(void)
{
    static const char msg[] = "usage: %s [options] <kvdb_home>\n"
                              "-h       this help list\n"
                              "-i       ignore errors\n"
                              "-w file  write raw MDC data to file\n"
                              "kvdb_home home dir of the kvdb\n";

    printf(msg, progname);
}

int
main(int argc, char **argv)
{
    struct mpool_mdc *mdc;
    char *wpath;
    FILE *fp;
    hse_err_t err;
    int ignore, c;
    const char *home;
    const char *config = NULL;
    struct mpool *mp;
    struct mpool_rparams params = { 0 };
    struct kvdb_meta meta;

    progname_set(argv[0]);

    wpath = 0;
    ignore = 0;

    while ((c = getopt(argc, argv, ":hiw:Z:")) != -1) {
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

        case 'Z':
            config = optarg;
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

    if (argc != 1) {
        syntax("Insufficient or extraneous positional parameters, %d given", argc);
        exit(EX_USAGE);
    }

    home = argv[argc - 1];

    err = hse_init(config, 0, NULL);
    if (err)
        fatal("hse_init", err);

    fp = 0;
    if (wpath) {
        fp = fopen(wpath, "w");
        if (!fp)
            fatal(wpath, errno);
    }

    err = kvdb_meta_deserialize(&meta, home);
    if (err)
        fatal("kvdb_meta_deserialize", err);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_CAPACITY; i++)
        strlcpy(params.mclass[i].path, meta.km_storage[i].path, sizeof(params.mclass[i].path));

    err = mpool_open(home, &params, O_RDWR, &mp);
    if (err)
        fatal("mpool_open", err);

    eopen_mdc(mp, &meta, &mdc);

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

    hse_fini();

    return 0;
}
