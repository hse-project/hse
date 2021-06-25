/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * mdc_tool - dump or manipulate an MDC or file
 */

#include <sysexits.h>

#include <hse_util/logging.h>

#include <hse/hse.h>
#include <mpool/mpool.h>

#define ERROR_BUF_SIZE 256

static const char *progname;

/*
 * MDC logs will never exceed a few MB
 * and I/O is always page sized.
 */
static char buf[8192];

void
fatal(char *who, hse_err_t err)
{
    char buf[ERROR_BUF_SIZE];
    hse_err_to_string(err, buf, sizeof(buf), NULL);
    hse_log(HSE_ERR "mdc_tool: %s: %s", who, buf);
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
void
eopen_mdc(const char *home, struct mpool_mdc **mdc)
{
    merr_t err;
    u64 oid1, oid2;

    err = mpool_mdc_rootid_get(&oid1, &oid2);
    if (err)
        fatal("mpool_mdc_rootid_get", err);

    err = mpool_mdc_root_open(home, oid1, oid2, mdc);
    if (err)
        fatal("mpool_mdc_root_open", err);

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
    struct mpool_mdc  *mdc;
    char              *wpath;
    FILE              *fp;
    hse_err_t          err;
    int                ignore, c;
    const char        *home;

    err = hse_init();
    if (err)
        fatal("hse_init", err);

    progname = basename(argv[0]);

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

    if (argc != 1) {
        syntax("Insufficient or extraneous positional parameters, %d given", argc);
        exit(EX_USAGE);
    }

    home = argv[argc - 1];

    fp = 0;
    if (wpath) {
        fp = fopen(wpath, "w");
        if (!fp)
            fatal(wpath, errno);
    }

    eopen_mdc(home, &mdc);

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
