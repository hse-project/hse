/*
 * Copyright (C) 2015-2017,2019,2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * pscan - the simplest possible client to scan prefixes
 *
 * Search for MAIN to get to the interesting logic.
 */

#define USE_EVENT_TIMER

#include <getopt.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <xxhash.h>
#include <hse_util/event_timer.h>
#include <hse_util/fmt.h>
#include <hse_util/hse_params_helper.h>
#include <hse_util/inttypes.h>
#include <hse_util/timing.h>

#include <tools/common.h>

const char * progname;
int          verbosity;
bool         headers = true;
bool         uniq = false;
sig_atomic_t sigint;

/**
 * struct shr - Data shared between pthreads...
 * @count:      total number of keys retrieved
 * @mark:       time in seconds between status updates
 * @uniq:       total number of unique keys retrieved
 */
struct shr {
    volatile u64 count;
    volatile u32 mark;
    u64          uniq;
    pthread_t    tid;
};

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
usage()
{
    printf(
        "usage: %s [options] mp kvdb kvs [param=value ...]\n"
        "-C       count keys (no checksum)\n"
        "-c       count keys (compute running checksum)\n"
        "-D       delete keys as you find them\n"
        "-H       suppress column headers\n"
        "-h       print this help list\n"
        "-i iter  call cursor read at most $iter times\n"
        "-k klen  limit keys to $klen bytes (-klen means first klen)\n"
        "-l       show length of keys / values\n"
        "-m mark  print status every $mark seconds\n"
        "-p pfx   limit scans to prefix $pfx\n"
        "-r       use reverse scan\n"
        "-s skey  seek to $skey before first cursor read\n"
        "-t       show timing stats at end of run\n"
        "-u       count only unique keys\n"
        "-V vmax  limit vals to $vmax bytes (-vmax means first vmax)\n"
        "-v       increase verbosity\n"
        "-x       output in hexadecimal\n",
        progname);

    if (verbosity > 0)
        rp_usage();

    exit(0);
}

void
sigint_isr(int sig)
{
    ++sigint;
}

void *
status(void *arg)
{
    struct shr *shr = arg;
    u64         tstart, tprev, now;
    u64         cnt, cntprev, delta;
    char        hdr[128], fmt[128];
    uint        line;

    snprintf(
        hdr,
        sizeof(hdr),
        "\n%9s %12s %10s %10s %10s %10s\n",
        "ELAPSED",
        "tKEYS",
        "tKEYS/s",
        "iKEYS",
        "iUSECS",
        uniq ? "tUNIQ" : "");

    snprintf(fmt, sizeof(fmt), "%%s%%9ld %%12ld %%10lu %%10lu %%10lu%s\n", uniq ? " %10lu" : "");

    tstart = tprev = get_time_ns();
    cnt = cntprev = 0;
    delta = 50;
    line = 0;

    while (shr->mark > 0 || cntprev < shr->count) {
        uint delay = shr->mark * 1000000;

        if (delay > 0)
            usleep(delay - delta);

        now = get_time_ns();
        cnt = shr->count;

        if ((now - tprev) / 1000 > (delay - delta)) {
            delta += (now - tprev) / 1000 - (delay - delta);
            delta /= 2;
            if (delta > 500)
                delta = 500;
        }

        printf(
            fmt,
            (line++ % 24) == 0 && headers ? hdr : "",
            (now - tstart) / 1000000,
            cnt,
            (cnt * 1000000000) / (now - tstart),
            cnt - cntprev,
            (now - tprev) / 1000,
            shr->uniq);
        fflush(stdout);

        cntprev = cnt;
        tprev = now;
    }

    pthread_exit(NULL);
}

int
main(int argc, char **argv)
{
    char                   kbuf[1024], pbuf[128], sbuf[128];
    struct hse_params *    params;
    const char *           mpname, *kvname;
    char *                 prefix, *seek;
    struct hse_kvdb_opspec opspec;
    struct hse_kvs_cursor *cursor;
    struct hse_kvdb *      kvdb_h;
    struct hse_kvs *       kvs_h;
    u64                    keyhash, valhash;
    int                    showlen;
    int                    seeklen, pfxlen;
    bool                   eof, countem, cksum, deletem, stats;
    bool                   reverse = false;
    unsigned               opt_help = 0;
    u64                    iter, max_iter;
    int                    c, rc, err;
    struct shr             shr = { 0 };

    EVENT_TIMER(to);
    EVENT_TIMER(tc);
    EVENT_TIMER(ts);
    EVENT_TIMER(tr);
    EVENT_TIMER(td);

    EVENT_INIT(to);
    EVENT_INIT(tc);
    EVENT_INIT(ts);
    EVENT_INIT(tr);
    EVENT_INIT(td);

    progname = basename(argv[0]);
    countem = deletem = stats = false;
    showlen = seeklen = pfxlen = 0;
    cksum = true;
    prefix = "";
    seek = NULL;
    max_iter = ULONG_MAX;

    Opts.kmax = HSE_KVS_KLEN_MAX;
    Opts.vmax = HSE_KVS_VLEN_MAX;
    Opts.hexonly = 0;

    while ((c = getopt(argc, argv, ":CcDHhi:k:lm:p:rs:t:uV:vx")) != -1) {
        char *end = NULL;

        errno = 0;

        switch (c) {
            case 'C':
                countem = true;
                cksum = false;
                break;
            case 'c':
                countem = true;
                break;
            case 'D':
                deletem = true;
                break;
            case 'H':
                headers = false;
                break;
            case 'h':
                opt_help++;
                break;
            case 'i':
                max_iter = strtoul(optarg, &end, 0);
                break;
            case 'k':
                Opts.kmax = strtoul(optarg, &end, 0);
                break;
            case 'l':
                showlen = 1;
                break;
            case 'm':
                shr.mark = strtoul(optarg, &end, 0);
                break;
            case 'p':
                prefix = optarg;
                break;
            case 'r':
                reverse = true;
                break;
            case 's':
                seek = optarg;
                break;
            case 't':
                stats = true;
                break;
            case 'u':
                uniq = true;
                break;
            case 'V':
                Opts.vmax = strtoul(optarg, &end, 0);
                break;
            case 'v':
                ++verbosity;
                break;
            case 'x':
                Opts.hexonly = 1;
                break;

            case '?':
                syntax("invalid option -%c", optopt);
                exit(EX_USAGE);

            case ':':
                syntax("option -%c requires a parameter", optopt);
                exit(EX_USAGE);

            default:
                syntax("invalid option: -%c", c);
                exit(EX_USAGE);
        }

        if (end && *end) {
            syntax("invalid option argument `-%c %s'", c, optarg);
            exit(EX_USAGE);
        }
    }

    if (opt_help)
        usage();

    HSE_KVDB_OPSPEC_INIT(&opspec);

    err = hse_kvdb_init();
    if (err)
        fatal(err, "failed to initialize kvdb");

    /* Set default KVDB and KVS rparams */
    hse_params_create(&params);

    /* Allow user to over-ride */
    err = hse_parse_cli(argc - optind, argv + optind, &optind, 0, params);
    if (err)
        fatal(err, "invalid parameter (use -C for more info)");

    argc -= optind;
    argv += optind;

    if (argc < 2) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    if (argc > 2) {
        syntax("extraneous argument: %s", argv[argc - 1]);
        exit(EX_USAGE);
    }

    mpname = argv[0];
    kvname = argv[1];

    if (deletem && isatty(fileno(stdin))) {
        printf("WARNING!! This will delete all keys from this kvs.\n");
        printf("Type YES to continue, else will abort: ");
        fflush(stdout);
        if (!fgets(kbuf, sizeof(kbuf), stdin) || strcmp(kbuf, "YES\n")) {
            printf("aborted\n");
            exit(1);
        }
    }

    pfxlen = fmt_data(pbuf, prefix);
    seeklen = fmt_data(sbuf, seek);

    prefix = pbuf;
    seek = sbuf;

    err = hse_kvdb_open(mpname, params, &kvdb_h);
    if (err)
        fatal(err, "cannot open kvdb %s", mpname);

    EVENT_START(to);
    err = hse_kvdb_kvs_open(kvdb_h, kvname, params, &kvs_h);
    EVENT_SAMPLE(to);
    if (err)
        fatal(err, "cannot open kvs %s/%s", mpname, kvname);

    EVENT_START(tc);
    if (reverse)
        opspec.kop_flags |= HSE_KVDB_KOP_FLAG_REVERSE;

    err = hse_kvs_cursor_create(kvs_h, &opspec, prefix, pfxlen, &cursor);
    EVENT_SAMPLE(tc);
    if (err) {
        fmt_pe(kbuf, pfxlen, prefix, pfxlen);
        fatal(err, "cannot create cursor for prefix %s", kbuf);
    }

    if (seeklen) {
        EVENT_START(ts);
        err = hse_kvs_cursor_seek(cursor, &opspec, seek, seeklen, 0, 0);
        EVENT_SAMPLE(ts);
        if (err)
            fatal(err, "cannot seek to %.*s", seeklen, seek);
    }

    if (Opts.kmax == 0)
        uniq = false;

    if (SIG_ERR == signal(SIGINT, sigint_isr))
        fatal(errno, "cannot install signal handler");

    if (shr.mark > 0) {
        rc = pthread_create(&shr.tid, NULL, status, &shr);
        if (rc)
            fatal(rc, "pthread_create failed");
    }

    keyhash = valhash = 0;
    eof = false;

    for (iter = 0; iter < max_iter; iter++) {
        const void *key, *val;
        size_t      klen, vlen;

        if (stats)
            EVENT_START(tr);

        err = hse_kvs_cursor_read(cursor, 0, &key, &klen, &val, &vlen, &eof);

        if (stats)
            EVENT_SAMPLE(tr);

        if (err || eof || sigint)
            break;

        ++shr.count;

        if (deletem) {
            err = hse_kvs_delete(kvs_h, &opspec, key, klen);
            if (err) {
                fmt_pe(kbuf, klen, key, klen);
                fatal(err, "cannot delete %s", kbuf);
            }
            continue;
        }

        if (uniq) {
            static char   keyprev[HSE_KVS_KLEN_MAX];
            static size_t klenprev;
            size_t        len = klen;

            if (klen > Opts.kmax)
                len = Opts.kmax;

            if (len == klenprev && 0 == memcmp(keyprev, key, len))
                continue;

            memcpy(keyprev, key, len);
            klenprev = len;
            ++shr.uniq;
        }

        if (countem) {
            if (cksum) {
                keyhash = XXH64(key, klen, keyhash);
                if (Opts.vmax > 0) {
                    if (vlen > Opts.vmax)
                        vlen = Opts.vmax;
                    valhash = XXH64(val, vlen, valhash);
                }
            }
        } else {
            if (Opts.hexonly)
                show_hex(key, klen, val, vlen, showlen);
            else
                show(key, klen, val, vlen, showlen);
        }
    }

    if (shr.mark > 0) {
        shr.mark = 0;
        pthread_kill(shr.tid, SIGINT);
        pthread_join(shr.tid, NULL);
    }

    if (err)
        fatal(err, "cannot read cursor at iteration %lu", iter);

    EVENT_START(td);
    hse_kvs_cursor_destroy(cursor);
    EVENT_SAMPLE(td);

    if (deletem)
        printf("%lu deleted\n", shr.count);
    if (uniq)
        printf("%lu unique\n", shr.uniq);
    if (countem)
        printf("%lu %016lx %016lx\n", shr.count, keyhash, valhash);

    if (stats) {
        EVENT_PRINT(to, "hse_kvdb_kvs_open");
        EVENT_PRINT(tc, "kvdb_begin_scan"); /* aka cursor_create */
        if (seeklen)
            EVENT_PRINT(ts, "kvdb_cursor_seek");
        EVENT_PRINT(tr, "kvdb_cursor_read");
        EVENT_PRINT(td, "kvdb_end_scan"); /* aka cursor_destroy */
    }

    err = hse_kvdb_close(kvdb_h);
    if (err)
        warn(err, "hse_kvdb_close");

    hse_params_destroy(params);

    hse_kvdb_fini();

    return 0;
}
