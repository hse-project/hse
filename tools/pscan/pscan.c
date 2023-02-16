/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/*
 * pscan - the simplest possible client to scan prefixes
 *
 * Search for MAIN to get to the interesting logic.
 */

#define USE_EVENT_TIMER

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <xxhash.h>

#include <hse/flags.h>
#include <hse/hse.h>

#include <hse/cli/output.h>
#include <hse/cli/program.h>
#include <hse/util/arch.h>
#include <hse/util/event_timer.h>
#include <hse/util/fmt.h>

#include <hse/tools/common.h>
#include <hse/tools/parm_groups.h>

int verbosity;
bool headers = true;
bool uniq = false;
sig_atomic_t sigint;

struct parm_groups *pg;
struct svec hse_gparm = { 0 };
struct svec db_oparm = { 0 };
struct svec kv_oparm = { 0 };

/**
 * struct shr - Data shared between pthreads...
 * @count:      total number of keys retrieved
 * @mark:       time in seconds between status updates
 * @uniq:       total number of unique keys retrieved
 */
struct shr {
    volatile uint64_t count;
    volatile uint32_t mark;
    uint64_t uniq;
    pthread_t tid;
};

void
usage(void)
{
    printf(
        "usage: %s [options] mp kvdb kvs [param=value ...]\n"
        "-C        count keys (no checksum)\n"
        "-c        count keys (compute running checksum)\n"
        "-D        delete keys as you find them\n"
        "-H        suppress column headers\n"
        "-h        print this help list\n"
        "-i iter   call cursor read at most $iter times\n"
        "-k klen   limit keys to $klen bytes (-klen means first klen)\n"
        "-l        show length of keys / values\n"
        "-m mark   print status every $mark seconds\n"
        "-p pfx    limit scans to prefix $pfx\n"
        "-r        use reverse scan\n"
        "-s skey   seek to $skey before first cursor read\n"
        "-t        show timing stats at end of run\n"
        "-u        count only unique keys\n"
        "-V vmax   limit vals to $vmax bytes (-vmax means first vmax)\n"
        "-v        increase verbosity\n"
        "-x        output in hexadecimal\n"
        "-Z config path to global config file\n",
        progname);

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
    uint64_t tstart, tprev, now;
    uint64_t cnt, cntprev, delta;
    char hdr[128], fmt[128];
    uint line;

    snprintf(
        hdr, sizeof(hdr), "\n%9s %12s %10s %10s %10s %10s\n", "ELAPSED", "tKEYS", "tKEYS/s",
        "iKEYS", "iUSECS", uniq ? "tUNIQ" : "");

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
            fmt, (line++ % 24) == 0 && headers ? hdr : "", (now - tstart) / 1000000, cnt,
            (cnt * 1000000000) / (now - tstart), cnt - cntprev, (now - tprev) / 1000, shr->uniq);
        fflush(stdout);

        cntprev = cnt;
        tprev = now;
    }

    pthread_exit(NULL);
}

int
main(int argc, char **argv)
{
    const char *config = NULL;
    char kbuf[1024], pbuf[128], sbuf[128];
    struct parm_groups *pg = NULL;
    const char *mpname, *kvname;
    char *prefix, *seek;
    struct hse_kvs_cursor *cursor;
    struct hse_kvdb *kvdb_h;
    struct hse_kvs *kvs_h;
    uint64_t keyhash, valhash;
    int showlen;
    int seeklen, pfxlen;
    bool eof, countem, cksum, deletem, stats;
    bool reverse = false;
    unsigned opt_help = 0, flags = 0;
    uint64_t iter, max_iter;
    int c, rc, err;
    struct shr shr = { 0 };

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

    countem = deletem = stats = false;
    showlen = seeklen = pfxlen = 0;
    cksum = true;
    prefix = "";
    seek = NULL;
    max_iter = ULONG_MAX;

    Opts.kmax = HSE_KVS_KEY_LEN_MAX;
    Opts.vmax = HSE_KVS_VALUE_LEN_MAX;
    Opts.hexonly = 0;

    progname_set(argv[0]);

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "pg_create");

    while ((c = getopt(argc, argv, ":CcDHhi:k:lm:p:rs:t:uV:vxZ:")) != -1) {
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

    if (argc - optind < 2) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    mpname = argv[optind++];
    kvname = argv[optind++];

    /* get hse parms from command line */
    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
    case 0:
        if (optind < argc)
            fatalx("unknown parameter: %s", argv[optind]);
        break;
    case EINVAL:
        fatalx("missing group name (e.g. %s) before parameter %s\n", PG_KVDB_OPEN, argv[optind]);
        break;
    default:
        fatal(rc, "error processing parameter %s\n", argv[optind]);
        break;
    }

    rc = rc ?: svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ?: svec_append_pg(&db_oparm, pg, PG_KVDB_OPEN, NULL);
    rc = rc ?: svec_append_pg(&kv_oparm, pg, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_apppend_pg failed");

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

    err = hse_init(config, hse_gparm.strc, hse_gparm.strv);
    if (err)
        fatal(err, "failed to initialize kvdb");

    err = hse_kvdb_open(mpname, db_oparm.strc, db_oparm.strv, &kvdb_h);
    if (err)
        fatal(err, "cannot open kvdb %s", mpname);

    EVENT_START(to);
    err = hse_kvdb_kvs_open(kvdb_h, kvname, kv_oparm.strc, kv_oparm.strv, &kvs_h);
    EVENT_SAMPLE(to);
    if (err)
        fatal(err, "cannot open kvs %s/%s", mpname, kvname);

    EVENT_START(tc);
    if (reverse)
        flags |= HSE_CURSOR_CREATE_REV;

    err = hse_kvs_cursor_create(kvs_h, flags, NULL, prefix, pfxlen, &cursor);
    EVENT_SAMPLE(tc);
    if (err) {
        fmt_pe(kbuf, pfxlen, prefix, pfxlen);
        fatal(err, "cannot create cursor for prefix %s", kbuf);
    }

    if (seeklen) {
        EVENT_START(ts);
        err = hse_kvs_cursor_seek(cursor, 0, seek, seeklen, 0, 0);
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
        size_t klen, vlen;

        if (stats)
            EVENT_START(tr);

        if (countem && !cksum)
            err = hse_kvs_cursor_read(cursor, 0, &key, &klen, NULL, NULL, &eof);
        else
            err = hse_kvs_cursor_read(cursor, 0, &key, &klen, &val, &vlen, &eof);

        if (stats)
            EVENT_SAMPLE(tr);

        if (err || eof || sigint)
            break;

        ++shr.count;

        if (deletem) {
            err = hse_kvs_delete(kvs_h, 0, NULL, key, klen);
            if (err) {
                fmt_pe(kbuf, klen, key, klen);
                fatal(err, "cannot delete %s", kbuf);
            }
            continue;
        }

        if (uniq) {
            static char keyprev[HSE_KVS_KEY_LEN_MAX];
            static size_t klenprev;
            size_t len = klen;

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
        error(err, "hse_kvdb_close");

    pg_destroy(pg);
    svec_reset(&hse_gparm);
    svec_reset(&db_oparm);
    svec_reset(&kv_oparm);

    hse_fini();

    return 0;
}
