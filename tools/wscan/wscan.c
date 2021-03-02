/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */

/*
 * wscan - scan/write loop
 *
 * Search for MAIN to get to the interesting logic.
 */

#define USE_EVENT_TIMER

#include <getopt.h>
#include <libgen.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <hse/hse.h>

#include <hse_util/event_timer.h>
#include <hse_util/fmt.h>
#include <hse_util/hse_params_helper.h>
#include <hse_util/inttypes.h>

#include <tools/common.h>

void
showkey(const void *key, size_t klen)
{
    char kbuf[150]; /* 2.25x the max unformatted len */

    fmt_pe(kbuf, 50, key, klen);
    printf("%lu %s\n", klen, kbuf);
}

u32
mk_key(char *buf, u64 key)
{
    return snprintf((char *)buf, 1000, "%08x", (u32)key);
}

u32
mk_val(char *buf, u64 val)
{
    *(u64 *)buf = val;
    return sizeof(val);
}

void
usage(const char *prog, bool params)
{
    fprintf(
        stderr,
        "usage: %s [options] [kvdb kvs] [param=value ...]\n"
        "-0    disable c0 seeding -- requires cn has prev run\n"
        "-C    list tunable parameters\n"
        "-g    get the key just put using hse_kvs_get\n"
        "-i n  do $n iterations between cursors\n"
        "-s n  start with $n\n"
        "-U    update cursor (vs restart it)\n"
        "-v n  set verbosity to $n\n",
        prog);

    if (params)
        rp_usage();

    exit(1);
}

int _sig;

void
sighandler(int signo)
{
    ++_sig;
}

int
main(int argc, char **argv)
{
    static char kbuf[HSE_KVS_KLEN_MAX];
    static char vbuf[HSE_KVS_VLEN_MAX];

    struct hse_params *    params;
    const char *           mpname, *dsname, *kvname, *prog;
    struct hse_kvdb_opspec opspec;
    struct hse_kvs_cursor *cur;
    struct hse_kvdb *      h;
    struct hse_kvs *       kvs;
    u64                    start = 0;
    u64                    incr = 100000;
    int                    update, c0, get;
    int                    c;
    int                    err;
    unsigned               opt_params = 0;
    unsigned               opt_help = 0;

    EVENT_TIMER(tb);
    EVENT_TIMER(ts);
    EVENT_TIMER(tr);
    EVENT_TIMER(tu);
    EVENT_TIMER(cl);

    EVENT_INIT(tb);
    EVENT_INIT(ts);
    EVENT_INIT(tr);
    EVENT_INIT(tu);
    EVENT_INIT(cl);

    prog = basename(argv[0]);
    update = 0;
    c0 = 1;
    get = 0;

    while ((c = getopt(argc, argv, "?CU0gi:s:")) != -1) {
        switch (c) {
            case 'C':
                opt_params++;
                break;
            case 'U':
                update = 1;
                break;
            case '0':
                c0 = 0;
                break;
            case 'g':
                ++get;
                break;
            case 's':
                start = strtoull(optarg, 0, 0);
                break;
            case 'i':
                incr = strtoull(optarg, 0, 0);
                break;
            case '?': /* fallthru */
            default:
                opt_help++;
                break;
        }
    }

    if (opt_help)
        usage(prog, opt_params);
    if (opt_params)
        rp_usage();

    err = hse_kvdb_init();
    if (err)
        fatal(err, "failed to initialize kvdb");

    hse_params_create(&params);

    hse_params_set(params, "kvdb.perfc_enable", "0");
    hse_params_set(params, "kvdb.rdonly", "0");

    hse_params_set(params, "kvs.cn_mcache_wbt", "0");
    hse_params_set(params, "kvs.cn_bloom_lookup", "0");

    err = hse_parse_cli(argc - optind, argv + optind, &optind, 0, params);
    if (err)
        rp_usage();

    argc -= optind;
    argv += optind;

    if (argc < 3)
        usage(prog, false);

    mpname = argv[0];
    dsname = argv[1];
    kvname = argv[2];

    /* ==================================================
	 * MAIN: Everything else is preamble to get to here.
	 * This is the stuff you really wanted to see.
	 */

    HSE_KVDB_OPSPEC_INIT(&opspec);

    err = hse_kvdb_open(mpname, params, &h);
    if (err)
        fatal(err, "cannot open %s/%s", mpname, dsname);

    err = hse_kvdb_kvs_open(h, kvname, params, &kvs);
    if (err)
        fatal(err, "cannot open %s/%s/%s", mpname, dsname, kvname);

    /* MU_REVISIT: bypass bug where c0sk params not plumbed thru */
    err = hse_kvdb_sync(h);
    if (err)
        fatal(err, "cannot flush");
    err = hse_kvdb_sync(h);
    if (err)
        fatal(err, "cannot flush");

    /*
	// loop:
	// create cursor
	// put keys
	// read cursor -- not newly added keys
	// close cursor
	// goto loop
	// should show a problem in spill
	// need a signal handler to exit loop cleanly on ctl-c
	*/

    u64              key = start;
    u64              end = start + incr;
    size_t           klen, vlen;
    bool             eof;
    time_t           t, tnext = 0;
    char *           errmsg = 0;
    struct sigaction sact;

    bzero(&sact, sizeof(sact));
    sact.sa_handler = sighandler;
    sigemptyset(&sact.sa_mask);
    sact.sa_flags = 0;
    sigaction(SIGINT, &sact, 0);

    /* 100k test setup */
    if (c0) {
        printf("==== putting %ld keys ====\n", incr);
        while (!_sig && ++key < end) {
            klen = mk_key(kbuf, key);
            vlen = mk_val(vbuf, 0);

            err = hse_kvs_put(kvs, &opspec, kbuf, klen, vbuf, vlen);
            if (err) {
                errmsg = "cannot put key";
                goto error;
            }
        }
    }

#define begin()                                                \
    do {                                                       \
        EVENT_START(tb);                                       \
        err = hse_kvs_cursor_create(kvs, &opspec, 0, 0, &cur); \
        EVENT_SAMPLE(tb);                                      \
        if (err) {                                             \
            errmsg = "cannot begin scan";                      \
            break;                                             \
        }                                                      \
    } while (0)

#define seek()                                                          \
    do {                                                                \
        EVENT_START(ts);                                                \
        err = hse_kvs_cursor_seek(cur, &opspec, kbuf, klen, &k, &vlen); \
        EVENT_SAMPLE(ts);                                               \
        if (err) {                                                      \
            errmsg = "cannot seek";                                     \
            break;                                                      \
        }                                                               \
                                                                        \
        if (vlen != klen || memcmp(kbuf, k, vlen) != 0) {               \
            printf("wanted: ");                                         \
            showkey(kbuf, klen);                                        \
            printf("found: ");                                          \
            showkey(k, vlen);                                           \
            errmsg = "seek did not return match";                       \
            break;                                                      \
        }                                                               \
    } while (0)

#define cread()                                                        \
    do {                                                               \
        EVENT_START(tr);                                               \
        err = hse_kvs_cursor_read(cur, 0, &k, &klen, &v, &vlen, &eof); \
        EVENT_SAMPLE(tr);                                              \
        if (err) {                                                     \
            errmsg = "cannot read cursor";                             \
            break;                                                     \
        }                                                              \
    } while (0)

#define end()                              \
    do {                                   \
        err = hse_kvs_cursor_destroy(cur); \
        if (err) {                         \
            errmsg = "cannot end scan";    \
            break;                         \
        }                                  \
    } while (0)

    printf("==== starting update loop ====\n");

    /* once, at start of loop */
    if (update)
        begin();

    key = start;
    while (!_sig && ++key < end) {
        const void *k, *v;
        u64         n = 1;

        klen = mk_key(kbuf, key);

        if (update == 0)
            begin();
        seek();
        cread();

        if (errmsg)
            break;

        if (!c0)
            n = *(u64 *)v + 1;
        vlen = mk_val(vbuf, n);
        err = hse_kvs_put(kvs, &opspec, kbuf, klen, vbuf, vlen);
        if (err) {
            errmsg = "cannot update key";
            break;
        }

        if (get == 1 || get == 3) {
            char   xbuf[1024];
            bool   fnd = 0;
            size_t xlen;

            err = hse_kvs_get(kvs, &opspec, kbuf, klen, &fnd, xbuf, sizeof(xbuf), &xlen);
            if (err || !fnd) {
                errmsg = "cannot get key just put";
                break;
            }

            if (vlen != xlen || memcmp(xbuf, vbuf, vlen)) {
                errmsg = "get incorrect value after put";
                break;
            }
        }

        if (update == 0) {
            end();
            begin();
            if (errmsg)
                break;
        } else {
            EVENT_START(tu);
            err = hse_kvs_cursor_update(cur, &opspec);
            EVENT_SAMPLE(tu);
            if (err) {
                errmsg = "cannot update cursor";
                break;
            }
        }

        seek();
        if (errmsg)
            break;
        cread();
        if (errmsg)
            break;

        if (*(u64 *)v != n) {
            const void *x = vbuf;

            printf("key %ld  val %ld  wrote %ld  expect %ld\n", key, *(u64 *)v, *(u64 *)x, n);
            err = key;
            errmsg = "value not updated!";
            break;
        }

        if (get > 1) {
            char   xbuf[1024];
            bool   fnd = 0;
            size_t xlen;

            err = hse_kvs_get(kvs, &opspec, kbuf, klen, &fnd, xbuf, sizeof(xbuf), &xlen);
            if (err || !fnd) {
                errmsg = "cannot get key after cursor update";
                break;
            }

            if (vlen != xlen || memcmp(xbuf, vbuf, vlen)) {
                errmsg = "get incorrect value after update";
                break;
            }
        }

        if (update == 0)
            end();

        t = time(0);
        if (t > tnext) {
            printf("---------- interval --------- %s", ctime(&t));
            EVENT_PRINT(tb, "begin_scan");
            EVENT_PRINT(ts, "cursor_seek");
            EVENT_PRINT(tr, "cursor_read");
            EVENT_PRINT(tu, "cursor_update");
            tnext = t + 10;
        }
    }

    if (errmsg) {
        if (err)
            printf("ERROR: %s: %d\n", errmsg, err);
        else
            printf("ERROR: %s\n", errmsg);
    }

    if (update)
        end();

    t = time(0);
    printf("---------- end --------- %s", ctime(&t));
    EVENT_PRINT(tb, "begin_scan");
    EVENT_PRINT(ts, "cursor_seek");
    EVENT_PRINT(tr, "cursor_read");
    EVENT_PRINT(tu, "cursor_update");

error:
    EVENT_START(cl);
    hse_kvdb_close(h);
    EVENT_SAMPLE(cl);
    EVENT_PRINT(cl, "hse_kvdb_close");
    if (err)
        fatal(err, errmsg);

    hse_params_destroy(params);

    hse_kvdb_fini();

    return 0;
}
