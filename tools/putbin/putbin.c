/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */

/*
 * putbin - the simplest possible client to just put sequential binary keys
 *
 * this is useful for creating bulk, controlled ingest loads of new keys
 * it is hardly useful for simulating any real life application
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <hse/hse.h>

#include <hse_util/event_timer.h>
#include <hse_util/hse_params_helper.h>

#include <tools/common.h>

enum Actions { PUT = 0, GET = 1, DEL = 2 };

struct Action {
    char *name;
    char *verb;
} tab[] = {
    { "put", "writing" },
    { "get", "reading" },
    { "del", "deleting" },
};

/* --------------------------------------------------
 * Action functions
 */

struct info {
    pthread_t tid;
    int       joined;
    void *    kvs;
    void *    kvdb;
    char *    buf;
    int       paws;
    int       niter;
    int       action;
    int       error;
    unsigned  start;
    unsigned  last;
    unsigned  stride;
    unsigned  endian;

    void * key;
    size_t klen;
    void * val;
    size_t vlen;
};

struct hse_kvdb_opspec opspec;

void *
run(void *p)
{
    struct info *   ti = p;
    uint32_t *      seq = ti->key;
    uint32_t *      uniq = ti->val + sizeof(*seq);
    void *          h = ti->kvs;
    char *          test = tab[ti->action].name;
    unsigned        i;
    bool            found;
    int             now;
    struct timespec ts;
    char            msg[256];

    EVENT_TIMER(t);
    EVENT_INIT(t);

    HSE_KVDB_OPSPEC_INIT(&opspec);

    /*
	 * fake a unique value that is likely unique, but really fast,
	 * and is comparable in time, but not checked for correctness:
	 * this is useful for debugging compaction for same keys
	 */
    now = 0;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        now = (ts.tv_sec << 20) | (ts.tv_nsec >> 10);

    for (i = ti->start; i < ti->last; ++i) {
        int rc = 0;

        /* give system a chance to catch up */
        if (ti->paws && i != ti->start && i % ti->paws == 0) {
            printf("sleep(2) after %d keys....\n", i - ti->start);
            sleep(2);
        }

        *seq = ti->endian == LITTLE_ENDIAN ? htole32(i) : htobe32(i);
        *uniq = htonl(now++);
        found = false;

        /*
		 * The Meat-N-Potatos is all in this one switch.
		 */
        switch (ti->action) {
            case GET:
                EVENT_START(t);

                rc = hse_kvs_get(
                    h, &opspec, ti->key, ti->klen, &found, ti->val, ti->vlen, &ti->vlen);
                EVENT_SAMPLE(t);
                break;

            case DEL:
                EVENT_START(t);
                rc = hse_kvs_delete(h, &opspec, ti->key, ti->klen);
                EVENT_SAMPLE(t);
                break;

            case PUT:
                EVENT_START(t);
                rc = hse_kvs_put(h, &opspec, ti->key, ti->klen, ti->val, ti->vlen);
                EVENT_SAMPLE(t);
                break;

            default:
                fatal(ESRCH, "invalid action");
        }

        if (rc)
            fatal(rc, test);

        if (ti->action == GET) {
            if (!found) {
                ++ti->error;
                printf("key %d not found\n", ntohl(*seq));
                break;
            }
            if (*seq != *(uint32_t *)ti->val) {
                printf("key %d has wrong value: %d\n", ntohl(*seq), *(uint32_t *)ti->val);
                break;
            }
        }
    }

    snprintf(
        msg, sizeof(msg), "%s: tid 0x%0lx: keys %d..%d", test, ti->tid, ti->start, ti->last - 1);
    EVENT_PRINT(t, msg);
    return 0;
}

/* --------------------------------------------------
 * Driver
 */

int
do_open(
    const char *       mpname,
    const char *       kvname,
    struct hse_params *params,
    struct hse_kvdb ** kvdb,
    void **            h)
{
    int rc;

    rc = hse_kvdb_open(mpname, params, kvdb);
    if (rc)
        fatal(rc, "cannot open kvdb %s", mpname);

    rc = hse_kvdb_kvs_open(*kvdb, kvname, params, (struct hse_kvs **)h);
    if (rc)
        fatal(rc, "cannot open kvs %s/%s", mpname, kvname);

    return 0;
}

void
do_close(void *h, bool sync)
{
    int rc;

    if (sync) {
        rc = hse_kvdb_sync(h);
        if (rc)
            fatal(rc, "cannot sync");
        return;
    }

    rc = hse_kvdb_close(h);
    if (rc)
        fatal(rc, "cannot close kvdb/kvs");
}

void
do_params(int *argc, char ***argv, struct hse_params *params)
{
    int idx = optind;

    if (hse_parse_cli(*argc - idx, *argv + idx, &idx, 0, params))
        rp_usage();

    *argc -= idx;
    *argv += idx;
    optind = 0;
}

void
usage(char *prog)
{
    fprintf(
        stderr,
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-C    list tunable parameters\n"
        "-c n  do count $n operations per iteration, default 1000\n"
        "-D    delete puts\n"
        "-i n  repeat for $n iterations; default 1\n"
        "-L n  length of values is $n; default keylen\n"
        "-l n  length of keys and values is $n; default 4\n"
        "-n n  nop; pauses n ms to allow compaction\n"
        "-p n  pause 2 seconds after every $n keys; default none\n"
        "-s n  start sequence at $n; default 1\n"
        "-t n  run in $n threads; default 1\n"
        "-V    verify puts, fails on first miss\n"
        "-v n  set hse_log_pri to $n\n"
        "-X    exit with sync instead of close\n",
        prog);

    exit(1);
}

int
main(int argc, char **argv)
{
    struct hse_params *params;
    char *             mpname, *prog;
    const char *       kvname;
    unsigned char      data[4096];
    struct hse_kvdb *  kvdb;
    void *             h;
    struct info *      info;
    int                tc;
    int                rc;
    int                i, c;
    unsigned           action, endian, iter, paws, comp;
    unsigned           cnt, start, klen, vlen;
    unsigned           opt_params = 0;
    unsigned           opt_help = 0;
    unsigned           opt_sync = 0;

    prog = basename(argv[0]);
    klen = 4;
    vlen = klen + 4;
    cnt = 1000;
    start = 0;
    iter = 1;
    tc = 1;
    comp = 0;
    paws = 0;
    action = PUT;
    endian = BIG_ENDIAN;

    while ((c = getopt(argc, argv, "?VDCXen:p:t:i:l:L:c:s:o:")) != -1) {
        switch (c) {
            case 'V':
                action = GET;
                break;
            case 'D':
                action = DEL;
                break;
            case 'C':
                opt_params++;
                break;
            case 'X':
                opt_sync++;
                break;
            case 'e':
                endian = LITTLE_ENDIAN;
                break;
            case 'n':
                comp = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'p':
                paws = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 't':
                tc = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'i':
                iter = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'l':
                klen = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'L':
                vlen = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'c':
                cnt = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 's':
                start = (unsigned)strtoul(optarg, 0, 0);
                break;
            case '?': /* fallthru */
            default:
                opt_help++;
                break;
        }
    }

    if (opt_help)
        usage(prog);
    if (opt_params)
        rp_usage();

    rc = hse_init();
    if (rc)
        fatal(rc, "failed to initialize kvdb");

    hse_params_create(&params);

    do_params(&argc, &argv, params);

    if (argc != 2)
        usage(prog);

    mpname = argv[0];
    kvname = argv[1];

    /*
	 * putbin makes an easy vehicle for compression cycles
	 * short-circuit here
	 */
    if (comp) {
        do_open(mpname, kvname, params, &kvdb, &h);

        /* wait a while -- compaction happens during this interval */
        poll(0, 0, comp);

        do_close(kvdb, 0);
        return 0;
    }

    info = calloc(tc, sizeof(*info));
    if (!info)
        fatal(0, "cannot alloc thread info");

    /*
	 * keys and values share the same data buffer,
	 * which is modified to hold the sequence number;
	 * this makes for easier visual verification
	 */
    for (c = 0; c < sizeof(data); ++c)
        data[c] = c & 0xff;

    for (c = 0; c < tc; ++c) {
        char *buf;
        int   len = klen > vlen ? klen : vlen;

        buf = malloc(len);
        if (!buf)
            fatal(0, "cannot alloc thread buffers");

        memcpy(buf, data, len);

        info[c].klen = klen;
        info[c].key = buf;
        info[c].vlen = vlen;
        info[c].val = buf;
    }

    for (i = 0; i < iter; ++i) {
        struct info *ti;
        unsigned     stride = cnt / (tc ?: 1);
        int          rc;

        printf(
            "%s %u binary keys of len %d, starting with %u, "
            "in %d threads\n",
            tab[action].verb,
            cnt,
            klen,
            start,
            tc);

        if (i == 0 || !opt_sync)
            do_open(mpname, kvname, params, &kvdb, &h);

        for (c = 0; c < tc; ++c) {
            ti = &info[c];
            ti->kvdb = kvdb;
            ti->kvs = h;
            ti->joined = 1;
            ti->paws = paws;
            ti->start = start + stride * c;
            ti->last = ti->start + stride;
            ti->action = action;
            ti->endian = endian;

            rc = pthread_create(&ti->tid, 0, run, ti);
            if (rc)
                warn(rc, "cannot create thread %d", c);
            else
                ti->joined = 0;
        }

        for (c = 0; c < tc; ++c) {
            ti = &info[c];
            if (ti->joined)
                continue;
            rc = pthread_join(ti->tid, 0);
            if (rc)
                warn(rc, "cannot join tid[%d]=%d: %d %s", c, ti->tid, rc, strerror(rc));
            else
                ti->joined = 1;
        }

        for (c = 0; c < tc;) {
            ti = &info[c];
            if (ti->joined) {
                ++c;
                continue;
            }
            rc = pthread_join(ti->tid, 0);
            if (rc) {
                warn(rc, "repeated join tid[%d]=%d: %d %s", c, ti->tid, rc, strerror(rc));
                usleep(2000);
            } else
                ++c;
        }

        /* this is used to allow compact/spill to run */
        if (tc == 0 && paws) {
            printf("sleeping for %d seconds....\n", paws);
            sleep(paws);
        }

        do_close(kvdb, opt_sync);

        start += cnt;
    }

    rc = 0;
    for (c = 0; c < tc; ++c)
        if (info[c].error)
            rc = 1;

    for (c = 0; c < tc; ++c)
        free(info[c].key);
    free(info);

    hse_params_destroy(params);

    hse_fini();

    return rc;
}
