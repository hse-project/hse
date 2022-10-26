/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2021-2022 Micron Technology, Inc. All rights reserved.
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

#include <hse/util/event_timer.h>

#include <tools/common.h>
#include <tools/parm_groups.h>

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
    struct hse_kvs *kvs;
    struct hse_kvdb *kvdb;
    char *    buf;
    int       paws;
    int       niter;
    int       action;
    int       error;
    unsigned  long start;
    unsigned  long last;
    unsigned  stride;
    unsigned  endian;

    void * key;
    size_t klen;
    void * val;
    size_t vlen;
};

void *
run(void *p)
{
    struct info *   ti = p;
    uint32_t *      seq = ti->key;
    uint32_t *      uniq = ti->val + sizeof(*seq);
    struct hse_kvs *h = ti->kvs;
    char *          test = tab[ti->action].name;
    unsigned long   i;
    bool            found;
    int             now;
    struct timespec ts;
    char            msg[256];

    EVENT_TIMER(t);
    EVENT_INIT(t);

    /*
	 * fake a unique value that is likely unique, but really fast,
	 * and is comparable in time, but not checked for correctness:
	 * this is useful for debugging compaction for same keys
	 */
    now = 0;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        now = (ts.tv_sec << 20) | (ts.tv_nsec >> 10);

    for (i = ti->start; i < ti->last; ++i) {
        hse_err_t rc = 0;

        /* give system a chance to catch up */
        if (ti->paws && i != ti->start && i % ti->paws == 0) {
            printf("sleep(2) after %lu keys....\n", i - ti->start);
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
                    h, 0, NULL, ti->key, ti->klen, &found, ti->val, ti->vlen, &ti->vlen);
                EVENT_SAMPLE(t);
                break;

            case DEL:
                EVENT_START(t);
                rc = hse_kvs_delete(h, 0, NULL, ti->key, ti->klen);
                EVENT_SAMPLE(t);
                break;

            case PUT:
                EVENT_START(t);
                rc = hse_kvs_put(h, 0, NULL, ti->key, ti->klen, ti->val, ti->vlen);
                EVENT_SAMPLE(t);
                break;

            default:
                fatal(ESRCH, "invalid action");
        }

        if (rc)
            fatal(rc, "%s", test);

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
        msg, sizeof(msg), "%s: tid 0x%0lx: keys %lu..%lu", test, ti->tid, ti->start, ti->last - 1);
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
    struct parm_groups * pg,
    struct hse_kvdb ** kvdb,
    struct hse_kvs **  kvs)
{
    hse_err_t rc;

    struct svec sv = { 0 };

    rc = svec_append_pg(&sv, pg, PG_KVDB_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_append_pg");

    rc = hse_kvdb_open(mpname, sv.strc, sv.strv, kvdb);
    if (rc)
        fatal(rc, "cannot open kvdb %s", mpname);

    svec_reset(&sv);

    rc = svec_append_pg(&sv, pg, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "svec_append_pg");

    rc = hse_kvdb_kvs_open(*kvdb, kvname, sv.strc, sv.strv, kvs);
    if (rc)
        fatal(rc, "cannot open kvs %s/%s", mpname, kvname);

    svec_reset(&sv);

    return 0;
}

void
do_close(struct hse_kvdb *kvdb, bool sync)
{
    hse_err_t rc;

    if (sync) {
        rc = hse_kvdb_sync(kvdb, 0);
        if (rc)
            fatal(rc, "cannot sync");
        return;
    }

    rc = hse_kvdb_close(kvdb);
    if (rc)
        fatal(rc, "cannot close kvdb");
}

void
usage(char *prog)
{
    fprintf(
        stderr,
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-c n       do count $n operations per iteration, default 1000\n"
        "-D         delete puts\n"
        "-h         print help\n"
        "-i n       repeat for $n iterations; default 1\n"
        "-L n       length of values is $n; default keylen\n"
        "-l n       length of keys and values is $n; default 4\n"
        "-n n       nop; pauses n ms to allow compaction\n"
        "-p n       pause 2 seconds after every $n keys; default none\n"
        "-s n       start sequence at $n; default 1\n"
        "-t n       run in $n threads; default 1\n"
        "-V         verify puts, fails on first miss\n"
        "-v n       set hse_log_pri to $n\n"
        "-X         exit with sync instead of close\n"
        "-Z config  path to global config file\n",
        prog);

    exit(0);
}

int
main(int argc, char **argv)
{
    const char *       config = NULL;
    char *             mpname, *prog;
    struct parm_groups  *pg = NULL;
    const char *       kvname;
    unsigned char      data[4096];
    struct hse_kvdb *  kvdb;
    struct hse_kvs *   kvs;
    struct info *      info;
    int                c, tc;
    int                rc;
    unsigned           action, endian, iter, paws, comp;
    unsigned           klen, vlen;
    unsigned long      start, cnt;
    unsigned           opt_sync = 0;
    struct svec        hse_gparm = { 0 };

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

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        fatal(rc, "pg_create");

    opterr = 0;

    while ((c = getopt(argc, argv, "?hVDC:Xen:p:t:i:l:L:c:s:o:Z:")) != -1) {
        switch (c) {
            case 'V':
                action = GET;
                break;
            case 'D':
                action = DEL;
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
                cnt = strtoul(optarg, 0, 0);
                break;
            case 's':
                start = strtoul(optarg, 0, 0);
                break;
            case 'Z':
                config = optarg;
                break;
            case 'h':
                usage(prog);
                break;
            case '?': /* fallthru */
            default:
                fatal(0, "invalid option: -%c\nuse -h for help\n", c);
                break;
        }
    }

    if (argc - optind < 2)
        fatal(0, "missing required parameter\nuse -h for help");

    mpname = argv[optind++];
    kvname = argv[optind++];

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

    rc = svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    if (rc)
        fatal(rc, "failed to parse hse-gparams");

    rc = hse_init(config, hse_gparm.strc, hse_gparm.strv);
    if (rc)
        fatal(rc, "failed to initialize kvdb");

    /* putbin makes an easy vehicle for compression cycles
     * short-circuit here
     */
    if (comp) {
        do_open(mpname, kvname, pg, &kvdb, &kvs);

        /* wait a while -- compaction happens during this interval */
        poll(0, 0, comp);

        do_close(kvdb, 0);
        pg_destroy(pg);
        hse_fini();
        return 0;
    }

    info = calloc(tc, sizeof(*info));
    if (!info)
        fatal(0, "cannot alloc thread info");

    /* keys and values share the same data buffer,
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

    for (int i = 0; i < iter; ++i) {
        struct info *ti;
        unsigned     stride = cnt / (tc ? tc : 1);
        int          rc;

        printf(
            "%s %lu binary keys of len %d, starting with %lu, "
            "in %d threads\n",
            tab[action].verb,
            cnt,
            klen,
            start,
            tc);

        if (i == 0 || !opt_sync)
            do_open(mpname, kvname, pg, &kvdb, &kvs);

        for (c = 0; c < tc; ++c) {
            ti = &info[c];
            ti->kvdb = kvdb;
            ti->kvs = kvs;
            ti->joined = 1;
            ti->paws = paws;
            ti->start = start + (unsigned long)(stride * c);
            ti->last = c == tc - 1 ? start + cnt : ti->start + stride;
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
                warn(rc, "cannot join tid[%d]=%ld: %d %s", c, ti->tid, rc, strerror(rc));
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
                warn(rc, "repeated join tid[%d]=%ld: %d %s", c, ti->tid, rc, strerror(rc));
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

    /* Call hse_fini only if the kvdb was closed.
     */
    if (!opt_sync)
        hse_fini();

    pg_destroy(pg);
    svec_reset(&hse_gparm);

    return rc;
}
