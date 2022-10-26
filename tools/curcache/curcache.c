/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc. All rights reserved.
 */
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hse/hse.h>

#include <hse/util/compiler.h>

int              verbose = 0;
int              nthreads = 128;
int              niter = 10000;
struct hse_kvdb *kvdb;

void * HSE_PRINTF(2, 3)
tdie(int err, char *fmt, ...)
{
    static int fail = 1;

    char    buf[256];
    int     n;
    va_list ap;

    memset(buf, 0, sizeof(buf));
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (err)
        n += snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(err));
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
    return &fail;
}

void HSE_PRINTF(2, 3)
die(int err, char *fmt, ...)
{
    char    buf[256];
    int     n;
    va_list ap;

    memset(buf, 0, sizeof(buf));
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (err)
        n += snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(err));
    fprintf(stderr, "%s\n", buf);
    exit(1);
}

int
generate_random(int min, int max)
{
    double r = (double)rand() / (double)RAND_MAX;
    double tmp = min + r * (max - min);

    return (int)tmp;
}

struct cursor_info {
    struct hse_kvs *kvs;
};

void *
parallel_cursors(void *info)
{
    struct cursor_info *   ci = info;
    struct hse_kvs_cursor *c;
    char                   buf[32];
    const void *           k, *v;
    size_t                 klen, vlen, slen;
    int                    i;
    int                    err;

    for (i = 0; i < niter; ++i) {
        int  r = generate_random(100, 1000);
        bool eof;

        /* create different prefixes each time */
        sprintf(buf, "%d", r);
        err = hse_kvs_cursor_create(ci->kvs, 0, NULL, buf, 3, &c);
        if (err)
            return tdie(err, "cannot create cursor iter %d", i);

        klen = strlen(buf);
        err = hse_kvs_cursor_seek(c, 0, buf, klen, &k, &slen);
        if (err)
            return tdie(err, "cannot seek cursor iter %d to pfx %.3s", i, buf);
        if (slen == 0)
            return tdie(0, "cursor iter %d wanted %.3s, found eof", i, buf);
        if (slen != klen || memcmp(k, buf, klen) != 0)
            return tdie(0, "cursor iter %d found %.*s, wanted %.3s", i, (int)slen, (char *)k, buf);

        err = hse_kvs_cursor_read(c, 0, &k, &klen, &v, &vlen, &eof);
        if (err)
            return tdie(err, "cannot read cursor iter %d", i);
        if (eof)
            return tdie(err, "read eof cursor iter %d, key %.3s", i, buf);
        if (memcmp(k, buf, klen) != 0)
            return tdie(0, "cursor iter %d read %.*s, wanted %.3s", i, (int)klen, (char *)k, buf);
        if (memcmp(v, buf, vlen) != 0)
            return tdie(
                0,
                "cursor iter %d key %.3s, read value %.*s, "
                "wanted %.3s",
                i,
                (char *)k,
                (int)vlen,
                (char *)v,
                buf);

        err = hse_kvs_cursor_destroy(c);
        if (err)
            return tdie(err, "cannot destroy cursor iter %d", i);
    }

    return 0;
}

void *
maker(void *h)
{
    struct hse_kvs *kvs = h;
    int             loops = (niter + 99) / 100;
    int             i, j;
    int             err;

    int mod[] = { 10, 5, 3, 2, 1 };

    for (j = 0; j < loops; ++j) {
        for (i = 100; i < 1000; ++i) {
            char buf[32];
            int  len = sprintf(buf, "%d", i);

            err = hse_kvs_put(kvs, 0, NULL, buf, len, buf, len);
            if (err)
                tdie(err, "cannot put");
        }

        /* we want a kvms to be ingested */
        err = hse_kvdb_sync(kvdb, HSE_KVDB_SYNC_ASYNC);
        if (err)
            tdie(err, "cannot sync");

        if (verbose && j % mod[verbose] == 0) {
            printf("maker: loop %d/%d: put keys 100..1000\n", j, loops);
            fflush(stdout);
        }

        /* sleep 10ms between creates */
        poll(0, 0, 10);
    }
    return 0;
}

void
stress(char *mp, char *kv)
{
    struct hse_kvs *   kvs = NULL;
    pthread_t          t[nthreads];
    pthread_t          mt;
    struct cursor_info info;
    int                err;
    int                i, rc;

    err = hse_kvdb_open(mp, 0, NULL, &kvdb);
    if (err) {
        die(err, "cannot open kvdb");
    }

    err = hse_kvdb_kvs_open(kvdb, kv, 0, NULL, &kvs);
    if (err && err != ENOENT) {
        die(err, "cannot open kvs");
    }
    if (err) {
        err = hse_kvdb_kvs_create(kvdb, kv, 0, NULL);
        if (err) {
            die(err, "cannot make kvs");
        }
        err = hse_kvdb_kvs_open(kvdb, kv, 0, NULL, &kvs);
        if (err) {
            die(err, "cannot open kvs");
        }
    }

    info.kvs = kvs;

    /*
     * seed the c0kvms with 900 keys, "100" .. "999"
     * each key has at least 3 bytes, so prefixes work
     * and get enough variation that some will age more than others
     * and the rb-tree in the cache sees sufficient churn
     */
    rc = pthread_create(&mt, 0, maker, kvs);
    if (rc) {
        die(rc, "cannot create maker thread");
    }
    poll(0, 0, 1);

    printf(
        "put keys 100.1000 into kvs %s; creating %d threads;"
        "each threads doing %d iterations\n",
        kv,
        nthreads,
        niter);

    for (i = 0; i < nthreads; ++i) {
        rc = pthread_create(t + i, 0, parallel_cursors, &info);
        if (rc) {
            die(rc, "cannot create thread");
        }
    }

    for (i = 0; i < nthreads; ++i) {
        rc = pthread_join(t[i], 0);
        if (rc) {
            die(rc, "cannot join thread");
        }
    }
    pthread_join(mt, 0);

    err = hse_kvdb_close(kvdb);
    if (err) {
        die(err, "cannot close kvdb");
    }
}

void
usage(char *prog)
{
    fprintf(
        stderr,
        "usage: %s [-t n][-i n] kvdb/kvs\n"
        "-t n       number of threads; default 128\n"
        "-i n       number of iterations; default 10000\n"
        "-v         report progress\n"
        "-Z config  path to global config file\n"
        "stress test of kvs cursor caching:\n"
        "runs nthreads, each doing niter create/seek/read/destroy\n\n",
        prog);
    exit(1);
}

int
main(int argc, char **argv)
{
    const char *config = NULL;
    char *      prog = basename(argv[0]);
    char *      parts[3];
    int         c, err;

    while ((c = getopt(argc, argv, "?vt:i:Z:")) != -1) {
        switch (c) {
            case 'Z':
                config = optarg;
                break;
            case 't':
                nthreads = atoi(optarg);
                break;
            case 'i':
                niter = atoi(optarg);
                break;
            case 'v':
                ++verbose;
                break;
            case '?': /* fallthrough */
            default:
                usage(prog);
        }
    }

    argc -= optind;
    argv += optind;

    parts[0] = strsep(&argv[0], "/");
    parts[1] = strsep(&argv[0], "/");

    if (!parts[0] || !parts[1])
        usage(prog);

    err = hse_init(config, 0, NULL);
    if (err)
        die(err, "failed to initialize kvdb");

    stress(parts[0], parts[1]);

    hse_fini();

    return 0;
}
