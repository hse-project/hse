/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2018-2019,2021 Micron Technology, Inc.  All rights reserved.
 *
 * The user provides the number of prefixes and suffixes to use in the database.
 * Each prefix will get all the suffixes, i.e. the total number of keys in the
 * DB is the product of number of prefixes and suffixes.
 */

#include <hse_util/platform.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

#include <xoroshiro.h>

#include <endian.h>
#include <getopt.h>
#include <libgen.h>
#include <sysexits.h>
#include <stdlib.h>
#include <sys/resource.h>

#include <cli/param.h>

#include "kvs_helper.h"

#if HDR_HISTOGRAM_C_FROM_SUBPROJECT == 1
#include <hdr_histogram.h>
#else
#include <hdr/hdr_histogram.h>
#endif

const char *progname;

struct thread_info {
    uint64_t              sfx_start;
    uint64_t              sfx_end;
} HSE_ACP_ALIGNED;

struct lat_hist {
    struct hdr_histogram *lat_create;
    struct hdr_histogram *lat_seek;
    struct hdr_histogram *lat_read;
    struct hdr_histogram *lat_full;
} HSE_ACP_ALIGNED;

enum phase {
    NONE = 0,
    LOAD = 1,
    EXEC = 2,
};

struct opts {
    char *blens;
    char *vsep;
    uint threads;
    uint upd_threads;
    uint phase;
    uint nsfx;
    uint sfx_start;
    uint vlen;
    uint npfx;
    uint duration;
    uint range;
    bool verify;
    bool use_update;
    uint warmup;
    char *tests;
} opts = {
    .threads = 96,
    .upd_threads = 0,
    .phase = NONE,
    .nsfx = 1000 * 1000,
    .sfx_start = 0,
    .vlen  = 1024,
    .npfx  = 8,
    .duration = 300,
    .range = 42,
    .verify = false,
    .use_update = false,
    .warmup = false,
    .tests = "cursor,get",
};

static volatile bool stopthreads HSE_ACP_ALIGNED;

atomic_ulong n_write HSE_ACP_ALIGNED;
atomic_ulong n_cursor HSE_ACP_ALIGNED;
atomic_ulong n_read HSE_ACP_ALIGNED;


u64 gtod_usec(void)
{
    struct timeval ctime;

    gettimeofday(&ctime, 0);
    return (u64)ctime.tv_sec * (u64)1000000
        + (u64)ctime.tv_usec;
}

long
system_memory()
{
    ulong free, avail;

    hse_meminfo(&free, &avail, 0);

    return avail;
}

static thread_local uint64_t xrand64_state[2];

static void
xrand64_init(uint64_t seed)
{
    if (seed == 0) {
        while (!(seed >> 56))
            seed = (seed << 8) | ((get_cycles() >> 1) & 0xfful);
    }

    xoroshiro128plus_init(xrand64_state, seed);
}

static uint64_t
xrand64(void)
{
    return xoroshiro128plus(xrand64_state);
}

void
loader(void *arg)
{
    struct thread_arg    *targ = arg;
    struct thread_info   *ti = targ->arg;
    uint64_t             *p = 0; /* prefix */
    uint64_t             *s = 0; /* suffix */
    int                   i, j;
    char                  key[sizeof(*p) + sizeof(*s)];
    unsigned char        *val;
    u64                   nwrite;

    val = malloc(opts.vlen);
    if (!val)
        fatal(ENOMEM, "Failed to allocate resources for cursor thread");

    memset(val, 0xfe, opts.vlen);
    pthread_setname_np(pthread_self(), __func__);

    p  = (uint64_t *)key;
    s  = p + 1;
    nwrite = 0;

    for (i = 0; i < opts.npfx; i++) {
        *p = htobe64(i);

        for (j = ti->sfx_start; j < ti->sfx_end; j++) {
            int rc;

            *s = htobe64(j);

            rc = hse_kvs_put(targ->kvs, 0, NULL, key, sizeof(key),
                             val, opts.vlen);
            if (rc)
                fatal(rc, "Put failed");

            if (++nwrite % 1024 == 0)
                atomic_add(&n_write, 1024);
        }
    }

    atomic_add(&n_write, nwrite & 1023);
    free(val);
}

void
rand_key(u64 *pfx, u64 *sfx)
{
    *pfx = xrand64() % opts.npfx;
    *sfx = xrand64() % opts.nsfx;
}

void
point_get(void *arg)
{
    struct thread_arg    *targ = arg;
    struct lat_hist      *lat = targ->arg;
    unsigned char        *vbuf;
    size_t                vlen;
    uint64_t             *p = 0; /* prefix */
    uint64_t             *s = 0; /* suffix */
    char                  kbuf[sizeof(*p) + sizeof(*s)];

    u64                   ncursor, nread;
    pthread_t             tid = pthread_self();

    xrand64_init(tid);
    pthread_setname_np(tid, __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for point-get thread");

    p  = (uint64_t *)kbuf;
    s  = p + 1;

    hdr_record_value(lat->lat_create, 0);
    hdr_record_value(lat->lat_seek, 0);
    hdr_record_value(lat->lat_read, 0);

    ncursor = 0;
    nread = 0;
    while (!stopthreads) {
        uint64_t           pfx, sfx;
        int                i, inc = 1;
        bool               found;
        u64                t_start, dt;

        rand_key(&pfx, &sfx);

        *p = htobe64(pfx);
        t_start = get_time_ns();
        for (i = 0; i < opts.range && sfx < opts.nsfx; i++, sfx += inc) {
            merr_t err;

            *s = htobe64(sfx);
            err = hse_kvs_get(targ->kvs, 0, 0, kbuf, sizeof(kbuf), &found, vbuf, opts.vlen, &vlen);
            if (err)
                fatal(err, "error");
            if (!found)
                fatal(ENOKEY, "Key not found\n");

            if (++nread % 1024 == 0)
                atomic_add(&n_read, 1024);
        }
        dt = get_time_ns() - t_start;
        hdr_record_value(lat->lat_full, dt);

        if (++ncursor % 128 == 0)
            atomic_add(&n_cursor, 128);
    }
    atomic_add(&n_read, nread & 1023);
    atomic_add(&n_cursor, ncursor & 127);

    free(vbuf);
}

void
cursor(void *arg)
{
    struct thread_arg    *targ = arg;
    struct lat_hist      *lat = targ->arg;
    unsigned char         kbuf[2 * sizeof(uint64_t)];
    unsigned char        *vbuf;
    uint64_t             *p = (void *)kbuf;
    uint64_t             *s = p + 1;
    bool                  eof = false;

    u64                   ncursor, nread;
    pthread_t             tid = pthread_self();

    struct hse_kvs_cursor *cur[opts.npfx];

    xrand64_init(tid);
    pthread_setname_np(tid, __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for cursor thread");

    if (opts.use_update) {
        for (int i = 0; i < opts.npfx; i++) {
            *p = htobe64(i);
            cur[i] = kh_cursor_create(targ->kvs, 0, NULL, kbuf, sizeof(*p));
        }
    }

    ncursor = 0;
    nread = 0;
    while (!stopthreads) {
        uint64_t           pfx, sfx;
        int                i, inc = 1;
        u64                t_start;
        u64                t_create, t_seek, t_read, t_full;
        struct hse_kvs_cursor *c;

        rand_key(&pfx, &sfx);
        *p = htobe64(pfx);
        *s = htobe64(sfx);

        t_start = get_time_ns();

        if (opts.use_update) {
            c = cur[pfx];
            kh_cursor_update_view(cur[pfx], 0);
        } else {
            c = cur[0] = kh_cursor_create(targ->kvs, 0, NULL, kbuf, sizeof(*p));
        }

        t_create = get_time_ns();

        kh_cursor_seek(c, kbuf, sizeof(kbuf));
        t_seek = get_time_ns();

        /* read the range of keys */
        for (i = 0; i < opts.range; i++, sfx += inc) {
            const void *key, *val;
            size_t      klen, vlen;

            eof = kh_cursor_read(c, &key, &klen, &val, &vlen);
            if (eof)
                break;

            if (++nread % 1024 == 0)
                atomic_add(&n_read, 1024);

            if (!opts.verify)
                continue;

            /* verify keys */
            *s = htobe64(sfx);
            if (HSE_UNLIKELY(klen != sizeof(kbuf) ||
                             memcmp(key, kbuf, klen)))
                fatal(ENOKEY, "unexpected key. Expected %lu-%lu "
                      "Got %lu-%lu\n", pfx, sfx,
                      be64toh(*(uint64_t *)key),
                      be64toh(*((uint64_t *)key + 1)));
        }
        t_read = get_time_ns();

        if (!opts.use_update)
            kh_cursor_destroy(c);

        t_full = get_time_ns();

        hdr_record_value(lat->lat_create, t_create - t_start);
        hdr_record_value(lat->lat_seek, t_seek - t_create);
        hdr_record_value(lat->lat_read, (t_read - t_seek) / (i ?: 1));
        hdr_record_value(lat->lat_full, t_full - t_start);

        if (++ncursor % 128 == 0)
            atomic_add(&n_cursor, 128);
    }
    atomic_add(&n_read, nread & 1023);
    atomic_add(&n_cursor, ncursor & 127);

    free(vbuf);

    if (opts.use_update) {
        int i;

        for (i = 0; i < NELEM(cur); i++)
            kh_cursor_destroy(cur[i]);
    }
}

void
print_stats()
{
    uint32_t second = 0;
    uint64_t nw, nr, nc;
    uint64_t last_writes = 0, last_reads = 0, last_cursors = 0;

    while (!stopthreads) {
        usleep(999 * 1000);

        nw = atomic_read(&n_write);
        nr = atomic_read(&n_read);
        nc = atomic_read(&n_cursor);

        if (second % 20 == 0)
            printf("\n%18s %8s %12s %12s %12s %8s %8s %8s\n",
                    "timestamp", "elapsed", "writes", "reads",
                    "cursors", "lRate", "rRate", "cRate");

        printf("%18lu %8u %12lu %12lu %12lu %8lu %8lu %8lu\n",
                gtod_usec(), second, nw, nr, nc,
                nw - last_writes, nr - last_reads, nc - last_cursors);

        last_writes  = nw;
        last_reads   = nr;
        last_cursors = nc;

        second++;
    }
}

/* Driver */
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
    printf(
        "usage: %s [options] mp kvs [param=value ...]\n"
        "-b blens   Burst Lengths: Number of sequential reads performed "
        "starting at a randomly selected key (comma separated list)\n"
        "-c vsep    string to separate values in log file (default: [%s])\n"
        "-d dur     Duration of exec in seconds (default: %u)\n"
        "-e         Exec\n"
        "-h         Print this help menu\n"
        "-j jobs    Number of threads (default: %u)\n"
        "-l         Load\n"
        "-p npfx    Number of prefixes (default: %u)\n"
        "-s nsfx    Number of suffixes per prefix (default: %u)\n"
        "-S start   Starting suffix (default: %u)\n"
        "-T tests   List of tests to run (default: \"%s\")\n"
        "-u         Reuse cursor (default: %s)\n"
        "-V         Verify data (default: %s)\n"
        "-v vlen    Value length (default: %u)\n"
        "-w         Warmup the cache (default: %s)\n"
        "-Z config  path to global config file\n"
        "\n",
        progname, opts.vsep, opts.duration, opts.threads,
        opts.npfx, opts.nsfx, opts.sfx_start,
        opts.tests, opts.use_update ? "true" : "false",
        opts.verify ? "true" : "false",
        opts.vlen, opts.warmup ? "true" : "false");

    printf(
        "Examples:\n\n"
        "  1. Load:\n"
        "    %s mp1 kvs1 -j96 -p4 -s10000 -l\n\n"
        "  2. Exec:\n"
        "    %s mp1 kvs1 -j96 -p4 -s10000 -e -b10,20,25 -d60\n"
        "\n", progname, progname);
}

static void
print_hist_one(const char *label, struct hdr_histogram *hist)
{
    unsigned long min, max, mean, stdev, lat90, lat95, lat99, lat999, lat9999;
    const char *lat_fmt = "%8s: %8lu %12lu %8lu %8lu %8lu %8lu %8lu %8lu %12lu\n";

    min = hdr_min(hist);
    max = hdr_max(hist);
    mean = hdr_mean(hist);
    stdev = hdr_stddev(hist);
    lat90 = hdr_value_at_percentile(hist, 90.0);
    lat95 = hdr_value_at_percentile(hist, 95.0);
    lat99 = hdr_value_at_percentile(hist, 99.0);
    lat999 = hdr_value_at_percentile(hist, 99.9);
    lat9999 = hdr_value_at_percentile(hist, 99.99);

    printf(lat_fmt, label, min, max, mean, stdev, lat90, lat95, lat99, lat999, lat9999);
}

void
print_hist(struct lat_hist *lat)
{
    const char *hdr_fmt = "%18s %12s %8s %8s %8s %8s %8s %8s %12s\n";

    printf(hdr_fmt, "min", "max", "mean", "stddev", "90.0", "95.0", "99.0", "99.9", "99.99");
    print_hist_one("create", lat->lat_create);
    print_hist_one("seek", lat->lat_seek);
    print_hist_one("read", lat->lat_read);
    print_hist_one("full", lat->lat_full);
}

int
main(
    int       argc,
    char    **argv)
{
    struct parm_groups *pg = NULL;
    struct svec         hse_gparms = { 0 };
    struct svec         kvdb_oparms = { 0 };
    struct svec         kvs_cparms = { 0 };
    struct svec         kvs_oparms = { 0 };
    int                 i, rc;
    const char         *mpool, *kvs, *config = NULL;
    int                 c;
    struct thread_info *ti = 0;
    bool                freet = false;
    void               *blens_base HSE_MAYBE_UNUSED = NULL;

    progname = basename(argv[0]);

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    opts.vsep = ",";

    while ((c = getopt(argc, argv, ":b:c:d:ehj:lp:s:S:T:uVv:wZ:")) != -1) {
        char *errmsg, *end;

        errmsg = end = NULL;
        errno = 0;

        switch (c) {
        case 'b':
            opts.blens = strdup(optarg);
            blens_base = opts.blens;
            errmsg = "invalid burst lengths";
            break;
        case 'c':
            opts.vsep = strdup(optarg);
            errmsg = "invalid value separator";
            break;
        case 'd':
            opts.duration = strtoul(optarg, &end, 0);
            errmsg = "invalid duration";
            break;
        case 'e':
            opts.phase |= EXEC;
            break;
        case 'h':
            usage();
            exit(0);
        case 'j':
            opts.threads = strtoul(optarg, &end, 0);
            errmsg = "invalid thread count";
            break;
        case 'l':
            opts.phase |= LOAD;
            break;
        case 'p':
            opts.npfx = strtoul(optarg, &end, 0);
            errmsg = "invalid number of prefixes";
            break;
        case 's':
            opts.nsfx = strtoul(optarg, &end, 0);
            errmsg = "invalid number of suffixes";
            break;
        case 'S':
            opts.sfx_start = strtoul(optarg, &end, 0);
            errmsg = "invalid suffix start";
            break;
        case 'T':
            opts.tests = strdup(optarg);
            errmsg = "invalid tests";
            freet = true;
            break;
        case 'u':
            opts.use_update = true;
            break;
        case 'V':
            opts.verify = true;
            break;
        case 'v':
            opts.vlen = strtoul(optarg, &end, 0);
            errmsg = "invalid value length";
            break;
        case 'w':
            opts.warmup = true;
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
            fprintf(stderr, "option -%c ignored\n", c);
            break;
        }

        if (errno && errmsg) {
            syntax("%s", errmsg);
            exit(EX_USAGE);
        } else if (end && *end) {
            syntax("%s '%s'", errmsg, optarg);
            exit(EX_USAGE);
        }
    }

    if (argc - optind < 2) {
        syntax("missing required parameters");
        exit(EX_USAGE);
    }

    mpool = argv[optind++];
    kvs   = argv[optind++];

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

	rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
	rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
	if (rc)
		fatal(rc, "failed to parse params\n");

    kh_init(config, mpool, &hse_gparms, &kvdb_oparms);

    if (opts.phase == NONE) {
        fprintf(stderr, "Choose a phase to run\n");
        pg_destroy(pg);
        exit(EX_USAGE);
    }

    if (opts.phase & LOAD) {
        uint thread_share;
        uint thread_extra;
        uint tot_keys;

        thread_share = opts.nsfx / opts.threads;
        thread_extra = opts.nsfx % opts.threads;

        tot_keys = opts.npfx * opts.nsfx;
        ti = malloc(opts.threads * sizeof(*ti));
        if (!ti)
            fatal(ENOMEM, "Cannot allocate memory for thread data");

        /* distribute suffixes across jobs */
        for (i = 0; i < opts.threads; i++) {
            ti[i].sfx_start = opts.sfx_start + (thread_share * i);
            ti[i].sfx_end   = ti[i].sfx_start + thread_share;

            if (i == opts.threads - 1)
                ti[i].sfx_end += thread_extra;
        }

        /* Start all the loaders in a detached state so we can have them
         * running while the exec phase is running too.
         */
        kh_register(0, &print_stats, 0);
        for (i = 0; i < opts.threads; i++)
            kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &loader, &ti[i]);

        while (atomic_read(&n_write) < tot_keys)
            sleep(5);
    }

    if (opts.phase & EXEC) {
        struct lat_hist *lat;

        lat = aligned_alloc(HSE_ACP_LINESIZE, sizeof(*lat) * opts.threads);
        if (!lat)
            fatal(ENOMEM, "Cannot allocate mmeory for histogram data");

        for (i = 0; i < opts.threads; i++) {
            hdr_init(1, 10UL * 1000 * 1000 * 1000, 4, &lat[i].lat_create);
            hdr_init(1, 10UL * 1000 * 1000 * 1000, 4, &lat[i].lat_seek);
            hdr_init(1, 10UL * 1000 * 1000 * 1000, 4, &lat[i].lat_read);
            hdr_init(1, 10UL * 1000 * 1000 * 1000, 4, &lat[i].lat_full);
        }

        if (opts.warmup) {
            long tot_mem;
            uint warmup_nkeys;
            uint tot_keys;

            stopthreads = false;

            tot_mem = system_memory();
            warmup_nkeys = tot_mem / (opts.vlen + (2 * sizeof(uint64_t)));
            tot_keys = opts.npfx * opts.nsfx;
            warmup_nkeys = warmup_nkeys < tot_keys ? warmup_nkeys : tot_keys;
            warmup_nkeys = (warmup_nkeys * 3) / 2;

            /* 1. Warm up mcache using point gets */
            printf("System memory %lu\n", tot_mem);
            printf("Warmup keycnt %u\n", warmup_nkeys);
            opts.range=1;
            atomic_set(&n_cursor, 0);
            atomic_set(&n_read, 0);

            for (i = 0; i < opts.threads; i++)
                kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &point_get, &lat[i]);

            while (!stopthreads && atomic_read(&n_read) < warmup_nkeys)
                sleep(5);

            stopthreads = true;
            kh_wait();
        }

        /* 2. Start actual test */
        printf("Starting test\n");

        char *s = strsep(&opts.blens, ",.;:/");
        while (s) {
            uint duration;
            int j;
            struct op {
                const char *opname;
                kh_func *opfunc;
            } op[2] = {
                {.opname = "cursor", .opfunc = &cursor},
                {.opname = "get",    .opfunc = &point_get},
            };

            opts.range = strtoul(s, 0, 0);
            for (j = 0; j < NELEM(op); j++) {
                if (!strcasestr(opts.tests, op[j].opname))
                    continue;

                printf("%s: npfx %u nsfx %u burstlen %u\n",
                       op[j].opname, opts.npfx, opts.nsfx, opts.range);

                atomic_set(&n_cursor, 0);
                atomic_set(&n_read, 0);
                stopthreads = false;

                /* hdr_reset take a while, so reset the histograms upfront before all the op
                 * threads are started.
                 */
                for (i = 0; i < opts.threads; i++) {
                    hdr_reset(lat[i].lat_create);
                    hdr_reset(lat[i].lat_seek);
                    hdr_reset(lat[i].lat_read);
                    hdr_reset(lat[i].lat_full);
                }

                kh_register(0, &print_stats, 0);
                for (i = 0; i < opts.threads; i++)
                    kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, op[j].opfunc, &lat[i]);

                duration = opts.duration;
                while (!stopthreads && duration--)
                    sleep(1);

                stopthreads = true;
                kh_wait();

                /* Accumulate latency data into lat[0].
                 */
                for (i = 1; i < opts.threads; i++) {
                    hdr_add(lat[0].lat_create, lat[i].lat_create);
                    hdr_add(lat[0].lat_seek, lat[i].lat_seek);
                    hdr_add(lat[0].lat_read, lat[i].lat_read);
                    hdr_add(lat[0].lat_full, lat[i].lat_full);
                }

                printf("\nLatency histogram (ns):\n");
                print_hist(&lat[0]);
            }

            s = strsep(&opts.blens, ",.;:/");
        }

        for (i = 0; i < opts.threads; i++) {
            hdr_close(lat[i].lat_create);
            hdr_close(lat[i].lat_seek);
            hdr_close(lat[i].lat_read);
            hdr_close(lat[i].lat_full);
        }

        free(lat);
    }

    kh_fini();

    free(ti);
    free(blens_base);
    if (freet)
        free(opts.tests);

    pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

    return 0;
}
