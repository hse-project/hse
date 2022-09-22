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

#include <hse/cli/param.h>

#include "kvs_helper.h"

#include <hdr/hdr_histogram.h>

const char *progname;

struct thread_info {
    uint64_t key_start;
    uint64_t key_end;
} HSE_ACP_ALIGNED;

enum lat_type {
    LAT_CUR_CREATE = 0,
    LAT_CUR_SEEK,
    LAT_CUR_READ,
    LAT_CUR_FULL,
    LAT_GET_FULL,
    LAT_CNT
};

struct lat_hist {
    struct hdr_histogram *lat[LAT_CNT];
} HSE_ACP_ALIGNED;

enum phase {
    NONE = 0,
    LOAD = 1,
    EXEC = 2,
};

struct opts {
    char *blens;
    char *vsep;
    uint  threads;
    uint  phase;
    uint  nkeys;
    uint  vlen;
    uint  duration;
    uint  range;
    bool  verify;
    bool  use_update;
    uint  warmup;
    char *tests;
    char *keyfmt;
} opts = {
    .threads = 96,
    .phase = NONE,
    .vlen  = 1024,
    .nkeys  = 100,
    .duration = 300,
    .range = 42,
    .verify = false,
    .use_update = false,
    .warmup = false,
    .tests = "cursor,get",
    .keyfmt = NULL, /* binary keys */
};

static volatile bool stopthreads HSE_ACP_ALIGNED;

atomic_ulong n_write HSE_ACP_ALIGNED;
atomic_ulong n_get HSE_ACP_ALIGNED;
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

uint
make_key(int idx, char *kbuf, size_t kbufsz)
{
    uint64_t *k = (void *)kbuf;

    if (opts.keyfmt)
        return snprintf(kbuf, kbufsz, opts.keyfmt, idx);

    *k = htobe64(idx);
    return sizeof(*k);
}

void
loader(void *arg)
{
    struct thread_arg    *targ = arg;
    struct thread_info   *ti = targ->arg;
    int                   i;
    char                  kbuf[HSE_KVS_KEY_LEN_MAX] = {};
    unsigned char        *val;
    u64                   nwrite;

    val = malloc(opts.vlen);
    if (!val)
        fatal(ENOMEM, "Failed to allocate resources for cursor thread");

    memset(val, 0xfe, opts.vlen);
    pthread_setname_np(pthread_self(), __func__);

    nwrite = 0;
    for (i = ti->key_start; i < ti->key_end; i++) {
        int rc;
        size_t klen = make_key(i, kbuf, sizeof(kbuf));

        rc = hse_kvs_put(targ->kvs, 0, NULL, kbuf, klen, val, opts.vlen);
        if (rc)
            fatal(rc, "Put failed");

        if (++nwrite % 1024 == 0)
            atomic_add(&n_write, 1024);
    }

    atomic_add(&n_write, nwrite & 1023);
    free(val);
}

u64
rand_key()
{
    return xrand64() % opts.nkeys;
}

void
point_get(void *arg)
{
    struct thread_arg    *targ = arg;
    struct lat_hist      *lat = targ->arg;
    unsigned char        *vbuf;
    size_t                vlen;
    char                  kbuf[HSE_KVS_KEY_LEN_MAX] = {};

    u64                   nget;
    pthread_t             tid = pthread_self();

    xrand64_init(tid);
    pthread_setname_np(tid, __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for point-get thread");

    nget = 0;
    while (!stopthreads) {
        bool found;
        u64  t_start, dt, i, key_start;
        uint klen;

        key_start = rand_key();

        t_start = get_time_ns();
        for (i = key_start; i < opts.range && i < opts.nkeys; i++) {
            merr_t err;

            klen = make_key(i, kbuf, sizeof(kbuf));
            err = hse_kvs_get(targ->kvs, 0, 0, kbuf, klen, &found, vbuf, opts.vlen, &vlen);
            if (err)
                fatal(err, "error");
            if (!found)
                fatal(ENOKEY, "Key not found\n");

            if (++nget % 1024 == 0)
                atomic_add(&n_get, 1024);
        }
        dt = get_time_ns() - t_start;
        hdr_record_value(lat->lat[LAT_GET_FULL], dt);
    }

    atomic_add(&n_get, nget & 1023);
    free(vbuf);
}

void
cursor(void *arg)
{
    struct thread_arg    *targ = arg;
    struct lat_hist      *lat = targ->arg;
    char                  kbuf[HSE_KVS_KEY_LEN_MAX] = {};
    uint                  kbuf_klen;
    unsigned char        *vbuf;
    bool                  eof = false;

    u64                   nread;
    pthread_t             tid = pthread_self();

    xrand64_init(tid);
    pthread_setname_np(tid, __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for cursor thread");

    nread = 0;
    while (!stopthreads) {
        int i;
        u64 t_start;
        u64 t_create, t_seek, t_read, t_full;
        u64 key_start;

        struct hse_kvs_cursor *c;

        key_start = rand_key();

        t_start = get_time_ns();
        c = kh_cursor_create(targ->kvs, 0, NULL, NULL, 0);

        t_create = get_time_ns();

        kbuf_klen = make_key(key_start, kbuf, sizeof(kbuf));
        kh_cursor_seek(c, kbuf, kbuf_klen);
        t_seek = get_time_ns();

        /* read the range of keys */
        for (i = key_start; i < key_start + opts.range; i++) {
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
            kbuf_klen = make_key(i, kbuf, sizeof(kbuf));
            if (HSE_UNLIKELY(klen != kbuf_klen || memcmp(key, kbuf, klen)))
                fatal(ENOKEY, "Incorrect key\n");
        }
        t_read = get_time_ns();

        kh_cursor_destroy(c);
        t_full = get_time_ns();

        hdr_record_value(lat->lat[LAT_CUR_CREATE], t_create - t_start);
        hdr_record_value(lat->lat[LAT_CUR_SEEK], t_seek - t_create);
        hdr_record_value(lat->lat[LAT_CUR_READ], t_read - t_seek);
        hdr_record_value(lat->lat[LAT_CUR_FULL], t_full - t_start);
    }

    atomic_add(&n_read, nread & 1023);
    free(vbuf);
}

void
print_stats()
{
    uint32_t second = 0;
    uint64_t nw, nr, ng;
    uint64_t last_writes = 0, last_reads = 0, last_gets = 0;

    while (!stopthreads) {
        usleep(999 * 1000);

        nw = atomic_read(&n_write);
        nr = atomic_read(&n_read);
        ng = atomic_read(&n_get);

        if (second % 20 == 0)
            printf("\n%18s %8s %12s %8s %12s %8s %12s %8s\n",
                   "timestamp", "elapsed", "tPut", "iPut", "tRead", "iRead", "tGet", "iGet");

        printf("%18lu %8u %12lu %8lu %12lu %8lu %12lu %8lu\n",
                gtod_usec(), second,
                nw, nw - last_writes,
                nr, nr - last_reads,
                ng, ng - last_gets);

        last_writes = nw;
        last_reads  = nr;
        last_gets   = ng;

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
        "-f keyfmt  Key format (default: %s)\n"
        "-h         Print this help menu\n"
        "-j jobs    Number of threads (default: %u)\n"
        "-l         Load\n"
        "-n nkeys   Number of keys (default: %u)\n"
        "-T tests   List of tests to run (default: \"%s\")\n"
        "-u         Reuse cursor (default: %s)\n"
        "-V         Verify data (default: %s)\n"
        "-v vlen    Value length (default: %u)\n"
        "-w         Warmup the cache (default: %s)\n"
        "-Z config  path to global config file\n"
        "\n",
        progname, opts.vsep,
        opts.duration,  opts.keyfmt ?: "binary", opts.nkeys,
        opts.threads, opts.tests, opts.use_update ? "true" : "false",
        opts.verify ? "true" : "false",
        opts.vlen, opts.warmup ? "true" : "false");

    printf(
        "Examples:\n\n"
        "  1. Load:\n"
        "    %s /mnt/kvdb kvs1 -j96 -p4 -s10000 -l\n\n"
        "  2. Exec:\n"
        "    %s /mnt/kvdb kvs1 -j96 -p4 -s10000 -e -b10,20,25 -d60 -w\n"
        "\n", progname, progname);
}

static void
print_hist_one(const char *opname, unsigned long cnt, struct hdr_histogram *hist)
{
    unsigned long sample_cnt, min, max, mean, stdev, lat90, lat95, lat99, lat999, lat9999;
    const char *lat_fmt = "%12s: %16lu %8lu %12lu %8lu %8lu %8lu %8lu %8lu %8lu %12lu\n";

    sample_cnt = cnt;
    min = hdr_min(hist);
    max = hdr_max(hist);
    mean = hdr_mean(hist);
    stdev = hdr_stddev(hist);
    lat90 = hdr_value_at_percentile(hist, 90.0);
    lat95 = hdr_value_at_percentile(hist, 95.0);
    lat99 = hdr_value_at_percentile(hist, 99.0);
    lat999 = hdr_value_at_percentile(hist, 99.9);
    lat9999 = hdr_value_at_percentile(hist, 99.99);

    printf(lat_fmt, opname, sample_cnt, min, max, mean, stdev, lat90, lat95, lat99, lat999, lat9999);
}

void
print_hist(struct lat_hist *lat, unsigned long cur_cnt, unsigned long get_cnt)
{
    const char *hdr_fmt = "%12s %17s %8s %12s %8s %8s %8s %8s %8s %8s %12s\n";

    printf(hdr_fmt, "operation", "samples", "min", "max", "mean", "stddev", "90.0", "95.0", "99.0", "99.9", "99.99");
    if (strcasestr(opts.tests, "cursor")) {
        print_hist_one("cur_create", cur_cnt, lat->lat[LAT_CUR_CREATE]);
        print_hist_one("cur_seek", cur_cnt, lat->lat[LAT_CUR_SEEK]);
        print_hist_one("cur_read", cur_cnt, lat->lat[LAT_CUR_READ]);
        print_hist_one("cur_full", cur_cnt, lat->lat[LAT_CUR_FULL]);
    }

    if (strcasestr(opts.tests, "get"))
        print_hist_one("get_full", get_cnt, lat->lat[LAT_GET_FULL]);
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
    int                 rc;
    const char         *mpool, *kvs, *config = NULL;
    int                 c;
    struct thread_info *ti = 0;
    void               *blens_base HSE_MAYBE_UNUSED = NULL;
    void               *keyfmt_base HSE_MAYBE_UNUSED = NULL;
    void               *tests_base HSE_MAYBE_UNUSED = NULL;
    void               *vsep_base HSE_MAYBE_UNUSED = NULL;

    progname = basename(argv[0]);

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    opts.vsep = ",";

    while ((c = getopt(argc, argv, ":b:c:d:ef:hj:ln:T:uVv:wZ:")) != -1) {
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
            vsep_base = opts.vsep;
            errmsg = "invalid value separator";
            break;
        case 'd':
            opts.duration = strtoul(optarg, &end, 0);
            errmsg = "invalid duration";
            break;
        case 'e':
            opts.phase |= EXEC;
            break;
        case 'f':
            if (strcmp(optarg, "binary")) {
                opts.keyfmt = strdup(optarg);
                keyfmt_base = opts.keyfmt;
            }
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
        case 'n':
            opts.nkeys = strtoul(optarg, &end, 0);
            errmsg = "invalid number of keys";
            break;
        case 'T':
            opts.tests = strdup(optarg);
            tests_base = opts.tests;
            errmsg = "invalid tests";
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
        uint thread_share = opts.nkeys / opts.threads;
        uint thread_extra = opts.nkeys % opts.threads;

        ti = malloc(opts.threads * sizeof(*ti));
        if (!ti)
            fatal(ENOMEM, "Cannot allocate memory for thread data");

        /* distribute suffixes across jobs */
        for (unsigned int i = 0; i < opts.threads; i++) {
            ti[i].key_start = (uint64_t)thread_share * i;
            ti[i].key_end   = ti[i].key_start + thread_share;

            if (i == opts.threads - 1)
                ti[i].key_end += thread_extra;
        }

        /* Start all the loaders in a detached state so we can have them
         * running while the exec phase is running too.
         */
        kh_register(0, &print_stats, 0);
        for (int i = 0; i < opts.threads; i++)
            kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &loader, &ti[i]);

        while (atomic_read(&n_write) < opts.nkeys)
            sleep(5);
    }

    if (opts.phase & EXEC) {
        struct lat_hist *lat;

        lat = aligned_alloc(HSE_ACP_LINESIZE, sizeof(*lat) * opts.threads);
        if (!lat)
            fatal(ENOMEM, "Cannot allocate mmeory for histogram data");

        for (int i = 0; i < opts.threads; i++) {
            for (int l = 0; l < LAT_CNT; l++)
                hdr_init(1, 10UL * 1000 * 1000 * 1000, 4, &lat[i].lat[l]);
        }

        if (opts.warmup) {
            long tot_mem;
            uint warmup_nkeys;

            stopthreads = false;

            tot_mem = system_memory();
            warmup_nkeys = tot_mem / (opts.vlen + (2 * sizeof(uint64_t)));
            warmup_nkeys = warmup_nkeys < opts.nkeys ? warmup_nkeys : opts.nkeys;
            warmup_nkeys = (warmup_nkeys * 3) / 2;

            /* 1. Warm up mcache using point gets */
            printf("System memory %lu\n", tot_mem);
            printf("Warmup keycnt %u\n", warmup_nkeys);
            opts.range=1;
            atomic_set(&n_get, 0);
            atomic_set(&n_read, 0);

            for (int i = 0; i < opts.threads; i++)
                kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &point_get, &lat[i]);

            while (!stopthreads && atomic_read(&n_get) < warmup_nkeys)
                sleep(5);

            stopthreads = true;
            kh_wait();
        }

        /* 2. Start actual test */
        printf("Starting test\n");

        char *s = strsep(&opts.blens, ",.;:/");
        while (s) {
            uint duration;
            unsigned long get_cnt= 0;
            unsigned long cur_cnt= 0;
            int j;
            struct op {
                const char *opname;
                kh_func *opfunc;
            } op[2] = {
                {.opname = "cursor", .opfunc = &cursor},
                {.opname = "get",    .opfunc = &point_get},
            };

            /* hdr_reset takes a while, so reset the histograms upfront before all the op
             * threads are started.
             */
            for (int i = 0; i < opts.threads; i++) {
                for (int l = 0; l < LAT_CNT; l++)
                    hdr_reset(lat[i].lat[l]);
            }

            opts.range = strtoul(s, 0, 0);
            for (j = 0; j < NELEM(op); j++) {
                if (!strcasestr(opts.tests, op[j].opname))
                    continue;

                atomic_set(&n_get, 0);
                atomic_set(&n_read, 0);

                printf("%s: nkeys %u burstlen %u\n", op[j].opname, opts.nkeys, opts.range);
                stopthreads = false;

                kh_register(0, &print_stats, 0);
                for (int i = 0; i < opts.threads; i++)
                    kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, op[j].opfunc, &lat[i]);

                duration = opts.duration;
                while (!stopthreads && duration--)
                    sleep(1);

                stopthreads = true;
                kh_wait();

                get_cnt = atomic_read(&n_get) ?: get_cnt;
                cur_cnt = atomic_read(&n_read) ?: cur_cnt;
            }

            /* Accumulate latency data into lat[0].
             */
            for (int i = 1; i < opts.threads; i++) {
                for (int l = 0; l < LAT_CNT; l++)
                    hdr_add(lat[0].lat[l], lat[i].lat[l]);
            }

            printf("\nLatency summary (ns):\n");
            print_hist(&lat[0], cur_cnt, get_cnt);

            s = strsep(&opts.blens, ",.;:/");
        }

        for (int i = 0; i < opts.threads; i++) {
            for (int l = 0; l < LAT_CNT; l++)
                hdr_close(lat[i].lat[l]);
        }

        free(lat);
    }

    kh_fini();

    free(ti);
    free(blens_base);
    free(keyfmt_base);
    free(tests_base);
    free(vsep_base);

    pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

    return 0;
}
