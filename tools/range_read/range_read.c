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
#include <hse_util/timing.h>
#include <xoroshiro/xoroshiro.h>

#include <endian.h>
#include <getopt.h>
#include <libgen.h>
#include <sysexits.h>
#include <sys/resource.h>

#include <cli/param.h>

#include "kvs_helper.h"

const char *progname;

struct thread_info {
    uint64_t    sfx_start;
    uint64_t    sfx_end;
} HSE_ALIGNED(SMP_CACHE_BYTES);

#define DT_CNT 10 * 1000 * 1000

struct delta_time {
    u64 *dt;
    uint dt_cnt;
    uint dt_skip;
} HSE_ALIGNED(SMP_CACHE_BYTES);

enum phase {
    NONE = 0,
    LOAD = 1,
    EXEC = 2,
};

struct opts {
    char logdir[1024];
    char *blens;
    char *vsep;
    uint threads;
    uint upd_threads;
    uint warmup_threads;
    uint phase;
    uint nsfx;
    uint sfx_start;
    uint vlen;
    uint npfx;
    uint duration;
    uint range;
    bool verify;
    char *tests;
} opts = {
    .threads = 96,
    .warmup_threads = 64,
    .upd_threads = 0,
    .phase = NONE,
    .nsfx = 1000 * 1000,
    .sfx_start = 0,
    .vlen  = 1024,
    .npfx  = 8,
    .duration = 300,
    .range = 42,
    .verify = false,
    .tests = "cursor,get",
};

static volatile bool stopthreads HSE_ALIGNED(SMP_CACHE_BYTES * 2);

atomic64_t n_write HSE_ALIGNED(SMP_CACHE_BYTES * 2) = ATOMIC64_INIT(0);
atomic64_t n_cursor HSE_ALIGNED(SMP_CACHE_BYTES * 2) = ATOMIC64_INIT(0);
atomic64_t n_read HSE_ALIGNED(SMP_CACHE_BYTES * 2) = ATOMIC64_INIT(0);


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

    xrand64_init(0);

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
                atomic64_add(1024, &n_write);
        }
    }

    atomic64_add(nwrite & 1023, &n_write);
    free(val);
}

void
rand_key(u64 *pfx, u64 *sfx)
{
    *pfx = xrand64() % opts.npfx;
    *sfx = xrand64() % opts.nsfx;
}

void
point_get(
    void *arg)
{
    struct thread_arg    *targ = arg;
    unsigned char        *vbuf;
    size_t                vlen;
    uint64_t             *p = 0; /* prefix */
    uint64_t             *s = 0; /* suffix */
    char                  kbuf[sizeof(*p) + sizeof(*s)];

    struct delta_time    *dt = targ->arg;
    uint                  dt_idx = 0;
    const size_t          dt_size = dt ? DT_CNT : 0;
    u64                   opcnt, ncursor, nread;

    xrand64_init(0);
    pthread_setname_np(pthread_self(), __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for point-get thread");

    p  = (uint64_t *)kbuf;
    s  = p + 1;

    ncursor = 0;
    nread = 0;
    opcnt = 0;
    while (!stopthreads) {
        uint64_t           pfx, sfx;
        int                i, inc = 1;
        bool               found;
        u64                start, end;

        rand_key(&pfx, &sfx);

        *p = htobe64(pfx);
        start = get_time_ns();
        for (i = 0; i < opts.range && sfx < opts.nsfx; i++, sfx += inc) {

            *s = htobe64(sfx);
            hse_kvs_get(targ->kvs, 0, NULL, kbuf, sizeof(kbuf), &found, vbuf, opts.vlen, &vlen);
            if (!found)
                fatal(ENOKEY, "Key not found\n");

            if (++nread % 1024 == 0)
                atomic64_add(1024, &n_read);
        }
        end = get_time_ns();

        if (dt && (opcnt % dt->dt_skip == 0) && dt_idx < dt_size)
            dt->dt[dt_idx++] = end - start;

        if (++ncursor % 128 == 0)
            atomic64_add(128, &n_cursor);
        opcnt++;
    }
    atomic64_add(nread & 1023, &n_read);
    atomic64_add(ncursor & 127, &n_cursor);

    if (dt)
        dt->dt_cnt = dt_idx;

    free(vbuf);
}

void
cursor(
    void *arg)
{
    struct thread_arg    *targ = arg;
    unsigned char         kbuf[2 * sizeof(uint64_t)];
    unsigned char        *vbuf;
    uint64_t             *p = (void *)kbuf;
    uint64_t             *s = p + 1;
    bool                  eof = false;

    struct delta_time    *dt = targ->arg;
    uint                  dt_idx = 0;
    u64                   opcnt, ncursor, nread;
    const size_t          dt_size = DT_CNT;

    pthread_setname_np(pthread_self(), __func__);

    vbuf = malloc(opts.vlen);
    if (!vbuf)
        fatal(ENOMEM, "Failed to allocate resources for cursor thread");

    ncursor = 0;
    nread = 0;
    opcnt = 0;
    while (!stopthreads) {
        struct hse_kvs_cursor *c;
        uint64_t           pfx, sfx;
        int                i, inc = 1;
        u64                start;

        rand_key(&pfx, &sfx);
        *p = htobe64(pfx);
        *s = htobe64(sfx);

        start = get_time_ns();
        c = kh_cursor_create(targ->kvs, 0, NULL, kbuf, sizeof(*p));
        kh_cursor_seek(c, kbuf, sizeof(kbuf));

        /* read the range of keys */
        for (i = 0; i < opts.range; i++, sfx += inc) {
            const void *key, *val;
            size_t      klen, vlen;

            eof = kh_cursor_read(c, &key, &klen, &val, &vlen);
            if (eof)
                break;

            if (++nread % 1024 == 0)
                atomic64_add(1024, &n_read);

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

        kh_cursor_destroy(c);

        if ((opcnt % dt->dt_skip == 0) && dt_idx < dt_size)
            dt->dt[dt_idx++] = get_time_ns() - start;

        if (++ncursor % 128 == 0)
            atomic64_add(128, &n_cursor);
    }
    atomic64_add(nread & 1023, &n_read);
    atomic64_add(ncursor & 127, &n_cursor);

    if (dt)
        dt->dt_cnt = dt_idx;

    free(vbuf);
}

void
print_stats(
    void *arg)
{
    struct thread_arg    *targ = arg;
    uint32_t second = 0;
    uint64_t nw, nr, nc;
    uint64_t last_writes = 0, last_reads = 0, last_cursors = 0;
    char logfile[2048];
    FILE *logfd;

    snprintf(logfile, sizeof(logfile), "%s/%s", opts.logdir, (char *)targ->arg);
    logfd = fopen(logfile, "w");
    if (!logfd)
        fatal(errno, "Could not open log file %s", logfile);

    fprintf(logfd, "\n%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
            "timestamp", opts.vsep,
            "elapsed", opts.vsep,
            "writes", opts.vsep,
            "reads", opts.vsep,
            "cursors", opts.vsep,
            "lRate", opts.vsep,
            "rRate", opts.vsep,
            "cRate");

    while (!stopthreads) {
        usleep(999 * 1000);

        nw = atomic64_read(&n_write);
        nr = atomic64_read(&n_read);
        nc = atomic64_read(&n_cursor);

        fprintf(logfd, "%lu%s%u%s%lu%s%lu%s%lu%s%lu%s%lu%s%lu\n",
                gtod_usec(), opts.vsep,
                second, opts.vsep,
                nw, opts.vsep,
                nr, opts.vsep,
                nc, opts.vsep,
                nw - last_writes, opts.vsep,
                nr - last_reads, opts.vsep,
                nc - last_cursors);
        fflush(logfd);

        last_writes  = nw;
        last_reads   = nr;
        last_cursors = nc;

        second++;
    }

    fclose(logfd);
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
        "-f logdir  Log directory (default: %s)\n"
        "-h         Print this help menu\n"
        "-j jobs    Number of threads (default: %u)\n"
        "-l         Load\n"
        "-p npfx    Number of prefixes (default: %u)\n"
        "-s nsfx    Number of suffixes per prefix (default: %u)\n"
        "-S start   Starting suffix (default: %u)\n"
        "-T tests   List of tests to run (default: \"%s\")\n"
        "-V         Verify data (default: %s)\n"
        "-v vlen    Value length (default: %u)\n"
        "-w wjobs   number of warmup threads (default: %u)\n"
        "\n",
        progname, opts.vsep, opts.duration, opts.logdir,
        opts.threads, opts.npfx, opts.nsfx, opts.sfx_start,
        opts.tests, opts.verify ? "true" : "false",
        opts.vlen, opts.warmup_threads);

    printf(
        "Examples:\n\n"
        "  1. Load:\n"
        "    %s mp1 kvs1 -j96 -p4 -s10000 -l\n\n"
        "  2. Exec:\n"
        "    %s mp1 kvs1 -j96 -p4 -s10000 -e -b10,20,25 -d60\n"
        "\n", progname, progname);
}

int
main(
    int       argc,
    char    **argv)
{
    struct parm_groups *pg = NULL;
    struct svec         hse_gparms = {};
    struct svec         kvdb_oparms = {};
    struct svec         kvs_cparms = {};
    struct svec         kvs_oparms = {};
    int                 i, rc;
    const char         *mpool, *kvs;
    char                c;
    struct thread_info *ti = 0;
    bool                freet = false;
    void               *blens_base HSE_MAYBE_UNUSED = NULL;

    progname = basename(argv[0]);

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    opts.vsep = ",";

    strncpy(opts.logdir, "/tmp/range_read_logs", sizeof(opts.logdir));

    while ((c = getopt(argc, argv, ":b:c:d:ef:hj:lp:s:S:T:Vv:w:")) != -1) {
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
        case 'f':
            strncpy(opts.logdir, optarg, sizeof(opts.logdir) - 1);
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
        case 'V':
            opts.verify = true;
            break;
        case 'v':
            opts.vlen = strtoul(optarg, &end, 0);
            errmsg = "invalid value length";
            break;
        case 'w':
            opts.warmup_threads = strtoul(optarg, &end, 0);
            errmsg = "invalid warmup threads count";
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

    kh_init(mpool, &hse_gparms, &kvdb_oparms);

    if (opts.phase == NONE) {
        fprintf(stderr, "Choose a phase to run\n");
        pg_destroy(pg);
        exit(EX_USAGE);
    }

    rc = mkdir(opts.logdir, 0755);
    if (rc!= 0 && errno != EEXIST)
        fatal(errno, "Cannot create directory for logs");

    if (opts.phase & LOAD) {
        uint thread_share;
        uint thread_extra;
        uint tot_keys;
        char logfile[1024];

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
        stopthreads = false;
        snprintf(logfile, sizeof(logfile), "rr_load_%u.log", opts.sfx_start);
        kh_register(KH_FLAG_DETACH, &print_stats, logfile);
        for (i = 0; i < opts.threads; i++)
            kh_register_kvs(kvs, KH_FLAG_DETACH, &kvs_cparms, &kvs_oparms, &loader, &ti[i]);

        while (!stopthreads && atomic64_read(&n_write) < tot_keys)
            sleep(5);
    }

    if (opts.phase & EXEC) {
        long tot_mem;
        uint warmup_nkeys;
        uint tot_keys;
        char logfile[2048];

        stopthreads = false;

        tot_mem = system_memory();
        warmup_nkeys = tot_mem / (opts.vlen + (2 * sizeof(uint64_t)));
        tot_keys = opts.npfx * opts.nsfx;
        warmup_nkeys = warmup_nkeys < tot_keys ? warmup_nkeys : tot_keys;

        printf("Memory %lu\n", tot_mem);
        printf("Warmup %u\n", warmup_nkeys);

        /* 1. Warm up mcache using point gets */
        printf("Warming up cache\n");
        opts.range=1;
        atomic64_set(&n_cursor, 0);
        atomic64_set(&n_read, 0);

        snprintf(logfile, sizeof(logfile), "rr_warmup.log");
        kh_register(0, &print_stats, logfile);

        for (i = 0; i < opts.warmup_threads; i++)
            kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &point_get, 0);

        while (!stopthreads && atomic64_read(&n_read) < warmup_nkeys)
            sleep(5);

        stopthreads = true;
        kh_wait();

        /* 2. Start actual test */
        printf("Starting test\n");

        struct delta_time *dt;
        dt = malloc(opts.threads * sizeof(*dt));
        if (!dt)
            fatal(ENOMEM, "Failed to allocate memory for latencies");

        for (i = 0; i < opts.threads; i++) {
            rc = posix_memalign((void **)&dt[i].dt, SMP_CACHE_BYTES, sizeof(*dt[i].dt) * DT_CNT);
            if (rc)
                fatal(rc, "Failed to allocate memory for latency buffers");
        }

        char *s;
        s = strsep(&opts.blens, ",.;:/");
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
            printf("npfx %u nsfx %u burst Len %u\n", opts.npfx, opts.nsfx, opts.range);

            for (j = 0; j < 2; j++) {
                FILE *logfd;

                if (!strcasestr(opts.tests, op[j].opname))
                    continue;

                atomic64_set(&n_cursor, 0);
                atomic64_set(&n_read, 0);
                stopthreads = false;

                snprintf(logfile, sizeof(logfile), "rr_%s_%s_out.log", op[j].opname, s);
                kh_register(0, &print_stats, logfile);

                for (i = 0; i < opts.threads; i++) {
                    memset(dt[i].dt, 0x00, DT_CNT);
                    dt[i].dt_skip = 5;
                    dt[i].dt_cnt = 0;
                    kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, op[j].opfunc, &dt[i]);
                }

                duration = opts.duration;
                while (!stopthreads && duration--)
                    sleep(1);

                stopthreads = true;
                kh_wait();

                snprintf(logfile, sizeof(logfile), "%s/rr_%s_%s_lat_out.log", opts.logdir, op[j].opname, s);
                logfd = fopen(logfile, "w");
                for (i = 0; i < opts.threads; i++) {
                    struct delta_time d = dt[i];
                    int k;

                    for (k = 0; k < d.dt_cnt; k++)
                        fprintf(logfd, "%lu\n", d.dt[k]);
                }
                fclose(logfd);

            }

            s = strsep(&opts.blens, ",.;:/");
        }
        for (i = 0; i < opts.threads; i++)
            free(dt[i].dt);

        free(dt);
    }

    stopthreads = true;
    kh_wait_all(); /* Catch all threads - including detached */
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
