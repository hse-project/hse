/*
 * Copyright (C) 2018 Micron Technology, Inc.  All rights reserved.
 *
 * This test emulates the behavior of a capped kvs.
 *
 * This test consists of
 * 1. Writer threads: add keys to the kvs
 * 2. Reader threads: read keys from the kvs  in the same order in which they
 *                    were added.
 * 3. pfx del thread: This thread maintains a cap of a certain number of
 *                    prefixes in the kvs
 * 4. sync thread:    This thread sleeps for a second and then syncs the
 *                    contents on the kvdb to media.
 *
 * Each writer thread performs the following operations in a loop:
 *   1. picks up a global prefix and a global suffix and constructs its key.
 *   2. In a txn, puts this key into the kvs.
 *
 * All writer threads atomically increment and read the suffix thus ensuring
 * that the kvs contains all unique keys.
 * The set of writer threads has one leader which is reponsible for updating
 * the prefix.
 *
 * Each reader thread performs the following operations in a loop:
 *   1. create a cursor
 *   2. seek cursor just past the last-read-key
 *   3. read until eof or until we have a batch size worth of data
 *   4. record the last-read-key and destroy the cursor
 *
 */

#include <endian.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>
#include <hse_util/time.h>
#include <hse_util/timing.h>

#include <cli/param.h>

#include "kvs_helper.h"

HSE_ALIGNED(SMP_CACHE_BYTES)
    static atomic64_t  pfx = ATOMIC64_INIT(1);

HSE_ALIGNED(SMP_CACHE_BYTES)
    static atomic64_t  sfx = ATOMIC64_INIT(1);

HSE_ALIGNED(SMP_CACHE_BYTES)
    static uint64_t    last_del;

pthread_barrier_t   put_barrier1;
pthread_barrier_t   put_barrier2;

char *progname;
int exrc;

static volatile bool killthreads;
static volatile bool exit_puts;
static volatile int progress;

struct opts {
    ulong batch;
    uint chunk;
    uint cap;
    uint put_threads;
    uint cur_threads;
    uint headstart;
    uint duration;
    bool verify;
    bool wide;
} opts = {
    .batch = ULONG_MAX,
    .chunk = 2000,
    .cap = 10,
    .put_threads = 64,
    .cur_threads = 1,
    .duration = (30 * 60),
    .verify = false,
};


struct thread_info {
    int           idx;
    atomic64_t    ops HSE_ALIGNED(SMP_CACHE_BYTES);
    volatile int  state;
};

struct thread_info *g_ti;

void
pdel(void *arg)
{
    struct thread_arg *targ = arg;
    struct hse_kvdb_txn *txn;
    hse_err_t err;

    txn = hse_kvdb_txn_alloc(targ->kvdb);
    if (!txn)
        fatal(ENOMEM, "Failed to allocate resources for txn");

    pthread_setname_np(pthread_self(), __func__);

    while (!killthreads) {
        char      key[sizeof(uint64_t)];
        size_t    kvs_plen;
        uint64_t  curr_safe;
        uint64_t  curr;
        uint64_t *p;

        /* Compute how many entries is it safe to delete */
        curr = atomic64_read(&pfx);
        curr_safe = curr > opts.cap ? curr - opts.cap : 0;
        if (last_del >= curr_safe) {
            usleep(333);
            continue;
        }

        /* delete a prefix */

        p = (uint64_t *)key;
        *p = htobe64(last_del + 1);

        err = hse_kvdb_txn_begin(targ->kvdb, txn);
        if (err)
            fatal(err, "Failed to begin txn");

        err = hse_kvs_prefix_delete(targ->kvs, 0, txn, key, sizeof(*p), &kvs_plen);
        if (err) {
            if (hse_err_to_errno(err) == ECANCELED) {
                err = hse_kvdb_txn_abort(targ->kvdb, txn);
                if (err)
                    fatal(err, "Failed to abort txn");
                continue;
            }

            fatal(err, "Failed to insert prefix delete");

            killthreads = 1;
            fprintf(stderr, "prefix delete failure, KVS pfxlen = %lu. Must be %lu\n",
                    kvs_plen, sizeof(key));
            exrc = EX_DATAERR;
        }

        err = hse_kvdb_txn_commit(targ->kvdb, txn);
        if (err)
            fatal(err, "Failed to commit txn");

        last_del++;
    }
}

#define VLEN 1024

void
txput(void *arg)
{
    struct thread_arg *targ = arg;
    struct thread_info *ti = targ->arg;
    struct hse_kvdb_txn    *txn;
    uint64_t *p = 0; /* prefix */
    uint64_t *s = 0; /* suffix */
    hse_err_t err;
    uint32_t added;
    bool leader = ti->idx == 0;

    char key[2 * sizeof(uint64_t)];
    char val[VLEN] = { 0xfe };

    pthread_setname_np(pthread_self(), __func__);

    if (0 == getpriority(PRIO_PROCESS, 0))
        setpriority(PRIO_PROCESS, 0, 1);

    p = (uint64_t *)key;
    s = (uint64_t *)(key + sizeof(*p));

    txn = hse_kvdb_txn_alloc(targ->kvdb);
    if (!txn)
        fatal(ENOMEM, "Failed to allocate resources for txn");

    added = 0;
    while (!exit_puts) {
        *p = htobe64(atomic64_read(&pfx));       /* prefix */
        *s = htobe64(atomic64_inc_return(&sfx)); /* suffix */

        ti->state = 'b';
        err = hse_kvdb_txn_begin(targ->kvdb, txn);
        if (err)
            fatal(err, "Failed to begin txn");

        ti->state = 'p';
        err = hse_kvs_put(targ->kvs, 0, txn, key, sizeof(key),
                          val, sizeof(val));
        if (err) {
            if (hse_err_to_errno(err) == ECANCELED) {
                ti->state = 'a';
                err = hse_kvdb_txn_abort(targ->kvdb, txn);
                if (err)
                    fatal(err, "Failed to abort txn");
                usleep(1000);
                continue;
            }

            fatal(err, "Failed to put key");
        }

        atomic64_inc(&ti->ops);
        if (!err) {
            ti->state = 'c';
            err = hse_kvdb_txn_commit(targ->kvdb, txn);
            if (err)
                fatal(err, "Failed to commit txn");
            added++;
        } else {
            ti->state = 'A';
            err = hse_kvdb_txn_abort(targ->kvdb, txn);
            if (err)
                fatal(err, "Failed to abort txn");
        }

        if (killthreads || added == opts.chunk) {
            int rc;

            ti->state = 'w';
            added = 0;
            rc = pthread_barrier_wait(&put_barrier1);
            if (rc > 0)
                fatal(rc, "Failed to barrier wait");

            if (leader) {
                atomic64_inc(&pfx);
                if (killthreads)
                    exit_puts = true;
            }

            ti->state = 'W';
            pthread_barrier_wait(&put_barrier2);
        }

        ti->state = '.';
    }

    hse_kvdb_txn_free(targ->kvdb, txn);
}

void
syncme(void *arg)
{
    struct thread_arg *targ = arg;

    pthread_setname_np(pthread_self(), __func__);

    while (!killthreads) {
        sleep(1);

        hse_kvdb_sync(targ->kvdb, 0);
    }
}

void
print_stats(void *arg)
{
    char         statev[opts.put_threads + opts.cur_threads + 1];
    uint32_t     second = 0;
    uint64_t     puts_last, reads_last;
    uint64_t     puts, reads;
    uint64_t     start;
    long         minflt = 0;
    long         majflt = 0;
    int          i;
    unsigned int keys_per_pfx = opts.chunk * opts.put_threads;

    puts_last = reads_last = 0;

    start = get_time_ns();
    while (!killthreads) {
        struct thread_info *t = &g_ti[0];
        struct rusage       rusage;
        uint64_t            dt;
        double              lag;
        unsigned int        pfx_lag;

        usleep(999 * 1000);
        getrusage(RUSAGE_SELF, &rusage);

        puts = reads = 0;
        for (i = 0; i < opts.put_threads; i++) {
            puts += atomic64_read(&t->ops);
            statev[i] = t->state;
            ++t;
        }

        for (i = 0; i < opts.cur_threads; i++) {
            reads += atomic64_read(&t->ops);
            statev[i + opts.put_threads] = t->state;
            ++t;
        }

        statev[i + opts.put_threads] = '\000';
        if (!opts.wide)
            memmove(statev, statev + opts.put_threads, opts.cur_threads + 1);

        /* All readers must read each and every put.
         */
        reads /= (opts.cur_threads ?: 1);

        pfx_lag = (puts - reads) / keys_per_pfx;

        lag = (puts - reads) / (reads - reads_last + 0.000001);
        if (lag > 99999)
            lag = 99999.99;

        dt = get_time_ns() - start;
        if (second % 20 == 0)
            printf("\n%8s %8s %8s %10s %10s %8s %8s %8s %8s %8s %8s %s\n",
                   "seconds", "cpfx", "dpfx", "puts",
                   "reads", "lag", "pfxLag", "pRate", "rRate",
                   "majflt", "minflt", "state");

        printf("%8lu %8lu %8lu %10lu %10lu %8.2lf %8u %8lu %8lu %8ld %8ld %s\n",
               dt / NSEC_PER_SEC,
               atomic64_read(&pfx), last_del,
               puts, reads, lag, pfx_lag,
               puts - puts_last, reads - reads_last,
               rusage.ru_majflt - majflt,
               rusage.ru_minflt - minflt, statev);
        fflush(stdout);

        reads_last = reads;
        puts_last = puts;

        majflt = rusage.ru_majflt;
        minflt = rusage.ru_minflt;
        second++;
    }
}

void
reader(void *arg)
{
    struct thread_arg  *targ = arg;
    struct thread_info *ti = targ->arg;
    struct hse_kvdb_txn *txn;
    struct hse_kvs_cursor  *c;
    uint32_t            cnt;
    bool                eof = false;
    uint64_t            klast[2] = { 0 };
    const void         *key, *val;
    const uint64_t     *key64;
    size_t              klen, vlen;
    hse_err_t           err;

    pthread_setname_np(pthread_self(), __func__);

    txn = hse_kvdb_txn_alloc(targ->kvdb);

    while (!killthreads) {
        uint64_t last_safe_pfx = atomic64_read(&pfx) - 1;

        ti->state = 'b';
        err = hse_kvdb_txn_begin(targ->kvdb, txn);
        if (err)
            fatal(err, "Failed to begin txn");

        /* [MU_REVISIT] Consider adding an option to replace
         * destroy-create-seek with an update to test positional
         * stability
         */
        ti->state = 'c';
        err = hse_kvs_cursor_create(targ->kvs, 0, txn, NULL, 0, &c);
        if (err)
            fatal(err, "hse_kvs_cursor_create failure");

        if (klast[0]) {
            klen = 0;

            ti->state = 's';
            err = hse_kvs_cursor_seek(c, 0, klast, sizeof(klast), &key, &klen);
            if (err)
                fatal(err, "hse_kvs_cursor_seek failure");

            if (klen != sizeof(klast) || memcmp(klast, key, klen)) {
                key64 = key;

                fatal(ENOENT, "Lost capped position at seek: "
                      "expected %lu-%lu found %lu-%lu "
                      "last del %lu",
                      be64toh(klast[0]), be64toh(klast[1]),
                      key ? be64toh(key64[0]) : 0,
                      key ? be64toh(key64[1]) : 0,
                      last_del);
            }

            ti->state = 'r';
            err = hse_kvs_cursor_read(c, 0, &key, &klen, &val, &vlen, &eof);
            if (err)
                fatal(err, "Failed to read from the cursor");
        }

        eof = false;
        cnt = 0;

        while (cnt < opts.batch) {
            ti->state = 'R';
            err = hse_kvs_cursor_read(c, 0, &key, &klen, &val, &vlen, &eof);
            if (err)
                fatal(err, "Failed to read from the cursor");

            ti->state = 'v';
            key64 = key;
            if (eof || be64toh(key64[0]) > last_safe_pfx)
                break;

            if (opts.verify && klast[0]) {
                uint64_t found[2], last[2];

                found[0] = be64toh(key64[0]);
                found[1] = be64toh(key64[1]);
                last[0]  = be64toh(klast[0]);
                last[1]  = be64toh(klast[1]);

                if (!(found[1] == 1 + last[1] ||
                      (found[1] == 0 && found[0] == 1 + last[0])))
                    fatal(EINVAL, "Found unexpected key\n");
            }

            klast[0] = key64[0];
            klast[1] = key64[1];

            if (++cnt % 1024 == 0) {
                atomic64_add(1024, &ti->ops);
                if (killthreads)
                    break;
            }
        }

        /* Abort txn: This was a read-only txn */
        ti->state = 'a';
        err = hse_kvdb_txn_abort(targ->kvdb, txn);
        if (err)
            fatal(err, "Failed to abort txn");

        atomic64_add(cnt % 1024, &ti->ops);

        ti->state = 'd';
        hse_kvs_cursor_destroy(c);

        ti->state = '.';
    }

    hse_kvdb_txn_free(targ->kvdb, txn);
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

void
usage(void)
{
    printf(
        "usage: %s [options] kvdb kvs [param=value ...]\n"
        "-b bsz  Reader batch size\n"
        "-c csz  Chunk size per writer thread\n"
        "-d dur  Duration of run (in seconds)\n"
        "-h      Print this help menu\n"
        "-j wtd  Number of writer threads\n"
        "-m pfx  How many most recent prefixes to keep alive\n"
        "-s sec  Headstart for put threads (in seconds)\n"
        "-t rtd  Number of reader threads\n"
        "-v      Verify data\n"
        "-w      Wide output (i.e., show put threads state)\n"
        , progname);

    printf("\nDescription:\n");
    printf("Number of kv-pairs per prefix = "
           "chunk_size * number_of_put_threads\n");
    printf("Each cursor thread will read a max of 'batch size' "
           "(set using the '-b' option) kv-pairs before it updates the "
           "cursor and continues reading. The default value (0) will let "
           "it read to EOF\n");
    printf("\n");
}

int
main(int argc, char **argv)
{
    struct parm_groups *pg = 0;
    struct svec         hse_gparms = { 0 };
    struct svec         kvdb_oparms = { 0 };
    struct svec         kvs_cparms = { 0 };
    struct svec         kvs_oparms = { 0 };
    const char         *mpool, *kvs;
    size_t              sz;
    uint                i;
    char                c;
    int                 rc;

    progname = basename(argv[0]);

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc)
        fatal(rc, "pg_create");

    while ((c = getopt(argc, argv, ":b:c:d:hj:t:m:s:vw")) != -1) {
        char *errmsg = NULL, *end = NULL;

        errno = 0;

        switch (c) {
        case 'b':
            opts.batch = strtoul(optarg, &end, 0);
            errmsg = "invalid batch size";
            break;
        case 'c':
            opts.chunk = strtoul(optarg, &end, 0);
            errmsg = "invalid chunk size";
            break;
        case 'd':
            opts.duration = strtoul(optarg, &end, 0);
            errmsg = "invalid duration";
            break;
        case 'h':
            usage();
            exit(0);
        case 'j':
            opts.put_threads = strtoul(optarg, &end, 0);
            errmsg = "invalid writer thread count";
            break;
        case 't':
            opts.cur_threads = strtoul(optarg, &end, 0);
            errmsg = "invalid reader thread count";
            break;
        case 'm':
            opts.cap = strtoul(optarg, &end, 0);
            errmsg = "invalid data size cap";
            break;
        case 's':
            opts.headstart = strtoul(optarg, &end, 0);
            errmsg = "invalid headstart";
            break;
        case 'v':
            opts.verify = true;
            break;
        case 'w':
            opts.wide = true;
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
        syntax("missing required arguments");
        exit(EX_USAGE);
    }

    mpool = argv[optind++];
    kvs = argv[optind++];

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
    rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
    if (rc) {
        fprintf(stderr, "svec_append_pg failed: %d", rc);
        exit(EX_USAGE);
    }

    kh_init(mpool, &hse_gparms, &kvdb_oparms);

    pthread_barrier_init(&put_barrier1, NULL, opts.put_threads);
    pthread_barrier_init(&put_barrier2, NULL, opts.put_threads);

    sz = (opts.put_threads + opts.cur_threads) * sizeof(*g_ti);

    g_ti = aligned_alloc(SMP_CACHE_BYTES * 2, roundup(sz, SMP_CACHE_BYTES * 2));
    if (!g_ti) {
        fatal(ENOMEM, "Allocation failed");
    }

    memset(g_ti, 0, sz);

    for (i = 0; i < opts.put_threads; i++) {
        g_ti[i].idx = i;
        atomic64_set(&g_ti[i].ops, 0);
        g_ti[i].state = 'i';
        kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &txput, &g_ti[i]);
    }

    if (opts.headstart) {
        printf("%d second headstart...\n", opts.headstart);
        sleep(opts.headstart);
    }

    for (i = 0; i < opts.cur_threads; i++) {
        int j = i + opts.put_threads;

        g_ti[j].idx = i;
        atomic64_set(&g_ti[j].ops, 0);
        g_ti[j].state = 'i';
        kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &reader, &g_ti[j]);
    }

    if (opts.cap)
        kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &pdel, 0);

    kh_register(0, &print_stats, NULL);
    kh_register(0, &syncme, NULL);

    /* run time */
    while (!killthreads && opts.duration--)
        sleep(1);

    killthreads = true;

    kh_wait();

    pthread_barrier_destroy(&put_barrier1);
    pthread_barrier_destroy(&put_barrier2);

    kh_fini();

    free(g_ti);
    svec_reset(&hse_gparms);
    svec_reset(&kvdb_oparms);
    svec_reset(&kvs_cparms);
    svec_reset(&kvs_oparms);
    pg_destroy(pg);

    return exrc;
}
