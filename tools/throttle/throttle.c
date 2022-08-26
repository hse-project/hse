/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <getopt.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <hse/hse.h>

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>
#include <hse_util/parse_num.h>
#include <hse_util/time.h>

#include <tools/parm_groups.h>

#include <tools/key_generation.h>

/* Default key/value lengths */
#define KLEN_DEFAULT   23
#define VLEN_DEFAULT   1018

#define KLEN_MAX  1000
#define VLEN_MAX  (10*1024)

struct opts {
    bool    help;
    char   *config;
    char   *mpool;
    char   *kvs;
    char   *weight;
    u64     keys;
    uint    klen;
    uint    vlen;
    uint    threads;
    bool    show_ops;
    bool    dryrun;
    bool    close;
    bool    binary;
    u64     kstart;
    u32     errcnt;
    u32     ingiters;
    u64     ingestcycle;
    u64     sleepcycle;
    u64     runtime;
};


#define KEY_SHOWLEN  23
#define VAL_SHOWLEN  35

char *VAL_PREFIX = "V%016lx_%016u";

struct opts opt;

const char *mode = "";
const char *progname = NULL;
struct timeval tv_start;
int verbose = 0;
u32 errors = 0;

static struct key_generator *key_gen;
static const long key_space_size = 4000000000UL;

pthread_barrier_t   barrier;
struct hse_kvdb *kvdb;
struct hse_kvs  **kvs_h;
char **kvs_names;
uint  *kvs_weight;
char **kvswt_param;
uint   kvs_cnt;

struct parm_groups *pg;
struct svec         hse_gparm = { 0 };
struct svec         db_oparm = { 0 };
struct svec         kv_oparm = { 0 };

struct thread_info {
    struct hse_kvs         *kvs;
    pthread_t           tid;
    uint                id;

    bool        joined;

    /* reference key */
    void       *ref_key;
    size_t      ref_klen;

    /* reference value */
    void       *ref_val;
    size_t      ref_vlen;

    /* buffer for kvdb_get */
    void       *get_val;

    void       *pfx;
    int         pfxlen;
    u64         ops;
    u64         time;
};

static void syntax(const char *fmt, ...);
static void quit(const char *fmt, ...);
static void usage(void);

static void
quit(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    if (fmt && *fmt) {
        va_start(ap, fmt);
        vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);
        fprintf(stderr, "%s: %s\n", progname, msg);
        fflush(stderr);
    }
    exit(-1);
}

static void
syntax(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s\nUse -h for help.\n", progname, msg);
    exit(EX_USAGE);
}

static
void
_error_quit(
    const char *detail,
    u64         err,
    const char *file,
    int         line)
{
    char err_buf[300];

    hse_strerror(err, err_buf, sizeof(err_buf));

    quit("%s:%d: %s: %s", file, line,
         (detail && *detail) ? detail : "",
         err_buf);
}

#define error_quit(detail, err) \
    _error_quit(detail, err, REL_FILE(__FILE__), __LINE__)

void
announce_header(void)
{
    if (!verbose)
        return;

    printf("*** %8s %7s %7s %7s %8s  %s\n",
           "TID", "USER", "SYS", "REAL", "MODE", "MESSAGE");
}

void
announce(const char *msg)
{
    struct timeval tv_now;
    struct rusage rusage;
    int rc;

    if (!verbose)
        return;

    gettimeofday(&tv_now, NULL);

    rc = getrusage(RUSAGE_SELF, &rusage);
    if (rc == 0) {
        long utime, stime, rtime;

        rtime = (tv_now.tv_sec - tv_start.tv_sec) * 1000000;
        rtime += (tv_now.tv_usec - tv_start.tv_usec);
        utime = rusage.ru_utime.tv_sec * 1000000
            + rusage.ru_utime.tv_usec;
        stime = rusage.ru_stime.tv_sec * 1000000
            + rusage.ru_stime.tv_usec;

        printf("*** %8lx %7ld %7ld %7ld %8s  %s\n",
               pthread_self() & 0xffffffffu,
               utime / 1000, stime / 1000, rtime / 1000,
               mode, msg);
    }
}

/*----------------------------------------------------------------
 * Command Line Processing
 */

enum opt_enum {
    opt_config = 'Z',
    opt_binary	= 'b',
    opt_keys	= 'c',
    opt_help	= 'h',
    opt_klen        = 'l',
    opt_vlen        = 'L',
    opt_dryrun	= 'n',
    opt_close       = 'x',

    opt_verbose	= 'v',
    opt_kstart      = 's',
    opt_threads     = 't',
    opt_ingestcycle = 'i',
    opt_sleepcycle  = 'S',
    opt_ingiters    = 'I',
    opt_runtime     = 'T',
};


struct option longopts[] = {
    { "config",      required_argument,  NULL,  opt_config},
    { "binary",      no_argument,        NULL,  opt_binary },
    { "dryrun",      no_argument,        NULL,  opt_dryrun },
    { "close",       no_argument,        NULL,  opt_close},
    { "help",        no_argument,        NULL,  opt_help },
    { "keys",        required_argument,  NULL,  opt_keys },
    { "klen",        required_argument,  NULL,  opt_klen },
    { "vlen",        required_argument,  NULL,  opt_vlen },
    { "threads",     required_argument,  NULL,  opt_threads },

    { "ingestcycle", required_argument,  NULL,  opt_ingestcycle },
    { "ingiters",    required_argument,  NULL,  opt_ingiters },
    { "sleepcycle",  required_argument,  NULL,  opt_sleepcycle },
    { "runtime",     required_argument,  NULL,  opt_runtime },

    { "verbose",     optional_argument,  NULL,  opt_verbose },
    { "kstart",      required_argument,  NULL,  opt_kstart  },

    { 0, 0, 0, 0 }
};

/* A thread-safe version of strerror().
 */
char *
strerror(int errnum)
{
    static thread_local char tls_errbuf[128];

    return strerror_r(errnum, tls_errbuf, sizeof(tls_errbuf));
}


static
void
options_default(
    struct opts *opt)
{
    memset(opt, 0, sizeof(*opt));
    opt->keys = 10;
    opt->threads = 1;
    opt->errcnt = 1;
    opt->klen = KLEN_DEFAULT;
    opt->vlen = VLEN_DEFAULT;

    opt->ingestcycle  = 30;
    opt->ingestcycle *= NSEC_PER_SEC;
    opt->sleepcycle   = NSEC_PER_SEC;
    opt->ingiters     = 1;
    opt->runtime      = 180UL * NSEC_PER_SEC;
    opt->dryrun       = false;
    opt->close        = false;
}

#define GET_VALUE(TYPE, OPTARG, VALUE)					\
    do {                                                                \
	if (parse_##TYPE(OPTARG, VALUE)) {				\
            syntax("Unable to parse "#TYPE" number: '%s'", OPTARG);	\
	}								\
    } while (0)

#define GET_DOUBLE(OPTARG, VALUE)                               \
    do {                                                        \
	if (1 != sscanf(OPTARG, "%lg", VALUE)) {                \
            syntax("Unable to parse double: '%s'", OPTARG);     \
	}                                                       \
    } while (0)

void
options_parse(
    int argc,
    char **argv,
    struct opts *opt)
{
    int done;

    /* Dynamically build optstring from longopts[] for getopt_long_only().
     */
    const size_t optstringsz =
        (sizeof(longopts) / sizeof(longopts[0])) * 3 + 3;
    char optstring[optstringsz + 1];
    const struct option *longopt;
    char *pc = optstring;

    *pc++ = ':';    /* Disable getopt error messages */

    for (longopt = longopts; longopt->name; ++longopt) {
        if (!longopt->flag && isprint(longopt->val)) {
            *pc++ = longopt->val;
            if (longopt->has_arg == required_argument) {
                *pc++ = ':';
            } else if (longopt->has_arg == optional_argument) {
                *pc++ = ':';
                *pc++ = ':';
            }
        }
    }
    *pc = '\000';

    done = 0;
    while (!done) {
        int curind = optind;
        int longidx = 0;
        int c;

        c = getopt_long(argc, argv, optstring, longopts, &longidx);
        if (-1 == c)
            break; /* got '--' or end of arg list */

        switch (c) {
        case opt_config:
            opt->config = optarg;
            break;

        case opt_binary:
            opt->binary = true;
            break;

        case opt_help:
            opt->help = true;
            break;

        case opt_kstart:
            GET_VALUE(u64, optarg, &opt->kstart);
            break;

        case opt_verbose:
            if (optarg)
                GET_VALUE(int, optarg, &verbose);
            else
                ++verbose;
            opt->show_ops = (verbose > 1);
            break;

        case opt_keys:
            GET_VALUE(u64, optarg, &opt->keys);
            break;

        case opt_klen:
            GET_VALUE(uint, optarg, &opt->klen);
            break;

        case opt_vlen:
            GET_VALUE(uint, optarg, &opt->vlen);
            break;

        case opt_threads:
            GET_VALUE(uint, optarg, &opt->threads);
            break;

        case opt_dryrun:
            opt->dryrun = true;
            break;

        case opt_close:
            opt->close = true;
            break;

        case opt_ingiters:
            GET_VALUE(uint, optarg, &opt->ingiters);
            break;

        case opt_ingestcycle:
            GET_VALUE(u64, optarg, &opt->ingestcycle);
            opt->ingestcycle *= NSEC_PER_SEC;
            break;

        case opt_sleepcycle:
            GET_VALUE(u64, optarg, &opt->sleepcycle);
            opt->sleepcycle *= NSEC_PER_SEC;
            break;
            break;

        case ':':
            syntax("missing argument for option '%s'",
                   argv[curind]);
            break;

        case opt_runtime:
            GET_VALUE(u64, optarg, &opt->runtime);
            opt->runtime *= NSEC_PER_SEC;
            break;

        case '?':
            syntax("invalid option '%s'", argv[optind-1]);
            break;

        default:
            if (c == 0) {
                if (!longopt[longidx].flag) {
                    syntax("unhandled option '--%s'",
                           longopts[longidx].name);
                }
            } else {
                syntax("unhandled option '%s'", argv[curind]);
            }
            break;
        }
    }

    if (opt->help)
        usage();
}

static void
usage(void)
{
    printf("usage: %s [options] <kvdb> <kvslist> <weight> "
           "[param=value ...]\n", progname);

    printf("Key/value count and format:\n"
           "  -t, --threads     number of threads\n"
           "  -s, --kstart      starting index of keys, default=0\n"
           "  -c, --keys COUNT  put/get COUNT keys\n"
           "  -b, --binary      generate binary keys and values\n"
           "  -l, --klen LEN    keys are LEN bytes\n"
           "  -L, --vlen LEN    values are LEN bytes\n"
           "  -i, --ingestcycle ingest time in seconds\n"
           "  -S, --sleepcycle  sleep time in seconds\n"
           "  -I, --iterations  how many ingest and sleep cycles to "
           "                    repeat in a single test cycle\n"
           "  -Z, --config      path to global config file\n"
           "Other:\n"
           "  -v, --verbose=LVL  increase[or set] verbosity\n"
           "  -h, --help         print this help list\n"
           "\n");

    if (!verbose) {
        printf("Give -hv for more detail.\n\n");
        return;
    }

    printf("Mandatory parameters:\n"
           "  <kvdb>\n"
           "  <kvslist> -- A kvs name, a comma or colon separated list\n"
           "      of kvs names, a format string with a %%d conversion\n"
           "      specifier that will be replaced with the logical\n"
           "      thread ID, or any combination thereof.  The list is\n"
           "      iterated over from left to right in round-robin\n"
           "      fashion as each thread is created.\n"
           "  <weight> -- Weigh of kvses in the <kvslist>\n"
           "\n"
           "Examples:\n"
           "  throttle kvdb1 kvs1,kvs2,kvs3 50:40:10 -t 8\n"
           "  throttle kvdb1 kvs1 100 -t 8\n\n"
           "The example below will generate 10 seconds ingest cycles and "
           "2 seconds sleep cycles which is repeated 10 times\n"
           "throttle  mp1 db1 kvs1 100 -i 10 -S 2 -I 10\n"
           "\n");
}

void
test_open_kvdb(void)
{
    u64 rc;

    if (kvdb)
        return;

    rc = hse_kvdb_open(opt.mpool, db_oparm.strc, db_oparm.strv, &kvdb);
    if (rc)
        error_quit("hse_kvdb_open failed", rc);

    assert(kvdb);
}

void
test_close_kvdb(void)
{
    u64 rc;

    if (!kvdb)
        return;

    rc = hse_kvdb_close(kvdb);
    if (rc)
        error_quit("hse_kvdb_close failed", rc);

    kvdb = NULL;
}

void
test_open_kvs(char *kvs_name, struct hse_kvs **kvs)
{
    u64 rc;

    if (kvs && *kvs)
        return;

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, kv_oparm.strc, kv_oparm.strv, kvs);
    if (rc)
        error_quit("hse_kvdb_kvs_open failed", rc);
}

void
test_close_kvs(char *kvs_name, struct hse_kvs *kvs)
{
    u64 rc;

    if (!kvs)
        return;

    rc = hse_kvdb_kvs_close(kvs);
    if (rc)
        error_quit("hse_kvdb_kvs_close failed", rc);
}

void
fmt_string(
    char *str,
    int len,
    int max_len,
    char fill,
    char *fmt,
    u64 fmt_arg1,
    int fmt_arg2)
{
    int i;

    if (len > max_len)
        quit("key or value too large: %u (limit is %u)", len, max_len);

    snprintf(str, len, fmt, fmt_arg1, fmt_arg2);
    i = strlen(str);
    while (i+1 < len)
        str[i++] = fill;
    str[i] = '\0';
}

void
fmt_key(
    struct thread_info *ti,
    int len,
    unsigned long num)
{
    static atomic_int u;
    unsigned char *str = ti->ref_key;
    uint v;

    if (len < 8) {
        memcpy(str, "BAD", len);
        return;
    }

    if (key_gen) {
        get_key(key_gen, str, num);
        *(u32 *)str = ti->id;
        str[len-1] = 0;
    } else {
        v = atomic_inc_return(&u);
        *(u32 *)str       = ti->id;
        *(u32 *)(str + 4) = v;
        for (len -= 8, str += 8; len > 0; --len)
            *str++ = v & 255;
    }
}

int key_showlen;
int val_showlen;

void
set_kv(
    struct thread_info          *ti,
    u64                        keynum,
    uint                       salt)
{
    if (opt.binary) {
        uint32_t *pdata = (uint32_t *)ti->ref_val;
        uint32_t *data = (uint32_t *)ti->ref_key;
        int idx;

        /* Each binary key/value is a function of the previous
         * key/value.
         */
        idx = keynum % 8;
        ti->ref_klen = (idx + 1) * sizeof(*data);
        data[idx] = keynum;

        idx = keynum % 32;
        ti->ref_vlen = (idx + 1) * sizeof(*pdata);
        pdata[idx] = keynum + salt;

        *(uint64_t *)ti->get_val = 0xdeadbeefabadcafe;

        return;
    }

    fmt_key(ti, opt.klen, keynum);

    if (opt.vlen > 0)
        fmt_string(ti->ref_val,
                   opt.vlen, VLEN_MAX, '*', VAL_PREFIX,
                   keynum, salt);

    ti->ref_klen  = opt.klen;
    ti->ref_vlen  = opt.vlen;

    key_showlen = ti->ref_klen;
    val_showlen = ti->ref_vlen;

    if (key_showlen > KEY_SHOWLEN)
        key_showlen = KEY_SHOWLEN;
    if (val_showlen > VAL_SHOWLEN)
        val_showlen = VAL_SHOWLEN;

    /*
     * ti->get is the buffer for 'kvs_get' results. Initialize it to
     * something that will not match a key, and set vt_plen to the
     * size of the buffer it points to.
     */
    sprintf(ti->get_val, "**UNINITIALIZED_BUFFER**");
}

void
test_put_impl(
    struct thread_info *ti,
    uint salt,
    u64  time)
{
    hse_err_t  err;
    u64     tmelapsed = 0;
    u64     i;
    u64     start;
    int     idx;
    int     cnt;

    start = get_time_ns();
    idx   = 0;
    cnt   = 0;

    for (i = opt.kstart; ; i++) {
        tmelapsed = get_time_ns() - start;

        if (tmelapsed >= time)
            break;

        set_kv(ti, i, salt);
        if (opt.show_ops) {
            printf("T%u: PUT(%lu,%u): key[%zu]=%.*s..."
                   " val[%zu]=%.*s...\n",
                   ti->id, i, salt, ti->ref_klen,
                   key_showlen,
                   (char *)ti->ref_key,
                   ti->ref_vlen,
                   val_showlen,
                   (char *)ti->ref_val);
        }

        if (opt.dryrun)
            continue;

        err = hse_kvs_put(kvs_h[idx], 0, NULL,
                          (char *)ti->ref_key,
                          ti->ref_klen,
                          (char *)ti->ref_val,
                          ti->ref_vlen);
        if (err)
            error_quit("kvdb_put failed", err);

        ti->ops++;
        cnt++;

        if (cnt > kvs_weight[idx]) {
            cnt = 0;
            idx++;
            idx %= kvs_cnt;
        }
    }

    ti->time += tmelapsed;

    start = get_time_ns();
    hse_kvdb_sync(kvdb, 0);
    tmelapsed = get_time_ns() - start;

    ti->time += tmelapsed;

}

void
test_put(struct thread_info *ti, uint salt)
{
    struct timespec req = {0};

    u32 i;

    ti->ops  = 0;
    ti->time = 0;

    for (i = 0; i < opt.ingiters; i++) {
        test_put_impl(ti, salt, opt.ingestcycle);
        if (!opt.sleepcycle)
            continue;

        req.tv_sec  = opt.sleepcycle / NSEC_PER_SEC;
        req.tv_nsec = opt.sleepcycle % NSEC_PER_SEC;

        nanosleep(&req, 0);
    }

}

void *
thread_main(void *arg)
{
    struct thread_info *ti = arg;
    uint salt;

    salt = 0;

    pthread_barrier_wait(&barrier);

    test_put(ti, salt);

    if (errors >= opt.errcnt)
        quit("Exiting, because %u error(s) were encountered\n", errors);

    announce("Successful");

    return NULL;
}

void
extract_fields(char *str, uint max, char **fields, uint *out)
{
    char *pctx; /* parse context */
    char *cp;   /* generic char ptr */
    uint  count;

    pctx  = str;
    count = 0;

    while (1) {

        do {
            cp = strsep(&pctx, ":,; \t\r\n");
        } while (cp && !*cp);

        if (cp) {
            char *tmp;

            tmp = cp;
            fields[count] = cp;
            cp = strchr(tmp, '/');
            if (cp) {
                *cp++ = 0;
                fields[count] = cp;
            }
        } else {
            if (count == 0)
                quit("Invalid kvs name: %s", opt.kvs);
            break;
        }
        count++;
        if (count >= max) {
            count--;
            break;
        }
    }

    *out = count;
}

int
run_test(
    struct thread_info *threads,
    char               *kvs,
    char               *weight)
{
    struct thread_info *ti;

    uint   kvsc;
    uint   kvswtc;
    int    rc;
    uint   i;

    kvsc = 0;

    extract_fields(kvs, 1024, kvs_names, &kvsc);
    if (!kvsc)
        quit("Zero kvs");

    if (kvsc > 1024)
        quit("Too many kvses");

    kvswtc = 0;
    extract_fields(weight, 1024, kvswt_param, &kvswtc);
    if (kvswtc && (kvsc != kvswtc))
        quit("Improper weights");

    for (i = 0; i < kvsc; i++) {
        if (!kvswtc)
            kvs_weight[i] = 100 / kvsc;
        else
            kvs_weight[i] = atol(kvswt_param[i]);
    }

    kvs_cnt = kvsc;

    test_open_kvdb();

    for (i = 0; i < kvsc; i++)
        test_open_kvs(kvs_names[i], &kvs_h[i]);

    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        ti->id = i;
        ti->ref_key = calloc(KLEN_MAX, KLEN_MAX);
        ti->get_val = calloc(VLEN_MAX, VLEN_MAX);
        ti->ref_val = calloc(VLEN_MAX, VLEN_MAX);
        if (!ti->ref_key || !ti->get_val || !ti->ref_val)
            quit("Out of memory");
    }

    announce_header();
    pthread_barrier_init(&barrier, NULL, opt.threads + 1);

    /* Start the threads */
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        rc = pthread_create(&ti->tid, NULL, thread_main, ti);
        if (rc) {
            printf("%s: pthread_create failed: %s\n",
                   progname, strerror(rc));
            ti->joined = true;
            continue;
        }
    }

    pthread_barrier_wait(&barrier);

    /* If running as root, bump priority to help run-to-run consistency. */
    setpriority(PRIO_PROCESS, 0, -15);

    /* Reap all the threads. */
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {

        if (ti->joined)
            continue;

        rc = pthread_join(ti->tid, NULL);
        if (rc && rc != EINVAL && rc != ESRCH) {
            printf("%s: pthread_join failed: %s\n",
                   progname, strerror(rc));
            continue;
        }

        ti->joined = true;
    }

    if (opt.close) {
        for (i = 0; i < kvsc; i++) {
            test_close_kvs(kvs_names[i], kvs_h[i]);
            kvs_h[i] = 0;
        }

        test_close_kvdb();
    }

    pthread_barrier_destroy(&barrier);

    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        free(ti->ref_key);
        free(ti->get_val);
        free(ti->ref_val);
    }

    return 0;
}

static void
print_header(void)
{
    printf("%5s %10s %10s %10s %12s %10s %10s %10s %12s %10s\n",
           "idx", "ops_min", "ops_max", "ops_avg", "ops_aggr",
           "bps_min", "bps_max", "bps_avg", "bps_aggr", "msec");
}

int
main(int argc, char **argv)
{
    struct thread_info *threads = NULL;

    int     rc;
    hse_err_t  err;
    uint    i;
    u64     time;
    int     cnt;
    char   *kvs;
    char   *weight;
    u64     tot_opsmin = 0;
    u64     tot_opsmax = 0;
    u64     tot_opsavg = 0;
    u64     tot_time   = 0;

    gettimeofday(&tv_start, NULL);

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        quit("pg_create");

    options_default(&opt);
    options_parse(argc, argv, &opt);

    if (opt.help)
        goto done;

    if (argc - optind < 3)
        syntax("missing required parameters");

    opt.mpool  = argv[optind++];
    opt.kvs    = argv[optind++];
    opt.weight = argv[optind++];

    /* get hse parms from command line */
    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
        case 0:
            if (optind < argc)
                quit("unknown parameter: %s", argv[optind]);
            break;
        case EINVAL:
            quit("missing group name (e.g. %s) before parameter %s\n",
                PG_KVDB_OPEN, argv[optind]);
            break;
        default:
            quit("error processing parameter %s\n", argv[optind]);
            break;
    }

    rc = rc ?: svec_append_pg(&hse_gparm, pg, PG_HSE_GLOBAL, NULL);
    rc = rc ?: svec_append_pg(&db_oparm, pg, PG_KVDB_OPEN, NULL);
    rc = rc ?: svec_append_pg(&kv_oparm, pg, PG_KVS_OPEN, NULL);
    if (rc)
        quit("svec_apppend_pg failed: %d", rc);

    if (!opt.keys)
        syntax("number of keys must be > 0");

    /* pgd expects null-terminated strings, thus klen-1 */
    key_gen = create_key_generator(key_space_size, opt.klen-1);
    if (!key_gen && opt.klen < 8)
        key_gen = create_key_generator(key_space_size/100, opt.klen-1);

    if (opt.threads == 0)
        opt.threads = 1;

    threads = calloc(opt.threads, sizeof(*threads));
    if (!threads)
        quit("unable to calloc %zu bytes for thread_info",
             opt.threads * sizeof(*threads));

    kvs_h = calloc(1024 * sizeof(*kvs_h), 1024 * sizeof(*kvs_h));
    if (!kvs_h)
        quit("Out of memory");

    kvs_names = malloc(1024 * sizeof(*kvs_names));
    if (!kvs_names)
        quit("Out of memory");

    kvswt_param = malloc(1024 * sizeof(*kvswt_param));
    if (!kvswt_param)
        quit("Out of memory");

    kvs_weight = malloc(1024 * sizeof(*kvs_weight));
    if (!kvs_weight)
        quit("Out of memory");

    gettimeofday(&tv_start, NULL);

    printf("Ingest cycle %ld sec. sleep cycle %ld sec. iterations %ld "
           "runtime %ld sec. threads %d klen %d vlen %d",
           (unsigned long)opt.ingestcycle / NSEC_PER_SEC,
           (unsigned long)opt.sleepcycle / NSEC_PER_SEC,
           (unsigned long)opt.ingiters,
           (unsigned long)opt.runtime / NSEC_PER_SEC,
           opt.threads, opt.klen, opt.vlen);

    if (opt.dryrun)
        printf("dryrun");

    printf("\n");

    err = hse_init(opt.config, hse_gparm.strc, hse_gparm.strv);
    if (err)
        quit("failed to initialize kvdb");

    time = get_time_ns();

    cnt = 0;
    while ((get_time_ns() - time) < opt.runtime) {
        u64 minops;
        u64 maxops;
        u64 ops;
        u64 tmp;
        u64 avgtime;
        u64 mintime;
        u64 maxtime;
        u64 runtime;

        if (!(cnt++ % 20))
            print_header();


        kvs = strdup(opt.kvs);
        weight = strdup(opt.weight);
        if (!kvs || !weight)
            quit("Out of memory");

        runtime = get_time_ns();
        run_test(threads, kvs, weight);
        runtime = get_time_ns() - runtime;

        free(kvs);
        free(weight);

        avgtime = threads[0].time;
        minops  = (threads[0].ops * NSEC_PER_SEC) /
            threads[0].time;
        maxops  = minops;
        ops     = minops;

        mintime = maxtime = avgtime;

        for (i = 1; i < opt.threads; i++) {
            tmp = (threads[i].ops * NSEC_PER_SEC) /
                threads[i].time;

            if (minops > tmp)
                minops = tmp;

            if (maxops < tmp)
                maxops = tmp;

            avgtime += threads[i].time;

            if (mintime > threads[i].time)
                mintime = threads[i].time;

            if (maxtime < threads[i].time)
                maxtime = threads[i].time;

            ops += tmp;
        }

        tot_time += runtime;

        minops  = (minops * NSEC_PER_SEC) / mintime;
        maxops  = (maxops * NSEC_PER_SEC) / maxtime;
        avgtime = avgtime / opt.threads;
        ops     = (ops * NSEC_PER_SEC) / avgtime;

        printf("%5d %10ld %10ld %10ld %12ld %10ld %10ld %10ld "
               "%12ld %10ld\n",
               (unsigned int)cnt,
               (unsigned long)minops,
               (unsigned long)maxops,
               (unsigned long)ops / opt.threads,
               (unsigned long)ops,
               (unsigned long)minops * (opt.klen + opt.vlen),
               (unsigned long)maxops * (opt.klen + opt.vlen),
               (unsigned long)(ops * (opt.klen + opt.vlen)) /
               opt.threads,
               (unsigned long)ops * (opt.klen + opt.vlen),
               (unsigned long)tot_time / (1000 * 1000));

        memset(threads, 0, opt.threads * sizeof(*threads));
        tot_opsmin += minops;
        tot_opsmax += maxops;
        tot_opsavg += ops / opt.threads;
    }

    printf("%5s %10ld %10ld %10ld %12ld %10ld %10ld %10ld %12ld %10ld\n",
           "exit",
           (unsigned long)tot_opsmin / cnt,
           (unsigned long)tot_opsmax / cnt,
           (unsigned long)tot_opsavg / cnt,
           (unsigned long)tot_opsavg * opt.threads / cnt,
           (unsigned long)tot_opsmin * (opt.klen + opt.vlen) / cnt,
           (unsigned long)tot_opsmax  * (opt.klen + opt.vlen) / cnt,
           (unsigned long)(tot_opsavg * (opt.klen + opt.vlen)) / cnt,
           (unsigned long)(tot_opsavg * (opt.klen + opt.vlen) *
                           opt.threads) / cnt,
           (unsigned long)tot_time / (1000 * 1000));

    if (!opt.close) {
        for (i = 0; i < kvs_cnt; i++) {
            test_close_kvs(kvs_names[i], kvs_h[i]);
            kvs_h[i] = 0;
        }

        test_close_kvdb();
    }

    free(kvs_h);
    free(kvs_names);
    free(kvs_weight);
    free(kvswt_param);

    if (verbose) {
        struct timeval tv_stop;
        struct rusage rusage;

        gettimeofday(&tv_stop, NULL);

        rc = getrusage(RUSAGE_SELF, &rusage);
        if (rc == 0) {
            long utime, stime, rtime;

            rtime = (tv_stop.tv_sec - tv_start.tv_sec) * 1000000;
            rtime += (tv_stop.tv_usec - tv_start.tv_usec);
            utime = rusage.ru_utime.tv_sec * 1000000
                + rusage.ru_utime.tv_usec;
            stime = rusage.ru_stime.tv_sec * 1000000
                + rusage.ru_stime.tv_usec;

            printf("%s: resource usage:\n"
                   "%12ld  real time (milliseconds)\n"
                   "%12ld  user time (milliseconds)\n"
                   "%12ld  system time (milliseconds)\n"
                   "%12ld  max resident set size (KiB)\n"
                   "%12ld  page reclaims\n"
                   "%12ld  page faults\n"
                   "%12ld  block input operations\n"
                   "%12ld  block output operations\n"
                   "%12ld  voluntary context switches\n"
                   "%12ld  involuntary context switches\n",
                   progname,
                   rtime / 1000,
                   utime / 1000,
                   stime / 1000,
                   rusage.ru_minflt,
                   rusage.ru_majflt,
                   rusage.ru_inblock,
                   rusage.ru_oublock,
                   rusage.ru_nvcsw,
                   rusage.ru_nivcsw,
                   rusage.ru_maxrss);
        }
    }

  done:
    free(threads);
    pg_destroy(pg);
    svec_reset(&hse_gparm);
    svec_reset(&db_oparm);
    svec_reset(&kv_oparm);
    destroy_key_generator(key_gen);

    hse_fini();

    return errors == 0 ? 0 : -1;
}
