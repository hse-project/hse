/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2017-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/time.h>
#include <tools/key_generation.h>
#include <tools/parm_groups.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/util/atomic.h>
#include <hse/util/compiler.h>
#include <hse/util/parse_num.h>

/* Default key/value lengths */
#define KLEN_DEFAULT 23
#define VLEN_DEFAULT 1018

#define KLEN_MAX 1000
#define VLEN_MAX (10 * 1024)

struct opts {
    bool help;
    bool version;
    char *config;
    char *kvdb;
    char *kvs;
    uint64_t keys;
    uint klen;
    uint vlen;
    uint threads;
    uint pfxlen;
    bool unclean;
    bool show_ops;
    bool dryrun;
    bool do_all;
    bool do_put;
    bool do_vput;
    bool do_up;
    bool do_vup;
    bool do_del;
    bool do_vdel;
    bool do_pdel;
    bool do_vpdel;
    bool binary;
    bool do_txn;
    bool ingest;
    uint64_t kstart;
    uint32_t errcnt;
    bool params;
};

#define KEY_SHOWLEN 23
#define VAL_SHOWLEN 35

char *KEY_PREFIX = "K%016lx";
char *VAL_PREFIX = "V%016lx_%016u";

struct opts opt;

struct parm_groups *pg;
struct svec kvs_oparms;

const char *mode = "";
struct timeval tv_start;
int verbose = 0;
atomic_ulong errors;
static bool ingest_mode;
static uint32_t sync_time;

static struct key_generator *key_gen;
static const long key_space_size = 4000000000UL;
static bool single_kvs;

struct hse_kvdb *kvdb;
atomic_long put_cnt;
atomic_long del_cnt;
atomic_long put_verify_cnt;
atomic_long del_verify_cnt;

struct thread_info {
    struct hse_kvdb *kvdb;
    struct hse_kvs *kvs;
    pthread_t tid;
    uint id;

    char *kvs_name;
    bool joined;

    /* reference key */
    void *ref_key;
    size_t ref_klen;

    /* reference value */
    void *ref_val;
    size_t ref_vlen;

    /* buffer for kvdb_get */
    void *get_val;

    void *pfx;
    int pfxlen;
};

static void
syntax(const char *fmt, ...);
static void
quit(const char *fmt, ...);
static void
usage(void);

static void HSE_PRINTF(1, 2)
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
}

static void
syntax(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help.\n", progname, msg);
    exit(EX_USAGE);
}

#define merr_quit(detail, err) \
    quit("%s:%d: %s: %ld", REL_FILE(__FILE__), __LINE__, (detail), (err));

void
announce_header(void)
{
    if (!verbose)
        return;

    printf("*** %8s %7s %7s %7s %8s  %s\n", "TID", "USER", "SYS", "REAL", "MODE", "MESSAGE");
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
        utime = rusage.ru_utime.tv_sec * 1000000 + rusage.ru_utime.tv_usec;
        stime = rusage.ru_stime.tv_sec * 1000000 + rusage.ru_stime.tv_usec;

        printf(
            "*** %8lx %7ld %7ld %7ld %8s  %s\n", pthread_self() & 0xffffffffu, utime / 1000,
            stime / 1000, rtime / 1000, mode, msg);
    }
}

/*----------------------------------------------------------------
 * Command Line Processing
 */

enum opt_enum {
    opt_binary = 'b',
    opt_keys = 'c',
    opt_params = 'C',
    opt_do_del = 'd',
    opt_do_pdel = 'D',
    opt_errcnt = 'e',
    opt_pfxlen = 'f',
    opt_help = 'h',
    opt_ingest = 'I',
    opt_klen = 'l',
    opt_vlen = 'L',
    opt_dryrun = 'n',
    opt_do_put = 'p',
    opt_kstart = 's',
    opt_threads = 't',
    opt_time = 'T',
    opt_do_up = 'u',
    opt_verbose = 'v',
    opt_version = 'V',
    opt_do_txn = 'x',
    opt_config = 'Z',

    opt_unclean,
};

struct option longopts[] = { { "config", required_argument, NULL, opt_config },
                             { "binary", no_argument, NULL, opt_binary },
                             { "keys", required_argument, NULL, opt_keys },
                             { "params", no_argument, NULL, opt_params },
                             { "del", no_argument, NULL, opt_do_del },
                             { "pdel", no_argument, NULL, opt_do_pdel },
                             { "errcnt", required_argument, NULL, opt_errcnt },
                             { "pfxlen", required_argument, NULL, opt_pfxlen },
                             { "help", no_argument, NULL, opt_help },
                             { "ingest", no_argument, NULL, opt_ingest },
                             { "klen", required_argument, NULL, opt_klen },
                             { "vlen", required_argument, NULL, opt_vlen },
                             { "dryrun", no_argument, NULL, opt_dryrun },
                             { "put", no_argument, NULL, opt_do_put },
                             { "kstart", required_argument, NULL, opt_kstart },
                             { "threads", required_argument, NULL, opt_threads },
                             { "time", required_argument, NULL, opt_time },
                             { "up", no_argument, NULL, opt_do_up },
                             { "verbose", optional_argument, NULL, opt_verbose },
                             { "version", no_argument, NULL, opt_version },
                             { "txn", no_argument, NULL, opt_do_txn },
                             { 0, 0, 0, 0 } };

/* A thread-safe version of strerror().
 */
char *
strerror(int errnum)
{
    static thread_local char tls_errbuf[128];

    if (!strerror_r(errnum, tls_errbuf, sizeof(tls_errbuf)))
        snprintf(tls_errbuf, sizeof(tls_errbuf), "error %d", errnum);

    return tls_errbuf;
}

static void
options_default(struct opts *opt)
{
    memset(opt, 0, sizeof(*opt));
    opt->keys = 10;
    opt->threads = 1;
    opt->errcnt = 1;
    opt->klen = KLEN_DEFAULT;
    opt->vlen = VLEN_DEFAULT;
}

#define GET_INT(TYPE, OPTARG, VALUE)                                  \
    do {                                                              \
        if (parse_int(OPTARG, VALUE)) {                               \
            syntax("Unable to parse " #TYPE " number: '%s'", OPTARG); \
        }                                                             \
    } while (0)

#define GET_UINT(TYPE, OPTARG, VALUE)                                 \
    do {                                                              \
        if (parse_uint(OPTARG, VALUE)) {                              \
            syntax("Unable to parse " #TYPE " number: '%s'", OPTARG); \
        }                                                             \
    } while (0)

#define GET_UINT32(TYPE, OPTARG, VALUE)                               \
    do {                                                              \
        if (parse_u32(OPTARG, VALUE)) {                               \
            syntax("Unable to parse " #TYPE " number: '%s'", OPTARG); \
        }                                                             \
    } while (0)

#define GET_UINT64(TYPE, OPTARG, VALUE)                               \
    do {                                                              \
        if (parse_u64(OPTARG, VALUE)) {                               \
            syntax("Unable to parse " #TYPE " number: '%s'", OPTARG); \
        }                                                             \
    } while (0)

#define GET_DOUBLE(OPTARG, VALUE)                           \
    do {                                                    \
        if (1 != sscanf(OPTARG, "%lg", VALUE)) {            \
            syntax("Unable to parse double: '%s'", OPTARG); \
        }                                                   \
    } while (0)

void
options_parse(int argc, char **argv, struct opts *opt)
{
    int done;

    /* Dynamically build optstring from longopts[] for getopt_long_only().
     */
    const size_t optstringsz = (sizeof(longopts) / sizeof(longopts[0])) * 3 + 3;
    char optstring[optstringsz + 1];
    const struct option *longopt;
    char *pc = optstring;

    *pc++ = ':'; /* Disable getopt error messages */

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

        case opt_ingest:
            opt->ingest = true;
            ingest_mode = true;
            break;

        case opt_binary:
            opt->binary = true;
            break;

        case opt_params:
            opt->params = true;
            break;

        case opt_help:
            opt->help = true;
            break;

        case opt_kstart:
            GET_UINT64(uint64_t, optarg, &opt->kstart);
            break;

        case opt_errcnt:
            GET_UINT32(uint32_t, optarg, &opt->errcnt);
            if (opt->errcnt == 0)
                opt->errcnt = (1L << 32) - 1;
            break;

        case opt_verbose:
            if (optarg)
                GET_INT(int, optarg, &verbose);
            else
                ++verbose;
            opt->show_ops = (verbose > 1);
            break;

        case opt_version:
            opt->version = true;
            break;

        case opt_keys:
            GET_UINT64(uint64_t, optarg, &opt->keys);
            break;

        case opt_klen:
            GET_UINT(uint, optarg, &opt->klen);
            break;

        case opt_vlen:
            GET_UINT(uint, optarg, &opt->vlen);
            break;

        case opt_threads:
            GET_UINT(uint, optarg, &opt->threads);
            break;

        case opt_pfxlen:
            GET_UINT(uint, optarg, &opt->pfxlen);
            break;

        case opt_dryrun:
            opt->dryrun = true;
            break;

        case opt_do_put:
            if (ingest_mode)
                opt->do_put = true;
            else
                opt->do_vput = true;
            break;

        case opt_do_up:
            if (ingest_mode) {
                opt->do_up = true;
            } else {
                opt->do_vup = true;
                opt->do_vput = false;
            }
            break;

        case opt_do_del:
            if (ingest_mode) {
                opt->do_del = true;
            } else {
                opt->do_vdel = true;
                opt->do_vup = false;
                opt->do_vput = false;
            }
            break;

        case opt_do_pdel:
            if (ingest_mode) {
                opt->do_pdel = true;
            } else {
                opt->do_vpdel = true;
                opt->do_vdel = false;
                opt->do_vup = false;
                opt->do_vput = false;
            }
            break;

        case opt_do_txn:
            opt->do_txn = true;
            break;

        case ':':
            syntax("missing argument for option '%s'", argv[curind]);
            break;

        case '?':
            syntax("invalid option '%s'", argv[optind - 1]);
            break;

        case opt_time:
            GET_UINT(uint, optarg, &sync_time);
            break;

        default:
            if (c == 0) {
                if (!longopt[longidx].flag) {
                    syntax("unhandled option '--%s'", longopts[longidx].name);
                }
            } else {
                syntax("unhandled option '%s'", argv[curind]);
            }
            break;
        }
    }

    if (opt->do_del && opt->do_pdel)
        opt->do_del = false;

    if (ingest_mode && !opt->do_put && !opt->do_up && !opt->do_del)
        opt->do_all = true;

    if (!ingest_mode && !opt->do_vput && !opt->do_vup && !opt->do_vdel && !opt->do_vpdel)
        opt->do_vdel = true;

    /* Below are few restrictions in the tool while running in
     * transaction mode and/or doing prefix deletes.
     * These restrictions will be removed in a future update.
     */
    if (opt->do_txn && opt->threads > 1)
        opt->binary = true;

    if (opt->do_pdel || opt->do_vpdel) {
        if (opt->pfxlen == 0) {
            printf("pfxlen param is required for prefix del\n");
            usage();
            exit(0);
        }

        opt->klen = opt->pfxlen;
        opt->binary = false;
        if (opt->threads > 1)
            opt->do_txn = false;
    }

    if (opt->help)
        usage();
}

static void
usage(void)
{
    printf("usage: %s [options] <kvdb_home> <kvslist> [param=value]\n", progname);
    printf("Key/value count and format:\n"
           "  -b, --binary         generate binary keys and values\n"
           "  -c, --keys COUNT     put/get COUNT keys\n"
           "  -C, --params         list tunable params (config vars)\n"
           "  -d, --del            delete keys\n"
           "  -D, --pdel           prefix delete keys\n"
           "  -e, --errcnt N       stop verify after N errors, 0=infinite\n"
           "  -f, --pfxlen         prefix len\n"
           "  -h, --help           print this help list\n"
           "  -l, --klen LEN       keys are LEN bytes\n"
           "  -L, --vlen LEN       values are LEN bytes\n"
           "  -n, --dryrun         show operations w/o executing them\n"
           "  -p, --put            put keys\n"
           "  -s, --kstart         starting index of keys, default=0\n"
           "  -t, --threads        number of threads\n"
           "  -T, --Time seconds   c1 flush time in ms\n"
           "  -u, --up             update keys\n"
           "  -v, --verbose=LVL    increase[or set] verbosity\n"
           "  -V, --version        print build version\n"
           "  -x, --txn            do transaction tests\n"
           "  -Z, --config CONFIG  path to global config file\n"
           "\n");

    if (!verbose) {
        printf("Give -hv for more detail.\n\n");
        return;
    }

    printf("Mandatory parameters:\n"
           "  <kvdb_home>\n"
           "  <kvslist> -- A kvs name, a comma or colon separated list\n"
           "      of kvs names, a format string with a %%d conversion\n"
           "      specifier that will be replaced with the logical\n"
           "      thread ID, or any combination thereof.  The list is\n"
           "      iterated over from left to right in round-robin\n"
           "      fashion as each thread is created.\n"
           "\n");
}

static void HSE_PRINTF(1, 2)
add_error(const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    atomic_inc(&errors);

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (*msg)
        fprintf(stderr, "%s: %s\n", progname, msg);
}

void
test_kvdb_open(void)
{
    struct svec sv = {};
    hse_err_t rc;

    if (opt.dryrun) {
        kvdb = (void *)1;
        return;
    }

    if (verbose)
        printf("T%u: hse_kvdb_open %s\n", 0, opt.kvdb);

    rc = svec_append_pg(&sv, pg, PG_KVDB_OPEN, NULL);
    if (rc)
        quit("svec_append_pg: rc %d", (int)rc);

    rc = hse_kvdb_open(opt.kvdb, sv.strc, sv.strv, &kvdb);
    if (rc)
        merr_quit("hse_kvdb_open failed", rc);

    svec_reset(&sv);
}

void
test_kvs_open(struct thread_info *ti, char *message)
{
    hse_err_t err;

    if (opt.dryrun) {
        ti->kvs = (void *)1;
        return;
    }

    err = hse_kvdb_kvs_open(kvdb, ti->kvs_name, kvs_oparms.strc, kvs_oparms.strv, &ti->kvs);
    if (err)
        merr_quit("hse_kvdb_kvs_open failed", err);

    assert(ti->kvs);
}

void
test_start_phase(struct thread_info *ti, char *message)
{
    hse_err_t err;

    if (verbose)
        printf("T%u: %s\n", ti->id, message);

    memset(ti->ref_key, 0, KLEN_MAX);
    memset(ti->ref_val, 0, VLEN_MAX);
    memset(ti->get_val, 0, VLEN_MAX);

    assert(kvdb);

    if (!ti->kvs) {
        ti->kvdb = kvdb;
        if (verbose)
            printf("T%u: hse_kvdb_kvs_open %s\n", ti->id, ti->kvs_name);
        if (!opt.dryrun) {
            err = hse_kvdb_kvs_open(kvdb, ti->kvs_name, kvs_oparms.strc, kvs_oparms.strv, &ti->kvs);
            if (err)
                merr_quit("hse_kvdb_kvs_open failed", err);
        } else {
            ti->kvs = (void *)1;
        }
        assert(ti->kvs);
    }
}

void
test_end_phase(struct thread_info *ti, bool final)
{
}

void
fmt_string(char *str, int len, int max_len, char fill, char *fmt, uint64_t fmt_arg1, int fmt_arg2)
{
    int i;

    if (len > max_len)
        quit("key or value too large: %u (limit is %u)", len, max_len);

    snprintf(str, len, fmt, fmt_arg1, fmt_arg2);
    i = strlen(str);
    while (i + 1 < len)
        str[i++] = fill;
    str[i] = '\0';
}

void
fmt_key(struct thread_info *ti, int len, unsigned long num)
{
    static atomic_int u;
    unsigned char *str = ti->ref_key;

    if (len < 3) {
        memcpy(str, "BAD", len);
        return;
    }

    if (key_gen) {
        get_key(key_gen, str, num);
        str[len - 1] = 0;
    } else {
        uint32_t v;

        v = atomic_inc_return(&u);
        *(uint32_t *)str = v;
        for (len -= 4, str += 4; len > 0; --len)
            *str++ = v & 255;
    }

    if (ti->pfxlen && ti->pfxlen < len)
        memcpy(ti->ref_key, ti->pfx, ti->pfxlen);
}

int key_showlen;
int val_showlen;

void
set_kv(struct thread_info *ti, uint64_t keynum, uint salt)
{
    if (opt.binary) {
        uint64_t *pdata = (uint64_t *)ti->ref_val;
        uint32_t *data = (uint32_t *)ti->ref_key;
        int idx;

        /* Each binary key/value is a function of the previous
         * key/value.
         */
        /*idx = keynum % (KLEN_MAX / sizeof(*data) - 32);*/
        idx = keynum % 8;
        ti->ref_klen = (idx + 1) * sizeof(*data);
        data[idx] = keynum + strtol(ti->kvs_name, NULL, 36);

        /*idx = keynum % (VLEN_MAX / 8 / sizeof(*pdata));*/
        idx = keynum % 32;
        ti->ref_vlen = (idx + 1) * sizeof(*pdata);
        pdata[idx] = keynum + salt + strtol(ti->kvs_name, NULL, 36);

        *(uint64_t *)ti->get_val = 0xdeadbeefabadcafe;

        return;
    }

    fmt_key(ti, opt.klen, keynum);

    if (opt.vlen > 0)
        fmt_string(ti->ref_val, opt.vlen, VLEN_MAX, '*', VAL_PREFIX, keynum, salt);

    ti->ref_klen = opt.klen;
    ti->ref_vlen = opt.vlen;

    key_showlen = ti->ref_klen;
    val_showlen = ti->ref_vlen;

    if (key_showlen > KEY_SHOWLEN)
        key_showlen = KEY_SHOWLEN;
    if (val_showlen > VAL_SHOWLEN)
        val_showlen = VAL_SHOWLEN;

    /*
     * ti->get is the buffer for 'hse_kvs_get' results. Initialize it to
     * something that will not match a key, and set vt_plen to the
     * size of the buffer it points to.
     */
    sprintf(ti->get_val, "**UNINITIALIZED_BUFFER**");
}

void
test_put(struct thread_info *ti, uint salt, bool istxn)
{
    hse_err_t err;
    uint64_t i, last_key;

    struct hse_kvdb_txn *txn = NULL;

    test_start_phase(ti, salt ? "Update existing keys" : "Insert new keys");

    if (istxn)
        txn = hse_kvdb_txn_alloc(ti->kvdb);

    last_key = opt.kstart + opt.keys;
    for (i = opt.kstart; i < last_key; i++) {
        char *txkey = 0;
        uint *txkeyp = 0, nkeys = 0;

        set_kv(ti, i, salt);
        if (opt.show_ops) {
            printf(
                "T%u: PUT(%lu,%u): key[%zu]=%.*s..."
                " val[%zu]=%.*s...\n",
                ti->id, i, salt, ti->ref_klen, key_showlen, (char *)ti->ref_key, ti->ref_vlen,
                val_showlen, (char *)ti->ref_val);
        }

        if (opt.dryrun)
            continue;

        if (istxn)
            hse_kvdb_txn_begin(ti->kvdb, txn);

        err = hse_kvs_put(
            ti->kvs, 0, txn, (char *)ti->ref_key, ti->ref_klen, (char *)ti->ref_val, ti->ref_vlen);
        if (err)
            merr_quit("kvdb_put failed", err);

        atomic_inc(&put_cnt);

        /* If txn mode, PUT two more keys. */
        while (istxn && nkeys++ < 2) {
            if (nkeys == 1) {
                txkey = calloc(1, ti->ref_klen);
                if (!txkey)
                    merr_quit("Tx calloc failed", merr(ENOMEM));
                memcpy(txkey, (char *)ti->ref_key, ti->ref_klen);
                txkeyp = (uint *)txkey;
            }

            *txkeyp ^= (nkeys == 1) ? 9973 : 6991;

            err = hse_kvs_put(
                ti->kvs, 0, txn, (char *)txkey, ti->ref_klen, (char *)ti->ref_val, ti->ref_vlen);
            if (err)
                merr_quit("kvdb_put failed", err);

            atomic_inc(&put_cnt);
        }

        if (istxn)
            hse_kvdb_txn_commit(ti->kvdb, txn);
    }

    test_end_phase(ti, false);
}

void
test_delete(struct thread_info *ti, bool prefix, bool istxn)
{
    hse_err_t err;
    uint64_t i, last_key;
    uint salt = -1; /* not important for delete */

    struct hse_kvdb_txn *txn = NULL;

    test_start_phase(ti, prefix ? "Prefix delete keys" : "Delete keys");

    if (istxn)
        txn = hse_kvdb_txn_alloc(ti->kvdb);

    last_key = opt.kstart + opt.keys;
    for (i = opt.kstart; i < last_key; i++) {
        set_kv(ti, i, salt);
        if (opt.show_ops)
            printf(
                "T%u: DEL(%lu,NA): key[%zu]=%.*s...\n", ti->id, i, ti->ref_klen, key_showlen,
                (char *)ti->ref_key);

        if (opt.dryrun)
            continue;

        if (istxn)
            hse_kvdb_txn_begin(ti->kvdb, txn);

        if (!prefix) {
            err = hse_kvs_delete(ti->kvs, 0, txn, (char *)ti->ref_key, ti->ref_klen);
            if (err)
                merr_quit("kvs_del failed", err);
        } else {
            err = hse_kvs_prefix_delete(ti->kvs, 0, txn, (char *)ti->ref_key, ti->ref_klen);
            if (err)
                merr_quit("kvs_prefix_del failed", err);
        }

        atomic_inc(&del_cnt);

        if (istxn)
            hse_kvdb_txn_commit(ti->kvdb, txn);
    }

    test_end_phase(ti, false);
}

void
test_put_verify(struct thread_info *ti, uint salt, bool istxn)
{
    uint64_t i, last_key;
    size_t get_vlen;
    void *get_val = ti->get_val;

    test_start_phase(ti, salt ? "Verify updated keys" : "Verify inserted keys");

    last_key = opt.kstart + opt.keys;
    for (i = opt.kstart; i < last_key; i++) {
        hse_err_t err;
        bool found = false;
        bool found_err = false;
        uint *txkeyp = NULL, nkeys = 0;
        char *txkey = NULL;
        const char *key;

        if (atomic_read(&errors) >= opt.errcnt)
            break;

        key = (char *)ti->ref_key;

        set_kv(ti, i, salt);

        if (opt.show_ops)
            printf(
                "T%u: VERIFY_PUT(%lu,%d): key[%zu]=%.*s...\n", ti->id, i, salt, ti->ref_klen,
                key_showlen, key);

        if (opt.dryrun)
            continue;

        get_vlen = (size_t)-1;
        err = hse_kvs_get(
            ti->kvs, 0, NULL, ti->ref_key, ti->ref_klen, &found, get_val, VLEN_MAX, &get_vlen);
        if (err)
            merr_quit("hse_kvs_get failed", err);

        if (!found) {
            add_error(
                "key not found: tid %d "
                "key#%lu[%zu]=%.*s...",
                ti->id, i, ti->ref_klen, key_showlen, key);
            if (istxn) {
                found_err = true;
                goto txn_atomic;
            }
            continue;
        }

        if (get_vlen != ti->ref_vlen) {
            add_error(
                "vput: key found, but value has wrong length:"
                " key#%lu[%zu]=%.*s..."
                " expected len=%zu got %zu",
                i, ti->ref_klen, key_showlen, key, ti->ref_vlen, get_vlen);
            continue;
        }

        if (opt.show_ops)
            printf(
                "T%u: VERIFY_PUT(%lu,%d): val[%zu]=%.*s...\n", ti->id, i, salt, get_vlen,
                val_showlen, (char *)get_val);

        if (ti->ref_vlen > 0 && memcmp(get_val, ti->ref_val, ti->ref_vlen)) {
            add_error(
                "vput: key found, but value wrong:"
                " kvs %s: key#%lu[%zu]=%.*s..."
                " val[%zu]=%.*s..."
                " expected %.*s",
                ti->kvs_name, i, ti->ref_klen, key_showlen, key, ti->ref_vlen, val_showlen,
                (char *)ti->ref_val, val_showlen, (char *)get_val);
        }

    txn_atomic:
        while (istxn && nkeys++ < 2) {
            if (nkeys == 1) {
                txkey = calloc(1, ti->ref_klen);
                if (!txkey)
                    merr_quit("Tx alloc failed", merr(ENOMEM));
                memcpy(txkey, ti->ref_key, ti->ref_klen);
                txkeyp = (uint *)txkey;
            }

            *txkeyp ^= (nkeys == 1) ? 9973 : 6991;
            get_vlen = (size_t)-1;

            err = hse_kvs_get(
                ti->kvs, 0, NULL, txkey, ti->ref_klen, &found, get_val, VLEN_MAX, &get_vlen);
            if (err) {
                free(txkey);
                merr_quit("hse_kvs_get failed", err);
            }

            if (!found && !found_err)
                add_error(
                    "Tx atomicity bug, key%d not found: "
                    "key#%lu[%zu]=%.*s...",
                    nkeys, i, ti->ref_klen, key_showlen, txkey);

            if (found && found_err)
                add_error(
                    "Tx atomicity bug, key%d found: "
                    "key#%lu[%zu]=%.*s...",
                    nkeys, i, ti->ref_klen, key_showlen, txkey);

            if (nkeys == 2) {
                free(txkey);
                atomic_add(&put_verify_cnt, nkeys);
            }
        }
    }
    atomic_add(&put_verify_cnt, i - atomic_read(&errors));

    test_end_phase(ti, false);
}

void
test_delete_verify(struct thread_info *ti)
{
    uint64_t i, last_key;
    uint salt = -1; /* not important for delete */
    size_t get_vlen;
    void *get_val = ti->get_val;

    test_start_phase(ti, "Verify deleted keys");

    memset(ti->ref_key, 0, KLEN_MAX);
    memset(ti->ref_val, 0, VLEN_MAX);

    last_key = opt.kstart + opt.keys;
    for (i = opt.kstart; i < last_key; i++) {

        hse_err_t err;
        bool found = false;

        if (atomic_read(&errors) >= opt.errcnt)
            break;

        set_kv(ti, i, salt);
        if (opt.show_ops)
            printf(
                "T%u: VERIFY_DEL(%lu,NA): key[%zu]=%.*s...\n", ti->id, i, ti->ref_klen, key_showlen,
                (char *)ti->ref_key);
        if (opt.dryrun)
            continue;

        err = hse_kvs_get(
            ti->kvs, 0, NULL, ti->ref_key, ti->ref_klen, &found, get_val, VLEN_MAX, &get_vlen);
        if (err)
            merr_quit("hse_kvs_get failed", err);

        if (found) {
            add_error(
                "found key after it was deleted:"
                "key#%lu[%zu]=%.*s...",
                i, ti->ref_klen, key_showlen, (char *)ti->ref_key);
        }
    }

    atomic_add(&del_verify_cnt, i - atomic_read(&errors));

    test_end_phase(ti, false);
}

void *
thread_main(void *arg)
{
    struct thread_info *ti = arg;
    uint salt;

    salt = 0;

    if (opt.do_all || opt.do_put)
        test_put(ti, salt, opt.do_txn);

    if (atomic_read(&errors) < opt.errcnt && opt.do_vput)
        test_put_verify(ti, salt, opt.do_txn);

    salt = 1;

    if (atomic_read(&errors) < opt.errcnt && (opt.do_all || opt.do_up))
        test_put(ti, salt, opt.do_txn);

    if (atomic_read(&errors) < opt.errcnt && opt.do_vup)
        test_put_verify(ti, salt, opt.do_txn);

    if (atomic_read(&errors) < opt.errcnt && (opt.do_all || opt.do_del))
        test_delete(ti, false, opt.do_txn);
    if (atomic_read(&errors) < opt.errcnt && opt.do_vdel)
        test_delete_verify(ti);

    if (atomic_read(&errors) < opt.errcnt && opt.do_pdel)
        test_delete(ti, true, opt.do_txn);

    if (atomic_read(&errors) < opt.errcnt && opt.do_vpdel)
        test_delete_verify(ti);

    test_end_phase(ti, true);

    return NULL;
}

void
print_result(void)
{
    if (atomic_read(&put_cnt))
        printf("waltest : No. of successful puts %ld\n", atomic_read(&put_cnt));

    if (atomic_read(&put_verify_cnt))
        printf("waltest : No. of successful verified puts %ld\n", atomic_read(&put_verify_cnt));

    if (atomic_read(&del_cnt))
        printf("waltest : No. of successful deletes %ld\n", atomic_read(&del_cnt));

    if (atomic_read(&del_verify_cnt))
        printf("waltest : No. of successful verified deletes %ld\n", atomic_read(&del_verify_cnt));

    if (atomic_read(&errors) >= opt.errcnt)
        quit("Exiting, because %lu error(s) were encountered\n", atomic_read(&errors));

    announce("Successful");
}

int
waltest_run(int argc, char **argv)
{
    struct thread_info *threads = NULL;
    struct thread_info *ti;
    char *pctx; /* parse context */
    char *cp;   /* generic char ptr */
    uint kvsc;
    int rc;
    uint i;

    gettimeofday(&tv_start, NULL);

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    if (!opt.keys)
        syntax("number of keys must be > 0");

    /* pgd expects null-terminated strings, thus klen-1 */
    key_gen = create_key_generator(key_space_size, opt.klen - 1);
    if (!key_gen && opt.klen < 8)
        key_gen = create_key_generator(key_space_size / 100, opt.klen - 1);

    if (opt.threads == 0)
        opt.threads = 1;

    threads = calloc(opt.threads, sizeof(*threads));
    if (!threads)
        quit("unable to calloc %zu bytes for thread_info", opt.threads * sizeof(*threads));

    /* Figure each thread's kvs name and kvs prefix.
     * Example input with 5 threads:
     *   "AA/foo_%d,ABC/bar_%d,dog_%d"
     * Resulting kvs names and prefixes:
     *	foo_0, pfx AA
     *	bar_1, pfx ABC
     *	dog_2, no pfx
     *	foo_3, pfx AA
     *	bar_2, pfx ABC
     * First loop computes format strings, second loop
     * converts them to kvs names.
     */
    pctx = opt.kvs;
    kvsc = 0;
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        do {
            cp = strsep(&pctx, ":,; \t\r\n");
        } while (cp && !*cp);
        if (cp) {
            kvsc++;
            ti->kvs_name = cp;
            cp = strchr(ti->kvs_name, '/');
            if (cp) {
                if (cp[1] == 0)
                    quit("prefix missing kvs: %s", ti->kvs_name);
                *cp++ = 0;
                ti->pfx = ti->kvs_name;
                ti->pfxlen = strlen(ti->pfx);
                ti->kvs_name = cp;
            } else {
                ti->pfx = 0;
                ti->pfxlen = 0;
            }
        } else {
            /* use kvs name and prefix from thread i % kvsc */
            if (kvsc == 0)
                quit("Invalid kvs name: %s", opt.kvs);
            assert(i >= kvsc);
            ti->kvs_name = threads[i % kvsc].kvs_name;
            ti->pfx = threads[i % kvsc].pfx;
            ti->pfxlen = threads[i % kvsc].pfxlen;
        }
    }

    if ((kvsc == 1) && (opt.threads > 1)) {
        single_kvs = true;
        opt.keys /= opt.threads;
    }

    /* Convert format strings to kvs names */
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        int n;

        cp = ti->kvs_name;
        ti->kvs_name = 0;

        n = asprintf(&ti->kvs_name, cp, i);
        if (n <= 0)
            quit("cannot format kvs name: '%s'", cp);

        /* Ensure that no two threads are given the same kvs name. */
        for (n = 0; !single_kvs && n < i; n++)
            if (!strcmp(ti->kvs_name, threads[n].kvs_name))
                quit(
                    "no two threads may work"
                    " on the same kvs: %s",
                    ti->kvs_name);
    }

    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        ti->id = i;
        ti->ref_key = malloc(KLEN_MAX);
        ti->get_val = malloc(VLEN_MAX);
        ti->ref_val = malloc(VLEN_MAX);
        if (!ti->ref_key || !ti->get_val || !ti->ref_val)
            quit("Out of memory");
    }

    /*open kvdb */
    test_kvdb_open();

    if (single_kvs) {

        ti = threads;

        /*open the only kvs */
        test_kvs_open(ti, "Single kvset init");

        for (i = 1; i < opt.threads; i++) {
            ti++;
            ti->kvs = threads->kvs;
            ti->kvdb = threads->kvdb;
        }
    }

    announce_header();

    /* Start the threads */
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
        rc = pthread_create(&ti->tid, NULL, thread_main, ti);
        if (rc) {
            printf("%s: pthread_create failed: %s\n", progname, strerror(rc));
            ti->joined = true;
            continue;
        }

        if (verbose > 1)
            printf("created thread %lu (%d)\n", ti->tid, ti->id);
    }

    /* If running as root, bump priority to help run-to-run consistency. */
    setpriority(PRIO_PROCESS, 0, -15);

    /* Reap all the threads. */
    for (i = 0, ti = threads; i < opt.threads; i++, ti++) {

        if (ti->joined)
            continue;

        rc = pthread_join(ti->tid, NULL);
        if (rc && rc != EINVAL && rc != ESRCH) {
            printf("%s: pthread_join failed: %s\n", progname, strerror(rc));
            continue;
        }

        if (verbose > 1)
            printf("joined thread %lu\n", ti->tid);
        ti->joined = true;
    }

    print_result();

    if (verbose) {
        struct timeval tv_stop;
        struct rusage rusage;

        gettimeofday(&tv_stop, NULL);

        rc = getrusage(RUSAGE_SELF, &rusage);
        if (rc == 0) {
            long utime, stime, rtime;

            rtime = (tv_stop.tv_sec - tv_start.tv_sec) * 1000000;
            rtime += (tv_stop.tv_usec - tv_start.tv_usec);
            utime = rusage.ru_utime.tv_sec * 1000000 + rusage.ru_utime.tv_usec;
            stime = rusage.ru_stime.tv_sec * 1000000 + rusage.ru_stime.tv_usec;

            printf(
                "%s: resource usage:\n"
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
                progname, rtime / 1000, utime / 1000, stime / 1000, rusage.ru_minflt,
                rusage.ru_majflt, rusage.ru_inblock, rusage.ru_oublock, rusage.ru_nvcsw,
                rusage.ru_nivcsw, rusage.ru_maxrss);
        }
    }

    if (threads) {
        for (i = 0; i < opt.threads; i++) {
            free(threads[i].kvs_name);
            free(threads[i].ref_key);
            free(threads[i].ref_val);
            free(threads[i].get_val);
        }
        free(threads);
    }

    destroy_key_generator(key_gen);

    return atomic_read(&errors) == 0 ? 0 : -1;
}

int
waltest_parse(int argc, char **argv)
{
    int rc;

    rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
    if (rc)
        quit("pg_create");

    options_default(&opt);
    options_parse(argc, argv, &opt);

    if (opt.help || opt.params) {
        pg_destroy(pg);
        exit(0);
    }

    /* You can perform non-txn reads on a txn kvs */
    if (opt.do_txn) {
        rc = svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, "transactions.enabled=true", NULL);
        if (rc)
            quit("svec_append_pg failed: %d", rc);
    } else {
        rc = svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
        if (rc)
            quit("svec_append_pg failed: %d", rc);
    }

    opt.kvdb = argv[optind++];
    opt.kvs = argv[optind++];

    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
    case 0:
        if (optind < argc)
            quit("unknown parameter: %s", argv[optind]);
        break;

    case EINVAL:
        quit("missing group name (e.g. %s) before parameter %s\n", PG_KVDB_OPEN, argv[optind]);
        break;

    default:
        quit("error processing parameter %s\n", argv[optind]);
        break;
    }

    if (!opt.keys)
        syntax("number of keys must be > 0");

    return 0;
}

int
main(int argc, char **argv)
{
    hse_err_t err;

    progname_set(argv[0]);

    ingest_mode = false;
    err = waltest_parse(argc, argv);
    if (err)
        return err;

    err = hse_init(opt.config, 0, NULL);
    if (err)
        return err;

    if (!ingest_mode)
        printf("Running in replay mode\n");
    else
        printf("Running in ingest mode, %s\n", opt.do_txn ? "Tx" : "non-Tx");

    if (ingest_mode) {
        err = waltest_run(argc, argv);
        if (!err) {
            printf(
                "Ingest is over, waiting for %u ms "
                "to abort\n",
                sync_time);
            usleep(sync_time * 1000);
        }

        printf("Aborting process (err=%lx) ...\n", err);

        kill(getpid(), 9);
        _exit(1);
    }

    err = waltest_run(argc, argv);

    hse_kvdb_close(kvdb);

    pg_destroy(pg);
    svec_reset(&kvs_oparms);

    hse_fini();

    return err;
}
