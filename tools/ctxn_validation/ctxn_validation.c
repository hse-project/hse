/*
 * Copyright (C) 2015-2019,2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sysexits.h>
#include <signal.h>

#include <hse/hse.h>
#include <xoroshiro/xoroshiro.h>

#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>
#include <hse_util/minmax.h>
#include <hse_util/hse_params_helper.h>
#include <hse_util/timing.h>

const char *progname, *mp_name, *kvs_name;
sig_atomic_t done;
ulong       secmax = 0;
ulong       itermax = 1;
ulong       jobsmax = 1;
ulong       keymax = 1;
bool        keybase_random = true;
const char *keybase_fmt = "k%lx";
ulong       keybase = 0;
bool        reusetxn = false;
int         verbosity;
ulong       perfmode = 0;
bool        commit = true;
bool        mode_put = true;
bool        mixed_sz = false;
uint        seed;
int         cpustart = -1;
int         cpuskip = 1;

struct hse_kvdb    *kvdb;
struct hse_kvs     *kvs;
struct hse_params  *params;

ulong           viter;

struct stats {
    ulong       puts_c0;
    ulong       gets_c0;
    ulong       puts_txn;
    ulong       gets_txn;
    ulong       puts_fail;
    ulong       begin_fail;
    ulong       commits;
    ulong       aborts;
    ulong       topen;
    ulong       tstart;
    ulong       tstop;
    ulong       tclose;
} stats;

struct tdargs;
typedef void spawn_cb_t(struct tdargs *);

struct tdargs {
    pthread_t               tid;
    ulong                   tidx;
    spawn_cb_t             *func;
    ulong                   keybase;
    ulong                   viter;
    struct hse_kvdb_txn    *txn;
    pthread_barrier_t      *barriers;
    cpu_set_t               cpuset;
    struct stats            stats;
} HSE_ALIGNED(128);

static void ctxn_validation_fini(void);

static thread_local uint64_t xrand_state[2];

static void
xrand_init(uint64_t seed)
{
    xoroshiro128plus_init(xrand_state, seed);
}

static uint64_t
xrand(void)
{
    return xoroshiro128plus(xrand_state);
}

__attribute__((format(printf, 1, 2)))
static void
eprint(const char *fmt, ...)
{
    char        msg[256];
    va_list     ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s", progname, msg);
}

__attribute__((format(printf, 1, 2)))
void
syntax(const char *fmt, ...)
{
    char        msg[256];
    va_list     ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

__attribute__((format(printf, 2, 3), __noreturn__))
void
fatal(uint64_t err, const char *fmt, ...)
{
    char        msg[128], errbuf[300];
    va_list     ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    hse_err_to_string(err, errbuf, sizeof(errbuf), 0);
    fprintf(stderr, "%s: %s: %s\n", progname, msg, errbuf);

    exit(1);
}

void
ctxn_validation_init(void)
{
    uint64_t    rc;

    rc = hse_kvdb_open(mp_name, params, &kvdb);
    if (rc)
        fatal(rc, "hse_kvdb_open(%s)", mp_name);

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, params, &kvs);
    if (rc)
        fatal(rc, "hse_kvdb_kvs_open(%s)", kvs_name);
}

void
ctxn_validation_fini(void)
{
    char        errbuf[300];
    u64         rc;

    if (!kvdb)
        return;

    rc = hse_kvdb_close(kvdb);
    if (rc)
        eprint("hse_kvdb_close: %s\n",
               hse_err_to_string(rc, errbuf, sizeof(errbuf), 0));

    kvdb = NULL;
}

void
ctxn_validation_init_c0(void)
{
    int         i;
    u64         rc;
    size_t      klen;
    char        key[1024];
    struct hse_kvdb_opspec  os;

    HSE_KVDB_OPSPEC_INIT(&os);

    if (keybase_random)
        keybase = xrand();

    os.kop_txn = hse_kvdb_txn_alloc(kvdb);
    if (!os.kop_txn)
        fatal(rc, "hse_kvdb_txn_alloc");

    rc = hse_kvdb_txn_begin(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    /* First, load c0 with a bunch of unique k/v tuples (each key
     * and value are unique).
     */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt, keybase + i);

        ++viter;
        rc = hse_kvs_put(kvs, &os, key, klen, &viter, sizeof(viter));
        if (rc)
            fatal(rc, "kvdb_put c0");

        ++stats.puts_c0;
    }

    rc = hse_kvdb_txn_commit(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_commit");

    hse_kvdb_txn_free(kvdb, os.kop_txn);
}

void *
basic_collision_main(void *arg)
{
    struct tdargs          *tdargs = arg;
    struct hse_kvdb_txn    *txn = tdargs->txn;
    pthread_barrier_t      *barriers = tdargs->barriers;
    struct stats           *stats = &tdargs->stats;
    struct hse_kvdb_opspec  os;
    int                     i;
    u64                     rc;
    size_t                  klen;
    char                    key[256];
    u32                     vtxn;

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn;
    os.kop_flags = 0;

    rc = hse_kvdb_txn_begin(kvdb, txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    pthread_barrier_wait(&barriers[0]);

    /* All these puts must fail because of txn0's puts */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt, keybase + i);

        rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
        if (!rc)
            fatal(EINVAL, "hse_kvs_put 1");

        ++stats->puts_fail;
    }

    pthread_barrier_wait(&barriers[1]);
    pthread_barrier_wait(&barriers[2]);

    /* All these puts must still fail because other transactions that were
     * active at txn0's commit are still active.
     */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt, keybase + i);

        rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
        if (!rc)
            fatal(EINVAL, "hse_kvs_put 2");

        ++stats->puts_fail;
    }

    pthread_barrier_wait(&barriers[3]);

    if (xrand() % 10 < 8) {
        rc = hse_kvdb_txn_commit(kvdb, txn);
        if (rc)
            fatal(rc, "hse_kvdb_txn_commit");
        ++stats->commits;
    } else {
        rc = hse_kvdb_txn_abort(kvdb, txn);
        if (rc)
            fatal(rc, "hse_kvdb_txn_abort");
        ++stats->aborts;
    }

    return NULL;
}

void
ctxn_validation_basic_collision(void)
{
    struct hse_kvdb_txn    *txn[jobsmax];
    struct tdargs          *tdargsv;
    pthread_barrier_t       barriers[4];
    struct hse_kvdb_opspec  os;
    int                     i;
    u64                     rc;
    size_t                  klen;
    char                    key[64];
    u32                     vtxn;

    tdargsv = aligned_alloc(alignof(*tdargsv), sizeof(*tdargsv) * jobsmax);
    if (!tdargsv)
        abort();

    memset(tdargsv, 0, sizeof(*tdargsv) * jobsmax);

    if (keybase_random)
        keybase = xrand();

    keymax = 200;

    for (i = 0; i < jobsmax; i++) {
        txn[i] = hse_kvdb_txn_alloc(kvdb);
        if (!txn[i])
            fatal(ENOMEM, "hse_kvdb_txn_alloc");
    }

    for (i = 0; i < 4; i++)
        pthread_barrier_init(&barriers[i], NULL, jobsmax);

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn[0];
    os.kop_flags = 0;

    rc = hse_kvdb_txn_begin(kvdb, txn[0]);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    /* Load txn0 with a set of key-value pairs. */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt, keybase + i);

        vtxn = ++viter;
        rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
        if (rc)
            fatal(rc, "hse_kvs_put 3");

        ++stats.puts_txn;
    }

    for (i = 0; i < jobsmax - 1; i++) {
        struct tdargs *args = tdargsv + i;

        args->txn = txn[i + 1];
        args->barriers = barriers;

        rc = pthread_create(&args->tid, 0, basic_collision_main, args);
        if (rc)
            fatal(rc, "pthread_create");
    }

    pthread_barrier_wait(&barriers[0]);
    pthread_barrier_wait(&barriers[1]);

    /* Commit txn0, the keys must remain locked until all others finish. */
    rc = hse_kvdb_txn_commit(kvdb, txn[0]);
    if (rc)
        fatal(rc, "hse_kvdb_txn_commit");

    ++stats.commits;

    pthread_barrier_wait(&barriers[2]);
    pthread_barrier_wait(&barriers[3]);

    for (i = 0; i < jobsmax - 1; i++) {
        struct tdargs  *args = tdargsv + i;

        rc = pthread_join(args->tid, NULL);
        if (rc)
            fatal(rc, "pthread_join");

        stats.puts_fail += args->stats.puts_fail;
        stats.commits += args->stats.commits;
        stats.aborts += args->stats.aborts;
    }

    /* Begin a new transaction, its puts should go through */
    rc = hse_kvdb_txn_begin(kvdb, txn[1]);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn[1];
    os.kop_flags = 0;

    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt, keybase + i);

        vtxn = ++viter;
        rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
        if (rc)
            fatal(rc, "kvdb_put");

        ++stats.puts_txn;
    }

    hse_kvdb_txn_abort(kvdb, txn[1]);

    for (i = 0; i < jobsmax; i++)
        hse_kvdb_txn_free(kvdb, txn[i]);

    free(tdargsv);
}

void
ctxn_validation_perf(
    struct tdargs *tdargs)
{
    struct stats           *stats = &tdargs->stats;
    struct hse_kvdb_opspec  os;
    struct hse_kvdb_txn    *txn;
    int                     i;
    u64                     rc;
    u64                     vtxn = 0;
    size_t                  klen;
    char                    key[1024];
    size_t                  vtxnlen;
    bool                    found;

    txn = tdargs->txn;
    if (!txn) {
        txn = hse_kvdb_txn_alloc(kvdb);
        if (!txn)
            fatal(ENOMEM, "hse_kvdb_txn_alloc");
        tdargs->txn = txn;
    }

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn;
    os.kop_flags = 0;

    rc = hse_kvdb_txn_begin(kvdb, txn);
    if (rc) {
        ++stats->begin_fail;
        if (hse_err_to_errno(rc) == ENOMEM) {
            usleep(333 * 1000);
            return;
        }
        fatal(rc, "hse_kvdb_txn_begin");
    }

    if (mode_put) {
        tdargs->keybase = keybase;
        if (keybase_random)
            tdargs->keybase = xrand();
        tdargs->keybase &= 0xffff;
        tdargs->keybase |= (tdargs->tidx << 48);
    } else {
        /* Initialized during the c0 puts. */
        tdargs->keybase = keybase;
    }

    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt,
                        tdargs->keybase + i);

        if (mode_put) {
            rc = hse_kvs_put(kvs, &os, key, klen, &vtxn,
                             sizeof(vtxn));
            if (rc)
                stats->puts_fail++;

            stats->puts_txn++;
        } else {
            rc = hse_kvs_get(kvs, &os, key, klen, &found, &vtxn,
                             sizeof(vtxn), &vtxnlen);
            if (rc)
                fatal(rc, "kvdb_txn_get");

            stats->gets_txn++;
        }
    }

    if (commit) {
        rc = hse_kvdb_txn_commit(kvdb, txn);
        if (rc)
            fatal(rc, "hse_kvdb_txn_commit");

        ++stats->commits;
    } else {
        rc = hse_kvdb_txn_abort(kvdb, txn);
        if (rc)
            fatal(rc, "hse_kvdb_txn_abort");

        ++stats->aborts;
    }

    if (!reusetxn) {
        hse_kvdb_txn_free(kvdb, tdargs->txn);
        tdargs->txn = NULL;
    }
}

void
ctxn_validation_stress(
    struct tdargs *tdargs)
{
    struct stats           *stats = &tdargs->stats;
    struct hse_kvdb_txn    *txn;
    struct hse_kvdb_opspec  os;

    size_t      klen, vlen, vcurlen, vtxnlen;
    u64         val, vcur, vtxn;
    char        key[64];
    bool        found;
    u64         rc;
    ulong       i;

    txn = tdargs->txn;
    if (!txn) {
        txn = hse_kvdb_txn_alloc(kvdb);
        if (!txn)
            fatal(ENOMEM, "hse_kvdb_txn_alloc");
        tdargs->txn = txn;
    }

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn;
    os.kop_flags = 0;

    rc = hse_kvdb_txn_begin(kvdb, txn);
    if (rc) {
        ++stats->begin_fail;
        if (hse_err_to_errno(rc) == ENOMEM) {
            usleep(333 * 1000);
            return;
        }
        fatal(rc, "hse_kvdb_txn_begin");
    }

    tdargs->keybase = keybase;
    if (keybase_random)
        tdargs->keybase = xrand();
    tdargs->keybase = (tdargs->keybase >> 20) | (tdargs->tidx << 48);

    /* First, load c0 with a bunch of unique k/v tuples (each key
     * and value are unique).
     */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt,
                        tdargs->keybase + i);

        vcur = ++tdargs->viter;
        rc = hse_kvs_put(kvs, &os, key, klen, &vcur, sizeof(vcur));
        if (rc)
            fatal(rc, "kvdb_put 1");

        ++stats->puts_c0;
    }
    hse_kvdb_txn_commit(kvdb, txn);
    rc = hse_kvdb_txn_begin(kvdb, txn);
    if (rc) {
        ++stats->begin_fail;
        if (hse_err_to_errno(rc) == ENOMEM) {
            usleep(333 * 1000);
            return;
        }
        fatal(rc, "hse_kvdb_txn_begin");
    }

    /* Next, load txn with the same set of unique keys from above,
     * but with values disjoint from the above set.
     */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt,
                        tdargs->keybase + i);

        vtxn = ++tdargs->viter;
        rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
        if (rc == ECANCELED) {
            hse_kvdb_txn_abort(kvdb, txn);

            if (!reusetxn) {
                hse_kvdb_txn_free(kvdb, txn);
                tdargs->txn = NULL;
            }

            ++stats->aborts;
            return;
        }

        if (rc)
            fatal(rc, "kvdb_put 2");

        ++stats->puts_txn;

        vcurlen = vtxnlen = 0;
        vcur = vtxn = 0;

        rc = hse_kvs_get(kvs, NULL, key, klen, &found,
                         &vcur, sizeof(vcur), &vcurlen);
        if (rc)
            fatal(rc, "kvdb_getco 1");

        if (!found)
            fatal(ENOENT, "kvdb_getco 1 not found");

        ++stats->gets_c0;

        rc = hse_kvs_get(kvs, &os, key, klen, &found,
                         &vtxn, sizeof(vtxn), &vtxnlen);
        if (rc)
            fatal(rc, "kvdb_getco 2");

        ++stats->gets_txn;

        if (!found)
            fatal(ENOENT, "kvdb_getco 2 not found");

        if (vcurlen != sizeof(vcur))
            fatal(EINVAL, "isolation error (vcurlen)");

        if (vtxnlen != sizeof(vtxn))
            fatal(EINVAL, "isolation error (vtxnlen)");

        if (vcur != tdargs->viter - keymax)
            fatal(EINVAL, "isolation error (vcur)");

        if (vtxn != tdargs->viter)
            fatal(EINVAL, "isolation error (vtxn)");
    }

    rc = hse_kvdb_txn_commit(kvdb, txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_commit");

    ++stats->commits;

    /* After the commit, the values visible via c0 should be the
     * values from txn.
     */
    for (i = 0; i < keymax; ++i) {
        klen = snprintf(key, sizeof(key), keybase_fmt,
                        tdargs->keybase + i);

        vlen = 0;
        val = 0;

        rc = hse_kvs_get(kvs, NULL, key, klen, &found,
                         &val, sizeof(val), &vlen);
        if (rc)
            fatal(rc, "kvdb_getco 3");
        ++stats->gets_c0;

        if (!found)
            fatal(ENOENT, "kvdb_getco 3 not found");

        if (vlen != sizeof(val))
            fatal(EINVAL, "isolation error (vlen)");

        if (val != tdargs->viter - keymax + i + 1)
            fatal(EINVAL, "isolation error (val)");
    }

    if (!reusetxn) {
        hse_kvdb_txn_free(kvdb, tdargs->txn);
        tdargs->txn = NULL;
    }
}

void
ctxn_validation_basic(void)
{
    struct hse_kvdb_txn    *txn;
    struct hse_kvdb_opspec  os;

    size_t      klen, klen_lg = 0, vlen, vcurlen, vtxnlen;
    char        key[64], key_lg[64];
    u64         val, vcur;
    bool        found;
    u32         vtxn;
    u64         rc;

    if (keybase_random)
        keybase = xrand();

    txn = hse_kvdb_txn_alloc(kvdb);
    if (!txn)
        fatal(ENOMEM, "hse_kvdb_txn_alloc");

    HSE_KVDB_OPSPEC_INIT(&os);
    os.kop_txn = txn;
    os.kop_flags = 0;

    rc = hse_kvdb_txn_begin(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    klen = snprintf(key, sizeof(key), "key.%09lu", keybase);
    if (mixed_sz)
        klen_lg = snprintf(key_lg, sizeof(key_lg),
                           "key_lg.%09lu", keybase);

    vcur = ++viter;
    rc = hse_kvs_put(kvs, &os, key, klen, &vcur, sizeof(vcur));
    if (rc)
        fatal(rc, "kvdb_put 1");

    rc = hse_kvdb_txn_commit(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_commit");

    ++stats.puts_c0;

    rc = hse_kvdb_txn_begin(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_begin");

    vtxn = ++viter;
    rc = hse_kvs_put(kvs, &os, key, klen, &vtxn, sizeof(vtxn));
    if (rc)
        fatal(rc, "kvdb_put 2");

    ++stats.puts_txn;

    if (mixed_sz) {
        char    val_lg[237];

        rc = hse_kvs_put(kvs, &os, key_lg, klen_lg,
                         &val_lg, sizeof(val_lg));
        if (rc)
            fatal(rc, "kvdb_put large");
    }

    vcurlen = vtxnlen = 0;
    vcur = vtxn = 0;

    rc = hse_kvs_get(kvs, NULL, key, klen, &found,
                     &vcur, sizeof(vcur), &vcurlen);
    if (rc)
        fatal(rc, "kvdb_getco 1");

    ++stats.gets_c0;

    if (!found)
        fatal(ENOENT, "kvdb_getco 1 not found");

    rc = hse_kvs_get(kvs, &os, key, klen, &found,
                     &vtxn, sizeof(vtxn), &vtxnlen);
    if (rc)
        fatal(rc, "kvdb_getco 2");
    if (!found)
        fatal(ENOENT, "kvdb_getco 2 not found");

    ++stats.gets_txn;

    if (vcurlen != sizeof(vcur))
        fatal(EINVAL, "isolation error (vcurlen)");

    if (vtxnlen != sizeof(vtxn))
        fatal(EINVAL, "isolation error (vtxnlen)");

    if (vcur != viter - 1)
        fatal(EINVAL, "isolation error (vcur)");

    if (vtxn != viter)
        fatal(EINVAL, "isolation error (vtxn)");

    rc = hse_kvdb_txn_commit(kvdb, os.kop_txn);
    if (rc)
        fatal(rc, "hse_kvdb_txn_commit");

    ++stats.commits;

    vlen = 0;
    val = 0;

    rc = hse_kvs_get(kvs, NULL, key, klen, &found,
                     &val, sizeof(val), &vlen);
    if (rc)
        fatal(rc, "kvdb_getco 3");

    if (!found)
        fatal(ENOENT, "kvdb_getco 3 not found");

    ++stats.gets_c0;

    if (vlen != vtxnlen)
        fatal(EINVAL, "isolation error (vlen)");

    if (val != vtxn)
        fatal(EINVAL, "isolation error (val)");

    hse_kvdb_txn_free(kvdb, txn);
}

void *
spawn_main(void *arg)
{
    struct tdargs  *tdargs = arg;
    int rc, i;

    rc = pthread_setaffinity_np(tdargs->tid, sizeof(tdargs->cpuset), &tdargs->cpuset);
    if (rc) {
        eprint("pthread_setaffinity_np: %s", strerror(rc));
        exit(EX_OSERR);
    }

    pthread_barrier_wait(&tdargs->barriers[0]);

    xrand_init(tdargs->tidx ^ seed);

    for (i = 0; i < itermax && !done; ++i)
        tdargs->func(tdargs);

    if (tdargs->txn)
        hse_kvdb_txn_free(kvdb, tdargs->txn);

    pthread_barrier_wait(&tdargs->barriers[1]);

    return NULL;
}

void
spawn(spawn_cb_t *func)
{
    pthread_barrier_t barv[2];
    cpu_set_t cpuset_orig;
    cpu_set_t cpuset_avail;
    struct tdargs *tdargsv;
    int cpu_count, cpu, rc, i, j;

    for (i = 0; i < NELEM(barv); ++i)
        pthread_barrier_init(&barv[i], NULL, jobsmax);

    tdargsv = aligned_alloc(alignof(*tdargsv), sizeof(*tdargsv) * jobsmax);
    if (!tdargsv)
        abort();

    memset(tdargsv, 0, sizeof(*tdargsv) * jobsmax);
    done = false;

    rc = pthread_getaffinity_np(pthread_self(), sizeof(cpuset_orig), &cpuset_orig);
    if (rc) {
        eprint("pthread_getaffinity_np: %s", strerror(rc));
        exit(EX_OSERR);
    }

    cpu_count = CPU_COUNT(&cpuset_orig);
    cpuset_avail = cpuset_orig;
    cpu = cpustart;

    for (i = 0; i < jobsmax; ++i) {
        struct tdargs *args = tdargsv + i;

        args->tidx = i;
        args->func = func;
        args->viter = (ulong)i << 48;
        args->barriers = barv;
        args->cpuset = cpuset_orig;

        if (cpustart >= 0) {
            if (CPU_COUNT(&cpuset_avail) == 0)
                cpuset_avail = cpuset_orig;

            cpu %= cpu_count;

            while (1) {
                for (j = 0; j < cpu_count; ++j) {
                    if (CPU_ISSET(cpu, &cpuset_avail))
                        break;

                    cpu = (cpu + cpuskip) % cpu_count;
                }

                if (j < cpu_count) {
                    CPU_CLR(cpu, &cpuset_avail);
                    break;
                }

                /* If cpuskip is an even multiple of the remaining
                 * available cpus then we increment cpu by one and
                 * continue searching for an available cpu.
                 */
                cpu = (cpu + 1) % cpu_count;
            }

            CPU_ZERO(&args->cpuset);
            CPU_SET(cpu, &args->cpuset);

            cpu += cpuskip;
        }

        rc = pthread_create(&args->tid, NULL, spawn_main, args);
        if (rc) {
            eprint("unable to create more than %d jobs: %s", i, strerror(rc));
            exit(EX_OSERR);
        }
    }

    if (secmax > 0) {
        sleep(secmax);
        done = true;
    }

    while (i-- > 0) {
        struct tdargs  *args = tdargsv + i;

        rc = pthread_join(args->tid, NULL);
        if (rc)
            fatal(rc, "pthread_join");

        stats.puts_c0 += args->stats.puts_c0;
        stats.gets_c0 += args->stats.gets_c0;
        stats.puts_txn += args->stats.puts_txn;
        stats.gets_txn += args->stats.gets_txn;
        stats.puts_fail += args->stats.puts_fail;
        stats.begin_fail += args->stats.begin_fail;
        stats.commits += args->stats.commits;
        stats.aborts += args->stats.aborts;
    }

    for (i = 0; i < NELEM(barv); ++i)
        pthread_barrier_destroy(&barv[i]);

    free(tdargsv);
}

void
usage(void)
{
    printf("usage: %s [options] <kvdb> <kvs> [param=value ...]\n",
           progname);
    printf("usage: %s -h [-v]\n", progname);

    printf("-a affine   affine each job to one logical cpu (requires {-p | -s}\n");
    printf("-c          run collision test\n");
    printf("-f fmt      specify printf format for key generation\n");
    printf("-h          print this help list\n");
    printf("-i iters    specify max number of test iterations (excludes -t)\n");
    printf("-j jobs     specify max number of jobs\n");
    printf("-K keybase  specify a starting number for key generation\n");
    printf("-k keys     specify max number of keys PUT per transaction\n");
    printf("-p mode     run perf test in given mode {pc | gc | pa | ga}\n");
    printf("-r          reuse txn between iterations\n");
    printf("-S seed     specify srand seed\n");
    printf("-s          run stress test (stringent verification)\n");
    printf("-t secs     specify max run time in seconds (requires {-p | -s})\n");
    printf("-v          increase verbosity\n");
    printf("affine  first[,skip]  specify first cpu and number of cpus to skip\n");
    printf("mode    pc:put+commit, gc:get+commit, pa:put+abort, ga:get+abort\n");
    printf("\n");

    if (verbosity > 0) {
        printf("Use -a1 to start first job on cpu 1, second job on cpu 2, ...\n");
        printf("Use -a1,16 to start first job on cpu 1, second job on cpu 17, ...\n");
        printf("Use -vvv for tabular output\n");
    } else {
        printf("Use -hv for more detail\n");
    }

    printf("\n");
}

int
main(int argc, char **argv)
{
    hse_err_t            err;
    uint8_t           given[256] = { };
    bool              help = false;
    ulong             i;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    err = hse_kvdb_init();
    if (err) {
        eprint("failed to initialize kvdb\n");
        exit(EX_OSERR);
    }

    hse_params_create(&params);
    hse_params_set(params, "kvdb.perfc_enable", "0");
    hse_params_set(params, "kvs.transactions_enable", "1");

    seed = time(NULL);

    while (1) {
        char   *errmsg, *end;
        int     c;

        c = getopt(argc, argv, ":a:cf:hi:j:K:k:p:rS:st:Vvwm");
        if (-1 == c)
            break;

        errmsg = end = NULL;
        errno = 0;

        ++given[c];

        switch (c) {
        case 'a':
            cpuskip = 1;
            errmsg = "invalid cpu start";
            cpustart = strtoul(optarg, &end, 0);
            if (end && *end == ',') {
                errmsg = "invalid cpu skip";
                cpuskip = strtoul(end + 1, &end, 0);
            }
            break;

        case 'c':
            break;

        case 'f':
            keybase_fmt = optarg;
            break;

        case 'h':
            help = true;
            break;

        case 'i':
            itermax = strtoul(optarg, &end, 0);
            errmsg = "invalid itermax count";
            break;

        case 'j':
            jobsmax = strtoul(optarg, &end, 0);
            errmsg = "invalid maxjobs";
            break;

        case 'K':
            keybase = strtoul(optarg, &end, 0);
            errmsg = "invalid keybase";
            keybase_random = false;
            break;

        case 'k':
            keymax = strtoul(optarg, &end, 0);
            errmsg = "invalid keymax count";
            break;

        case 'm':
            mixed_sz = true;
            break;

        case 'p':
            if (strlen(optarg) != 2 ||
                (optarg[0] != 'p' && optarg[0] != 'g') ||
                (optarg[1] != 'a' && optarg[1] != 'c'))
                errno = EINVAL;
            errmsg = "Invalid perf mode argument";
            mode_put = (optarg[0] == 'p');
            commit = (optarg[1] == 'c');
            break;

        case 'r':
            reusetxn = true;
            break;

        case 'S':
            seed = strtoul(optarg, &end, 0);
            errmsg = "invalid srand seed";
            break;

        case 's':
            break;

        case 't':
            secmax = strtoul(optarg, &end, 0);
            errmsg = "invalid seconds count";
            break;

        case 'v':
            ++verbosity;
            break;

        case 'w': /* deprecated */
            ++given['c'];
            break;

        case '?':
            syntax("invalid option -%c", optopt);
            exit(EX_USAGE);

        case ':':
            syntax("option -%c requires a parameter", optopt);
            exit(EX_USAGE);

        default:
            eprint("option -%c ignored\n", c);
            break;
        }

        if (errmsg && errno) {
            syntax("%s", errmsg);
            exit(EX_USAGE);
        } else if (end && *end) {
            syntax("%s '%s'", errmsg, optarg);
            exit(EX_USAGE);
        }
    }

    argc -= optind;
    argv += optind;

    if (help) {
        usage();
        exit(0);
    }

    if (argc < 2) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    mp_name = argv[0];
    kvs_name = argv[1];

    argc -= 2;
    argv += 2;

    if (argc > 0) {
        int last;

        last = 0;

        err = hse_parse_cli(argc, argv, &last, 0, params);
        if (err) {
            eprint("unable to parse parameters\n");
            exit(EX_OSERR);
        }

        if (last < argc) {
            syntax("invalid kvdb/kvs parameter '%s'", argv[last]);
            exit(EX_OSERR);
        }
    }

    xrand_init(seed);
    setpriority(PRIO_PROCESS, 0, -1);

    itermax = max_t(ulong, itermax, 1);
    itermax = min_t(ulong, itermax, 1ul << 30);
    jobsmax = max_t(ulong, jobsmax, 1);
    jobsmax = min_t(ulong, jobsmax, 32768);
    keymax = max_t(ulong, keymax, 0);
    keymax = min_t(ulong, keymax, 1048576);

    stats.topen = get_time_ns();

    ctxn_validation_init();

    stats.tstart = get_time_ns();

    if (given['c']) {
        jobsmax = 32;
        for (i = 0; i < itermax; ++i)
            ctxn_validation_basic_collision();
    } else if (given['p']) {
        if (!mode_put) {
            ctxn_validation_init_c0();
            stats.tstart = get_time_ns();
        }

        if (secmax > 0)
            itermax = ULONG_MAX;
        spawn(ctxn_validation_perf);
    } else if (given['s']) {
        if (secmax > 0)
            itermax = ULONG_MAX;
        spawn(ctxn_validation_stress);
    } else {
        for (i = 0; i < itermax; ++i)
            ctxn_validation_basic();
    }

    stats.tstop = get_time_ns();

    ctxn_validation_fini();

    stats.tclose = get_time_ns();

    if (verbosity > 0) {
        ulong usecs = (stats.tstop - stats.tstart) / 1000;
        struct rusage rusage;

        getrusage(RUSAGE_SELF, &rusage);

        if (verbosity > 2) {
            printf(
                "%4lu %lu %lu %lu %lu %lu %lu %9lu %lu %lu %.0lf "
                "%9lu %8.0lf %7lu %6lu %lu %lu %.3lf %.3lf %.3lf %.3lf\n",
                jobsmax, secmax, secmax ? 0 : itermax,
                stats.puts_c0, stats.gets_c0,
                stats.puts_txn, stats.puts_fail, stats.gets_txn, stats.begin_fail,
                stats.commits, (stats.commits * 1000000.0) / usecs,
                stats.aborts, (stats.aborts * 1000000.0) / usecs,
                rusage.ru_utime.tv_sec * 1000 + rusage.ru_utime.tv_usec / 1000,
                rusage.ru_stime.tv_sec * 1000 + rusage.ru_stime.tv_usec / 1000,
                rusage.ru_majflt, rusage.ru_minflt,
                usecs / 1000000.0,
                (stats.tstart - stats.topen) / 1000000000.0,
                (stats.tclose - stats.tstop) / 1000000000.0,
                (stats.tclose - stats.topen) / 1000000000.0);
        } else {
            printf("%12lu  jobsmax\n", jobsmax);
            printf("%12lu  secmax\n", secmax);
            printf("%12lu  itermax\n", secmax ? 0 : itermax);
            printf("%12lu  c0 puts\n", stats.puts_c0);
            printf("%12lu  c0 gets\n", stats.gets_c0);
            printf("%12lu  txn puts\n", stats.puts_txn);
            printf("%12lu  txn puts canceled\n", stats.puts_fail);
            printf("%12lu  txn gets\n", stats.gets_txn);
            printf("%12lu  begin_fail\n", stats.begin_fail);
            printf("%12lu  commits\n", stats.commits);
            printf("%12.0lf  commits/sec\n",
                   (stats.commits * 1000000.0) / usecs);
            printf("%12lu  aborts\n", stats.aborts);
            printf("%12.0lf  aborts/sec\n",
                   (stats.aborts * 1000000.0) / usecs);
            printf("%12lu  utime(ms)\n",
                   rusage.ru_utime.tv_sec * 1000 +
                   rusage.ru_utime.tv_usec / 1000);
            printf("%12lu  stime(ms)\n",
                   rusage.ru_stime.tv_sec * 1000 +
                   rusage.ru_stime.tv_usec / 1000);
            printf("%12lu  majflt\n", rusage.ru_majflt);
            printf("%12lu  minflt\n", rusage.ru_minflt);
            printf("%12.3lf  test elapsed secs\n",
                   usecs / 1000000.0);
            printf("%12.3lf  open elapsed secs\n",
                   (stats.tstart - stats.topen) / 1000000000.0);
            printf("%12.3lf  close elapsed secs\n",
                   (stats.tclose - stats.tstop) / 1000000000.0);
            printf("%12.3lf  total elapsed secs\n",
                   (stats.tclose - stats.topen) / 1000000000.0);
        }
    }

    hse_params_destroy(params);

    hse_kvdb_fini();

    if (secmax == 0) {
        if (commit) {
            if (stats.commits < itermax * jobsmax) {
                fprintf(stderr, "%s: commits %lu < expected %lu\n",
                        progname, stats.commits, itermax * jobsmax);
                exit(2);
            }
        } else {
            if (stats.aborts < itermax * jobsmax) {
                fprintf(stderr, "%s: aborts %lu < expected %lu\n",
                        progname, stats.aborts, itermax * jobsmax);
                exit(2);
            }
        }
    }

    return 0;
}
