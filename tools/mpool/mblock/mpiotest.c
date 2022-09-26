/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */
/*
 * This test tool exercises mpool and mcache.
 *
 * Examples:
 *    Given an kvdb named "kvdb1":
 *
 *    $ sudo mpiotest kvdb1
 *    $ sudo mpiotest -vv -j48 kvdb1 128k
 *    $ sudo mpiotest -vv -j48 kvdb1 1m 128m
 *    $ sudo mpiotest -v -j48 -i777 -l 8192 -o gpverify=0,rdverify=0 kvdb1 32m
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <bsd/string.h>

#include <hse/error/merr.h>
#include <hse/hse.h>
#include <hse_util/err_ctx.h>
#include <hse_util/minmax.h>
#include <hse_util/page.h>

#include <mpool/mpool.h>

#define MBLOCK_SIZE_MB_DEFAULT (32 << 20)
#define WANDERMAX              (1024 * 128)
#define WOBBLEMAX              (1024 * 128)

/* Per-iteration metadata.  Used to remember what mblocks
 * we have allocated so that we can check and delete them
 * at the end of the test.
 */
struct minfo {
    uint64_t objid;
    size_t   wander; /* offset into wbuf */
    size_t   wobble; /* wcc variability */

    struct mpool_mcache_map *map;
};

struct stats {
    ulong mbwrite;        /* Number of calls to mpool_mblock_write() */
    ulong mbread;         /* Number of calls to mpool_mblock_read() */
    ulong mbreaderr;      /* Number of mpool_mblock_read() errors */
    ulong mbreadcmperr;   /* Number of rdverify miscompares */
    ulong mbdel;          /* Number of calls to mpool_mblock_delete() */
    ulong mapcreate;      /* Number of calls to mpool_mcache_create() */
    ulong mapdestroy;     /* Number of calls to mpool_mcache_destroy() */
    ulong getpages;       /* Number of calls to mp_getpages() */
    ulong pread;          /* Number of calls to mpool_mcache_pread() */
    ulong getpagescmp;    /* Number of mcache pages verified */
    ulong getpagescmperr; /* Number of mcache page verification errors */
};

struct test {
    pthread_t     t_td;
    int           t_idx;
    ulong         t_iter;      /* Current test iteration */
    size_t        t_wcc;       /* Min bytes of data to write */
    size_t        t_wbufsz;    /* Base of random data buffer */
    size_t        t_wandermax; /* Max offset into wbuf */
    size_t        t_wobblemax; /* Max wcc variability */
    const char   *t_mpname;
    struct stats  t_stats;
    struct mpool *t_mp;
};

const char *infile = "/dev/urandom";
const char *progname;

uint   mballoc_max = 1024 * 1024 * 8;
size_t wbufsz = MBLOCK_SIZE_MB_DEFAULT;
uint   runtime_min = UINT_MAX;
ulong  iter_max = 1;
int    global_err = 0;
ulong  td_max = 5;
ulong  td_run;

/* Verification via mpool_mblock_read (which is not cached) */
ulong       rdverify = 13;
const ulong rdverify_min = 0;
const ulong rdverify_max = 100;

/* Verification via mcache */
ulong       mcverify = 17;
ulong       mcverifysz = PAGE_SIZE;
const ulong mcverify_min = 0;
const ulong mcverify_max = 100;
ulong       mcmaxpages = 1024;
const ulong mcmaxpages_min = 1;
const ulong mcmaxpages_max = 32768;
/* Set mcmaxmblocks_max to 254 as an object layout in mpool core can utmost have
 * only 255 references: 1 from allocation + 254 external references.
 */
ulong       mcmaxmblocks = 8;
const ulong mcmaxmblocks_min = 1;
const ulong mcmaxmblocks_max = 254;

char state[256];
int  verbosity;

char *wbuf;
uint  rows, row;
int   oflags;
int   debug;

#define RETSIGTYPE void

volatile sig_atomic_t sigalrm;
volatile sig_atomic_t sigint;

void HSE_PRINTF(1, 2)
syntax(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

/* Error print.
 */
static void HSE_PRINTF(1, 2)
eprint(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    snprintf(msg, sizeof(msg), "%s(%lx): ", progname, (long)pthread_self);

    va_start(ap, fmt);
    vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
    va_end(ap);

    fputs(msg, stderr);
}

/* Note that we received a signal.
 */
RETSIGTYPE
sigalrm_isr(int sig)
{
    ++sigalrm;
}

RETSIGTYPE
sigint_isr(int sig)
{
    ++sigint;
}

/* Reliable signal.
 */
int
signal_reliable(int signo, __sighandler_t func)
{
    struct sigaction nact;

    bzero(&nact, sizeof(nact));

    nact.sa_handler = func;
    sigemptyset(&nact.sa_mask);

    if (SIGALRM == signo || SIGINT == signo) {
#ifdef SA_INTERRUPT
        nact.sa_flags |= SA_INTERRUPT;
#endif
    } else {
#ifdef SA_RESTART
        nact.sa_flags |= SA_RESTART;
#endif
    }

    return sigaction(signo, &nact, (struct sigaction *)0);
}

/* Accumulate src stats into dst stats.
 */
void
stats_accum(struct stats *dst, const struct stats *src)
{
    dst->mbwrite += src->mbwrite;
    dst->mbread += src->mbread;
    dst->mbreaderr += src->mbreaderr;
    dst->mbreadcmperr += src->mbreadcmperr;
    dst->mbdel += src->mbdel;
    dst->mapcreate += src->mapcreate;
    dst->mapdestroy += src->mapdestroy;
    dst->getpages += src->getpages;
    dst->getpagescmp += src->getpagescmp;
    dst->getpagescmperr += src->getpagescmperr;
}

void
stats_print(struct stats *stats, const char *header, int idx)
{
    printf(
        "%3d: %-6s  wr=%lu del=%lu"
        " rd=%lu rderr=%lu rdcmperr=%lu"
        " mapcreate=%lu mapdestroy=%lu"
        " gp=%lu gpcmp=%lu gpcmperr=%lu\n",
        idx,
        header,
        stats->mbwrite,
        stats->mbdel,
        stats->mbread,
        stats->mbreaderr,
        stats->mbreadcmperr,
        stats->mapcreate,
        stats->mapdestroy,
        stats->getpages,
        stats->getpagescmp,
        stats->getpagescmperr);
}

/* Initialize runtime parameters for the given test.
 */
void
test_init(struct test *testv, int idx, ulong iter, const char *path, struct mpool *mp)
{
    struct test *t = testv + idx;

    memset(t, 0, sizeof(*t));
    t->t_idx = idx;
    t->t_iter = iter;
    t->t_mpname = path;
    t->t_mp = mp;

    t->t_wbufsz = wbufsz;
    t->t_wcc = wbufsz;

    t->t_wandermax = WANDERMAX;
    if (t->t_wandermax > t->t_wcc / 4)
        t->t_wandermax = t->t_wcc / 4;
    t->t_wandermax &= PAGE_MASK;
    if (t->t_wandermax < PAGE_SIZE)
        t->t_wandermax = PAGE_SIZE;

    t->t_wobblemax = 1;

    t->t_wcc -= (t->t_wandermax + t->t_wobblemax);
    t->t_wcc &= PAGE_MASK;
    if (t->t_wcc < PAGE_SIZE)
        abort();
}

int
verify_page_vec(
    struct minfo *minfo,
    void        **pagev,
    uint         *objnumv,
    off_t        *offsetv,
    uint64_t     *mbidv,
    int           pagec,
    struct stats *stats)
{
    int i;
    int rc;

    for (i = 0; i < pagec && mcverifysz > 0; ++i) {
        char *addr;

        if (sigint || sigalrm)
            return 0;

        addr = wbuf + offsetv[i] * PAGE_SIZE;
        addr += (minfo - objnumv[i])->wander;

        rc = memcmp(addr, pagev[i], mcverifysz);
        if (rc) {
            eprint(
                "%s: mbidv[%d]=%lx %lx offsetv[%d]=%-6zu"
                " page[%d]=%p miscompare @ %d\n",
                __func__,
                objnumv[i],
                (ulong)mbidv[objnumv[i]],
                (ulong)(minfo - objnumv[i])->objid,
                i,
                offsetv[i],
                i,
                pagev[i],
                rc);
            ++stats->getpagescmperr;
            return 1;
        }

        ++stats->getpagescmp;
    }
    return 0;
}

int
verify_with_mcache(
    struct mpool *mp,
    uint64_t      objid,
    struct minfo *minfo,
    struct minfo *minfov,
    size_t        wcc,
    size_t        wobble,
    struct stats *stats,
    struct test  *test,
    size_t        rss,
    size_t        vss)
{
    uint     objnumv[mcmaxpages];
    off_t    offsetv[mcmaxpages];
    void    *pagev[mcmaxpages];
    uint64_t mbidv[mcmaxmblocks];
    int      mbidc;
    int      pagec;
    int      i;
    merr_t   err;
    char     errbuf[64];
    char    *buf = NULL;
    int      fail = 0;

    /* Select a handful of mblock IDs from recent history.
	 * Must ensure mbidv[0] is unique over wloops as mcache
	 * uses it as the basis for the map file name.
	 */
    mbidc = min_t(ulong, (minfo - minfov) + 1, mcmaxmblocks);

    if (mcverify < 100)
        mbidc = (random() % mbidc) + 1;

    for (i = 0; i < mbidc; ++i)
        mbidv[i] = minfo[-i].objid;

    if (mcverify < 100)
        pagec = random() % mcmaxpages;
    else
        pagec = mcmaxpages;

    /* For each pagec, randomly choose an mblock from
	 * objnumv[] and then generate a random offset
	 * into the mblock (limited by how much data we
	 * actually wrote to it).
	 */
    for (i = 0; i < pagec; ++i) {
        if (mcverify < 100)
            objnumv[i] = random() % mbidc;
        else
            objnumv[i] = i % mbidc;

        offsetv[i] = wcc + (minfo - objnumv[i])->wobble;
        offsetv[i] /= PAGE_SIZE;
        offsetv[i] = (random() % offsetv[i]);

        pagev[i] = NULL;
    }

    /* If we don't already have a map, create it */
    if (!minfo->map) {
        err = mpool_mcache_mmap(mp, mbidc, mbidv, &minfo->map);
        if (err)
            goto mcache_map_err;

        ++stats->mapcreate;
    }

    for (i = 0; i < mbidc; ++i) {
        err = mpool_mcache_madvise(minfo->map, i, 0, wcc, MADV_WILLNEED);
        if (err) {
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint("mpool_mcache_madvise failed: map=%p mbid=%d: %s\n", (void *)minfo->map, i, errbuf);
        }
    }

    for (i = 0; i < pagec; ++i) {
        err = mpool_mcache_getpages(minfo->map, 1, objnumv[i], offsetv + i, pagev + i);
        if (err) {
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint(
                "mpool_mcache_getpages: %d objid=0x%lx len=%zu: %s\n",
                test->t_idx,
                objid,
                wcc + wobble,
                errbuf);
            goto err_out;
        }
    }

    ++stats->getpages;

    fail = verify_page_vec(minfo, pagev, objnumv, offsetv, mbidv, pagec, stats);
    if (fail)
        goto err_out;

    if (verbosity > 1)
        mpool_mcache_mincore(minfo->map, mp, &rss, &vss);

    return 0;

mcache_map_err:
    merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
    eprint("mpool_mcache_map_create failed: objid=0x%lx: %s\n", objid, errbuf);

err_out:
    if (buf)
        free(buf);

    return 1;
}

/* pthread worker main entry point.
 */
void *
test_start(void *arg)
{
    struct minfo *minfov;
    struct stats *stats;
    struct test  *test;
    struct iovec *iov;
    struct mpool *mp;
    merr_t        err = 0;

    size_t wander, wobble, wcc;
    char   errbuf[64];
    char  *rbuf;
    int    rloops;
    int    wloops;
    int    rc;

    uint     *objnumv;
    size_t   *offsetv;
    void     *pagev;
    uint64_t *mbidv;

    test = arg;
    wcc = test->t_wcc;
    stats = &test->t_stats;
    mp = test->t_mp;

    minfov = NULL;
    objnumv = NULL;
    iov = NULL;
    rbuf = NULL;

    memset(stats, 0, sizeof(*stats));

    minfov = malloc(sizeof(*minfov) * mballoc_max);

    iov = malloc(sizeof(*iov) * ((test->t_wbufsz / PAGE_SIZE) + 1));

    rc = posix_memalign((void **)&rbuf, PAGE_SIZE, test->t_wbufsz);

    if (rc || !minfov || !iov) {
        eprint("out of memory (minfov,iov,rbuf)\n");
        err = merr(rc);
        goto errout;
    }

    if (mcverify > 0) {
        size_t sz;

        sz = sizeof(*objnumv) + sizeof(*offsetv) * sizeof(*pagev);
        sz *= mcmaxpages;
        sz += sizeof(*mbidv) * mcmaxmblocks;

        objnumv = malloc(sz);
        if (!objnumv) {
            eprint("out of memory (objnumv)\n");
            err = merr(ENOMEM);
            goto errout;
        }

        offsetv = (void *)(objnumv + mcmaxpages);
        pagev = (void *)(offsetv + mcmaxpages);
        mbidv = (void *)(pagev + mcmaxpages);
    }

    if (debug > 0)
        printf(
            "%3d: start:  iter=%lu mballocmax=%u wbufsz=%zu wcc=%zu"
            " wandermax=%zu wobblemax=%zu\n",
            test->t_idx,
            test->t_iter,
            mballoc_max,
            test->t_wbufsz,
            test->t_wcc,
            test->t_wandermax,
            test->t_wobblemax);

    for (wloops = 0; wloops < mballoc_max; ++wloops) {
        struct mblock_props props;
        struct minfo       *minfo;
        uint64_t            objid;
        size_t              rss, vss;

        if (sigint || sigalrm)
            break;

        rss = vss = 0;

        minfo = minfov + wloops;
        wander = (random() % test->t_wandermax) & PAGE_MASK;
        wobble = (random() % test->t_wobblemax) & PAGE_MASK;

        err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &objid, &props);
        if (err) {
            if (merr_errno(err) == ENOSPC)
                break;

            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint("mpool_mblock_alloc failed: %s\n", errbuf);
            break;
        }

        minfo->objid = props.mpr_objid;
        minfo->wander = wander;
        minfo->wobble = wobble;
        minfo->map = NULL;

        char *base = wbuf + wander;
        int   niov;

        iov[0].iov_base = base;
        iov[0].iov_len = wcc + wobble;
        niov = 1;

        if ((random() % 100) < 30) {
            iov[0].iov_base = base;
            iov[0].iov_len = PAGE_SIZE;
            iov[1].iov_base = base + PAGE_SIZE;
            iov[1].iov_len = wcc + wobble - PAGE_SIZE;
            niov = 2;
        }

        err = mpool_mblock_write(mp, objid, iov, niov);
        if (err) {
            if (merr_errno(err) == ENOSPC)
                break;

            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint(
                "mpool_mblock_write: %d objid=0x%lx len=%zu: %s\n",
                test->t_idx,
                minfo->objid,
                wcc + wobble,
                errbuf);
            break;
        }

        ++stats->mbwrite;

        err = mpool_mblock_commit(mp, objid);
        if (err) {
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint("mb_mblock_commit failed: objid=0x%lx: %s\n", minfo->objid, errbuf);
            break;
        }

        /* Spot check some of the writes via mblock read.
		 */
        if ((random() % 100) < rdverify) {
            *(uint64_t *)rbuf = 0xdeadbeefbaadcafe;

            iov[0].iov_base = rbuf;
            iov[0].iov_len = wcc + wobble;

            err = mpool_mblock_read(mp, objid, iov, 1, 0);
            if (err) {
                merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
                eprint(
                    "mpool_mblock_read: %d objid=0x%lx len=%zu: %s\n",
                    test->t_idx,
                    minfo->objid,
                    wcc + wobble,
                    errbuf);
                break;
            }

            rc = memcmp(wbuf + wander, rbuf, wcc + wobble);
            if (rc) {
                eprint(
                    "mpool_mblock_read: %d objidx=0x%lx len=%zu miscompare\n",
                    test->t_idx,
                    minfo->objid,
                    wcc + wobble);
                ++stats->mbreadcmperr;
                break;
            }

            ++stats->mbread;
        }

        /* Spot check some of the pages via mcache.  Note the
		 * use of (mcverify == 100) used to switch off most of
		 * the randomness of the test.
		 */
        if ((random() % 100) < mcverify)
            if (verify_with_mcache(mp, objid, minfo, minfov, wcc, wobble, stats, test, rss, vss))
                break;

        if (verbosity > 0) {
            if ((__sync_fetch_and_add(&row, 1) % rows) == 0) {
                printf(
                    "\n%4s %4s %4s %8s %8s %9s %8s %8s "
                    "%9s %6s %8s %5s %9s %5s %16s\n",
                    "TID",
                    "TDS",
                    "ITER",
                    "RLOOPS",
                    "WLOOPS",
                    "WCC",
                    "WANDER",
                    "WOBBLE",
                    "VSS",
                    "RSS",
                    "GETPAGES",
                    "PREAD",
                    "MCVERIFY",
                    "MCERR",
                    "OBJID");
                fflush(stdout);
            }

            printf(
                "%4d %4lu %4lu %8d %8d %9zu %8zu %8zu "
                "%9zu %6zu %8lu %5lu %9lu %5lu %16lx\n",
                test->t_idx,
                td_run,
                test->t_iter,
                0,
                wloops,
                test->t_wcc,
                wander,
                wobble,
                vss,
                rss,
                stats->getpages,
                stats->pread,
                stats->getpagescmp,
                stats->getpagescmperr,
                minfo->objid);
        }
    }

    if (debug > 0)
        stats_print(stats, "verify", test->t_idx);
    fflush(stdout);

    if (td_run > 1 && !sigint && !sigalrm)
        sleep(9); /* quasi rendezvous */

    /* For now, sleep a bit to allow in-progress read-ahead to complete
	 * (to avoid crashing in mpool core due to non-refcounted descriptors
	 * being made invalid while mcache is using them).
	 */
    if (mcverify > 0)
        sleep(9);

    /* Must delete in reverse order of allocation to ensure
	 * that mcache maps are released before deleting the mblocks
	 * which underpin them.
	 */
    rloops = wloops;
    while (rloops-- > 0) {
        struct minfo *minfo = minfov + rloops;
        size_t        wander = minfo->wander;
        size_t        wobble = minfo->wobble;
        size_t        rss, vss;

        if (sigint > 1)
            break;

        rss = vss = 0;
        if (minfo->map && verbosity > 1)
            mpool_mcache_mincore(minfo->map, mp, &rss, &vss);

        if (verbosity > 0) {
            if ((__sync_fetch_and_add(&row, 1) % rows) == 0) {
                printf(
                    "\n%4s %4s %4s %8s %8s %9s %8s %8s "
                    "%9s %6s %8s %5s %9s %5s %16s\n",
                    "TID",
                    "TDS",
                    "ITER",
                    "RLOOPS",
                    "WLOOPS",
                    "WCC",
                    "WANDER",
                    "WOBBLE",
                    "VSS",
                    "RSS",
                    "GETPAGES",
                    "PREAD",
                    "MCVERIFY",
                    "MCERR",
                    "OBJID");
                fflush(stdout);
            }

            printf(
                "%4d %4lu %4lu %8d %8d %9zu %8zu %8zu "
                "%9zu %6zu %8lu %5lu %9lu %5lu %16lx\n",
                test->t_idx,
                td_run,
                test->t_iter,
                rloops,
                wloops,
                test->t_wcc,
                wander,
                wobble,
                vss,
                rss,
                stats->getpages,
                stats->pread,
                stats->getpagescmp,
                stats->getpagescmperr,
                minfo->objid);
        }

        if ((random() % 100) < rdverify && !sigint && !sigalrm) {
            iov[0].iov_base = rbuf;
            iov[0].iov_len = wcc + wobble;

            err = mpool_mblock_read(mp, minfo->objid, iov, 1, 0);
            if (err) {
                merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
                eprint("mpool_mblock_read: objid=0x%lx: %s\n", minfo->objid, errbuf);
                ++stats->mbreaderr;
            }

            if (!err && 0 != memcmp(wbuf + wander, rbuf, wcc + wobble)) {
                eprint(
                    "mpool_mblock_read: %d objidx=0x%lx len=%zu miscompare\n",
                    test->t_idx,
                    minfo->objid,
                    wcc + wobble);
                ++stats->mbreadcmperr;
            }

            ++stats->mbread;
        }

        if (minfo->map) {
            mpool_mcache_munmap(minfo->map);
            minfo->map = NULL;
            ++stats->mapdestroy;
        }

        err = mpool_mblock_delete(mp, minfo->objid);
        if (err) {
            merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
            eprint(
                "%3d, %8d %8d %8zu %8zu %16lx"
                " ms_mblock_delete failed: %s\n",
                test->t_idx,
                rloops,
                wloops,
                wander,
                wobble,
                minfo->objid,
                errbuf);
        }

        ++stats->mbdel;
    }

errout:
    global_err = merr_errno(err);
    __sync_fetch_and_sub(&td_run, 1);

    if (debug || stats->mbreaderr || stats->mbreadcmperr || stats->getpagescmperr) {
        if (td_run > 1)
            sleep(3);

        stats_print(stats, "done", test->t_idx);
    }

    if (objnumv)
        free(objnumv);
    if (rbuf)
        free(rbuf);
    if (iov)
        free(iov);
    if (minfov)
        free(minfov);

    return NULL;
}

int
cvt_strtoul(const char *value, int base, ulong *resultp)
{
    ulong result;
    char *end;

    end = NULL;
    errno = 0;

    result = strtoul(value, &end, base);

    if ((result == ULONG_MAX && errno) || end == value || *end)
        return end ? EINVAL : errno;

    *resultp = result;

    return 0;
}

/* Scan the list for name/value pairs separated by the given separator.
 * Decode each name/value pair and store the result accordingly.
 *
 * Returns an error code from errno.h on failure.
 * Returns 0 on success.
 */
int
prop_decode(const char *list, const char *sep, const char *valid)
{
    char *nvlist, *nvlist_base;
    char *name, *value;
    int   rc;

    if (!list)
        return EINVAL;

    nvlist = strdup(list);
    if (!nvlist)
        return ENOMEM;

    nvlist_base = nvlist;
    value = NULL;
    rc = 0;

    for (rc = 0; nvlist; rc = 0) {
        while (isspace(*nvlist))
            ++nvlist;

        value = strsep(&nvlist, sep);
        name = strsep(&value, "=");

        if (debug)
            printf("%s: scanned name=%-16s value=%s\n", __func__, name, value);

        if (!name || !*name)
            continue;

        if (!value || !*value) {
            syntax("property '%s' has no value", name);
            rc = EINVAL;
            break;
        }

        if (valid && !strstr(valid, name)) {
            syntax("invalid property '%s'", name);
            rc = EINVAL;
            break;
        }

        errno = 0;

        if (0 == strcmp(name, "mcverify")) {
            rc = cvt_strtoul(value, 0, &mcverify);
            if (rc)
                break;
            if (mcverify > 100)
                mcverify = 100;
            continue;
        }

        if (0 == strcmp(name, "mcverifysz")) {
            rc = cvt_strtoul(value, 0, &mcverifysz);
            if (rc)
                break;
            if (mcverifysz > PAGE_SIZE)
                mcverifysz = PAGE_SIZE;
            continue;
        }

        if (0 == strcmp(name, "mcmaxpages")) {
            rc = cvt_strtoul(value, 0, &mcmaxpages);
            if (rc)
                break;
            continue;
        }

        if (0 == strcmp(name, "mcmaxmblocks")) {
            rc = cvt_strtoul(value, 0, &mcmaxmblocks);
            if (rc)
                break;

            mcmaxmblocks = clamp_t(ulong, mcmaxmblocks, mcmaxmblocks_min, mcmaxmblocks_max);
            continue;
        }

        if (0 == strcmp(name, "rdverify")) {
            rc = cvt_strtoul(value, 0, &rdverify);
            if (rc)
                break;
            if (rdverify > 100)
                rdverify = 100;
            continue;
        }

        if (0 == strcmp(name, "put"))
            continue;

        eprint("%s property '%s' ignored\n", valid ? "unhandled" : "invalid", name);
    }

    if (rc && value)
        syntax("invalid %s '%s': %s", name, value, strerror(rc));

    free(nvlist_base);

    return rc;
}

void
usage(void)
{
    printf("usage: %s [options] <storage_path> \n", progname);

    printf("-b           open mpool non-blocking\n");
    printf("-d           increase debug verbosity\n");
    printf("-h           print this list\n");
    printf("-i iter_max  number of iterations (default: %lu)\n", iter_max);
    printf(
        "-j <num>     specify number of concurrent jobs (threads)"
        " (default: %lu)\n",
        td_max);
    printf(
        "-l <num>     maximum number of mblocks per job"
        " (default: %u)\n",
        mballoc_max);
    printf("-o props     set one or more properties\n");
    printf("-T time_min  minimum time to run (in seconds)"
           " (incompatible with -i and -l)\n");
    printf("-v           increase verbosity\n");
    printf("-x           open exclusive\n");
    printf("props  comma separated list of properties\n");
    printf("storage_path  storage path for mpool to use\n");
    printf("\n");
    printf("DESCRIPTION:\n");
    printf("    TODO...\n");
    printf("\n");
    printf("    Give -v once to show per-thread iteration stats.\n");
    printf("    Give -v twice to show per-thread iteration plus vss/rss stats.\n");
    printf("    Type <ctrl-c> once to interrupt mballoc/mbwrite phase.\n");
    printf("    Type <ctrl-c> twice to interrupt mbverify/mbdelete phase.\n");
    printf("\n");

    printf("PROPERTIES:\n");
    printf("    rdverify      set uncached mblock_read/verify probability");
    printf(" (range: [0-100]  default: %lu)\n", rdverify);

    printf("    mcverify      set mcache verify probability");
    printf(" (range: [0-100]  default: %lu)\n", mcverify);

    printf("    mcverifysz    set max bytes in page to verify");
    printf(" (range: [0-4096] default: %lu)\n", mcverifysz);

    printf("    mcmaxpages    max pages to verify via getpages");
    printf(" (range: [%lu-%lu]  default: %lu)\n", mcmaxpages_min, mcmaxpages_max, mcmaxpages);

    printf("    mcmaxmblocks  set max mblocks to map per verification");
    printf(" (range: [%lu-%lu]  default: %lu)\n", mcmaxmblocks_min, mcmaxmblocks_max, mcmaxmblocks);
    printf("\n");

    printf("EXAMPLES:\n");
    printf("    mpiotest <storage_path>\n");

    printf("    mpiotest -vv -j7 -o rdverify=0,mcmaxpages=8765 <storage_path>\n");

    printf("    mpiotest -vv -j7"
           " -o rdverify=0,mcverify=33,mcmaxmblocks=3,mcmaxpages=4321"
           " <storage_path>\n");

    printf("    mpiotest -v -j7"
           " -o rdverify=0,mcverify=0 <storage_path>\n");

    printf("\n");
}

int
main(int argc, char **argv)
{
    struct mpool_cparams cparams = {0};
    struct mpool_rparams rparams = {0};
    struct mpool_dparams dparams = {0};
    struct stats       stats;
    struct test       *testv = NULL;
    struct mpool      *mp;
    struct mpool_props props;
    sigset_t           sigmask_block;
    sigset_t           sigmask_old;
    char              *path;

    merr_t   err;
    uint64_t herr;
    char     errbuf[64];
    size_t   limit;
    ulong    seed;
    ulong    iter;
    size_t   lwcc;
    ssize_t  cc;
    char    *end;
    FILE    *fp;
    int      fd, rc, i, given[256] = { 0 };

    progname = strrchr(argv[0], '/');
    progname = (progname ? progname + 1 : argv[0]);

    seed = time(NULL);
    oflags = O_RDWR;

    herr = hse_init(NULL, 0, NULL);
    if (herr)
        exit(1);

    while (1) {
        char *errmsg = NULL;
        int   c;

        c = getopt(argc, argv, ":Ddhi:j:L:l:o:rS:t:T:v");
        if (-1 == c)
            break;

        given[c]++;
        end = NULL;
        errno = 0;

        switch (c) {
            case 'D':
            case 'd':
                ++debug;
                break;

            case 'h':
                usage();
                exit(0);

            case 'i':
                iter_max = strtoul(optarg, &end, 0);
                runtime_min = UINT_MAX;
                errmsg = "invalid iter_max";
                break;

            case 'j':
            case 't': /* option -t is deprecated */
                td_max = strtoul(optarg, &end, 0);
                errmsg = "invalid maxjobs";
                break;

            case 'L':
                break;

            case 'l':
                mballoc_max = strtoul(optarg, &end, 0);
                errmsg = "invalid mballoc_max";
                break;

            case 'o':
                rc = prop_decode(optarg, ",", NULL);
                if (rc)
                    exit(EX_USAGE);
                break;

            case 'r':
                /* accept but ignore for compatibility */
                break;

            case 'S':
                seed = strtoul(optarg, &end, 0);
                errmsg = "invalid seed";
                break;

            case 'T':
                runtime_min = strtoul(optarg, &end, 0);
                iter_max = ULONG_MAX;
                errmsg = "invalid time_min";
                break;

            case 'v':
                ++verbosity;
                break;

            case ':':
                syntax("option '-%c' requires an argument", optopt);
                exit(EX_USAGE);

            case '?':
                syntax("invalid option '-%c'", optopt);
                exit(EX_USAGE);

            default:
                eprint("unhandled option '-%c' ignored\n", c);
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

    if (given['i'] && given['T']) {
        syntax("cannot supply both -T and -i arguments");
        exit(EX_USAGE);
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    initstate(seed, state, sizeof(state));

    rows = 24;
    if (isatty(0)) {
        fp = popen("stty size", "r");
        if (fp) {
            rc = fscanf(fp, "%u", &rows);
            if (rc != EOF && rows < 4)
                rows = 4;
            pclose(fp);
        }
        rows -= 1;
    }

    mpool_cparams_defaults(&cparams);
    path = strdup(argv[0]);
    strlcpy(cparams.mclass[HSE_MCLASS_CAPACITY].path, path,
            sizeof(cparams.mclass[HSE_MCLASS_CAPACITY].path));

    err = mpool_create(path, &cparams);
    if (err) {
        fprintf(stderr, "mpool creation at path %s failed\n", path);
        free(path);
        hse_fini();
        return -1;
    }

    strlcpy(rparams.mclass[HSE_MCLASS_CAPACITY].path, path,
            sizeof(rparams.mclass[HSE_MCLASS_CAPACITY].path));
    err = mpool_open(path, &rparams, oflags, &mp);
    if (err) {
        merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
        eprint("mpool_open(%s): %s\n", path, errbuf);
        goto err_exit;
    }

    err = mpool_props_get(mp, &props);
    if (err) {
        merr_strinfo(err, errbuf, sizeof(errbuf), err_ctx_strerror, NULL);
        eprint("mpool_props_get(%s): %s\n", path, errbuf);
        goto err_exit;
    }
    wbufsz = props.mclass[HSE_MCLASS_CAPACITY].mc_mblocksz;

    limit = wbufsz + WANDERMAX + WOBBLEMAX;

    fd = open(infile, O_RDONLY);
    if (-1 == fd) {
        eprint("open(%s): %s\n", infile, strerror(errno));
        err = merr(errno);
        goto err_exit;
    }

    rc = posix_memalign((void **)&wbuf, PAGE_SIZE, limit);
    if (rc || !wbuf) {
        err = merr(errno);
        goto err_exit;
    }

    for (lwcc = 0; lwcc < limit; lwcc += cc) {
        cc = read(fd, wbuf + lwcc, limit - lwcc);
        if (cc < 1) {
            eprint("read(%s): cc=%ld limit=%zu: %s\n", infile, cc, limit, strerror(errno));
            err = merr(errno);
            goto err_exit;
        }
    }

    close(fd);

    testv = calloc(td_max, sizeof(*testv));
    if (!testv) {
        eprint("calloc(testv): out of memory\n");
        err = merr(ENOMEM);
        goto err_exit;
    }

    memset(&stats, 0, sizeof(stats));
    iter = 0;

    /* Manage signals such that only the main thread
	 * will handle the ones we're interested in...
	 */
    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGALRM);

    signal_reliable(SIGINT, sigint_isr);
    signal_reliable(SIGALRM, sigalrm_isr);

    alarm(runtime_min);

    while (iter++ < iter_max && !sigint && !sigalrm) {
        sigprocmask(SIG_BLOCK, &sigmask_block, &sigmask_old);

        if (global_err != 0) {
            err = global_err;
            goto err_exit;
        }

        td_run = td_max;

        for (i = 0; i < td_max; ++i) {
            test_init(testv, i, iter, path, mp);

            rc = pthread_create(&testv[i].t_td, NULL, test_start, &testv[i]);
            if (rc) {
                eprint("pthread_create(%lx) idx=%d: %s\n", testv[i].t_td, testv[i].t_idx,
                    testv[i].t_mpname);
                testv[i].t_td = pthread_self();
                __sync_fetch_and_sub(&td_run, 1);
            }
        }

        sigprocmask(SIG_SETMASK, &sigmask_old, NULL);

        for (i = 0; i < td_max; ++i) {
            void *val;

            if (testv[i].t_td == pthread_self())
                continue;

            rc = pthread_join(testv[i].t_td, &val);
            if (rc) {
                eprint("pthread_join(%lx) idx=%d: %s\n", testv[i].t_td, testv[i].t_idx,
                    testv[i].t_mpname);
            }

            stats_accum(&stats, &testv[i].t_stats);
        }

        if (debug)
            stats_print(&stats, "total", -1);

        if (stats.mbreaderr || stats.mbreadcmperr || stats.getpagescmperr) {
            err = merr(EBUG);
            goto err_exit;
        }
    }

err_exit:
    mpool_close(mp);
    free(testv);

    if (!err) {
        strlcpy(dparams.mclass[HSE_MCLASS_CAPACITY].path, path,
                sizeof(dparams.mclass[HSE_MCLASS_CAPACITY].path));
        err = mpool_destroy(path, &dparams);
        if (err)
            fprintf(stderr, "mpool destroy at path %s failed\n", path);
    }

    free(path);
    hse_fini();

    if (err)
        exit(1);

    return 0;
}
