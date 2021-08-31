/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 *
 * This program stress tests the Bonsai tree insert and delete capabilities.
 */

#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <ctype.h>
#include <sysexits.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include <bsd/string.h>
#include <curses.h>
#include <term.h>
#include <sys/sysinfo.h>

#include <hse/hse.h>
#include <hse/version.h>

#include <hse_util/platform.h>
#include <hse_util/compiler.h>
#include <hse_util/page.h>
#include <hse_util/timer.h>
#include <hse_util/mutex.h>
#include <hse_util/bonsai_tree.h>

#include <xoroshiro/xoroshiro.h>

/* clang-format off */

#ifndef __aligned
#define __aligned(_sz)      __attribute__((__aligned__(_sz)))
#endif

#define __read_mostly       __attribute__((__section__(".read_mostly")))
#define __unused            __attribute__((__unused__))

#ifndef timespecsub
/* From FreeBSD */
#define timespecsub(tsp, usp, vsp)                        \
    do {                                                  \
        (vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;    \
        (vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec; \
        if ((vsp)->tv_nsec < 0) {                         \
            (vsp)->tv_sec--;                              \
            (vsp)->tv_nsec += 1000000000L;                \
        }                                                 \
    } while (0)
#endif

struct suftab {
    const char *list;   /* list of suffix characters */
    double      mult[]; /* list of multipliers */
};

/* kibibytes, mebibytes, ..., including the dd suffixes b and w.
 */
struct suftab suftab_iec = {
    "kmgtpezybw",
    { 0x1p10, 0x1p20, 0x1p30, 0x1p40, 0x1p50, 0x1p60, 0x1p70, 0x1p80, 512, sizeof(int) }
};

/* kilo, mega, giga, ...
 */
struct suftab suftab_si = { "kmgtpezy", { 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24 } };

/* seconds, minutes, hours, days, weeks, years, centuries.
 */
struct suftab suftab_time_t = {
    "smhdwyc",
    { 1, 60, 3600, 86400, 86400 * 7, 86400 * 365, 86400 * 365 * 100ul, }
};

typedef struct timespec tsi_t;

struct stats {
    u_long finds;
    u_long inserts;
    u_long deletes;
    u_long vgetlen;
    u_long vputlen;
    u_long latmin;
    u_long latmax;
    u_long lattot;
    u_long iters;
    u_long usecs;
    u_long nerrs;
} __aligned(64);

struct tdargs {
    struct stats stats;
    pthread_t    tid;
    uint64_t     seed;
    u_int        job;
    bool         full;
};

const u_char u64tostrtab[] __aligned(64) =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

uint8_t strtou64tab[256] __read_mostly;

struct kvtree {
    struct mutex        kvt_lock __aligned(128);
    u_long              kvt_inserts;
    u_long              kvt_deletes;

    struct bonsai_root *kvt_root __aligned(64);
};

struct kvrec {
    u_int          kvr_lock;
    u_int          kvr_keylen;
    uint64_t       kvr_keyid;
    struct kvtree *kvr_tree;
    char           kvr_keybuf[40];
};

sig_atomic_t sigint         __read_mostly;
sig_atomic_t sigalrm        __read_mostly;

struct kvtree *kvtreev      __read_mostly;
u_int kvtreec               __read_mostly;

struct kvrec *kvrecv        __read_mostly;
u_int kvrecc                __read_mostly;
u_int kvrecc_shift          __read_mostly;

u_int keybase               __read_mostly;
u_long updateprob           __read_mostly;

pthread_barrier_t bnt_barrier;

u_long testsecs = 60;

u_int tjobsmax, cjobsmax;

char *progname;
char *tgs_clrtoeol;
int verbosity;
u_long mark;

bool dryrun;
bool human;

static bonsai_ior_cb bnt_ior_cb;

static int bnt_test(void);
static void *bnt_test_main(void *arg);

static int bnt_check(void);
static void *bnt_check_main(void *arg);

static thread_local uint64_t xrand64_state[2];

static void
xrand64_init(uint64_t seed)
{
    if (seed == 0) {
        while (!(seed >> 56))
            seed = (seed << 8) | (__builtin_ia32_rdtsc() & 0xfful);
    }

    xoroshiro128plus_init(xrand64_state, seed);
}

static uint64_t
xrand64(void)
{
    return xoroshiro128plus(xrand64_state);
}

static inline __attribute__((const)) unsigned int
ilog2(unsigned long n)
{
    assert(n > 0);

    return (NBBY * sizeof(n) - 1) - __builtin_clzl(n);
}

/* Start a time stamp interval...
 */
void
tsi_start(tsi_t *tsip)
{
    clock_gettime(CLOCK_MONOTONIC, tsip);
}

/* Return the time interval in usecs since the given time stamp...
 */
u_long
tsi_delta(tsi_t *startp)
{
    tsi_t now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    timespecsub(&now, startp, &now);

    return now.tv_sec * 1000000 + now.tv_nsec / 1000;
}

static thread_local char    dmsg[256], emsg[256];
static thread_local int     dmsglen, emsglen;
static thread_local ssize_t dcc, ecc;
static thread_local u_int   job = UINT_MAX;

int
dputc(int c)
{
    dmsg[dmsglen++] = c;

    return c;
}

__attribute__((format(printf, 2, 3))) void
dprint(int lvl, const char *fmt, ...)
{
    size_t  dmsgsz = sizeof(dmsg) - 8;
    va_list ap;
    int     n;

    if (lvl > verbosity)
        return;

    dmsglen = 0;
    if (tgs_clrtoeol)
        dmsg[dmsglen++] = '\r';

    if (job < UINT_MAX) {
        n = snprintf(dmsg, dmsgsz, "%4u ", job);
        dmsglen += (n > 0) ? MIN(n, dmsgsz) : 0;
    }

    va_start(ap, fmt);
    n = vsnprintf(dmsg + dmsglen, dmsgsz - dmsglen, fmt, ap);
    dmsglen += (n > 0) ? MIN(n, dmsgsz - dmsglen) : 0;
    va_end(ap);

    if (tgs_clrtoeol)
        tputs(tgs_clrtoeol, 1, dputc);

    dmsg[dmsglen++] = '\n';

    dcc = write(1, dmsg, dmsglen);
}

int
eputc(int c)
{
    emsg[emsglen++] = c;

    return c;
}

__attribute__((format(printf, 2, 3))) void
eprint(hse_err_t err, const char *fmt, ...)
{
    size_t  emsgsz = sizeof(emsg) - 8;
    va_list ap;
    int     n;

    emsglen = snprintf(emsg, emsgsz, "%s: ", progname);

    if (job < UINT_MAX) {
        n = snprintf(emsg + emsglen, emsgsz - emsglen, "%4u ", job);
        emsglen += (n > 0) ? MIN(n, emsgsz - emsglen) : 0;
    }

    va_start(ap, fmt);
    n = vsnprintf(emsg + emsglen, emsgsz - emsglen, fmt, ap);
    emsglen += (n > 0) ? MIN(n, emsgsz - emsglen) : 0;
    va_end(ap);

    if (err) {
        emsglen += strlen(strcat(emsg + emsglen, ": "));
        hse_strerror(err, emsg + emsglen, emsgsz - emsglen);
        emsglen += strlen(emsg + emsglen);
    }

    emsglen = MIN(emsglen, emsgsz);

    if (tgs_clrtoeol)
        tputs(tgs_clrtoeol, 1, eputc);

    emsg[emsglen++] = '\n';

    ecc = write(2, emsg, emsglen);
}

__attribute__((format(printf, 1, 2))) void
status(const char *fmt, ...)
{
    size_t  dmsgsz = sizeof(dmsg) - 8;
    va_list ap;
    int     n;

    if (verbosity < 1)
        return;

    dmsglen = 0;
    if (tgs_clrtoeol)
        dmsg[dmsglen++] = '\r';

    va_start(ap, fmt);
    n = vsnprintf(dmsg + dmsglen, dmsgsz - dmsglen, fmt, ap);
    dmsglen += (n > 0) ? MIN(n, dmsgsz - dmsglen) : 0;
    va_end(ap);

    if (tgs_clrtoeol) {
        tputs(tgs_clrtoeol, 1, dputc);
        dmsg[dmsglen++] = '\r';
    } else {
        dmsg[dmsglen++] = '\n';
    }

    dcc = write(1, dmsg, dmsglen);
}

void
humanize(u_long *nump, char **sufp)
{
    if (*nump >= 10000000ul) {
        *nump /= 1000000;
        *sufp = "m";
    } else if (*nump > 10000ul) {
        *nump /= 1000;
        *sufp = "k";
    }
}

__attribute__((format(printf, 1, 2))) void
syntax(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(emsg, sizeof(emsg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, emsg);
}

uint64_t
strtou64(const void *str, char **endp, u_int base)
{
    const uint8_t *p8 = str;
    uint64_t       acc = 0, val;

    while (isspace(*p8))
        ++p8;

    while (*p8) {
        val = strtou64tab[*p8];

        if (val >= base)
            break;

        acc *= base;
        acc += val;
        ++p8;
    }

    if (endp)
        *endp = (char *)p8;

    return acc;
}

int
u64tostr(void *buf, size_t bufsz, uint64_t num, u_int base)
{
    uint64_t val = num;
    char *   right = buf;
    char *   left;
    int      len;

    assert(buf && base >= 2 && base < NELEM(u64tostrtab));

    do {
        uint64_t tmp = val;

        val /= base;
        *right++ = u64tostrtab[tmp - val * base];
    } while (val > 0);

    len = right - (char *)buf;
    assert(len < bufsz);

    *right-- = '\000';

    left = buf;
    while (left < right) {
        char tmp = *right;

        *right-- = *left;
        *left++ = tmp;
    }

    assert(base > 36 || num == strtoul(buf, NULL, base));

    return len;
}

void
strtou64_init(void)
{
    int i;

    for (i = 0; i < NELEM(strtou64tab); ++i)
        strtou64tab[i] = 255;

    for (i = 0; i < NELEM(u64tostrtab); ++i)
        strtou64tab[u64tostrtab[i]] = i;
}

u_long
cvt_strtoul(const char *str, char **endp, const struct suftab *suftab)
{
    char * pc, *end;
    u_long val;

    errno = 0;
    val = strtoul(str, &end, 0);

    if (!errno && end != str && *end && suftab) {
        pc = strchr(suftab->list, tolower(*end));
        if (pc) {
            val *= *(suftab->mult + (pc - suftab->list));
            ++end;
        }
    }

    if (endp)
        *endp = end;

    return val;
}

void
sigint_isr(int sig)
{
    ++sigint;
}

void
sigalrm_isr(int sig)
{
    ++sigalrm;
}

/* Reliable signal()...
 */
int
rsignal(int signo, __sighandler_t func)
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

static int
keyid2key(void *buf, size_t bufsz, uint64_t keyid, u_int base)
{
    if (base < 2) {
        uint8_t *buf8 = buf;

        while (keyid >= 256) {
            *buf8++ = keyid;
            keyid /= 256;
        }

        *buf8++ = keyid;

        return buf8 - (uint8_t *)buf;
    }

    return u64tostr(buf, bufsz, keyid, base);
}

static u_int
rid2skidx(u_int rid)
{
    return (rid / (PAGE_SIZE / sizeof(struct kvrec))) % 4;
}

static int
kvtree_init(void)
{
    hse_err_t err;
    size_t sz;

    sz = roundup(sizeof(*kvtreev) * kvtreec, alignof(*kvtreev) * 2);

    kvtreev = aligned_alloc(alignof(*kvtreev) * 2, sz);
    if (!kvtreev) {
        eprint(errno, "kvtreev %zu %u", sz, kvtreec);
        return EX_OSERR;
    }

    status("initializing %u kv trees...", kvtreec);

    for (u_int i = 0; i < kvtreec; ++i) {
        struct kvtree *kvt = kvtreev + i;

        memset(kvt, 0, sizeof(*kvt));
        mutex_init(&kvt->kvt_lock);
        err = bn_create(NULL, bnt_ior_cb, NULL, &kvt->kvt_root);
        if (err)
            abort();
    }

    status("\n");

    return 0;
}

static void
kvtree_fini(void)
{
    char buf[256];

    for (u_int i = 0; i < kvtreec; ++i) {
        struct kvtree *kvt = kvtreev + i;

        if (verbosity > 0 && bn_summary(kvt->kvt_root, buf, sizeof(buf)) > 0)
            printf("%2d: ins %lu  del %lu  %s\n",
                   i, kvt->kvt_inserts, kvt->kvt_deletes, buf);
        mutex_destroy(&kvt->kvt_lock);
        bn_destroy(kvt->kvt_root);
    }

    free(kvtreev);
}

static void
kvtree_lock(struct kvtree *kvt)
{
    mutex_lock(&kvt->kvt_lock);
}

static void
kvtree_unlock(struct kvtree *kvt)
{
    mutex_unlock(&kvt->kvt_lock);
}

int
kvrec_init(void)
{
    size_t sz;
    u_int rid;

    sz = roundup(sizeof(*kvrecv) * kvrecc, PAGE_SIZE);

    kvrecv = aligned_alloc(PAGE_SIZE, sz);
    if (!kvrecv) {
        eprint(errno, "kvrecv %zu %u", sz, kvrecc);
        return EX_OSERR;
    }

    status("initializing %u kv recs...", kvrecc);

    for (rid = 0; rid < kvrecc; ++rid) {
        struct kvrec *kvr = kvrecv + rid;
        int n;

        kvr->kvr_lock = 0;
        kvr->kvr_keyid = (UINT64_MAX << kvrecc_shift) | rid;
        kvr->kvr_tree = NULL;

        n = keyid2key(kvr->kvr_keybuf, sizeof(kvr->kvr_keybuf), kvr->kvr_keyid, keybase);
        if (n >= sizeof(kvr->kvr_keybuf)) {
            eprint(errno, "keyid %lx for rid %u exceeds sizeof keybuf %zu",
                   kvr->kvr_keyid, rid, sizeof(kvr->kvr_keybuf));
            return EX_SOFTWARE;
        }

        kvr->kvr_keylen = n;
    }

    status("\n");

    return 0;
}

void
kvrec_fini(void)
{
    free(kvrecv);
}

struct kvrec *
kvrec_trylock(u_int rid)
{
    struct kvrec *kvr = kvrecv + rid;
    u_int exp = 0;

    if (!__atomic_compare_exchange_n(&kvr->kvr_lock, &exp, 1, true,
                                     __ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
        return NULL;

    return kvr;
}

void
kvrec_unlock(u_int rid)
{
    struct kvrec *kvr = kvrecv + rid;
    u_int exp = 1;
    bool b __unused;

    b = __atomic_compare_exchange_n(&kvr->kvr_lock, &exp, 0, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
    assert(b);
}

u_long
prob_decode(const char *value, char **endp)
{
    double d;

    errno = 0;

    d = strtod(value, endp);
    if (errno)
        return d;

    if (d >= 1)
        return UINT64_MAX;

    return (d < 0) ? 0 : (d * UINT64_MAX);
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
    int rc;

    if (!list)
        return EINVAL;

    nvlist = strdup(list);
    if (!nvlist)
        return ENOMEM;

    nvlist_base = nvlist;
    value = NULL;
    rc = 0;

    while (nvlist) {
        char *end = NULL;

        while (isspace(*nvlist))
            ++nvlist;

        value = strsep(&nvlist, sep);
        name = strsep(&value, "=");

        if (verbosity > 2)
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

        if (0 == strcmp(name, "kvtreec")) {
            kvtreec = cvt_strtoul(value, &end, &suftab_iec);
            if (kvtreec < 1)
                kvtreec = 1;
        } else if (0 == strcmp(name, "updateprob")) {
            updateprob = prob_decode(value, &end);
        } else {
            eprint(0, "%s property '%s' ignored\n", valid ? "unhandled" : "invalid", name);
            continue;
        }

        if (errno || (end && *end)) {
            rc = errno ?: EINVAL;
            break;
        }
    }

    if (rc && value)
        syntax("invalid %s '%s': %s", name, value, strerror(rc));

    free(nvlist_base);

    return rc;
}

void
usage(void)
{
    printf("usage: %s [options] [name=value ...]\n", progname);
    printf("usage: %s -h\n", progname);
    printf("usage: %s -V\n", progname);
    printf("-b base   specify rid-to-key base [2 <= base <= %zu] (default: %u)\n",
           NELEM(u64tostrtab) - 1, keybase);
    printf("-h        show this help list\n");
    printf("-i kmax   limit initial load to at most kmax keys\n");
    printf("-j jobs   specify max number worker threads (default: %u)\n", tjobsmax);
    printf("-k kfmt   specify key generator snprintf format\n");
    printf("-m mark   show test status every mark seconds\n");
    printf("-n        dry run\n");
    printf("-o props  set one or more %s properties\n", progname);
    printf("-p        print numbers in machine-readable format\n");
    printf("-S seed   specify a seed for the RNG\n");
    printf("-t secs   specify test run time\n");
    printf("-V        show version\n");
    printf("-v        increase verbosity\n");
    printf("file  use '-' for stdin\n");
    printf("name  name of an HSE config or runtime parameter\n");

    if (verbosity == 0) {
        printf("\nuse -hv for detailed help\n");
        return;
    }

    printf("\nPROPERTIES:\n");
    printf("  kvtreec      specify number of bonsai trees (default: %u)\n", kvtreec);
    printf("  updateprob   probability to update a key (default: %.3lf)\n",
           (double)updateprob / ULONG_MAX);
}

int
main(int argc, char **argv)
{
    char area[64], *areap = area;
    bool help, version;
    char *keyfmt = NULL;
    u_long keymax;
    hse_err_t err;
    tsi_t tstart;
    int rc;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    version = help = false;
    human = true;

    setvbuf(stdout, NULL, _IONBF, 0);
    xrand64_init(0);
    strtou64_init();

    keymax = ULONG_MAX;

    updateprob = ULONG_MAX / 100 * 5;
    keybase = 10;

    if (isatty(1) && tgetent(NULL, getenv("TERM") ?: "noterm") > 0)
        tgs_clrtoeol = tgetstr("ce", &areap);

    while (1) {
        char *   errmsg, *end;
        uint64_t seed;
        int      c;

        c = getopt(argc, argv, ":b:hi:j:k:m:no:pS:t:Vv");
        if (-1 == c)
            break;

        errmsg = end = NULL;
        errno = 0;

        switch (c) {
        case 'b':
            errmsg = "invalid key base";
            keybase = strtoul(optarg, &end, 0);
            if (!errno && keybase > NELEM(u64tostrtab) - 1) {
                keybase = NELEM(u64tostrtab) - 1;
                eprint(0, "%s, using %u", errmsg, keybase);
            }
            break;

        case 'h':
            help = true;
            break;

        case 'i':
            errmsg = "invalid max keys";
            keymax = cvt_strtoul(optarg, &end, &suftab_iec);
            if (!errno) {
                if (end && *end && strchr(",:", *end)) {
                    errmsg = "invalid max init jobs";
                }
                if (!errno && keymax < 1)
                    keymax = 1;
            }
            break;

        case 'j':
            errmsg = "invalid max jobs";
            tjobsmax = strtoul(optarg, &end, 0);
            if (!errno) {
                if (tjobsmax > 1024) {
                    tjobsmax = 1024;
                    eprint(0, "%s, using %u", errmsg, cjobsmax);
                }

                if (end && *end && strchr(",:", *end)) {
                    errmsg = "invalid max check jobs";

                    cjobsmax = strtoul(end + 1, &end, 0);
                    if (!errno && cjobsmax > 1024) {
                        cjobsmax = 1024;
                        eprint(0, "%s, using %u", errmsg, cjobsmax);
                    }
                }
            }
            break;

        case 'k':
            keyfmt = optarg;
            break;

        case 'm':
            errmsg = "invalid progress mark";
            mark = cvt_strtoul(optarg, &end, &suftab_time_t);
            if (!errno && mark > 86400) {
                mark = 86400;
                eprint(0, "%s, using %lu", errmsg, mark);
            }
            break;

        case 'n':
            dryrun = true;
            break;

        case 'o':
            rc = prop_decode(optarg, ",", NULL);
            if (rc)
                exit(EX_USAGE);
            break;

        case 'p':
            human = false;
            break;

        case 'S':
            errmsg = "invalid seed";
            seed = cvt_strtoul(optarg, &end, &suftab_time_t);
            if (!errno)
                xrand64_init(seed);
            break;

        case 't':
            errmsg = "invalid test time";
            testsecs = cvt_strtoul(optarg, &end, &suftab_time_t);
            if (!errno && testsecs < 1)
                errno = EINVAL;
            if (!errno && end && *end && strchr(",:", *end)) {
                errmsg = "invalid max test jobs";
                tjobsmax = strtoul(end + 1, &end, 0);
                if (!errno && tjobsmax > 1024) {
                    tjobsmax = 1024;
                    eprint(0, "%s, using %u", errmsg, tjobsmax);
                }
            }
            break;

        case 'v':
            if (!mark)
                mark = 1;
            ++verbosity;
            break;

        case 'V':
            version = true;
            break;

        case '?':
            syntax("invalid option -%c", optopt);
            exit(EX_USAGE);

        case ':':
            syntax("option -%c requires a parameter", optopt);
            exit(EX_USAGE);

        default:
            eprint(0, "option -%c ignored", c);
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

    if (keymax < ULONG_MAX && !keyfmt) {
        kvrecc = keymax;
        keyfmt = "%08lx";
    }

    if (!tjobsmax)
        tjobsmax = (get_nprocs() * 3 / 4) + 1;
    if (!cjobsmax)
        cjobsmax = tjobsmax;

    if (!kvtreec)
        kvtreec = (tjobsmax / 2) + 1;

    if (!kvrecc)
        kvrecc = kvtreec << 20;

    kvrecc_shift = ilog2(kvrecc);
    if (kvrecc > (1u << kvrecc_shift))
        ++kvrecc_shift;

    if (keyfmt) {
        int klen;

        klen = snprintf(NULL, 0, keyfmt, keymax, keymax, keymax);

        if (klen < snprintf(NULL, 0, "%lx", keymax)) {
            eprint(EINVAL, "key format yields non-unique keys");
            return EX_USAGE;
        }

        if (klen > HSE_KVS_KEY_LEN_MAX) {
            eprint(EINVAL, "key format yields key longer than %u bytes", HSE_KVS_KEY_LEN_MAX);
            return EX_USAGE;
        }
    }

    if (help) {
        usage();
        exit(0);
    } else if (version) {
        printf("%s\n", HSE_VERSION_TAG);
        exit(0);
    }

    argc -= optind;
    argv += optind;

    tsi_start(&tstart);

    status("initializing hse...");
    err = hse_init(NULL, 0, NULL);
    if (err) {
        eprint(err, "hse_init");
        exit(EX_OSERR);
    }
    status("\n");

    rsignal(SIGHUP, sigint_isr);
    rsignal(SIGINT, sigint_isr);
    rsignal(SIGTERM, sigint_isr);
    rsignal(SIGUSR1, sigint_isr);
    rsignal(SIGUSR2, sigint_isr);

    rc = kvtree_init();
    if (rc)
        return rc;

    rc = kvrec_init();
    if (rc)
        return rc;

    dprint(1, "init completed in %.3lf seconds", tsi_delta(&tstart) / 1000000.0);

    tsi_start(&tstart);
    rc = bnt_test();
    if (rc)
        return rc;
    dprint(1, "test completed in %.3lf seconds", tsi_delta(&tstart) / 1000000.0);

    tsi_start(&tstart);
    rc = bnt_check();
    if (rc)
        return rc;
    dprint(1, "check completed in %.3lf seconds", tsi_delta(&tstart) / 1000000.0);

    tsi_start(&tstart);
    kvrec_fini();
    kvtree_fini();
    hse_fini();
    dprint(1, "fini completed %.3lf seconds", tsi_delta(&tstart) / 1000000.0);

    return rc;
}

static void
bnt_ior_cb(
    void *arg,
    enum bonsai_ior_code *code,
    struct bonsai_kv *kv,
    struct bonsai_val *newval,
    struct bonsai_val **oldvalp,
    uint height)
{
    assert(rcu_read_ongoing());

    if (IS_IOR_INS(*code)) {
        assert(newval == NULL);
        kv->bkv_valcnt++;
        return;
    }

    abort();
}

static int
bnt_test(void)
{
    sigset_t sigmask_block, sigmask_orig;
    struct tdargs *tdargv;
    struct itimerval itv;
    double uspercycle;
    tsi_t tstart;
    u_int done;
    int rc, i;

    char *itersuf = "";
    char *findsuf = "";
    char *inssuf = "";
    char *delsuf = "";

    if (sigint || testsecs < 1 || kvtreec < 1 || kvrecc < 1)
        return 0;

    if (tjobsmax * 2 > kvrecc)
        tjobsmax = (kvrecc / 2) | 1;

    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGTERM);
    sigaddset(&sigmask_block, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigmask_block, &sigmask_orig);

    tdargv = aligned_alloc(alignof(*tdargv), tjobsmax * sizeof(*tdargv));
    if (!tdargv) {
        eprint(errno, "calloc tdargv %u %zu", tjobsmax, sizeof(*tdargv));
        return EX_OSERR;
    }

    memset(tdargv, 0, tjobsmax * sizeof(*tdargv));

    rc = pthread_barrier_init(&bnt_barrier, NULL, tjobsmax);
    if (rc) {
        eprint(rc, "barrier init");
        free(tdargv);
        return EX_OSERR;
    }

    tsi_start(&tstart);

    status("testing...");

    for (i = 0; i < tjobsmax; ++i) {
        struct tdargs *args = tdargv + i;

        args->seed = xrand64();
        args->stats.latmin = ULONG_MAX;
        args->job = i;

        rc = pthread_create(&args->tid, NULL, bnt_test_main, args);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, tjobsmax);
            continue;
        }
    }

    memset(&itv, 0, sizeof(itv));
    itv.it_value.tv_sec = testsecs;
    rc = setitimer(ITIMER_REAL, &itv, NULL);
    if (rc) {
        eprint(errno, "setitimer");
        free(tdargv);
        return EX_OSERR;
    }

    pthread_sigmask(SIG_SETMASK, &sigmask_orig, NULL);
    rsignal(SIGALRM, sigalrm_isr);

    if (!(mark && isatty(1)))
        goto join;

    uspercycle = 1000000.0 / hse_tsc_freq;
    done = 0;

    while (done < tjobsmax && !(sigint || sigalrm)) {
        u_long iters = 0, finds = 0, inserts = 0, deletes = 0;
        u_long latmax = 0, latavg = 0;
        u_long latmin = ULONG_MAX;
        u_long delta, ips;
        char * ipssuf = "";

        usleep(mark * 1000000);
        done = 0;

        for (i = 0; i < tjobsmax; ++i) {
            finds += tdargv[i].stats.finds;
            inserts += tdargv[i].stats.inserts;
            deletes += tdargv[i].stats.deletes;

            if (tdargv[i].stats.latmin < latmin)
                latmin = tdargv[i].stats.latmin;
            if (tdargv[i].stats.latmax > latmax)
                latmax = tdargv[i].stats.latmax;
            latavg += tdargv[i].stats.lattot;

            iters += tdargv[i].stats.iters;
            done += (tdargv[i].stats.usecs > 0);
        }

        delta = tsi_delta(&tstart) / 1000000;
        if (delta == 0 || iters == 0)
            continue;

        latmin = latmin * uspercycle;
        latmax = latmax * uspercycle;
        latavg = (latavg * 128 * uspercycle) / iters;

        ips = iters / delta;

        if (human) {
            humanize(&ips, &ipssuf);
            humanize(&iters, &itersuf);
            humanize(&finds, &findsuf);
            humanize(&inserts, &inssuf);
            humanize(&deletes, &delsuf);
        }

        status("testing %lu %lu%s (%lu%s/s) %.2lf%%, find %lu%s, insert %lu%s, delete %lu%s, "
               "latency %lu %lu %lu",
               delta, iters, itersuf, ips, ipssuf,
               (delta * 100.0) / testsecs,
               finds, findsuf,
               inserts, inssuf,
               deletes, delsuf,
               latmin, latavg, latmax);
    }

join:
    for (i = 0; i < tjobsmax; ++i) {
        struct tdargs *args = tdargv + i;
        void *val;

        rc = pthread_join(args->tid, &val);
        if (rc) {
            eprint(rc, "pthread_join %d of %u", i, tjobsmax);
            continue;
        }

        if (val) {
            rc = (intptr_t)val;
            continue;
        }
    }

    if (verbosity > 0)
        putchar('\n');

    pthread_barrier_destroy(&bnt_barrier);
    free(tdargv);

    return rc;
}

static void *
bnt_test_main(void *arg)
{
    struct tdargs *args = arg;
    hse_err_t err;
    tsi_t tstart;
    int rc;

    job = args->job;
    xrand64_init(args->seed);

    rc = pthread_barrier_wait(&bnt_barrier);
    if (rc > 0) {
        eprint(rc, "barrier wait");
        pthread_exit((void *)(intptr_t)EX_OSERR);
    }

    tsi_start(&tstart);

    while (!(sigint || sigalrm)) {
        struct bonsai_skey skey;
        struct bonsai_sval sval;
        struct kvtree *kvt;
        struct kvrec *kvr;
        u_long cycles;
        u_int rid;

        rid = xrand64() % kvrecc;

        kvr = kvrec_trylock(rid);
        if (!kvr)
            continue;

        bn_skey_init(kvr->kvr_keybuf, kvr->kvr_keylen, 0, rid2skidx(rid), &skey);

        cycles = __builtin_ia32_rdtsc();
        kvt = kvr->kvr_tree;

        if (dryrun || xrand64() >= updateprob) {
            struct bonsai_kv *kv = NULL;
            size_t ulen, clen;
            bool found;

            /* Search the tree while holding the rcu read lock but not
             * the tree lock.
             */
            if (kvt) {
                rcu_read_lock();
                found = bn_find(kvt->kvt_root, &skey, &kv);
                if (!found)
                    abort();

                clen = bonsai_val_ulen(kv->bkv_values);
                ulen = bonsai_val_ulen(kv->bkv_values);
                if (clen != ulen)
                    abort();
                if (0 != memcmp(&kvr->kvr_keyid, kv->bkv_values->bv_value, ulen))
                    abort();
                rcu_read_unlock();

                ++args->stats.finds;
            }
        }
        else if (kvt) {
            kvtree_lock(kvt);

            rcu_read_lock();
            err = bn_delete(kvt->kvt_root, &skey);
            if (err)
                abort();
            rcu_read_unlock();

            ++kvt->kvt_deletes;
            kvtree_unlock(kvt);

            /* Generate a new key ID for next insert...
             */
            kvr->kvr_keyid = (xrand64() << kvrecc_shift) | rid;
            kvr->kvr_keylen = keyid2key(kvr->kvr_keybuf, sizeof(kvr->kvr_keybuf),
                                        kvr->kvr_keyid, keybase);

            ++args->stats.deletes;
            kvt = NULL;
        }
        else {
            bn_sval_init(&kvr->kvr_keyid, sizeof(kvr->kvr_keyid), 0, &sval);

            kvt = kvtreev + (xrand64() % kvtreec);

            kvtree_lock(kvt);

            rcu_read_lock();
            err = bn_insert_or_replace(kvt->kvt_root, &skey, &sval);
            if (err)
                abort();
            rcu_read_unlock();

            ++kvt->kvt_inserts;
            kvtree_unlock(kvt);

            ++args->stats.inserts;
        }

        cycles = __builtin_ia32_rdtsc() - cycles;

        kvr->kvr_tree = kvt;
        kvrec_unlock(rid);

        ++args->stats.iters;


        if (cycles < args->stats.latmin)
            args->stats.latmin = cycles;
        if (cycles > args->stats.latmax)
            args->stats.latmax = cycles;
        args->stats.lattot += cycles / 128;
    }

    args->stats.usecs = tsi_delta(&tstart);

    pthread_exit(NULL);
}

static int
bnt_check(void)
{
    sigset_t sigmask_block, sigmask_orig;
    struct tdargs *tdargv;
    double uspercycle;
    tsi_t tstart;
    u_int done;
    int rc, i;

    char *itersuf = "";
    char *findsuf = "";

    if (sigint || testsecs < 1 || kvtreec < 1 || kvrecc < 1)
        return 0;

    if (cjobsmax > kvrecc / 128)
        cjobsmax = (kvrecc / 128) | 1;

    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigmask_block, &sigmask_orig);

    tdargv = aligned_alloc(alignof(*tdargv), cjobsmax * sizeof(*tdargv));
    if (!tdargv) {
        eprint(errno, "calloc tdargv %u %zu", cjobsmax, sizeof(*tdargv));
        return EX_OSERR;
    }

    memset(tdargv, 0, cjobsmax * sizeof(*tdargv));

    rc = pthread_barrier_init(&bnt_barrier, NULL, cjobsmax);
    if (rc) {
        eprint(rc, "barrier init");
        free(tdargv);
        return EX_OSERR;
    }

    tsi_start(&tstart);

    status("checking...");

    for (i = 0; i < cjobsmax; ++i) {
        struct tdargs *args = tdargv + i;

        args->seed = xrand64();
        args->stats.latmin = ULONG_MAX;
        args->job = i;

        rc = pthread_create(&args->tid, NULL, bnt_check_main, args);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, cjobsmax);
            continue;
        }
    }

    if (!(mark && isatty(1)))
        goto join;

    uspercycle = 1000000.0 / hse_tsc_freq;
    done = 0;

    while (done < cjobsmax && !sigint) {
        u_long iters = 0, finds = 0;
        u_long latmax = 0, latavg = 0;
        u_long latmin = ULONG_MAX;
        u_long delta, ips;
        char * ipssuf = "";

        usleep(mark * 1000000);
        done = 0;

        for (i = 0; i < cjobsmax; ++i) {
            finds += tdargv[i].stats.finds;

            if (tdargv[i].stats.latmin < latmin)
                latmin = tdargv[i].stats.latmin;
            if (tdargv[i].stats.latmax > latmax)
                latmax = tdargv[i].stats.latmax;
            latavg += tdargv[i].stats.lattot;

            iters += tdargv[i].stats.iters;
            done += (tdargv[i].stats.usecs > 0);
        }

        delta = tsi_delta(&tstart) / 1000000;
        if (delta == 0 || iters == 0)
            continue;

        latmin = latmin * uspercycle;
        latmax = latmax * uspercycle;
        latavg = (latavg * 128 * uspercycle) / iters;

        ips = iters / delta;

        if (human) {
            humanize(&ips, &ipssuf);
            humanize(&iters, &itersuf);
            humanize(&finds, &findsuf);
        }

        status("checking %lu %lu%s (%lu%s/s) %.2lf%%, find %lu%s, "
               "latency %lu %lu %lu",
               delta, iters, itersuf, ips, ipssuf,
               (delta * 100.0) / testsecs,
               finds, findsuf,
               latmin, latavg, latmax);
    }

join:
    for (i = 0; i < cjobsmax; ++i) {
        struct tdargs *args = tdargv + i;
        void *val;

        rc = pthread_join(args->tid, &val);
        if (rc) {
            eprint(rc, "pthread_join %d of %u", i, cjobsmax);
            continue;
        }

        if (val) {
            rc = (intptr_t)val;
            continue;
        }
    }

    if (verbosity > 0)
        putchar('\n');

    pthread_barrier_destroy(&bnt_barrier);
    free(tdargv);

    return rc;
}

static void *
bnt_check_main(void *arg)
{
    struct tdargs *args = arg;
    u_int rid, ridmax;
    tsi_t tstart;
    int rc;

    job = args->job;
    xrand64_init(args->seed);

    rc = pthread_barrier_wait(&bnt_barrier);
    if (rc > 0) {
        eprint(rc, "barrier wait");
        pthread_exit((void *)(intptr_t)EX_OSERR);
    }

    tsi_start(&tstart);

    ridmax = kvrecc / cjobsmax;
    rid = args->job * ridmax;
    ridmax += rid;

    for (; rid < ridmax && !sigint; ++rid) {
        struct bonsai_skey skey;
        struct kvrec *kvr;
        size_t ulen, clen;
        u_long cycles;

        kvr = kvrec_trylock(rid);
        if (!kvr)
            abort();

        cycles = __builtin_ia32_rdtsc();

        if (kvr->kvr_tree) {
            struct bonsai_kv *kv = NULL;
            bool found;

            bn_skey_init(kvr->kvr_keybuf, kvr->kvr_keylen, 0, rid2skidx(rid), &skey);

            rcu_read_lock();
            found = bn_find(kvr->kvr_tree->kvt_root, &skey, &kv);
            if (!found)
                abort();

            clen = bonsai_val_ulen(kv->bkv_values);
            ulen = bonsai_val_ulen(kv->bkv_values);
            if (clen != ulen)
                abort();
            if (0 != memcmp(&kvr->kvr_keyid, kv->bkv_values->bv_value, ulen))
                abort();
            rcu_read_unlock();

            ++args->stats.finds;
        }
        kvrec_unlock(rid);

        cycles = __builtin_ia32_rdtsc() - cycles;
        ++args->stats.iters;

        if (cycles < args->stats.latmin)
            args->stats.latmin = cycles;
        if (cycles > args->stats.latmax)
            args->stats.latmax = cycles;
        args->stats.lattot += cycles / 128;
    }

    args->stats.usecs = tsi_delta(&tstart);

    pthread_exit(NULL);
}

/* clang-format on */
