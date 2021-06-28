/*
 * Stress + data integrity test tool for HSE KVDB.
 *
 * kvt creates simple database and continuously transforms it such that
 * the integrity of the database can be verified at any time.  It performs
 * this work in three distinct phases: load, test, and check.
 *
 * In the load phase all tables are first created and then loaded with keys
 * and values which either come from a given list of files or are generated
 * by kvt.  Each thread in the test phase continuously selects a random
 * record, verifies its integrity, and then transforms it to a new stat.
 * The check phase simply reads all the records, verifies that they each
 * are correct, and afterward verifies that the database as a whole is
 * in the expected state.
 *
 * How to run:
 *
 * Load: There are several way to load the database.
 *
 * 1) Load keys from a file or stdin.  In this mode the given file names
 * are used as the keys to the inodes table, and the first 1MB of file
 * data is used as the key's value in its data table:
 *
 *     $ find /var/tmp/ | kvt -f- -v mp0
 *
 * Specify the -l option to exclude files that don't have at least vlenmin
 * bytes, and to limit the value size to at most vlenmax bytes:
 *
 *     1a) -l 1,100    Exclude zero-length files and use at most 100 bytes
 *                     of the file data for the value
 *
 *     1b) -l 1048576  Use at most 1MB of the file data for the value
 *                     including zero-length files (this is the default)
 *
 *
 * 2) Load self-generated keys.  In this mode kvt will generate keys from
 * a default snprintf format or one given on the command line via the -k
 * option.  The -i option specifies the max number of keys to generate
 * (in this case 128 million), and the value will be randomly chosen
 * binary data with a random length between 0 and 128 bytes:
 *
 *    $ kvt -i128m -kfoo%lx -v mp0
 *
 * Specify the -l option to specify each key's value length.  For example:
 *
 *     2a) -l 127   All values will be exactly 127 bytes long (this is the default)
 *
 *     2b) -l 7,32  Value lengths will be random chosen between 7 and 2 bytes
 *
 * Specify the "runlen" property to use printable ASCII for the value data:
 *
 *     2c) -o runlen=7   Data will be random printable ASCII where each
 *                       each run of 7 bytes are identical.
 *
 *     2d) -o runlen=1   Data will be random printable ASCII data
 *
 *     2e) -o runlen=0   Data will be random binary data (this is the default)
 *
 *
 * Test
 *
 * 3) Run the test for 1 hour, performing a full data integrity check
 * after the test phase finishes.  The default probability that a key
 * will be updated is .50, but you can change that with the "updateprob"
 * property:
 *
 *     $ kvt -t1h -cv -o updateprob=.20 mp0
 *
 *
 * 4) Run a fully transactional test for 15 minutes, performing a full
 * data integrity check after the test finishes:
 *
 *     $ kvt -T15m -cv mp0
 *
 *
 * 5) Like (4), but kill (with SIGKILL) the test at a random time between
 * 200 and 400 seconds (i.e., it may or may not kill itself).  We run this
 * in a loop in order to test kvdb's log replay.  We provide an additional
 * -c option to perform a full data integrity check both before and after
 * the test:
 *
 *    $ while : ; do kvt -T300 -ccv -K9,200,400 mp0; done
 *
 *
 * Check
 *
 * 6) Verify that all records exist in the tables where we expect to find
 * them, and that there are no data integity errors:
 *
 *    $ kvt -cv mp0
 *
 *
 * 7) Like (6), but only check that the rids table and inodes keys are
 * intact (does not verify key values hence it cannot verify the data
 * integrity of the full database):
 *
 *
 * Misc
 *
 * You can run all phases in a single command:
 *
 *    $ kvt -i128m -T6h -cv mp0
 *
 * The default number of jobs (i.e. threads) used in all phases is determined
 * the kvt's initial cpu set.  However, you can specify the max number of
 * jobs to be used in all phases via the -j option, and you may individually
 * specify the max number of jobs for both the init and test phases by
 * appending it to the option.  For example, to use 192 load threads and
 * 333 test threads:
 *
 *    $ kvt -i128m,192 -T1h,333 -cv mp0
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdalign.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sysexits.h>
#include <math.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/resource.h>

#include <bsd/string.h>
#include <curses.h>
#include <term.h>

#include <hse/hse.h>

#include <tools/parm_groups.h>

#include <xoroshiro/xoroshiro.h>
#include <3rdparty/murmur3.h>

/* clang-format off */

#define NELEM(_arr)         (sizeof(_arr) / sizeof((_arr)[0]))
#define SCALEPOW2           (1ul << 32)

/* Base table names.  Note that both the inodes and data table
 * have their index appended to the base name.
 */
#define KVS_RIDS_NAME       "rids"
#define KVS_TOMBS_NAME      "tombs"
#define KVS_INODES_NAME     "inodes"
#define KVS_DATA_NAME       "data"

enum kvs_type {
    kvs_type_unknown,
    kvs_type_rids,
    kvs_type_tombs,
    kvs_type_inodes,
    kvs_type_data
};

/* inodes table record flags
 */
#define KF_ENTOMBED         (0x0001)

#ifndef thread_local
#define thread_local        _Thread_local
#endif

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
struct suftab suftab_si = {
    "kmgtpezy",
    { 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24 }
};

/* seconds, minutes, hours, days, weeks, years, centuries.
 */
struct suftab suftab_time_t = {
    "smhdwyc",
    { 1, 60, 3600, 86400, 86400 * 7, 84600 * 365, 86400 * 365 * 100ul, }
};

/* clang-format on */

typedef struct timespec tsi_t;

struct stats {
    u_long gets;
    u_long puts;
    u_long dels;
    u_long commits;
    u_long aborts;
    u_long entombs;
    u_long delays;
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
    uint64_t     hashv[2];
    size_t       databufsz;
    char *       databuf;
    pthread_t    tid;
    uint64_t     seed;
    u_int        job;
    bool         full;
    bool         dump;
};

struct work {
    struct work *next;
    u_long       rid;
    u_long       span;
    size_t       fnlen;
    const char * keyfmt;
    char         fn[HSE_KVS_KLEN_MAX + 1];
};

struct workq {
    u_long rid __aligned(64 * 2); /* updated atomically */

    bool   running __aligned(64);
    u_int  lwm;
    u_int  hwm;
    char * randbuf;
    size_t randbufsz;

    pthread_mutex_t mtx __aligned(64);
    struct work * head;
    struct work **tail;
    struct work * free;
    u_int         cnt;

    u_long         p_waits __aligned(64);
    u_long         p_wakeups;
    pthread_cond_t p_cv; /* producer */

    u_long         c_waits __aligned(64);
    u_long         c_wakeups;
    pthread_cond_t c_cv; /* consumer */
};

const u_char u64tostrtab[] __aligned(64) =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
uint8_t strtou64tab[256] __read_mostly;

struct hse_kvdb *kvdb __read_mostly;
sig_atomic_t sigint   __read_mostly;
sig_atomic_t sigusr1  __read_mostly;
sig_atomic_t sigalrm  __read_mostly;
size_t ridlockc       __read_mostly;
u_int *ridlockv       __read_mostly;

u_long ridmax                __read_mostly;
u_long kvs_datac             __read_mostly;
u_long kvs_inodesc           __read_mostly;
struct hse_kvs *kvs_rids     __read_mostly;
struct hse_kvs *kvs_tombs    __read_mostly;
struct hse_kvs **kvs_inodesv __read_mostly;
struct hse_kvs **kvs_datav   __read_mostly;

u_long txncdlyprob __read_mostly;
u_long txnfreeprob __read_mostly;
u_long updateprob  __read_mostly;
u_long tombprob    __read_mostly;

pthread_barrier_t kvt_test_barrier;
uint64_t          hash0, hash1;
struct workq      workq;

u_long killsecs = ULONG_MAX;
u_long testsecs;
int    killsig;
u_int  ridkeybase = NELEM(u64tostrtab) - 1;
size_t vlenmax = 127;
size_t vlenmin;
size_t vrunlen;
size_t ridpfxlen;
bool vcomp;

u_int     ijobsmax, tjobsmax, cjobsmax;
cpu_set_t cpuset;
// ends in _ because it will conflict with tsc_freq defined in hse/src/util/src/timer.c
u_long tsc_freq_;

char * progname, *mpname;
char * tgs_clrtoeol;
int    verbosity;
u_long mark;

bool initchkdups;
bool testtxn;
bool headers;
bool dryrun;
bool human;
bool force;

bool  sync_enabled = false;
ulong sync_timeout_ms = 0;

struct parm_groups *pg;

struct svec db_oparms;
struct svec rids_oparms, rids_cparms;
struct svec inodes_oparms, inodes_cparms;
struct svec tombs_oparms, tombs_cparms;
struct svec data_oparms, data_cparms;
struct svec empty_parms;


static int
kvt_create(
    const char *       mpname,
    const char *       keyfile,
    const char *       keyfmt,
    u_long             keymax,
    bool *             dump);

static int
kvt_open(u_int kvs_listc, char **kvs_listv);

static int
kvt_init(const char *keyfile, const char *keyfmt, u_long keymax, bool dump);

static void *
kvt_init_main(void *arg);

static int
kvt_check(int level, bool dump);

static void *
kvt_check_main(void *arg);

static int
kvt_test(void);

static void *
kvt_test_main(void *arg);

static int
kvt_test_impl(struct tdargs *args, unsigned int flags, struct hse_kvdb_txn *txn, u_long rid);

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
        hse_err_to_string(err, emsg + emsglen, emsgsz - emsglen, NULL);
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

#ifdef DEBUG
    uint64_t numv[] = { 0,
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        13,
                        14,
                        15,
                        16,
                        17,
                        18,
                        19,
                        31,
                        32,
                        33,
                        35,
                        36,
                        37,
                        63,
                        64,
                        65,
                        UINT8_MAX - 1,
                        UINT8_MAX,
                        UINT8_MAX + 1ul,
                        UINT16_MAX - 1,
                        UINT16_MAX,
                        UINT16_MAX + 1ul,
                        UINT32_MAX - 1,
                        UINT32_MAX,
                        UINT32_MAX + 1ul,
                        UINT64_MAX - 1,
                        UINT64_MAX };
    char     buf[1024], *end, *pc;
    uint64_t val;

    for (i = 0; i < NELEM(numv); ++i) {
        int basev[] = { 2,
                        3,
                        4,
                        5,
                        7,
                        8,
                        9,
                        10,
                        11,
                        15,
                        16,
                        17,
                        35,
                        36,
                        37,
                        NELEM(u64tostrtab) - 2,
                        NELEM(u64tostrtab) - 1 };
        int j;

        pc = buf;
        for (j = 0; j < NELEM(basev); ++j) {
            assert(pc - buf < sizeof(buf));
            pc += u64tostr(pc, sizeof(buf) - (pc - buf), numv[i], basev[j]);
            *pc++ = ' ';
        }

        *pc = '\000';
        end = buf;

        for (j = 0; j < NELEM(basev); ++j) {
            val = strtou64(end, &end, basev[j]);
            assert(val == numv[i]);
            assert(*end == ' ' || *end == '\000');
            ++end;
        }
    }
#endif
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
sigusr1_isr(int sig)
{
    ++sigusr1;
}

void
sigalrm_isr(int sig)
{
    if (killsig && killsecs <= testsecs && !sigint)
        kill(getpid(), killsig);

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


int
parm_vec_init(void)
{
    char *txn = testtxn ? "transactions_enable=1" : "transactions_enable=0";
    char *cmp = vcomp ? "value_compression=lz4" : "";
    char rids_pfx[64] = {};
    int rc = 0;

    if (ridpfxlen)
        snprintf(rids_pfx, sizeof(rids_pfx), "pfx_len=%zu", ridpfxlen);

    svec_init(&db_oparms);

    svec_init(&rids_oparms);
    svec_init(&data_oparms);
    svec_init(&tombs_oparms);
    svec_init(&inodes_oparms);

    svec_init(&rids_cparms);
    svec_init(&data_cparms);
    svec_init(&tombs_cparms);
    svec_init(&inodes_cparms);

    svec_init(&empty_parms);

    /* kvdb open params */
    rc = rc ?: svec_append_pg(&db_oparms, pg, "perfc_enable=0", PG_KVDB_OPEN, NULL);

    /* kvs open params: txn setting applies to all, only data and tombs get compression
     */
    rc = rc ?: svec_append_pg(&rids_oparms, pg, PG_KVS_OPEN, txn, NULL);
    rc = rc ?: svec_append_pg(&data_oparms, pg, PG_KVS_OPEN, txn, cmp, NULL);
    rc = rc ?: svec_append_pg(&tombs_oparms, pg, PG_KVS_OPEN, txn, cmp, NULL);
    rc = rc ?: svec_append_pg(&inodes_oparms, pg, PG_KVS_OPEN, txn, NULL);

    /* kvs create params
     */
    rc = rc ?: svec_append_pg(&rids_cparms, pg, PG_KVS_CREATE, rids_pfx, NULL);
    rc = rc ?: svec_append_pg(&data_cparms, pg, PG_KVS_CREATE, NULL);
    rc = rc ?: svec_append_pg(&tombs_cparms, pg, PG_KVS_CREATE, NULL);
    rc = rc ?: svec_append_pg(&inodes_cparms, pg, PG_KVS_CREATE, NULL);

    return rc;
}

void
parm_vec_fini(void)
{
    svec_reset(&db_oparms);
    svec_reset(&rids_oparms);
    svec_reset(&rids_cparms);
    svec_reset(&data_oparms);
    svec_reset(&data_cparms);
    svec_reset(&tombs_oparms);
    svec_reset(&tombs_cparms);
    svec_reset(&inodes_oparms);
    svec_reset(&inodes_cparms);
}

enum kvs_type
decode_kvs_name(
    const char *name,
    int *instance)
{
    *instance = 0;

    if (!strcmp(name, KVS_RIDS_NAME))
        return kvs_type_rids;

    if (!strcmp(name, KVS_TOMBS_NAME))
        return kvs_type_tombs;

    if (1 == sscanf(name, KVS_INODES_NAME"%d", instance))
        return kvs_type_tombs;

    if (1 == sscanf(name, KVS_DATA_NAME"%d", instance))
        return kvs_type_data;

    return kvs_type_unknown;
}

struct svec *
kvs_cparms_get(const char *kvs_name)
{
    int instance;

    switch (decode_kvs_name(kvs_name, &instance)) {
        case kvs_type_rids:
            return &rids_cparms;
        case kvs_type_data:
            return &data_cparms;
        case kvs_type_tombs:
            return &tombs_cparms;
        case kvs_type_inodes:
            return &data_cparms;
        default:
            break;
    }

    return &empty_parms;
}

struct svec *
kvs_oparms_get(const char *kvs_name)
{
    int instance;

    switch (decode_kvs_name(kvs_name, &instance)) {
        case kvs_type_rids:
            return &rids_oparms;
        case kvs_type_data:
            return &data_oparms;
        case kvs_type_tombs:
            return &tombs_oparms;
        case kvs_type_inodes:
            return &data_oparms;
        default:
            break;
    }

    return &empty_parms;
}

int
ridlock_init(size_t nlocks)
{
    size_t sz;

    ridlockc = roundup(nlocks, 1024);

    sz = roundup(sizeof(*ridlockv) * ridlockc, 4096);

    ridlockv = aligned_alloc(4096, sz);
    if (!ridlockv) {
        eprint(errno, "ridlockv %zu %zu %zu", sz, ridlockc, nlocks);
        return EX_OSERR;
    }

    memset(ridlockv, 0, sz);

    return 0;
}

void
ridlock_fini(void)
{
    free(ridlockv);
}

bool
ridlock_trylock(u_long rid)
{
    if (!ridlockv)
        return true;

    u_int *bkt = ridlockv + (rid % ridlockc);
    u_int  exp = 0;

    return __atomic_compare_exchange_n(bkt, &exp, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

void
ridlock_unlock(u_long rid)
{
    if (!ridlockv)
        return;

    u_int *bkt = ridlockv + (rid % ridlockc);
    u_int  exp = 1;

    __atomic_compare_exchange_n(bkt, &exp, 0, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

int
rid2key(void *buf, size_t bufsz, u_long rid, u_int base)
{
    if (base < 2) {
        uint8_t *p = buf;

        p[4] = rid & 0xfflu;
        p[3] = (rid >> 8) & 0xfflu;
        p[2] = (rid >> 16) & 0xfflu;
        p[1] = (rid >> 24) & 0xfflu;
        p[0] = (rid >> 32) & 0xfflu;
        return 5;
    }

    return u64tostr(buf, bufsz, rid, base);
}

static inline u_int
rid2inodes_idx(u_long rid)
{
    return rid % kvs_inodesc;
}

struct hse_kvs *
rid2inodes_kvs(u_long rid)
{
    return kvs_inodesv[rid2inodes_idx(rid)];
}

static inline u_int
rid2data_idx(u_long rid)
{
    return (rid & 0xfflu) % kvs_datac;
}

struct hse_kvs *
rid2data_kvs(u_long rid)
{
    return kvs_datav[rid2data_idx(rid)];
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
    int   rc;

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

        if (0 == strcmp(name, "datac")) {
            kvs_datac = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "inodesc")) {
            kvs_inodesc = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "txncdlyprob")) {
            txncdlyprob = prob_decode(value, &end);
        } else if (0 == strcmp(name, "txnfreeprob")) {
            txnfreeprob = prob_decode(value, &end);
        } else if (0 == strcmp(name, "tombprob")) {
            tombprob = prob_decode(value, &end);
        } else if (0 == strcmp(name, "updateprob")) {
            updateprob = prob_decode(value, &end);
        } else if (0 == strcmp(name, "vrunlen")) {
            vrunlen = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "ridpfxlen")) {
            ridpfxlen = cvt_strtoul(value, &end, &suftab_iec);
            if (ridpfxlen > 100) {
                eprint(0, "ridpfxlen too large: %zu (max value is 100)\n", ridpfxlen);
                errno = EINVAL;
            }
        } else if (0 == strcmp(name, "vcomp")) {
            vcomp = (bool)cvt_strtoul(value, &end, &suftab_iec);
        } else {
            eprint(0, "%s property '%s' ignored", valid ? "unhandled" : "invalid", name);
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

void *
periodic_sync(void *arg)
{
    struct timespec timeout = {
        .tv_sec = (sync_timeout_ms * 1000000) / 1000000,
        .tv_nsec = (sync_timeout_ms * 1000000) % 1000000
    };
    sigset_t sigmask;
    hse_err_t err;
    int rc;

    /* spawn() will send this thread a SIGUSR1 which will knock
     * it out of ppoll() (if necessary) and then cause it to exit.
     */
    pthread_sigmask(SIG_BLOCK, NULL, &sigmask);
    sigdelset(&sigmask, SIGUSR1);

    while (!sigusr1) {
        rc = ppoll(NULL, 0, &timeout, &sigmask);
        if (rc)
            continue;

        err = hse_kvdb_sync(kvdb);
        if (err)
            eprint(err, "%s: failed to sync kvdb", __func__);
    }

    pthread_exit(NULL);
}

void
usage(void)
{
    printf("usage: %s [options] kvdb [name=value ...]\n", progname);
    printf("usage: %s -h\n", progname);
    printf("usage: %s -V\n", progname);
    printf(
        "-b base   specify rid-to-key base [2 <= base <= %zu] (default: %u)\n",
        NELEM(u64tostrtab) - 1,
        ridkeybase);
    printf("-c        perform a full data integrity check of the kvdb\n");
    printf("-f file   initialize kvdb using keys from file (one key per line)\n");
    printf("-h        show this help list\n");
    printf("-i kmax   limit initial load to at most kmax keys\n");
    printf("-j jobs   specify max number worker threads (default: %u)\n", tjobsmax);
    printf("-K ksig   kill test workers at end of test (test mode only)\n");
    printf("-k kfmt   specify key generator snprintf format\n");
    printf(
        "-l vlen   specify min/max value length during load (default: %lu,%lu)\n",
        vlenmin,
        vlenmax);
    printf("-m mark   show test status every mark seconds\n");
    printf("-n        dry run\n");
    printf("-o props  set one or more %s properties\n", progname);
    printf("-p        print numbers in machine-readable format\n");
    printf("-S seed   specify a seed for the RNG\n");
    printf("-T secs   specify test run time (with transactions)\n");
    printf("-t secs   specify test run time (no transactions)\n");
    printf("-v        increase verbosity\n");
    printf("-y sync   time in milliseconds for periodic syncs");
    printf("file  use '-' for stdin\n");
    printf("ksig  sig[,min[,max]] specify signal and min/max time range\n");
    printf("name  name of an HSE config or runtime parameter\n");
    printf("kvdb  name of an mpool formatted as a kvdb\n");
    printf("vlen  random value length between [vlenmin,]vlenmax\n");

    if (verbosity == 0) {
        printf("\nuse -hv for detailed help\n");
        return;
    }

    printf("\nPROPERTIES:\n");
    printf("  datac        specify number of data tables (default: %lu)\n", kvs_datac);
    printf("  inodesc      specify number of inodes tables (default: %lu)\n", kvs_inodesc);
    printf(
        "  txncdlyprob  probabilty to delay a commit (default: %lf)\n",
        (double)txncdlyprob / UINT64_MAX);
    printf(
        "  txnfreeprob  probability to free a txn buffer (default: %lf)\n",
        (double)txnfreeprob / UINT64_MAX);
    printf(
        "  tombprob     probability to entomb an inode (default: %lf)\n",
        (double)tombprob / UINT64_MAX);
    printf(
        "  updateprob   probability to update a key (default: %lf)\n",
        (double)updateprob / UINT64_MAX);
    printf("  vrunlen      generated ascii value run length (default: %zu)\n", vrunlen);
    printf("  vcomp        enable value compression for data and tomb kvs (default: %d)\n", vcomp);
    printf("  ridpfxlen    set prefix len of rid kvs (default:  %zu)\n", ridpfxlen);

    printf("\nEXAMPLES:\n");
    printf("  load files:  find /usr | kvt -f- -cv mykvdb\n");
    printf("  load keys:   kvt -i128m -cv mykvdb\n");
    printf("  check:       kvt -cv mykvdb\n");
    printf("  test:        kvt -t60 mykvdb\n");
    printf("  test txn:    kvt -T60 mykvdb\n");
    printf("  combo:       kvt -i128m -t60 -cv mykvdb\n");

    printf("\nsee comments at top of kvt.c for more detailed examples\n");
}

int
main(int argc, char **argv)
{
    char               area[64], *areap = area;
    bool               help, dump;
    u_long             killmin, killmax;
    char *             keyfile = NULL;
    char *             keyfmt = NULL;
    int                check, rc;
    u_long             keymax;
    hse_err_t          err;
    tsi_t              tstart;
    FILE *             fp;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    dump = help = testtxn = false;
    initchkdups = headers = human = true;
    check = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    xrand64_init(0);
    strtou64_init();

    killmin = killmax = ULONG_MAX;
    keymax = ULONG_MAX;
    kvs_inodesc = 7;
    kvs_datac = 23;

    txncdlyprob = UINT64_MAX / 100000 * 3;
    txnfreeprob = UINT64_MAX / 100 * 3;
    updateprob = UINT64_MAX / 100 * 50;
    tombprob = UINT64_MAX / 100 * 13;

    if (isatty(1) && tgetent(NULL, getenv("TERM") ?: "dumb") > 0)
        tgs_clrtoeol = tgetstr("ce", &areap);

    rc = pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    if (rc) {
        eprint(rc, "pthread_getaffinity_np");
        exit(EX_OSERR);
    }

    tsc_freq_ = 1000000000;

#if __amd64__
    fp = popen("lscpu | sed -En 's/^Model.*([0-9].[0-9]+.)Hz$/\\1/p'", "r");
    if (fp) {
        char   line[256], *end;
        double val;

        if (fgets(line, sizeof(line), fp)) {
            errno = 0;
            val = strtod(line, &end);
            if (!errno && end != line) {
                tsc_freq_ = val * 1000000;
                if (tolower(*end) == 'g')
                    tsc_freq_ *= 1000;
            }
        }
        pclose(fp);
    }
#endif

    while (1) {
        char *   errmsg, *end;
        uint64_t seed;
        int      c;

        c = getopt(argc, argv, ":b:cDFf:hi:j:K:k:l:m:no:pS:T:t:vy:");
        if (-1 == c)
            break;

        errmsg = end = NULL;
        errno = 0;

        switch (c) {
            case 'b':
                errmsg = "invalid key base";
                ridkeybase = strtoul(optarg, &end, 0);
                if (!errno && ridkeybase > NELEM(u64tostrtab) - 1) {
                    ridkeybase = NELEM(u64tostrtab) - 1;
                    eprint(0, "%s, using %u", errmsg, ridkeybase);
                }
                break;

            case 'c':
                ++check;
                break;

            case 'D':
                dump = true;
                ++check;
                break;

            case 'F':
                force = true;
                break;

            case 'f':
                keyfile = optarg;
                break;

            case 'H':
                headers = false;
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
                        ijobsmax = strtoul(end + 1, &end, 0);
                        if (!errno && ijobsmax > 1024) {
                            ijobsmax = 1024;
                            eprint(0, "%s, using %u", errmsg, ijobsmax);
                        }
                    }
                    if (!errno && keymax < 1)
                        keymax = 1;
                }
                break;

            case 'j':
                errmsg = "invalid max jobs";
                cjobsmax = strtoul(optarg, &end, 0);
                if (!errno) {
                    if (cjobsmax > 1024) {
                        cjobsmax = 1024;
                        eprint(0, "%s, using %u", errmsg, cjobsmax);
                    }
                    if (!ijobsmax)
                        ijobsmax = cjobsmax;
                    if (!tjobsmax)
                        tjobsmax = cjobsmax;
                }
                break;

            case 'K':
                errmsg = "invalid kill signal";
                killsig = cvt_strtoul(optarg, &end, NULL);
                if (!errno && (killsig < 1 || killsig >= 31))
                    errno = EINVAL;
                if (!errno && end && *end && strchr(",:", *end)) {
                    errmsg = "invalid kill time";
                    killmin = cvt_strtoul(end + 1, &end, &suftab_time_t);
                    killmax = killmin;
                    if (!errno && killmin < 1)
                        errno = EINVAL;
                    if (!errno && end && *end && strchr(",:", *end)) {
                        errmsg = "invalid kill time range";
                        killmax = cvt_strtoul(end + 1, &end, &suftab_time_t);
                        if (!errno && killmax < killmin)
                            errno = EINVAL;
                    }
                }
                break;

            case 'k':
                keyfmt = optarg;
                break;

            case 'l':
                errmsg = "invalid max file length";
                vlenmax = cvt_strtoul(optarg, &end, &suftab_iec);
                vlenmin = vlenmax;
                if (!errno) {
                    if (end && *end && strchr(",:", *end)) {
                        errmsg = "invalid min file length";
                        vlenmax = cvt_strtoul(end + 1, &end, &suftab_iec);
                    }
                    if (vlenmax < vlenmin || vlenmax > HSE_KVS_VLEN_MAX)
                        errno = ERANGE;
                }
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

            case 'T':
                testtxn = true;
                /* FALLTHROUGH */

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

            case 'y':
                sync_enabled = true;
                sync_timeout_ms = strtoul(optarg, &end, 10);
                errmsg = "invalid sync timeout argument";
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

    if (keymax < ULONG_MAX && !keyfmt && !keyfile) {
        initchkdups = false;
        keyfmt = "%08lx";
    }

    if (keyfmt) {
        int klen;

        if (keyfile) {
            syntax("options -f and -k are mutually exclusive");
            exit(EX_USAGE);
        }

        klen = snprintf(NULL, 0, keyfmt, keymax, keymax, keymax);

        if (klen < snprintf(NULL, 0, "%lx", keymax)) {
            eprint(EINVAL, "key format yields non-unique keys");
            return EX_USAGE;
        }

        if (klen > HSE_KVS_KLEN_MAX) {
            eprint(EINVAL, "key format yields key longer than %u bytes", HSE_KVS_KLEN_MAX);
            return EX_USAGE;
        }
    }

    if (kvs_inodesc < 1 || kvs_inodesc > 255 || kvs_datac < 1 || kvs_datac > 255) {
        syntax("invalid inodesc (%lu) or datac (%lu)", kvs_inodesc, kvs_datac);
        return EX_USAGE;
    }
    if (kvs_inodesc + kvs_inodesc + 2 > HSE_KVS_COUNT_MAX) {
        syntax(
            "combined number of inodes and data tables must be less than %u",
            HSE_KVS_COUNT_MAX - 1);
        return EX_USAGE;
    }

    if (killsig) {
        if (killmin == ULONG_MAX)
            killmin = killmax = testsecs;
        killsecs = killmin + xrand64() % (killmax - killmin + 1);
    }

    if (help) {
        usage();
        exit(0);
    }

    if (argc - optind < 1) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

    mpname = argv[optind++];

    rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
    if (rc) {
        eprint(rc, "pg_create");
        exit(EX_OSERR);
    }

    rc = pg_parse_argv(pg, argc, argv, &optind);
    switch (rc) {
        case 0:
            if (optind < argc) {
                eprint(0, "unknown parameter: %s", argv[optind]);
                exit(EX_USAGE);
            }
            break;
        case EINVAL:
            eprint(0, "missing group name (e.g. %s) before parameter %s\n",
                PG_KVDB_OPEN, argv[optind]);
            exit(EX_USAGE);
            break;
        default:
            eprint(rc, "error processing parameter %s\n", argv[optind]);
            exit(EX_OSERR);
            break;
    }

    rc = parm_vec_init();
    if (rc) {
        eprint(rc, "svec_apppend_pg failed");
        exit(EX_OSERR);
    }

    tsi_start(&tstart);
    status("initializing hse...");

    err = hse_init(0, NULL);
    if (err) {
        eprint(err, "hse_kvb_init");
        exit(EX_OSERR);
    }

    status("opening kvdb %s...", mpname);

    err = hse_kvdb_open(mpname, db_oparms.strc, db_oparms.strv, &kvdb);
    if (err) {
        eprint(err, "unable to open kvdb `%s'", mpname);
        rc = EX_OSERR;
        goto errout;
    }

    dprint(1, "opened kvdb %s in %.3lf seconds", mpname, tsi_delta(&tstart) / 1000000.0);

    rsignal(SIGHUP, sigint_isr);
    rsignal(SIGINT, sigint_isr);
    rsignal(SIGTERM, sigint_isr);
    rsignal(SIGUSR1, sigusr1_isr);
    rsignal(SIGUSR2, sigint_isr);

    rc = kvt_create(mpname, keyfile, keyfmt, keymax, &dump);
    if (rc)
        goto errout;

    if (check > 1) {
        rc = kvt_check(check, false);
        if (rc)
            goto errout;
    }

    rc = kvt_test();
    if (rc)
        goto errout;

    rc = kvt_check(check, dump);

errout:
    tsi_start(&tstart);
    status("closing kvdb %s...", mpname);

    err = hse_kvdb_close(kvdb);
    if (err)
        eprint(err, "unable to close kvdb `%s'", mpname);

    dprint(1, "closed kvdb %s in %.3lf seconds", mpname, tsi_delta(&tstart) / 1000000.0);

    free(kvs_inodesv);
    hse_fini();
    ridlock_fini();
    parm_vec_fini();
    pg_destroy(pg);

    return rc;
}

static int
fnrec_encode(
    char *   buf,
    size_t   bufsz,
    u_long   rid,
    u_long   datasz,
    u_long   shift,
    u_long   flags,
    uint64_t hash)
{
    char *pc = buf;
    u_int base;

    /* Assume caller provides a sufficiently large buffer
     * for six large base 2 encoded numbers...
     */
    assert(bufsz >= 6 * 64);

    /* Choose a base in which to encode the large fields.  This
     * should yield a wildly varying fnrec length from record
     * to record.
     */
    base = (hash % (NELEM(u64tostrtab) - 2)) + 2;

    /* The first field is the base used to encode the remaining
     * fields, but is itself always encoded in base 10.
     */
    pc += u64tostr(pc, bufsz, base, 10);
    *pc++ = ' ';

    pc += u64tostr(pc, bufsz, rid, base);
    *pc++ = ' ';

    pc += u64tostr(pc, bufsz, datasz, base);
    *pc++ = ' ';

    pc += u64tostr(pc, bufsz, shift, base);
    *pc++ = ' ';

    pc += u64tostr(pc, bufsz, flags, 16);
    *pc++ = ' ';

    pc += u64tostr(pc, bufsz, hash, base);
    *pc = '\000';

    assert(pc - buf < bufsz);

    return pc - buf;
}

static void
fnrec_decode(
    char *    str,
    u_long *  ridp,
    u_long *  dataszp,
    u_long *  shiftp,
    u_long *  flagsp,
    uint64_t *hashp)
{
    u_int base;
    char *end;

    errno = 0;

    /* The first field is always the base used to encode
     * the remaining fields.
     */
    base = strtou64(str, &end, 10);

    if (base > NELEM(u64tostrtab) - 1) {
        eprint(EINVAL, "corrupt fnrec base %u; fnrec [%s]", base, str);
        abort();
    }

    *ridp = strtou64(end + 1, &end, base);

    *dataszp = strtou64(end + 1, &end, base);

    *shiftp = strtou64(end + 1, &end, base);

    *flagsp = strtou64(end + 1, &end, 16);

    *hashp = strtou64(end + 1, &end, base);

    if (errno) {
        eprint(EINVAL, "unable to decode fnrec: base %u, fnrec [%s]", base, str);
        abort();
    }
}

static int
kvt_create(
    const char *       mpname,
    const char *       keyfile,
    const char *       keyfmt,
    u_long             keymax,
    bool *             dump)
{
    char         key[128], val[128];
    char **      kvs_listv = NULL;
    u_int        kvs_listc = 0;
    char         kvsname[32];
    int          klen, vlen;
    hse_err_t    err;
    tsi_t        tstart;
    int          rc, i;
    struct svec *parms;

    err = hse_kvdb_get_names(kvdb, &kvs_listc, &kvs_listv);
    if (err) {
        eprint(err, "unable to get kvs list from `%s'", mpname);
        return EX_DATAERR;
    }

    if (kvs_listc > 0 && !force) {
        if (keyfile || keyfmt || keymax < ULONG_MAX) {
            eprint(EEXIST, "kvdb %s appears to exist, use -F to force re-creation", mpname);
            return EX_DATAERR;
        }

        goto open;
    }

    tsi_start(&tstart);

    for (i = 0; i < kvs_listc; ++i) {
        status("dropping kvs %s...", kvs_listv[i]);
        hse_kvdb_kvs_drop(kvdb, kvs_listv[i]);
    }

    /* Create the file name indexes.
     */
    for (i = 0; i < kvs_inodesc; ++i) {

        snprintf(kvsname, sizeof(kvsname), "%s%d", KVS_INODES_NAME, i);

        status("creating kvs %s...", kvsname);
        parms = kvs_cparms_get(kvsname);
        err = hse_kvdb_kvs_make(kvdb, kvsname, parms->strc, parms->strv);
        if (err) {
            eprint(err, "unable to create kvs `%s'", kvsname);
            return EX_CANTCREAT;
        }
    }

    /* Create the file data indexes.
     */
    for (i = 0; i < kvs_datac; ++i) {
        snprintf(kvsname, sizeof(kvsname), "%s%d", KVS_DATA_NAME, i);

        status("creating kvs %s...", kvsname);
        parms = kvs_cparms_get(kvsname);
        err = hse_kvdb_kvs_make(kvdb, kvsname, parms->strc, parms->strv);
        if (err) {
            eprint(err, "unable to create kvs `%s'", kvsname);
            return EX_CANTCREAT;
        }
    }

    status("creating kvs %s...", KVS_TOMBS_NAME);
    parms = kvs_cparms_get(KVS_TOMBS_NAME);
    err = hse_kvdb_kvs_make(kvdb, KVS_TOMBS_NAME, parms->strc, parms->strv);
    if (err) {
        eprint(err, "unable to create kvs '%s'", KVS_TOMBS_NAME);
        return EX_CANTCREAT;
    }

    status("creating kvs %s...", KVS_RIDS_NAME);
    parms = kvs_cparms_get(KVS_RIDS_NAME);
    err = hse_kvdb_kvs_make(kvdb, KVS_RIDS_NAME, parms->strc, parms->strv);
    if (err) {
        eprint(err, "unable to create kvs '%s'", KVS_RIDS_NAME);
        return EX_CANTCREAT;
    }

    hse_kvdb_free_names(kvdb, kvs_listv);

    err = hse_kvdb_get_names(kvdb, &kvs_listc, &kvs_listv);
    if (err) {
        eprint(err, "unable to get kvs list from %s", mpname);
        return EX_DATAERR;
    }

    dprint(1, "created %u kvs in %.3lf seconds", kvs_listc, tsi_delta(&tstart) / 1000000.0);

    /* Open the rids table and write the root record.  Do not use
     * open parms for this open.
     */
    err = hse_kvdb_kvs_open(kvdb, KVS_RIDS_NAME, 0, NULL, &kvs_rids);
    if (err) {
        eprint(err, "unable to open kvs `%s'", KVS_RIDS_NAME);
        return EX_DATAERR;
    }

    klen = snprintf(key, sizeof(key), ".root");
    vlen = snprintf(
        val,
        sizeof(val),
        "%lx %x %lx %lx %lx %lx",
        0ul,
        ridkeybase,
        kvs_inodesc,
        kvs_datac,
        0ul,
        0ul);

    if (klen < 1 || klen >= sizeof(key) || vlen < 1 || vlen >= sizeof(val)) {
        eprint(errno, "unable to format root record");
        return EX_SOFTWARE;
    }

    err = hse_kvs_put(kvs_rids, 0, NULL, key, klen, val, vlen);
    if (err) {
        eprint(err, "put root key=%s val=%s", key, val);
        return EX_SOFTWARE;
    }

    err = hse_kvdb_kvs_close(kvs_rids);
    if (err) {
        eprint(err, "kvdb kvs close %s", KVS_RIDS_NAME);
        return EX_SOFTWARE;
    }

    err = hse_kvdb_sync(kvdb);
    if (err) {
        eprint(err, "kvdb sync");
        return EX_SOFTWARE;
    }

    kvs_rids = NULL;

open:
    rc = kvt_open(kvs_listc, kvs_listv);
    if (rc)
        return rc;

    if (keyfile || keyfmt || keymax < ULONG_MAX) {
        rc = kvt_init(keyfile, keyfmt, keymax, *dump);
        if (rc)
            return rc;

        *dump = false;
    }

    free(kvs_listv);

    return 0;
}

static int
kvt_open(u_int kvs_listc, char **kvs_listv)
{
    char         key[128], val[128];
    int          klen, rc, n, i;
    hse_err_t    err;
    tsi_t        tstart;
    size_t       vlen;
    bool         found;
    size_t       sz;
    struct svec *parms;

    tsi_start(&tstart);

    /* Open the rids table and read the root record...
     */
    parms = kvs_oparms_get(KVS_RIDS_NAME);
    err = hse_kvdb_kvs_open(kvdb, KVS_RIDS_NAME, parms->strc, parms->strv, &kvs_rids);
    if (err) {
        eprint(err, "unable to open kvs `%s'", KVS_RIDS_NAME);
        return EX_DATAERR;
    }

    klen = snprintf(key, sizeof(key), ".root");

    err = hse_kvs_get(kvs_rids, 0, NULL, key, klen, &found, val, sizeof(val), &vlen);
    if (err || !found) {
        eprint(err, "unable to find root record in kvs `%s'", KVS_RIDS_NAME);
        return EX_DATAERR;
    }

    val[vlen] = '\000';

    n = sscanf(
        val, "%lx%x%lx%lx%lx%lx", &ridmax, &ridkeybase, &kvs_inodesc, &kvs_datac, &hash0, &hash1);
    if (n != 6) {
        eprint(0, "invalid root record: key=%s val=[%s]", key, val);
        return EX_DATAERR;
    }

    dprint(
        2,
        "root: ridmax %lu, ridkeybase %u, kvs_inodesc %lu, kvs_datac %lu, %lx.%lx",
        ridmax,
        ridkeybase,
        kvs_inodesc,
        kvs_datac,
        hash0,
        hash1);

    assert(kvs_inodesc > 0 && kvs_inodesc < 256);
    assert(kvs_datac > 0 && kvs_datac < 256);
    assert(ridkeybase < NELEM(u64tostrtab));

    sz = roundup(sizeof(*kvs_inodesv) * (kvs_inodesc + kvs_datac), 64);

    kvs_inodesv = aligned_alloc(64, sz);
    if (!kvs_inodesv) {
        eprint(errno, "malloc kvs_inodesv %zu", sz);
        return EX_OSERR;
    }

    memset(kvs_inodesv, 0, sz);
    kvs_datav = kvs_inodesv + kvs_inodesc;
    rc = 0;

    for (i = 0; i < kvs_listc; ++i) {
        struct hse_kvs *kvs;
        const char *    pc;
        hse_err_t       err;
        char *          end;
        long            id;

        if (0 == strcmp(KVS_RIDS_NAME, kvs_listv[i]))
            continue;

        status("opening kvs %s...", kvs_listv[i]);

        parms = kvs_oparms_get(kvs_listv[i]);
        err = hse_kvdb_kvs_open(kvdb, kvs_listv[i], parms->strc, parms->strv, &kvs);
        if (err) {
            eprint(err, "unable to open kvs `%s'", kvs_listv[i]);
            return EX_DATAERR;
        }

        if (0 == strcmp(KVS_TOMBS_NAME, kvs_listv[i])) {
            kvs_tombs = kvs;
            continue;
        }

        for (pc = kvs_listv[i]; *pc && !isdigit(*pc); ++pc)
            ; /* do nothing */

        errno = 0;
        end = NULL;
        id = strtol(pc, &end, 10);
        if (errno || *end || id < 0 || id > kvs_datac) {
            eprint(
                errno,
                "%s invalid kvs `%s' (id %ld)",
                force ? "ignoring" : "found",
                kvs_listv[i],
                id);
            if (force)
                continue;

            return EX_DATAERR;
        }

        if (id < kvs_inodesc && 0 == strncmp(KVS_INODES_NAME, kvs_listv[i], 5)) {
            kvs_inodesv[id] = kvs;
        } else if (id < kvs_datac && 0 == strncmp(KVS_DATA_NAME, kvs_listv[i], 4)) {
            kvs_datav[id] = kvs;
        } else {
            eprint(0, "%s rogue kvs `%s' (id %ld)", force ? "ignoring" : "found", kvs_listv[i], id);

            if (force)
                continue;

            return EX_DATAERR;
        }
    }

    if (!kvs_tombs) {
        eprint(0, "kvs `%s' not found", KVS_TOMBS_NAME);
        rc = EX_DATAERR;
    }

    for (i = 0; i < kvs_inodesc; ++i) {
        if (!kvs_inodesv[i]) {
            eprint(0, "kvs `%s%d' not found", KVS_INODES_NAME, i);
            rc = EX_DATAERR;
        }
    }

    for (i = 0; i < kvs_datac; ++i) {
        if (!kvs_datav[i]) {
            eprint(0, "kvs `%s%d' not found", KVS_DATA_NAME, i);
            rc = EX_DATAERR;
        }
    }

    dprint(1, "opened %u kvs in %.3lf seconds", kvs_listc, tsi_delta(&tstart) / 1000000.0);

    return rc;
}

static int
kvt_init(const char *keyfile, const char *keyfmt, u_long keymax, bool dump)
{
    char           key[128], val[128];
    sigset_t       sigmask_block, sigmask_orig;
    u_long         iters_status, delta, n, x;
    struct tdargs *tdargv;
    struct workq   batchq;
    FILE *         fpin = stdin;
    struct work *  work;
    size_t         fpinmax;
    int            klen, vlen;
    hse_err_t      err;
    tsi_t          tstart;
    bool           skip;
    int            rc, i;
    pthread_t      sync_thread;

    if (!ijobsmax) {
        ijobsmax = CPU_COUNT(&cpuset);
        if (!keyfile && !keyfmt)
            ijobsmax *= 4; /* use more jobs when loading from files */
    }

    memset(&workq, 0, sizeof(workq));
    pthread_mutex_init(&workq.mtx, NULL);
    pthread_cond_init(&workq.p_cv, NULL);
    pthread_cond_init(&workq.c_cv, NULL);
    workq.lwm = ijobsmax * 16;
    workq.hwm = workq.lwm * 2;
    workq.tail = &workq.head;
    workq.running = true;

    memset(&batchq, 0, sizeof(batchq));
    batchq.tail = &batchq.head;

    fpinmax = (keymax < ULONG_MAX) ? keymax : 1024 * 1024;

    if (keyfile && strcmp("-", keyfile)) {
        struct stat sb;

        fpin = fopen(keyfile, "r");
        if (!fpin) {
            eprint(errno, "unable to open `%s'", keyfile);
            return EX_NOINPUT;
        }

        /* Estimate max number of lines based on 80-bytes per line...
         */
        if (keymax >= ULONG_MAX && 0 == fstat(fileno(fpin), &sb))
            fpinmax = sb.st_size / 80;
    } else {
        char * randbuf, *end, *pc;
        size_t randbufsz;

        /* Construct the buffer of randomness such that we can start
         * from any offset from randbuf to (randbuf + randbufsz / 2)
         * and access up to vlenmax valid bytes.
         */
        randbufsz = roundup(HSE_KVS_VLEN_MAX * 8, 4096);

        randbuf = aligned_alloc(4096, randbufsz);
        if (!randbuf) {
            eprint(errno, "malloc randbuf %zu", randbufsz);
            return EX_OSERR;
        }

        end = randbuf + randbufsz;
        pc = randbuf;

        if (vrunlen > 0) {
            uint64_t runlen = vrunlen;
            uint64_t r = xrand64() >> 1;
            u_char   c = (r & 0x3f) + 32;

            /* Generate random ASCII data with the given run length of repitition.
             */
            while (pc < end) {
                *pc++ = c;

                if (--runlen > 0)
                    continue;

                if ((r >>= 7) == 0)
                    r = xrand64() >> 1;
                c = r & 0x7F;
                if (c < 32)
                    c += 32;
                runlen = vrunlen;
            }
        } else {

            /* Generate random binary data.
             */
            while (pc < end) {
                *(uint64_t *)pc = xrand64();
                pc += sizeof(uint64_t);
            }
        }

        workq.randbufsz = randbufsz;
        workq.randbuf = randbuf;
    }

    if (dump) {
        dprint(
            0,
            "%4s %9s %8s %9s %7s %5s %16s %5s %s",
            "job",
            "rid",
            "ridkey",
            "datarid",
            "shift",
            "flags",
            "minhash",
            "fnlen",
            "fn");
    } else {
        status("loading...");
    }

    tdargv = aligned_alloc(alignof(*tdargv), ijobsmax * sizeof(*tdargv));
    if (!tdargv) {
        eprint(errno, "calloc tdargv %u %zu", ijobsmax, sizeof(*tdargv));
        return EX_OSERR;
    }
    memset(tdargv, 0, ijobsmax * sizeof(*tdargv));

    iters_status = ULONG_MAX;
    if ((verbosity > 0 && verbosity < 3) && isatty(1)) {
        status("calibrating for %u jobs...", ijobsmax);
        iters_status = workq.hwm * 2;
    }

    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGUSR1);
    sigaddset(&sigmask_block, SIGTERM);
    sigaddset(&sigmask_block, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigmask_block, &sigmask_orig);

    tsi_start(&tstart);

    if (sync_enabled) {
        rc = pthread_create(&sync_thread, NULL, periodic_sync, NULL);
        if (rc) {
            eprint(rc, "%s: pthread_create failed for sync thread:", __func__);
        }
    }

    for (i = 0; i < ijobsmax; ++i) {
        struct tdargs *args = tdargv + i;

        args->seed = xrand64();
        args->dump = dump;
        args->job = i;

        rc = pthread_create(&args->tid, NULL, kvt_init_main, args);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, ijobsmax);
            continue;
        }
    }

    pthread_sigmask(SIG_SETMASK, &sigmask_orig, NULL);

    skip = false;
    n = 0;

    while (n < keymax && !sigint) {
        u_long span = 1, ips;
        char * itersuf = "";
        char * ipssuf = "";
        size_t fnlen;
        double pct;

        if (batchq.free) {
            work = batchq.free;
            batchq.free = work->next;
        } else {
            work = malloc(sizeof(*work));
            if (!work)
                abort();

            work->keyfmt = keyfmt;
            work->rid = ULONG_MAX;
        }

        if (keyfmt) {
            u_int r = (xrand64() % 17) + 16;

            if (n + r < keymax)
                span = r;
            fnlen = 0;
        } else {
            char *fn = work->fn;

            if (!fgets(fn, sizeof(work->fn), fpin))
                break;

            while (*fn && isspace(*fn))
                ++fn; /* eat leading white space */

            fnlen = strlen(fn);
            if (fnlen == 0)
                continue;

            if (fn[--fnlen] != '\n' || fnlen > HSE_KVS_KLEN_MAX) {
                skip = true; /* skip excessively long lines */
                continue;
            }

            if (skip) {
                skip = false;
                continue;
            }

            if (fnlen < 1 || fn[0] == '#')
                continue;

            fn[fnlen] = '\000';
            if (fn != work->fn)
                memmove(work->fn, fn, fnlen + 1);
        }

        work->fnlen = fnlen;
        work->span = span;

        *batchq.tail = work;
        batchq.tail = &work->next;
        batchq.cnt++;

        if (!batchq.free && batchq.cnt > ijobsmax) {
            pthread_mutex_lock(&workq.mtx);

            *workq.tail = batchq.head;
            workq.tail = batchq.tail;
            *workq.tail = NULL;
            workq.cnt += batchq.cnt;

            if (workq.c_waits > workq.c_wakeups)
                pthread_cond_broadcast(&workq.c_cv);

            if (workq.cnt > workq.hwm) {
                while (workq.cnt > workq.lwm && !sigint) {
                    ++workq.p_waits;
                    pthread_cond_wait(&workq.p_cv, &workq.mtx);
                    ++workq.p_wakeups;
                }
            }

            batchq.free = workq.free;
            workq.free = NULL;
            pthread_mutex_unlock(&workq.mtx);

            batchq.head = NULL;
            batchq.tail = &batchq.head;
            batchq.cnt = 0;
        }

        n += span;
        if (n < iters_status)
            continue;

        x = __atomic_load_n(&workq.rid, __ATOMIC_RELAXED);

        /* Update status about three times per second...
         */
        delta = tsi_delta(&tstart);
        iters_status += (x * 1000000) / (delta * 3);

        pct = (x * 100.0) / fpinmax;
        ips = (x * 1000000) / delta;
        if (human) {
            humanize(&ips, &ipssuf);
            humanize(&x, &itersuf);
        }

        status(
            "loading %lu %lu%s (%lu%s/s) %.2lf%%", delta / 1000000, x, itersuf, ips, ipssuf, pct);
    }

    pthread_mutex_lock(&workq.mtx);
    *workq.tail = batchq.head;
    workq.tail = batchq.tail;
    *workq.tail = NULL;
    workq.cnt += batchq.cnt;
    workq.running = false;
    pthread_cond_broadcast(&workq.c_cv);
    pthread_mutex_unlock(&workq.mtx);

    if (sync_enabled) {
        pthread_kill(sync_thread, SIGUSR1);
        pthread_join(sync_thread, NULL);
    }

    for (i = 0; i < ijobsmax; ++i) {
        struct tdargs *args = tdargv + i;
        void *         val;

        rc = pthread_join(args->tid, &val);
        if (rc) {
            eprint(rc, "pthread_join %d of %u", i, ijobsmax);
            continue;
        }

        if (val) {
            rc = (intptr_t)val;
            continue;
        }

        hash0 += args->hashv[0];
        hash1 += args->hashv[1];
    }

    delta = tsi_delta(&tstart);

    ridmax = __atomic_load_n(&workq.rid, __ATOMIC_RELAXED);

    dprint(
        1,
        "loaded %lu of %lu %s in %.2lfs (%lu/s), %lx.%lx (wakeups %lu %lu)%s",
        ridmax,
        (keymax < ULONG_MAX) ? keymax : n,
        keyfmt ? "keys" : "files",
        delta / 1000000.0,
        (ridmax * 1000000) / delta,
        hash0,
        hash1,
        workq.p_wakeups,
        workq.c_wakeups,
        sigint ? " (interrupted)" : "");

    if (dryrun) {
        assert(ridmax == n);
        ridmax = 0;
    }

    /* Write the number of records and the hash sums to the root record.
     */
    klen = snprintf(key, sizeof(key), ".root");
    vlen = snprintf(
        val,
        sizeof(val),
        "%lx %x %lx %lx %lx %lx",
        ridmax,
        ridkeybase,
        kvs_inodesc,
        kvs_datac,
        hash0,
        hash1);

    if (testtxn) {
        struct hse_kvdb_txn *txn;

        txn = hse_kvdb_txn_alloc(kvdb);
        if (!txn)
            eprint(ENOMEM, "Could not allocate txn");

        err = hse_kvdb_txn_begin(kvdb, txn);
        if (err)
            eprint(err, "hse_kvdb_txn_begin");

        err = hse_kvs_put(kvs_rids, 0, txn, key, klen, val, vlen);
        if (err)
            eprint(err, "put root key=%s val=%s", key, val);

        err = hse_kvdb_txn_commit(kvdb, txn);
        if (err)
            eprint(err, "hse_kvdb_txn_commit");

        hse_kvdb_txn_free(kvdb, txn);
        if (err)
            eprint(err, "hse_kvdb_txn_free");
    } else {
        err = hse_kvs_put(kvs_rids, 0, NULL, key, klen, val, vlen);
        if (err)
            eprint(err, "put root key=%s val=%s", key, val);
    }


    err = hse_kvdb_sync(kvdb);
    if (err)
        eprint(err, "kvdb sync");

    while ((work = workq.free)) {
        workq.free = work->next;
        free(work);
    }
    while ((work = batchq.free)) {
        batchq.free = work->next;
        free(work);
    }

    pthread_cond_destroy(&workq.c_cv);
    pthread_cond_destroy(&workq.p_cv);
    pthread_mutex_destroy(&workq.mtx);
    free(workq.randbuf);
    free(tdargv);
    fclose(fpin);

    return err ? EX_SOFTWARE : 0;
}

static void *
kvt_init_main(void *arg)
{
    char           fnrec[512], key[128];
    struct tdargs *args = arg;
    int            fnreclen, klen;
    struct work *  work;
    size_t         databufsz;
    hse_err_t      err;
    char *         databuf;
    u_long         flags;
    struct hse_kvdb_txn *txn = NULL;

    job = args->job;
    xrand64_init(args->seed);

    if (1) {
        struct sched_param param;
        int                policy, rc;

        pthread_getschedparam(pthread_self(), &policy, &param);

        rc = pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
        if (rc)
            eprint(rc, "setschedparam(SCHED_BATCH)");
    }

    databufsz = roundup(HSE_KVS_VLEN_MAX, 4096);

    databuf = aligned_alloc(4096, databufsz);
    if (!databuf) {
        eprint(errno, "malloc databuf %zu", databufsz);
        pthread_exit((void *)(intptr_t)ENOMEM);
    }

    memset(databuf, 0, databufsz);
    work = NULL;
    err = 0;

    if (testtxn) {
        txn = hse_kvdb_txn_alloc(kvdb);
        if (!txn)
            eprint(ENOMEM, "Could not allocate txn");
    }

    while (1) {
        uint64_t hashv[2] = { 0 };
        u_long   datarid, rid;
        ssize_t  cc = 0;
        char *   datasrc;
        bool     found;
        int      fd;

        if (!work || --work->span == 0) {
            pthread_mutex_lock(&workq.mtx);
            if (work) {
                work->next = workq.free;
                workq.free = work;
            }

            while (workq.running && !workq.head) {
                ++workq.c_waits;
                pthread_cond_wait(&workq.c_cv, &workq.mtx);
                ++workq.c_wakeups;
            }

            work = workq.head;
            if (work) {
                workq.head = work->next;
                if (!workq.head)
                    workq.tail = &workq.head;

                if (--workq.cnt < workq.lwm && workq.p_waits > workq.p_wakeups)
                    pthread_cond_signal(&workq.p_cv);
            }
            pthread_mutex_unlock(&workq.mtx);

            if (!work)
                break;
        }

        if (work->keyfmt) {
            rid = __atomic_fetch_add(&workq.rid, 1, __ATOMIC_RELAXED);

            work->fnlen = snprintf(work->fn, sizeof(work->fn), work->keyfmt, rid, rid, rid);

            cc = vlenmin + (xrand64() % (vlenmax - vlenmin + 1));

            datasrc = workq.randbuf + (xrand64() % (workq.randbufsz - cc + 1));
            datasrc = (char *)roundup((uintptr_t)datasrc, alignof(uint64_t));
        } else {
            struct stat sb;

            assert(work->fnlen > 0);

            if (stat(work->fn, &sb) || (sb.st_mode & S_IFMT) != S_IFREG)
                continue;

            fd = open(work->fn, O_RDONLY);
            if (fd == -1)
                continue;

            cc = read(fd, databuf, vlenmax);
            close(fd);

            if (cc < vlenmin)
                continue;

            rid = __atomic_fetch_add(&workq.rid, 1, __ATOMIC_RELAXED);

            datasrc = databuf;
        }

        klen = rid2key(key, sizeof(key), rid, ridkeybase);
        datarid = (rid << 8) | (rid & 0xfflu);

        if (initchkdups) {
            char   vbuf[32];
            size_t vlen;

            /* Check to verify that the record doesn't exist in the tomb...
             */
            err = hse_kvs_get(
                kvs_tombs, 0, NULL, work->fn, work->fnlen, &found, vbuf, sizeof(vbuf), &vlen);
            if (err) {
                eprint(err, "get %s verify %lu fn=%s", KVS_TOMBS_NAME, rid, work->fn);
                goto errout;
            }

            if (found) {
                eprint(
                    err,
                    "duplicate key %lu vlen=%zu vbuf=[%.16s] key=%s",
                    rid,
                    vlen,
                    vbuf,
                    work->fn);
                goto errout;
            }
        }

        flags = KF_ENTOMBED;
        murmur3_128(datasrc, MIN(cc, 128), &hashv);
        fnreclen = fnrec_encode(fnrec, sizeof(fnrec), datarid, cc, 0, flags, hashv[0]);

        if (dryrun)
            continue;

        if (testtxn) {
            err = hse_kvdb_txn_begin(kvdb, txn);
            if (err)
                eprint(err, "hse_kvdb_txn_begin");
        }

        err = hse_kvs_put(rid2data_kvs(datarid), 0, testtxn ? txn : NULL, key, klen, datasrc, cc);
        if (err) {
            eprint(
                err,
                "put %s%u %lu key=%s cc=%ld fn=%s",
                KVS_DATA_NAME,
                rid2data_idx(datarid),
                datarid,
                key,
                cc,
                work->fn);
            goto errout;
        }

        /* Load all file name keys into the tombs table so that we can attempt
         * to detect duplicates during initial load.
         */
        err = hse_kvs_put(kvs_tombs, 0, testtxn ? txn : NULL, work->fn, work->fnlen, fnrec, fnreclen);
        if (err) {
            eprint(
                err,
                "put %s %lu vlen=%d val=[%s] key=%s",
                KVS_TOMBS_NAME,
                rid,
                fnreclen,
                fnrec,
                work->fn);
            goto errout;
        }

        err = hse_kvs_put(kvs_rids, 0, testtxn ? txn : NULL, key, klen, work->fn, work->fnlen);
        if (err) {
            eprint(err, "xput %s %lu key=%s val=%s", KVS_RIDS_NAME, rid, key, work->fn);
            goto errout;
        }

        if (testtxn) {
            hse_kvdb_txn_commit(kvdb, txn);
            if (err)
                eprint(err, "hse_kvdb_txn_commit");
        }

        if (args->dump) {
            dprint(
                0,
                "%9lu %8s %9lx %7lu %5lx %16lx %5zu %s",
                rid,
                key,
                datarid,
                0ul,
                flags,
                hashv[0],
                work->fnlen,
                work->fn);
        }

        murmur3_128(datasrc, cc, &hashv);
        args->hashv[0] += hashv[0];
        args->hashv[1] += hashv[1];
    }

    if (testtxn) {
        hse_kvdb_txn_free(kvdb, txn);
        if (err)
            eprint(err, "hse_kvdb_txn_free");
    }

errout:
    if (err)
        kill(getpid(), SIGINT); /* Awaken main thread */

    free(databuf);
    free(work);

    pthread_exit((void *)(intptr_t)hse_err_to_errno(err));
}

static int
kvt_check(int check, bool dump)
{
    char           msg[128];
    sigset_t       sigmask_block, sigmask_orig;
    uint64_t       hashv_sum[2] = { 0 };
    u_long         iters_status, iters;
    u_long         vgetlen, vputlen;
    struct tdargs *tdargv;
    u_long         delta, nerrs;
    u_long         rid, ridcnt;
    u_long         skip, span;
    struct work *  work;
    tsi_t          tstart;
    u_int          cjobs;
    bool           full;
    int            rc, i;

    if (sigint)
        return 0;

    cjobs = cjobsmax;
    if (!cjobs)
        cjobs = CPU_COUNT(&cpuset);
    cjobs = MIN(cjobs, (ridmax * 3) / (100 * 8) + 1);

    /* full    (check > 0):  check every record
     * minimal (check < 0):  check first and last eight records
     * sparse  (check == 0): check at most ~4-million random records
     */
    span = MIN(ridmax / cjobs, 1024);
    skip = ULONG_MAX;
    full = (check > 0);

    if (check == 0) {
        skip = UINT64_MAX / 100;
    } else if (check < 0) {
        cjobs = 1;
        span = 1;
        skip = 0;
    }

    if (dump) {
        dprint(
            0,
            "%4s %9s %8s %9s %7s %5s %16s %5s %s",
            "job",
            "rid",
            "ridkey",
            "datarid",
            "shift",
            "flags",
            "minhash",
            "fnlen",
            "fn");
    } else {
        status("checking...");
    }

    iters_status = INT64_MAX;
    if ((verbosity > 0 && verbosity < 3) && isatty(1)) {
        iters_status = cjobs * 3 * 2;
        status("calibrating for %u jobs...", cjobs);
    }

    memset(&workq, 0, sizeof(workq));
    pthread_mutex_init(&workq.mtx, NULL);
    pthread_cond_init(&workq.p_cv, NULL);
    pthread_cond_init(&workq.c_cv, NULL);
    workq.lwm = cjobs * 2;
    workq.hwm = workq.lwm * 2;
    workq.tail = &workq.head;
    workq.running = true;

    tdargv = aligned_alloc(alignof(*tdargv), cjobs * sizeof(*tdargv));
    if (!tdargv) {
        eprint(errno, "calloc tdargv %u %zu", cjobs, sizeof(*tdargv));
        return EX_OSERR;
    }
    memset(tdargv, 0, cjobs * sizeof(*tdargv));

    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigmask_block, &sigmask_orig);

    tsi_start(&tstart);

    for (i = 0; i < cjobs; ++i) {
        struct tdargs *args = tdargv + i;

        args->seed = xrand64();
        args->full = full;
        args->dump = dump;
        args->job = i;

        rc = pthread_create(&args->tid, NULL, kvt_check_main, args);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, cjobs);
            continue;
        }
    }

    pthread_sigmask(SIG_SETMASK, &sigmask_orig, NULL);

    iters = ridcnt = vgetlen = vputlen = nerrs = 0;
    work = NULL;

    for (rid = 0; rid < ridmax && !sigint; rid += span) {
        char * ridsuf = "";
        char * ipssuf = "";
        u_long ips, n;

        if (rid + span >= ridmax)
            span = 1;

        /* If not a full check then sample only about 3% of the records,
         * ensuring we always check the first and last eight records.
         */
        if (!full && (xrand64() >= skip) && (rid > 7) && rid < (ridmax - 8)) {
            if (check < 0)
                span = ridmax - rid - 8;
            continue;
        }

        if (!work) {
            work = malloc(sizeof(*work));
            if (!work)
                abort();
        }

        work->next = NULL;
        work->span = span;
        work->rid = rid;

        pthread_mutex_lock(&workq.mtx);
        *workq.tail = work;
        workq.tail = &work->next;
        workq.cnt++;

        if (workq.c_waits > workq.c_wakeups)
            pthread_cond_signal(&workq.c_cv);

        if (workq.cnt > workq.hwm) {
            while (workq.cnt > workq.lwm && !sigint) {
                ++workq.p_waits;
                pthread_cond_wait(&workq.p_cv, &workq.mtx);
                ++workq.p_wakeups;
            }
        }

        work = workq.free;
        if (work)
            workq.free = work->next;
        pthread_mutex_unlock(&workq.mtx);

        ridcnt += span;

        if (iters++ < iters_status)
            continue;

        /* Update status about three times per second...
         */
        delta = tsi_delta(&tstart);
        iters_status += (iters * 1000000) / (delta * 3);

        n = ridcnt;
        ips = (n * 1000000) / delta;
        if (human) {
            humanize(&ips, &ipssuf);
            humanize(&n, &ridsuf);
        }

        status(
            "checking %lu %lu%s (%lu%s/s) %.2lf%%",
            delta / 1000000,
            n,
            ridsuf,
            ips,
            ipssuf,
            (rid * 100.0) / ridmax);
    }

    pthread_mutex_lock(&workq.mtx);
    pthread_cond_broadcast(&workq.c_cv);
    workq.running = false;
    pthread_mutex_unlock(&workq.mtx);

    for (i = 0; i < cjobs; ++i) {
        struct tdargs *args = tdargv + i;
        void *         val;

        rc = pthread_join(args->tid, &val);
        if (rc) {
            eprint(rc, "pthread_join %d of %u", i, cjobs);
            continue;
        }

        hashv_sum[0] += args->hashv[0];
        hashv_sum[1] += args->hashv[1];
        vgetlen += args->stats.vgetlen;
        vputlen += args->stats.vputlen;
        nerrs += args->stats.nerrs;
    }

    delta = tsi_delta(&tstart);

    if (full && !sigint) {
        if (ridcnt != ridmax) {
            eprint(0, "rid count mismatch (%lu != %lu)", ridcnt, ridmax);
            ++nerrs;
        }

        if (!dryrun && (hashv_sum[0] != hash0 || hashv_sum[1] != hash1)) {
            eprint(
                0,
                "hash sum mismatch (%lx != %lx) and/or (%lx != %lx)",
                hashv_sum[0],
                hash0,
                hashv_sum[1],
                hash1);
            ++nerrs;
        }
    }

    snprintf(
        msg,
        sizeof(msg),
        "checked %lu of %lu records in %.2lfs (%lu/s), valMB %lu (%lu MB/s)",
        ridcnt,
        ridmax,
        delta / 1000000.0,
        (ridcnt * 1000000) / delta,
        vgetlen >> 20,
        vgetlen / delta);

    dprint(
        1,
        "%s, %lx.%lx, (wakeups %lu %lu) errs %ld%s",
        msg,
        hashv_sum[0],
        hashv_sum[1],
        workq.p_wakeups,
        workq.c_wakeups,
        nerrs,
        sigint ? " (interrupted)" : "");

    free(work);
    while ((work = workq.free)) {
        workq.free = work->next;
        free(work);
    }

    pthread_cond_destroy(&workq.c_cv);
    pthread_cond_destroy(&workq.p_cv);
    pthread_mutex_destroy(&workq.mtx);
    free(tdargv);

    return nerrs ? EX_SOFTWARE : 0;
}

static void *
kvt_check_main(void *arg)
{
    char           fnrec[512], key[128], fn[HSE_KVS_KLEN_MAX * 2];
    size_t         databuflen, databufsz, datasz;
    struct tdargs *args = arg;
    struct work *  work;
    char *         databuf;
    hse_err_t      err;
    long           nerrs;
    int            klen;

    job = args->job;

    if (1) {
        struct sched_param param;
        int                policy, rc;

        pthread_getschedparam(pthread_self(), &policy, &param);

        rc = pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
        if (rc)
            eprint(rc, "setschedparam(SCHED_BATCH)");
    }

    //databufsz = (full || dump) ? HSE_KVS_VLEN_MAX : 4096;
    databufsz = roundup(HSE_KVS_VLEN_MAX, 4096);

    databuf = aligned_alloc(4096, databufsz);
    if (!databuf) {
        eprint(errno, "malloc databuf %zu", databufsz);
        pthread_exit((void *)(intptr_t)EX_OSERR);
    }

    memset(databuf, 0, databufsz);
    work = NULL;
    nerrs = 0;

    while (1) {
        uint64_t hashv[2] = { 0 }, minhash;
        size_t   fnlen, fnreclen;
        u_long   datarid, rid;
        u_long   shift, flags;
        bool     exhumed;
        bool     found;

        if (work && --work->span > 0) {
            ++work->rid;
        } else {
            pthread_mutex_lock(&workq.mtx);
            if (work) {
                work->next = workq.free;
                workq.free = work;
            }

            while (!workq.head && workq.running) {
                ++workq.c_waits;
                pthread_cond_wait(&workq.c_cv, &workq.mtx);
                ++workq.c_wakeups;
            }

            work = workq.head;
            if (work) {
                workq.head = work->next;
                if (!workq.head)
                    workq.tail = &workq.head;

                if (--workq.cnt < workq.lwm && workq.p_waits > workq.p_wakeups)
                    pthread_cond_signal(&workq.p_cv);
            }
            pthread_mutex_unlock(&workq.mtx);

            if (!work)
                break;
        }

        rid = work->rid;

        klen = rid2key(key, sizeof(key), rid, ridkeybase);

        err = hse_kvs_get(kvs_rids, 0, NULL, key, klen, &found, fn, sizeof(fn), &fnlen);
        if (err || !found) {
            eprint(
                err, "get %s rid=%lu key=%s%s", KVS_RIDS_NAME, rid, key, err ? "" : " not found");
            ++nerrs;
            continue;
        }

        if (fnlen > HSE_KVS_KLEN_MAX) {
            eprint(
                err,
                "unexpectedly large value (%zu) for rid %lu from %s",
                fnlen,
                rid,
                KVS_RIDS_NAME);
            abort();
        }

        fn[fnlen] = '\000';
        found = exhumed = false;

        err = hse_kvs_get(
            rid2inodes_kvs(rid), 0, NULL, fn, fnlen, &found, fnrec, sizeof(fnrec), &fnreclen);
        if (err) {
            eprint(err, "get %s%u rid=%lu key=%s", KVS_INODES_NAME, rid2inodes_idx(rid), rid, fn);
            ++nerrs;
            continue;
        }

        if (!found) {
            err = hse_kvs_get(kvs_tombs, 0, NULL, fn, fnlen, &found, fnrec, sizeof(fnrec), &fnreclen);
            if (err || !found) {
                eprint(
                    err,
                    "record not found in %s%u nor %s: rid=%lu key=%s",
                    KVS_INODES_NAME,
                    rid2inodes_idx(rid),
                    KVS_TOMBS_NAME,
                    rid,
                    fn);
                ++nerrs;
                continue;
            }

            exhumed = true;
        }

        if (fnreclen >= sizeof(fnrec))
            abort();

        fnrec[fnreclen] = '\000';
        fnrec_decode(fnrec, &datarid, &datasz, &shift, &flags, &minhash);

        if (args->dump)
            dprint(
                0,
                "%9lu %8s %9lx %7lu %5lx %16lx %5zu %s",
                rid,
                key,
                datarid,
                shift,
                flags,
                minhash,
                fnlen,
                fn);

        if (datarid >> 8 != rid)
            abort();

        if (dryrun)
            continue;

        err = hse_kvs_get(
            rid2data_kvs(datarid), 0, NULL, key, klen, &found, databuf, databufsz, &databuflen);
        if (err || !found) {
            if (nerrs < 8 || verbosity > 2) {
                eprint(
                    err,
                    "get %s%u datarid=%lu key=%s %s(fn=%s)",
                    KVS_DATA_NAME,
                    rid2data_idx(datarid),
                    datarid,
                    key,
                    err ? "" : "not found ",
                    fn);
            }
            ++nerrs;
            continue;
        }

        if (databuflen != datasz) {
            eprint(
                EINVAL, "datarid %lx key=%s (exp %zu, got %zu)", datarid, key, datasz, databuflen);
            abort();
        }

        args->stats.vgetlen += fnlen + fnreclen + databuflen;

        murmur3_128(databuf, MIN(databuflen, 128), &hashv);

        if (minhash != hashv[0]) {
            uint8_t *p8 = (uint8_t *)databuf;

            if (shift % 64) {
                uint64_t *p64 = (uint64_t *)databuf;

                p64[0] = xoroshiro_rotl(p64[0], 64 - (shift % 64));
            }

            eprint(
                0,
                "minhash miscompare rid=%lx datarid=%lx key=[%s] %zu fn=[%s] shift=%lu flags=%lx "
                "vlen=%lu val=[%02x%02x%02x%02x%02x%02x%02x%02x] from %s%u%s",
                rid,
                datarid,
                key,
                fnlen,
                fn,
                shift,
                flags,
                databuflen,
                p8[0],
                p8[1],
                p8[2],
                p8[3],
                p8[4],
                p8[5],
                p8[6],
                p8[7],
                exhumed ? KVS_TOMBS_NAME : KVS_INODES_NAME,
                rid2inodes_idx(rid),
                exhumed ? "\b" : "");
            ++nerrs;
        }

        if (args->full) {
            if (shift % 64) {
                uint64_t *p64 = (uint64_t *)databuf;
                uint64_t  val;

                p64[0] = xoroshiro_rotl(p64[0], 64 - (shift % 64));

                if (databuflen >= sizeof(val) * 2) {
                    memcpy(&val, databuf + databuflen - sizeof(val), sizeof(val));
                    val = xoroshiro_rotl(val, 64 - (shift % 64));
                    memcpy(databuf + databuflen - sizeof(val), &val, sizeof(val));
                }
            }

            murmur3_128(databuf, databuflen, &hashv);
            args->hashv[0] += hashv[0];
            args->hashv[1] += hashv[1];
        }
    }

    args->stats.nerrs = nerrs;

    free(databuf);
    free(work);

    pthread_exit(nerrs ? (void *)(intptr_t)EX_SOFTWARE : NULL);
}

static void
kvt_test_summary(struct tdargs *tdargv)
{
    const char * fmt = "test %4u %*.2lf %*lu %7lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %5lu";
    int          witers, wsecs, wgets, wgetsps, wcommits, waborts, wvgetlen;
    struct stats stats = { 0 };
    u_long       usecs;
    int          i;

    for (i = 0; i < tjobsmax; ++i) {
        struct tdargs *args = tdargv + i;

        stats.gets += args->stats.gets;
        stats.puts += args->stats.puts;
        stats.dels += args->stats.dels;
        stats.commits += args->stats.commits;
        stats.aborts += args->stats.aborts;
        stats.vgetlen += args->stats.vgetlen;
        stats.usecs += args->stats.usecs;
        stats.iters += args->stats.iters;
    }

    usecs = stats.usecs / tjobsmax;

    witers = snprintf(NULL, 0, "%5lu", stats.iters);
    wsecs = snprintf(NULL, 0, "%.2lf", stats.usecs / 1000000.0);
    wgets = snprintf(NULL, 0, "%4lu", stats.gets);
    wgetsps = snprintf(NULL, 0, "%6lu", (stats.gets * 1000000) / usecs);
    wcommits = snprintf(NULL, 0, "%6lu", stats.commits);
    waborts = snprintf(NULL, 0, "%5lu", stats.aborts);
    wvgetlen = snprintf(NULL, 0, "%5lu", stats.vgetlen >> 20);

    if (headers) {
        dprint(
            1,
            "test %4s %*s %*s %7s %*s %*s %*s %*s %*s %*s %*s %5s",
            "job",
            wsecs,
            "secs",
            witers,
            "iters",
            "iters/s",
            wgets,
            "gets",
            wgetsps,
            "gets/s",
            wgets,
            "puts",
            wgets,
            "dels",
            wcommits,
            "commit",
            waborts,
            "abort",
            wvgetlen,
            "valMB",
            "MB/s");
    }

    for (i = 0; i < tjobsmax && verbosity > 1; ++i) {
        struct tdargs *args = tdargv + i;

        dprint(
            1,
            fmt,
            i,
            wsecs,
            args->stats.usecs / 1000000.0,
            witers,
            args->stats.iters,
            (args->stats.iters * 1000000) / args->stats.usecs,
            wgets,
            args->stats.gets,
            wgetsps,
            (args->stats.gets * 1000000) / args->stats.usecs,
            wgets,
            args->stats.puts,
            wgets,
            args->stats.dels,
            wcommits,
            args->stats.commits,
            waborts,
            args->stats.aborts,
            wvgetlen,
            args->stats.vgetlen >> 20,
            args->stats.vgetlen / args->stats.usecs);
    }

    dprint(
        1,
        fmt,
        tjobsmax,
        wsecs,
        usecs / 1000000.0,
        witers,
        stats.iters,
        (stats.iters * 1000000) / usecs,
        wgets,
        stats.gets,
        wgetsps,
        (stats.gets * 1000000) / usecs,
        wgets,
        stats.puts,
        wgets,
        stats.dels,
        wcommits,
        stats.commits,
        waborts,
        stats.aborts,
        wvgetlen,
        stats.vgetlen >> 20,
        stats.vgetlen / usecs);
}

static int
kvt_test(void)
{
    sigset_t         sigmask_block, sigmask_orig;
    struct tdargs *  tdargv;
    struct itimerval itv;
    double           uspercycle;
    tsi_t            tstart;
    u_int            done;
    int              rc, i;

    char *itersuf = "";
    char *getsuf = "";
    char *putsuf = "";
    char *delsuf = "";
    char *entsuf = "";
    char *comsuf = "";
    char *absuf = "";

    if (sigint || testsecs == 0 || ridmax == 0)
        return 0;

    rc = kvt_check(-1, false);
    if (rc)
        return rc;

    if (!tjobsmax)
        tjobsmax = CPU_COUNT(&cpuset);
    if (tjobsmax * 2 > ridmax)
        tjobsmax = (ridmax / 2) | 1;

    /* In transaction mode let signals kill the process
     * dead in its tracks to facilitate testing kvdb's
     * transactional guarantees.
     */
    if (testtxn) {
        rsignal(SIGHUP, SIG_DFL);
        rsignal(SIGINT, SIG_DFL);
        rsignal(SIGTERM, SIG_DFL);
        rsignal(SIGUSR2, SIG_DFL);
    } else {
        rc = ridlock_init(tjobsmax * 16);
        if (rc)
            return rc;
    }

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

    rc = pthread_barrier_init(&kvt_test_barrier, NULL, tjobsmax);
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

        rc = pthread_create(&args->tid, NULL, kvt_test_main, args);
        if (rc) {
            eprint(rc, "pthread_create %d of %u", i, tjobsmax);
            continue;
        }
    }

    memset(&itv, 0, sizeof(itv));
    itv.it_value.tv_sec = (killsecs < testsecs) ? killsecs : testsecs;
    rc = setitimer(ITIMER_REAL, &itv, NULL);
    if (rc) {
        eprint(errno, "setitimer");
        return EX_OSERR;
    }

    pthread_sigmask(SIG_SETMASK, &sigmask_orig, NULL);
    rsignal(SIGALRM, sigalrm_isr);

    if (!(mark && isatty(1)))
        goto join;

    uspercycle = 1000000.0 / tsc_freq_;
    done = 0;

    while (done < tjobsmax && !(sigint || sigalrm)) {
        u_long iters = 0, gets = 0, puts = 0, dels = 0;
        u_long commits = 0, aborts = 0;
        u_long entombs = 0, delays = 0;
        u_long latmax = 0, latavg = 0;
        u_long latmin = ULONG_MAX;
        u_long delta, ips;
        char * ipssuf = "";

        usleep(mark * 1000000);
        done = 0;

        for (i = 0; i < tjobsmax; ++i) {
            gets += tdargv[i].stats.gets;
            puts += tdargv[i].stats.puts;
            dels += tdargv[i].stats.dels;
            commits += tdargv[i].stats.commits;
            aborts += tdargv[i].stats.aborts;
            entombs += tdargv[i].stats.entombs;
            delays += tdargv[i].stats.delays;

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
            humanize(&gets, &getsuf);
            humanize(&puts, &putsuf);
            humanize(&dels, &delsuf);
            humanize(&commits, &comsuf);
            humanize(&aborts, &absuf);
            humanize(&entombs, &entsuf);
        }

        status(
            "testing %lu %lu%s (%lu%s/s) %.2lf%%, get %lu%s, put %lu%s, del %lu%s, commit %lu%s, "
            "abort %lu%s, entomb %lu%s, delay %lu, latency %lu %lu %lu",
            delta,
            iters,
            itersuf,
            ips,
            ipssuf,
            (delta * 100.0) / testsecs,
            gets,
            getsuf,
            puts,
            putsuf,
            dels,
            delsuf,
            commits,
            comsuf,
            aborts,
            absuf,
            entombs,
            entsuf,
            delays,
            latmin,
            latavg,
            latmax);
    }

join:
    for (i = 0; i < tjobsmax; ++i) {
        struct tdargs *args = tdargv + i;
        void *         val;

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

    kvt_test_summary(tdargv);

    pthread_barrier_destroy(&kvt_test_barrier);
    free(tdargv);

    return rc;
}

static void *
kvt_test_main(void *arg)
{
    struct tdargs *        args = arg;
    struct hse_kvdb_txn *  txn;
    hse_err_t              err;
    tsi_t                  tstart;
    int                    rc;

    job = args->job;
    xrand64_init(args->seed);

    args->databufsz = roundup(HSE_KVS_VLEN_MAX, 4096);

    args->databuf = aligned_alloc(4096, args->databufsz);
    if (!args->databuf) {
        eprint(errno, "malloc databuf %zu", args->databufsz);
        pthread_exit((void *)(intptr_t)EX_OSERR);
    }

    memset(args->databuf, 0, args->databufsz);

    rc = pthread_barrier_wait(&kvt_test_barrier);
    if (rc > 0) {
        eprint(rc, "barrier wait");
        pthread_exit((void *)(intptr_t)EX_OSERR);
    }

    tsi_start(&tstart);
    txn = NULL;

    /* In non-tranaction mode each thread must lock its selected
     * record to prevent concurrent threads from operating on the
     * same record.  In transaction mode ridlock_trylock() always
     * returns true to expressly allow concurrent threads to
     * operate on the same record.
     */
    while (!(sigint || sigalrm)) {
        u_long rid = xrand64() % ridmax;
        u_long cycles;

        if (!ridlock_trylock(rid))
            continue;

        cycles = __builtin_ia32_rdtsc();

        ++args->stats.iters;

        if (testtxn) {
            if (!txn) {
                txn = hse_kvdb_txn_alloc(kvdb);
                if (!txn) {
                    eprint(ENOMEM, "hse_kvdb_txn_alloc");
                    rc = EX_SOFTWARE;
                    break;
                }
            }

            err = hse_kvdb_txn_begin(kvdb, txn);
            if (err) {
                eprint(err, "hse_kvdb_txn_begin");
                rc = EX_SOFTWARE;
                break;
            }
        }

        rc = kvt_test_impl(args, 0, txn, rid);
        if (rc) {
            if (txn) {
                hse_kvdb_txn_abort(kvdb, txn);

                if (rc != EAGAIN)
                    ++args->stats.aborts;
            }

            if (rc == EAGAIN || rc == ECANCELED) {
                rc = 0;
                goto unlock;
            }

            rc = EX_SOFTWARE;
            break;
        }

        if (txn) {
            ++args->stats.commits;

            /* Delay an occassional commit.  Running this test both with
             * and without txn commit delay enabled shouldn't make much
             * difference in average txn throughput (given a sufficient
             * number of threads).
             */
            if (txncdlyprob > 0 && xrand64() < txncdlyprob) {
                u_long avglat;

                avglat = tsi_delta(&tstart) / args->stats.commits;
                ++args->stats.delays;
                usleep(MIN(avglat * 10, 500000));
            }

            err = hse_kvdb_txn_commit(kvdb, txn);
            if (err) {
                eprint(err, "hse_kvdb_txn_commit");
                rc = EX_SOFTWARE;
                break;
            }

            /* Destroy the txn with some probability, just to shake
             * things up a bit...
             */
            if (txnfreeprob > 0 && xrand64() < txnfreeprob) {
                hse_kvdb_txn_free(kvdb, txn);
                txn = NULL;
            }
        }

    unlock:
        ridlock_unlock(rid); /* no-op in txn mode */

        cycles = __builtin_ia32_rdtsc() - cycles;

        if (cycles < args->stats.latmin)
            args->stats.latmin = cycles;
        if (cycles > args->stats.latmax)
            args->stats.latmax = cycles;
        args->stats.lattot += cycles / 128;
    }

    args->stats.usecs = tsi_delta(&tstart);

    if (txn) {
        hse_kvdb_txn_abort(kvdb, txn);
        hse_kvdb_txn_free(kvdb, txn);
    }
    free(args->databuf);

    pthread_exit((void *)(intptr_t)rc);
}

static int
kvt_test_impl(struct tdargs *args, unsigned int oflags, struct hse_kvdb_txn *txn, u_long rid)
{
    char            fnrec[512], key[128], fn[HSE_KVS_KLEN_MAX * 2];
    struct hse_kvs *kvs_inodes_src, *kvs_inodes_dst;
    struct hse_kvs *kvs_data_src, *kvs_data_dst;
    size_t          fnlen, fnreclen, databufsz, databuflen;
    u_long          odatarid, datarid, shift, flags;
    uint64_t        hashv[2], minhash;
    size_t          datasz;
    char *          databuf;
    hse_err_t       err;
    int             klen, rc;
    bool            exhumed;
    bool            found;

    databufsz = args->databufsz;
    databuf = args->databuf;

    klen = rid2key(key, sizeof(key), rid, ridkeybase);

    /* Use the rid to obtain a file name from the rids table...
     */
    err = hse_kvs_get(kvs_rids, oflags, txn, key, klen, &found, fn, sizeof(fn), &fnlen);
    if (err || !found) {
        eprint(err, "cannot find rid %lu in %s: key=%s", rid, KVS_RIDS_NAME, key);
        return err ? hse_err_to_errno(err) : ENOENT;
    }

    args->stats.gets++;
    args->stats.vgetlen += fnlen;

    if (fnlen > HSE_KVS_KLEN_MAX) {
        eprint(
            err, "unexpectedly large value (%zu) for rid %lu from %s", fnlen, rid, KVS_RIDS_NAME);
        abort();
    }

    fn[fnlen] = '\000';

    /* Look up the file name in the appropriate inodes table,
     * remembering which inodes table we found it in...
     */
    kvs_inodes_src = rid2inodes_kvs(rid);
    kvs_inodes_dst = kvs_inodes_src;
    found = exhumed = false;

    err = hse_kvs_get(kvs_inodes_src, oflags, txn, fn, fnlen, &found, fnrec, sizeof(fnrec), &fnreclen);
    if (err) {
        eprint(
            err,
            "cannot find key %s in inodes%u: rid=%lu ridkey=%s",
            fn,
            rid2inodes_idx(rid),
            rid,
            key);
        return hse_err_to_errno(err);
    }

    /* If not found then someone must have moved it to the tomb...
     */
    if (!found) {
        err = hse_kvs_get(kvs_tombs, oflags, txn, fn, fnlen, &found, fnrec, sizeof(fnrec), &fnreclen);
        if (err || !found) {
            eprint(
                err,
                "cannot find key %s in %s%u nor %s: rid=%lu ridkey=%s",
                fn,
                KVS_INODES_NAME,
                rid2inodes_idx(rid),
                KVS_TOMBS_NAME,
                rid,
                key);
            return err ? hse_err_to_errno(err) : ENOENT;
        }

        kvs_inodes_src = kvs_tombs;
        exhumed = true;
    }

    args->stats.gets++;
    args->stats.vgetlen += fnreclen;

    if (fnreclen >= sizeof(fnrec)) {
        eprint(
            err,
            "unexpectedly large value (%zu) for rid %lu from %s%u%s, fn %s",
            fnreclen,
            rid,
            exhumed ? KVS_TOMBS_NAME : KVS_INODES_NAME,
            rid2inodes_idx(rid),
            exhumed ? "\b" : "",
            fn);
        abort();
    }

    fnrec[fnreclen] = '\000';
    fnrec_decode(fnrec, &datarid, &datasz, &shift, &flags, &minhash);

    if (datarid >> 8 != rid)
        abort();

    /* Check to see that the fnrec agrees with where we found the fnkey...
     */
    if (flags) {
        bool entombed = flags & KF_ENTOMBED;

        if ((entombed && !exhumed) || (exhumed && !entombed)) {
            eprint(
                0,
                "%s but %s rid %lu, fn%s",
                entombed ? "entombed" : "exhumed",
                exhumed ? "not entombed" : "not exhumed",
                rid,
                fn);
            return EINVAL;
        }
    }

    kvs_data_src = rid2data_kvs(datarid);

    memset(databuf, 0xaa, 16);

    /* Now, retrieve the file data...
     */
    err = hse_kvs_get(kvs_data_src, oflags, txn, key, klen, &found, databuf, databufsz, &databuflen);
    if (err || !found) {
        eprint(
            err,
            "cannot find datarid %lx in data%u: rid=%lx key=%s",
            datarid,
            rid2data_idx(datarid),
            rid,
            key);
        return err ? hse_err_to_errno(err) : ENOENT;
    }

    args->stats.gets++;
    args->stats.vgetlen += databuflen;

    /* A data size mismatch probably means that the fn lookup returned
     * stale data, which should never happen and is a serious bug.
     */
    if (databuflen != datasz) {
        assert(databufsz == HSE_KVS_VLEN_MAX);

        eprint(
            0,
            "data size miscompare for rid %lu in data%u: key=%s (exp %zu, got %zu)",
            datarid,
            rid2data_idx(datarid),
            key,
            datasz,
            databuflen);
        return EINVAL;
    }

    /* The min hash (the hash of the first 128 bytes of the databuf) should
     * match the min hash stored with the file name in the inodes table...
     */
    murmur3_128(databuf, MIN(databuflen, 128), &hashv);

    if (minhash != hashv[0]) {
        uint8_t *p8 = (uint8_t *)databuf;

        if (shift % 64) {
            uint64_t *p64 = (uint64_t *)databuf;

            p64[0] = xoroshiro_rotl(p64[0], 64 - (shift % 64));
        }

        eprint(
            0,
            "minhash miscompare rid=%lx datarid=%lx key=[%s] fnlen=%zu fn=[%s] shift=%lu/%lu "
            "flags=%lx vlen=%zu val=[%02x%02x%02x%02x%02x%02x%02x%02x] (%lx != %lx) from %s%u%s",
            rid,
            datarid,
            key,
            fnlen,
            fn,
            shift,
            shift % 64,
            flags,
            databuflen,
            p8[0],
            p8[1],
            p8[2],
            p8[3],
            p8[4],
            p8[5],
            p8[6],
            p8[7],
            minhash,
            hashv[0],
            exhumed ? KVS_TOMBS_NAME : KVS_INODES_NAME,
            rid2inodes_idx(rid),
            exhumed ? "\b" : "");
        return EINVAL;
    }

    if (dryrun || xrand64() >= updateprob)
        return EAGAIN;

    /* Permute the first and last eight bytes of the value such that
     * we can reconstitute the original data during full check...
     */
    if (databuflen >= sizeof(uint64_t)) {
        uint64_t *p64 = (uint64_t *)databuf;
        uint64_t  val;

        p64[0] = xoroshiro_rotl(p64[0], 1);

        if (databuflen >= sizeof(val) * 2) {
            memcpy(&val, databuf + databuflen - sizeof(val), sizeof(val));
            val = xoroshiro_rotl(val, 1);
            memcpy(databuf + databuflen - sizeof(val), &val, sizeof(val));
        }

        murmur3_128(databuf, MIN(databuflen, 128), &hashv);
        minhash = hashv[0];
        ++shift;
    }

    /* Move the permuted data to the next data kvs (round-robin).
     */
    odatarid = datarid;
    datarid = (datarid & ~0xfflu) | ((datarid + 1) & 0xfflu);
    kvs_data_dst = rid2data_kvs(datarid);

    assert(kvs_data_src != kvs_data_dst || kvs_datac == 1);
    assert(databuflen == datasz);

    err = hse_kvs_put(kvs_data_dst, oflags, txn, key, klen, databuf, databuflen);
    if (err) {
        rc = hse_err_to_errno(err);
        if (rc != ECANCELED)
            eprint(err, "put datarid %lx to data%u key=%s", datarid, rid2data_idx(datarid), key);
        return rc;
    }

    args->stats.puts++;
    args->stats.vputlen += databuflen;

    /* There's a random chance we'll send this key to the tomb...
     */
    flags = 0;
    if (kvs_inodes_src != kvs_tombs && xrand64() < tombprob) {
        kvs_inodes_dst = kvs_tombs;
        ++args->stats.entombs;
        flags = KF_ENTOMBED;
    }

    fnreclen = fnrec_encode(fnrec, sizeof(fnrec), datarid, databuflen, shift, flags, minhash);
    assert(fnreclen < sizeof(fnrec));

    /* Update the inodes table with the new metadata (fnrec).
     */
    err = hse_kvs_put(kvs_inodes_dst, oflags, txn, fn, fnlen, fnrec, fnreclen);
    if (err) {
        rc = hse_err_to_errno(err);
        if (rc != ECANCELED) {
            eprint(
                err,
                "put %s%u%s key=%s val=%s",
                (flags & KF_ENTOMBED) ? KVS_TOMBS_NAME : KVS_INODES_NAME,
                rid2inodes_idx(rid),
                (flags & KF_ENTOMBED) ? "\b" : "",
                fn,
                fnrec);
        }
        return rc;
    }

    args->stats.puts++;
    args->stats.vputlen += fnreclen;

    /* If found the fn key in the tomb or are moving it to the tomb
     * then we must delete it from where we found it.
     */
    if (kvs_inodes_src == kvs_tombs || kvs_inodes_dst == kvs_tombs) {
        assert(kvs_inodes_src != kvs_inodes_dst);

        err = hse_kvs_delete(kvs_inodes_src, oflags, txn, fn, fnlen);
        if (err) {
            rc = hse_err_to_errno(err);
            if (rc != ECANCELED)
                eprint(
                    err,
                    "delete %s%u%s key=%s",
                    (kvs_inodes_src == kvs_tombs) ? KVS_TOMBS_NAME : KVS_INODES_NAME,
                    rid2inodes_idx(rid),
                    kvs_inodes_src == kvs_tombs ? "\b" : "",
                    fn);
            return rc;
        }

        ++args->stats.dels;
    }

    assert(kvs_data_src != kvs_data_dst || kvs_datac == 1);

    /* Delete the old data so that we can detect attempts to access
     * it via a stale fn key.
     */
    if (kvs_datac > 1) {
        err = hse_kvs_delete(kvs_data_src, oflags, txn, key, klen);
        if (err) {
            rc = hse_err_to_errno(err);
            if (rc != ECANCELED)
                eprint(
                    err,
                    "delete datarid %lx from data%u key=%s",
                    odatarid,
                    rid2data_idx(odatarid),
                    key);
            return rc;
        }

        ++args->stats.dels;
    }

    return 0;
}
