/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 *
 * kmt (kvs/mpool test) is a tool for stress testing kvs, mpool, and
 * raw/block devices in a multi-threaded environment.  It performs
 * data-integrity verification on each record retrieved via a "get"
 * operation, and is also useful for performance measurement.
 *
 * The tool does its work in three mutually exclusive phases:
 *
 * (1) Init - Create n records in the testbed, each with a unique key.
 *
 * (2) Test - Select two random records, swap them, repeat as desired.
 *
 * (3) Check - Verify that each and every unique record written in
 * phase (1) is intact and is neither missing nor duplicated.
 *
 *
 * Examples:
 *
 *   Stress testing:
 *
 *   First, create an mpool named "mp1":
 *
 *     disks="/dev/nmve0n1"
 *     sudo mpool create mp1 ${disks}
 *
 *   KVS mode:
 *     Create a kvdb and add a kvs to it:
 *         sudo hse kvdb create mp1
 *         sudo hse kvs create mp1/kvs1
 *
 *     Initialize the kvs with 1 million unique objects/records.
 *         sudo kmt -i 1m -s1 -j8 mp1/kvs1
 *
 *     Check that all objects/records were created successfully:
 *         sudo kmt -c -s1 -j8 mp1/kvs1
 *
 *     Run in test mode for 5 minutes:
 *         sudo kmt -t 5m -s1 -j8 mp1/kvs1
 *
 *     Check that all objects/records still exist and are valid:
 *         sudo kmt -c -s1 -j8 mp1/kvs1
 *
 *     Delete all objects/records:
 *         sudo kmt -D -s1 -j8 mp1/kvs1
 *
 *     Do it all in one pass:
 *         sudo kmt -i1m -t5m -cD -s1 -j8 mp1/kvs1
 *
 *
 *   MPOOL mode:
 *     Mpool testing is primarily the same as kvs testing, except
 *     that the maximum records specified by the -i option is
 *     limited roughly to your mpool size divided by 4M.  Also,
 *     the -k option that enables "kvs mode" must not be given.
 *
 *     Initialize the mpool with 32768 unique records (i.e., creates
 *     one record per mblock), test, check, and delete all in one pass:
 *
 *         sudo kmt -i32k -t5m -cD -s1 -j8 mp1
 *
 *   DEVICE mode:
 *     You can test a raw/block device in the same manner as mpool,
 *     with the additional capability to roughly control where the
 *     data goes.  You can estimate the -i argument roughly as
 *     (device-size-in-bytes / vebsz), where the default for vebsz
 *     is 4M.  So, for a 2.2T Micron 9100 nvme drive, we can create
 *     roughly 563K records:
 *
 *     Do it all in one pass:
 *         sudo kmt -i512k -t5m -cD -s1 -j48 /dev/nvme0n1
 *
 *     By default, kmt writes to mblocks and devices in 4K blocks.
 *     The default offset between blocks in "device" mode is 4M.
 *     The block size can be specified via '-o secsz=N', and the
 *     offset can be specified via '-o vebsz=N'.  For example,
 *     to make kmt read/write 512-byte blocks that are spaced
 *     512-bytes apart:
 *
 *         sudo kmt -i512k -t5m -cD -s1 -j48 -o secsz=512,vebsz=512 /dev/nvme0n1
 *
 *
 *   Performance testing:
 *
 *     kmt offers several options to lessen its impact upon the system
 *     under test and hence improve performance testing.
 *
 *       -b  Use binary keys
 *       -R  Disable read verification
 *       -w  Specify write/put percentage (writes / (reads + writes))
 *       -O  Keep the kvs/mpool/device open between init and test phases
 *
 *     mpool  For example, to compare the impact of the mpool stack on 4K
 *     reads vs direct device access, given a single device vs an mpool
 *     comprised of one device:
 *
 *         sudo kmt -i384k -t5m -bcDR -w0 -s1 -j768 /dev/nvme0n1
 *         sudo kmt -i384k -t5m -bcDR -w0 -s1 -j768 mp1/kvs1
 *
 *     Both these tests yield roughly the same result of 753K 4K reads/sec.
 *     Repeating the tests with a 1M r/w size (i.e.,  '-o secsz=1048576')
 *     shows mpool presents an ~8% write/put and an ~.5% read/get throughput
 *     degradation vs direct device access.
 *
 *     c0  For comparison testing against kvs c0, kmt has an "extreme" mode
 *     mode in which kmt is built with the -DXKMT option and the resulting
 *     binary installed as "xkmt".  xkmt uses an internal RAM-based k/v store
 *     mock of the kvs get/put/delete interfaces.  Note that for c0 testing
 *     you must specify the -O flag to prevent c0 from being flushed between
 *     the kmt init and test phases.
 *
 *         sudo kmt -i128 -t60 -bcDOR -w0 -s1 -j48 mp1/kvs1
 *         sudo xkmt -i128 -t60 -bcDOR -w0 -s1 -j48 mp1/kvs1
 *
 *     The above tests result in ~12 million gets/sec for kmt, and
 *     ~790 million gets/sec for xkmt.
 *
 *     cN  It's not fair to compare xkmt mode vs cN mode, but here are
 *     the results for 128 million keys:
 *
 *         sudo kmt -i128m -t5m -bcDOR -w0 -s1 -j48 mp1/kvs1
 *         sudo xkmt -i128m -t5m -bcDOR -w0 -s1 -j48 mp1/kvs1
 *
 *     The above tests result in ~52 thousand gets/sec for kmt, and
 *     ~17 million gets/sec for xkmt.
 */

/* Enable eXtreme KVS to override the default kvs_{get,put,del} operations
 * with an internal implementation for the purpose of evaluating kmt.
 *
#define XKMT
 */

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/log2.h>
#include <hse_util/minmax.h>
#include <hse_util/page.h>
#include <hse_util/timing.h>
#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

#include <xoroshiro/xoroshiro.h>

#if HDR_HISTOGRAM_C_FROM_SUBPROJECT == 1
#include <hdr_histogram.h>
#else
#include <hdr/hdr_histogram.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <bsd/string.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <sysexits.h>
#include <pthread.h>
#include <poll.h>
#include <math.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

extern void
malloc_stats(void);

/* Experimental support for MongoDB
 *
 * KMT interfaces with MongoDB using mongoc (requires libmongoc and libbson)
 * KVS requests are replaced with their equivalent mongoc calls
 * Keys are mapped to ObjectIDs for fast performance
 * Values are stored as key/value pairs in the corresponding document
 * Note that not all options are available when running KMT on MongoDB
 *
 * Known Issues:
 * PUTMB and GETMB do not match the reported size in MongoDB
 * Although the reported avgObjSize is close to what we expect
 */

#include <mongoc/mongoc.h>

#define MONGO_COLLECTIONS_MAX (1u << 8)
#define MONGO_COLLECTION_MASK (MONGO_COLLECTIONS_MAX - 1)

#ifdef XKMT
#undef RB_ROOT
#undef RB_PROTOTYPE_INTERNAL
#undef RB_GENERATE_INTERNAL
#include <bsd/sys/tree.h>

typedef uint64_t hse_err_t;

int
hse_err_to_errno(hse_err_t err);

#else

#include <hse/hse.h>
#endif

#include <tools/parm_groups.h>

#if !defined(__USE_ISOC11) || defined(USE_EFENCE)
#define aligned_alloc(_align, _size) memalign((_align), (_size))
extern void *memalign(size_t, size_t) __attribute_malloc__ __wur;
#endif

#include <3rdparty/murmur3.h>

#define KM_REC_KEY_MAX  (1024)
#define KM_REC_SZ_MAX   (1024 * 1024 * 4)
#define KM_REC_VLEN_MAX (KM_REC_SZ_MAX - sizeof(struct km_rec) - KM_REC_KEY_MAX)

#define KM_SWAPPCT_MODULUS (1024 * 1024)

#define RETSIGTYPE void
#define WCMAJSCALE (1u << 30)

const char *   cf_dir = "/var/tmp";
char           chk_path[PATH_MAX];
char           kvdb_home_realpath[PATH_MAX];
uint64_t       chk_recmax = 192 * 1024 * 1024;
struct timeval tv_init;
const char *   progname;
char *         randbuf;
size_t         randbufsz;
int            verbosity;
const char *   keyfmt;
size_t         keybinmin = 8;
size_t         keybinmax = 8;
bool           keybinary = false;
size_t         keydist = 8192;
float          wpctf = 20;
uint           swappct;
bool           swapexcl = true;
bool           swaptxn = false;
char          *fieldname_fmt = "field%u";
uint           fieldnamew_min; /* minimum fieldname width */
uint           fieldnamew_max; /* maximum fieldname width */
uint           fieldcount_max = 2048;
uint           fieldcount = 1;
uint           fieldlength = 0;
char          *fieldnamev;
uint           mongo = 0;
uint           cidshift = 20;
uint           collectionc = 1;
double         wcmajprob = 1.0 / 1000000.0;
uint           wcmaj = 0;
uint           wcmin = 0;
uint           vrunlen;
bool           wcmin_given = false;
bool           stayopen = false;
bool           recverify = true;
bool           initmode = false;
bool           testmode = false;
bool           sysbench = false;
bool           xstats = false;
bool           headers;
uint64_t       recmax;
uint           tdmax;
ulong          seed;
size_t         secsz;
size_t         vebsz = 4 * 1024 * 1024;
int            dev_oflags = O_RDWR | O_DIRECT;
int            oom_score_adj = -500;
uint           c0putval = UINT_MAX;
bool           kvdb_mode = false;
bool           latency = false;
long           sync_timeout_ms = 0;
int            mclass = MP_MED_CAPACITY;

struct parm_groups *pg;
struct svec         db_oparms;
struct svec         kv_oparms_notxn;
struct svec         kv_oparms_txn;
bool                kvs_txn;

struct suftab {
    const char *list;   /* list of suffix characters */
    double      mult[]; /* list of multipliers */
};

/* clang-format off */

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
	{ 1, 60, 3600, 86400, 86400 * 7, 86400 * 365, 86400 * 365 * 100ul }
};

sig_atomic_t sigusr1, sigusr2, sigalrm, sigint;

enum km_op {
    OP_NULL = 0,
    OP_START,
    OP_LOCK,
    OP_UNLOCK,
    OP_MB_ALLOC,
    OP_MB_ABORT,
    OP_MB_COMMIT,
    OP_MB_DELETE,
    OP_MB_READ,
    OP_MB_WRITE,
    OP_KVS_GET, /* GET, PUT and DEL should be in the same order */
    OP_KVS_PUT,
    OP_KVS_DEL,
    OP_VERIFY,
    OP_RUN,
    OP_EXIT,
    OP_TXN_BEGIN,
    OP_TXN_COMMIT,
    OP_TXN_ABORT,
};

#define KMT_LAT_REC_CNT ((OP_KVS_DEL - OP_KVS_GET) + 1)

static const char *const op2txt[] = {
    "null", "start", "lock", "unlock", "alloc", "abort", "commit", "delete", "read",  "write",
    "get",  "put",   "del",  "verify", "run",   "exit",  "begin",  "commit", "abort", "?",
};

/* clang-format on */

struct km_stats {
    enum km_op op;

    ulong get, getbytes;
    ulong put, putbytes;
    ulong del;
    ulong swap;
    ulong begin;
    ulong commit;
    ulong abort;
    ulong alloc;

    /* Keep active and old stats in different cache lines - the
     * worker thread modifies the fields above, while the status
     * thread modifies the fields below (both non-atomically).
     */
    HSE_ALIGNED(SMP_CACHE_BYTES * 2)
    ulong oget, ogetbytes;
    ulong oput, oputbytes;
    ulong odel;
    ulong oswap;
    ulong obegin;
    ulong ocommit;
    ulong oabort;
};

/* Each record in the testbed has a unique record ID (rid) from which
 * its key is generated.  The rid is used to look up the record's
 * meta-data in the check file (see struct chk below).
 *
 * Each record in the test bed has a minimum size of sizeof(struct km_rec)
 * and a maximum size of KM_REC_SZ_MAX.
 *
 * If c0putval mode is in effect and is less than the minimum record
 * size, then full value verification (via the hash) is inhibited.
 */
struct km_rec {
    uint64_t rid;  /* current rid, must be first */
    uint32_t vlen; /* value length */
    uint32_t klen; /* key length */
    union {
        uint64_t mbid;   /* mblock mode */
        off_t    offset; /* device mode */
    };
    uint64_t rid0; /* creation rid */
    uint64_t hash;
    uint8_t  data[];
};

#define CHK_F_INPLACE   (0x02)
#define CHK_F_KEYBINARY (0x04)

/* The mmap'd check file contains a chk record for each record in the dataset
 * or device, which is sufficient to verify data-integrity of records
 * retrieved from the dataset/device.
 */
struct chk {
    union {
        uint64_t hash64; /* kvs and mongo modes */
        uint64_t mbid;   /* mblock mode */
        off_t    offset; /* device mode */
    };

    uint32_t hash32; /* mblock and device modes */
    uint16_t vlen;
    uint8_t  flags;
    uint8_t  cnt;
};

struct km_inst;
struct km_impl;

struct km_rec_ops {
    void (*km_rec_alloc)(struct km_inst *, void **rp1, void **rp2);

    void (*km_rec_init)(struct km_inst *, struct km_rec *, uint64_t rid, const struct timeval *tv);

    void (*km_rec_swap)(struct km_inst *, struct km_rec *, struct km_rec *);

    hse_err_t (*km_rec_get)(struct km_inst *, struct km_rec *, uint64_t rid);

    hse_err_t (*km_rec_put)(struct km_inst *, struct km_rec *);

    hse_err_t (*km_rec_del)(struct km_inst *, uint64_t rid);
};

/**
 * struct km_lor - locality of reference parameters
 *
 * struct km_lor specifies the locality-of-reference parameters for record
 * selection when in test mode.  By default, %range specifies the range
 * from [0, impl->recmax) from which %base is randomly recomputed every
 * %opsmax iterations.  %range is further constrained to only a fraction
 * of impl->recmax if %constrain is non-zero.  %span is the limit of the
 * subrange starting at %base from which record IDs are randomly generated.
 */
struct km_lor {
    u64 range;
    u64 base;
    u64 span;
    u64 opscnt;
    u64 opsmax;
    u64 constrain;
};

/* The default locality-of-reference parameters specify that each thread
 * should operate on a small randomly selected contiguous span of 128
 * record IDs, choosing a new base for the span every 64 iterations.
 * The -o option can be used to modify the default LOR.  For example,
 * to specify a random distribution, give '-o lor=0:0:0'.
 */
struct km_lor km_lor = {
    .span = 128,
    .opsmax = 64,
    .constrain = 1,
};

struct km_latency {
    struct hdr_histogram *km_histogram;
    atomic64_t            km_samples;
    atomic64_t            km_samples_err;
};

struct km_sync_latency {
    atomic64_t km_sync_iterations;
    atomic64_t km_total_sync_latency_us;
};

/* The implementation object maintains both the methods and data
 * on a per-implemention basis (we have only two implementations,
 * kvs and mpool).
 *
 * The object is initialized at program start based on command
 * line arguments and remains static thereafter...
 */
struct km_impl {
    hse_err_t (*km_open)(struct km_impl *);
    hse_err_t (*km_close)(struct km_impl *);

    struct km_rec_ops km_rec_ops;

    char *        mpname;
    const char *  kvsname;
    uint          tdmax;
    struct chk *  chk;
    uint64_t      recmax;
    size_t        vlenmin;
    size_t        vlenmax;
    size_t        vlenmax_default;
    size_t        vlendiv;
    void *        kvdb;
    void *        kvs;
    struct mpool *ds;

    mongoc_uri_t *        active_uri;
    mongoc_client_pool_t *client_pool;

    atomic64_t keydistchunk HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct km_latency      km_latency[KMT_LAT_REC_CNT] HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct km_sync_latency km_sync_latency;
};

/* Each thread gets a unique thread-instance object.
 */
struct km_inst {
    struct km_rec_ops       ops;
    struct km_impl         *impl;
    bson_t                  query;
    bson_t                  update;
    bson_t                  ropts;
    bson_t                  wopts_wcmin;
    bson_t                  wopts_wcmaj;
    mongoc_collection_t    *collectionv[MONGO_COLLECTIONS_MAX];
    mongoc_write_concern_t *wcmin;
    mongoc_write_concern_t *wcmaj;
    void *                  tdval;
    unsigned int            flags;
    struct hse_kvdb_txn *   txn;
    char                    mode[32];
    pthread_t               td;
    hse_err_t                  err;
    char *                  fmt;
    u32                     tid;
    void (*func)(struct km_inst *);
    mongoc_client_t *client;
    bson_error_t     error;
    struct km_inst * next;
    struct km_stats  stats;

    struct km_latency latency[KMT_LAT_REC_CNT] HSE_ALIGNED(SMP_CACHE_BYTES * 2);
};

#define km_open(_impl)  ((_impl)->km_open((_impl)))
#define km_close(_impl) ((_impl)->km_close((_impl)))

#define km_rec_alloc(_inst, _rp1, _rp2) \
    ((_inst)->ops.km_rec_alloc((_inst), (void **)(_rp1), (void **)(_rp2)))

#define km_rec_init(_inst, _rec, _rid, _tv) \
    ((_inst)->ops.km_rec_init((_inst), (_rec), (_rid), (_tv)))

#define km_rec_swap(_inst, _rec1, _rec2) ((_inst)->ops.km_rec_swap((_inst), (_rec1), (_rec2)))

#define km_rec_get(_inst, _rec, _rid) ((_inst)->ops.km_rec_get((_inst), (_rec), (_rid)))

#define km_rec_put(_inst, _rec) ((_inst)->ops.km_rec_put((_inst), (_rec)))

#define km_rec_del(_inst, _rid) ((_inst)->ops.km_rec_del((_inst), (_rid)))

#define km_rec_verify(_inst, _rec) km_rec_verify_cmn((_inst), (_rec))

#define km_rec_print(_inst, _rec, _fmt, _err) km_rec_print_cmn((_inst), (_rec), (_fmt), (_err))

#define td_lock()   ((void)pthread_spin_lock(&td_exited_lock))
#define td_unlock() ((void)pthread_spin_unlock(&td_exited_lock))

pthread_spinlock_t td_exited_lock;
struct km_inst *   td_exited_head;

__attribute__((format(printf, 1, 2))) static void
eprint(char *fmt, ...);

#ifdef XKMT

struct kvnode {
    RB_ENTRY(kvnode) entry;

    uint64_t hash;
    uint     keylen;
    uint     datalen;
    char    *key;
    char    *data;
} HSE_ALIGNED(SMP_CACHE_BYTES);

static inline int
node_cmp(struct kvnode *lhs, struct kvnode *rhs)
{
    if (lhs->hash < rhs->hash)
        return -1;
    else if (lhs->hash > rhs->hash)
        return 1;

    if (keybinary)
        return 0;

    if (lhs->keylen < rhs->keylen)
        return -1;
    else if (lhs->keylen > rhs->keylen)
        return 1;

    return memcmp(lhs->key, rhs->key, lhs->keylen);
}

RB_HEAD(node_tree, kvnode);

RB_PROTOTYPE(node_tree, kvnode, entry, node_cmp);
RB_GENERATE(node_tree, kvnode, entry, node_cmp);

struct hse_kvs {
    const char *mpname;
    const char *kvsname;
};

struct hse_kvdb;
struct hse_kvdb_txn;

struct hse_kvs *kvs;
#endif /* XKMT */

static thread_local uint64_t xrand_state[2];

static void
xrand_init(uint64_t seed)
{
    xoroshiro128plus_init(xrand_state, seed);
}

static uint64_t
xrand64(void)
{
    return xoroshiro128plus(xrand_state);
}

static uint32_t
xrand32(void)
{
    return xoroshiro128plus(xrand_state);
}

#define SUPER_SZ    (2u << 20)

void *
super_alloc(size_t sz)
{
    int flags = MAP_ANON | MAP_HUGETLB | MAP_PRIVATE;
    int prot = PROT_READ | PROT_WRITE;
    void *mem;

    sz = ALIGN(sz, SUPER_SZ);

  again:
    mem = mmap(NULL, sz, prot, flags, -1, 0);

    if (mem == MAP_FAILED) {
        if (flags & MAP_HUGETLB) {
            flags &= ~MAP_HUGETLB;
            goto again;
        }

        mem = NULL;
    }

    return mem;
}

void
super_free(void *mem, size_t sz)
{
    sz = ALIGN(sz, SUPER_SZ);

    munmap(mem, sz);
}

struct bktlock {
    union {
        pthread_rwlock_t   rwlock;
        int spinlock;
    };
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

struct bkt {
#ifdef XKMT
    struct node_tree root;
#endif
    void *lock;
};

/* xkmt has a 4-to-1 mapping of buckets to locks, which consumes an entire
 * 2M super page.  Regular kmt has a 1-to-1 mapping of buckets to locks,
 * which cosumes a little of half of its super page.
 */
#ifdef XKMT
#define BKTLOCK_MAX     ((SUPER_SZ / 2) / sizeof(struct bktlock))
#define BKT_MAX         ((SUPER_SZ / 2) / sizeof(struct bkt))
#else
#define BKTLOCK_MAX     ((SUPER_SZ / 2) / sizeof(struct bktlock))
#define BKT_MAX         (BKTLOCK_MAX)
#endif

/* We create our own spin locks so that we can differentiate
 * them from pthread spin locks used by hse.
 */
static __always_inline bool
atomic_cas_acq(int *p, int oldv, int newv)
{
    int retv = oldv;

    return __atomic_compare_exchange_n(p, &retv, newv, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static __always_inline bool
atomic_cas_rel(int *p, int oldv, int newv)
{
    int retv = oldv;

    return __atomic_compare_exchange_n(p, &retv, newv, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

static __always_inline int
kmt_spin_lock(void *lockp)
{
    while (!atomic_cas_acq(lockp, 0, 1)) {
        do {
            __builtin_ia32_pause();
        } while (*(int *)lockp);
    }

    return true;
}

static __always_inline int
kmt_spin_trylock(void *lockp)
{
    return !atomic_cas_acq(lockp, 0, 1);
}

static __always_inline int
kmt_spin_unlock(void *lockp)
{
    return atomic_cas_rel(lockp, 1, 0);
}


typedef int lockfunc_t(void *);

struct {
    struct bkt     *bkt;
    lockfunc_t     *bktlock_rlock;
    lockfunc_t     *bktlock_runlock;
    lockfunc_t     *bktlock_wlock;
    lockfunc_t     *bktlock_trywlock;
    lockfunc_t     *bktlock_wunlock;

    struct bktlock *bktlock;
    size_t          bktlocksz;
}g HSE_ALIGNED(SMP_CACHE_BYTES * 2);

void
bkt_init(void)
{
    bool   use_spinlock, use_rwlock;
    int    i;

    g.bktlocksz = ALIGN(sizeof(*g.bktlock) * BKTLOCK_MAX, PAGE_SIZE);
    g.bktlocksz += ALIGN(sizeof(*g.bkt) * BKT_MAX, PAGE_SIZE);

    g.bktlock = super_alloc(g.bktlocksz);
    if (!g.bktlock)
        abort();

    g.bkt = (void *)(g.bktlock + BKTLOCK_MAX);

    use_rwlock = use_spinlock = false;

    /* Adapt locking style to the number of threads, bucket
     * depth, and swap percentage.
     *
     * If max threads is one then we don't need any locking.
     * If swap percentage is zero then we don't need any read
     * locking, but we do need write locking for both the init
     * and delete phases.
     */
    if (tdmax > 1) {
        g.bktlock_wlock = (lockfunc_t *)kmt_spin_lock;
        g.bktlock_trywlock = (lockfunc_t *)kmt_spin_trylock;
        g.bktlock_wunlock = (lockfunc_t *)kmt_spin_unlock;

        for (i = 0; i < BKTLOCK_MAX; ++i)
            g.bktlock[i].spinlock = 0;

        for (i = 0; i < BKT_MAX; ++i)
            g.bkt[i].lock = &g.bktlock[i % BKTLOCK_MAX].spinlock;

        if (swappct > 0) {
            use_rwlock = (recmax / BKT_MAX) > 1024;
            use_spinlock = !use_rwlock;
        }
    }

    if (use_rwlock) {
        g.bktlock_rlock = (lockfunc_t *)pthread_rwlock_rdlock;
        g.bktlock_runlock = (lockfunc_t *)pthread_rwlock_unlock;
        g.bktlock_wlock = (lockfunc_t *)pthread_rwlock_wrlock;
        g.bktlock_trywlock = (lockfunc_t *)pthread_rwlock_trywrlock;
        g.bktlock_wunlock = (lockfunc_t *)pthread_rwlock_unlock;

        for (i = 0; i < BKTLOCK_MAX; ++i)
            pthread_rwlock_init(&g.bktlock[i].rwlock, NULL);

        for (i = 0; i < BKT_MAX; ++i)
            g.bkt[i].lock = &g.bktlock[i % BKTLOCK_MAX].rwlock;
    } else if (use_spinlock) {
        g.bktlock_rlock = (lockfunc_t *)kmt_spin_lock;
        g.bktlock_runlock = (lockfunc_t *)kmt_spin_unlock;
    }
}

struct bkt *
bkt_get(uint64_t key)
{
    return g.bkt + (key % BKT_MAX);
}

#ifdef XKMT
static inline int
bkt_rlock(struct bkt *bkt)
{
    if (g.bktlock_rlock)
        g.bktlock_rlock(bkt->lock);
    return 0;
}

static inline int
bkt_runlock(struct bkt *bkt)
{
    if (g.bktlock_runlock)
        g.bktlock_runlock(bkt->lock);
    return 0;
}
#endif

static __always_inline int
bkt_wlock(struct bkt *bkt)
{
#ifdef XKMT
    if (g.bktlock_wlock)
        g.bktlock_wlock(bkt->lock);
#else
    if (g.bktlock_wlock)
        return kmt_spin_lock(bkt->lock);
#endif

    return 0;
}

static __always_inline int
bkt_trywlock(struct bkt *bkt)
{
#ifdef XKMT
    if (g.bktlock_trywlock)
        return g.bktlock_trywlock(bkt->lock);
#else
    if (g.bktlock_trywlock)
        return kmt_spin_trylock(bkt->lock);
#endif

    return 0;
}

static __always_inline int
bkt_wunlock(struct bkt *bkt)
{
#ifdef XKMT
    if (g.bktlock_wunlock)
        g.bktlock_wunlock(bkt->lock);
#else
    if (g.bktlock_wunlock)
        return kmt_spin_unlock(bkt->lock);
#endif

    return 0;
}

static inline u64
km_op_latency_init(struct km_impl *impl, enum km_op op)
{
    if (latency)
        return get_time_ns();
    return 0;
}

static inline void
km_op_latency_record(struct km_inst *inst, enum km_op op, u64 ns)
{
    struct km_latency *lat;

    if (!latency)
        return;

    assert(op >= OP_KVS_GET && op <= OP_KVS_DEL);

    ns = get_time_ns() - ns;

    lat = &inst->latency[op - OP_KVS_GET];

    if (ns >= 1000) {
        /* Any sample larger the maximum chosen value in hdr_init() will
         * be discarded. A counter is used to record such instances.
         */
        if (hdr_record_value_atomic(lat->km_histogram, ns / 1000))
            atomic64_inc(&lat->km_samples);
        else
            atomic64_inc(&lat->km_samples_err);
    }
}

#ifdef XKMT
static void *
hse_kvdb_txn_alloc(void *kvdb)
{
    return NULL;
};

static void
hse_kvdb_txn_free(void *kvdb, void *txn){};

static int
hse_kvdb_txn_begin(void *kvdb, void *txn)
{
    return EINVAL;
};

static int
hse_kvdb_txn_commit(void *kvdb, void *txn)
{
    return EINVAL;
};

static void
hse_kvdb_txn_abort(void *kvdb, void *txn){};

static char *
hse_err_to_string(u64 err, char *buf, size_t bufsz, void *dumb)
{
    return strerror_r(err, buf, bufsz);
}

#define hse_kvdb_open     kvdb_open_xkmt
#define hse_kvdb_kvs_open kvdb_kvs_open_xkmt
#define hse_kvdb_close    kvdb_close_xkmt
#define hse_kvs_get       kvs_get_xkmt
#define hse_kvs_put       kvs_put_xkmt
#define hse_kvs_delete    kvs_delete_xkmt

int
kvdb_open_xkmt(const char *mp_name, size_t pc, const char *const *pv, struct hse_kvdb **kvdb_handle)
{
    if (!kvs) {
        kvs = aligned_alloc(PAGE_SIZE, sizeof(*kvs));
        if (!kvs) {
            eprint("%s: unable to alloc aligned hse: %s\n", __func__, strerror(errno));
            exit(EX_OSERR);
        }

        memset(kvs, 0, sizeof(*kvs));
        kvs->mpname = mp_name;
    }

    *kvdb_handle = (struct hse_kvdb *)kvs;

    return 0;
}

int
kvdb_kvs_open_xkmt(
    struct hse_kvdb *  kvdb_handle,
    const char *       kvs_name,
    size_t parmc,
    const char *const *parmv,
    struct hse_kvs **  kvs_out)
{
    struct hse_kvs *k = (struct hse_kvs *)kvdb_handle;

    k->kvsname = kvs_name;

    *kvs_out = k;
    return 0;
}

int
kvdb_close_xkmt(struct hse_kvdb *hdl)
{
    return 0;
}

int
kvs_get_xkmt(
    struct hse_kvs *kvs_handle,
    unsigned int    flags,
    void *          txn,
    const void *    key,
    size_t          key_len,
    bool *          found,
    void *          valbuf,
    size_t          valbufsz,
    size_t *        val_len)
{
    struct kvnode *node, tmp;
    struct bkt *   bkt;

    tmp.keylen = key_len;
    tmp.key = (void *)key;

    if (keybinary) {
        tmp.hash = *(uint64_t *)tmp.key;
    } else {
        uint64_t hash[2];

        murmur3_128(tmp.key, tmp.keylen, hash);
        tmp.hash = hash[0];
    }

    bkt = bkt_get(tmp.hash);

    if (!testmode)
        bkt_rlock(bkt);

    node = RB_FIND(node_tree, &bkt->root, &tmp);
    if (node) {
        if (valbufsz >= node->datalen) {
            *val_len = node->datalen;
            memcpy(valbuf, node->data, *val_len);
        } else {
            node = NULL;
        }
    }

    if (!testmode)
        bkt_runlock(bkt);

    if (node) {
        *found = true;
        return 0;
    }

    *found = false;

    return ENOENT;
}

int
kvs_put_xkmt(
    struct hse_kvs *kvs_handle,
    unsigned int    flags,
    void *          txn,
    const void *    key,
    size_t          key_len,
    const void *    val,
    size_t          val_len)
{
    static thread_local struct kvnode *node;

    struct bkt *   bkt;
    struct kvnode *dup;
    char *         data;
    size_t         sz;

    data = NULL;

    if (node) {
        sz = ALIGN(node->keylen, 8) + ALIGN(node->datalen, 128);

        if (key_len + val_len > sz)
            free(node->key);
        else
            data = node->key;
    } else {
        node = malloc(sizeof(*node));
        if (!node)
            return ENOMEM;
    }

    if (!data) {
        sz = ALIGN(key_len, 8) + ALIGN(val_len, 128);

        data = malloc(sz);
        if (!data) {
            free(node);
            return ENOMEM;
        }
    }

    node->keylen = key_len;
    node->datalen = val_len;
    node->key = data;
    node->data = data + ALIGN(node->keylen, 8);

    memcpy(node->key, key, node->keylen);

    if (keybinary)
        node->hash = *(uint64_t *)node->key;
    else {
        uint64_t hash[2];

        murmur3_128(node->key, node->keylen, hash);
        node->hash = hash[0];
    }

    memcpy(node->data, val, node->datalen);

    bkt = bkt_get(node->hash);

    if (!testmode)
        bkt_wlock(bkt);

    dup = RB_INSERT(node_tree, &bkt->root, node);
    if (dup) {
        uint  datalen = dup->datalen;
        char *k = dup->key;

        /* Node exists, swap the key and data buffers so that we
         * can potentially re-use the old ones next time around.
         */
        dup->datalen = node->datalen;
        dup->key = node->key;
        dup->data = node->data;

        node->datalen = datalen;
        node->key = k;
    } else {
        node = NULL;
    }

    if (!testmode)
        bkt_wunlock(bkt);

    return 0;
}

int
kvs_delete_xkmt(
    struct hse_kvs *kvs_handle,
    unsigned int    flags,
    void *          txn,
    const void *    key,
    size_t          key_len)
{
    struct kvnode *node, tmp;
    struct bkt *   bkt;

    tmp.keylen = key_len;
    tmp.key = (void *)key;

    if (keybinary)
        tmp.hash = *(uint64_t *)tmp.key;
    else {
        uint64_t hash[2];

        murmur3_128(tmp.key, tmp.keylen, hash);
        tmp.hash = hash[0];
    }

    bkt = bkt_get(tmp.hash);

    if (!testmode)
        bkt_wlock(bkt);

    node = RB_FIND(node_tree, &bkt->root, &tmp);
    if (node)
        RB_REMOVE(node_tree, &bkt->root, node);

    if (!testmode)
        bkt_wunlock(bkt);

    if (node)
        return 0;

    return ENOENT;
}

#endif /* XKMT */

void
eprint(char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    (void)snprintf(msg, sizeof(msg), "%s: ", progname);

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
sigusr1_isr(int sig)
{
    ++sigusr1;
}

RETSIGTYPE
sigint_isr(int sig)
{
    ++sigalrm;
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

void
chk_pair_lock(struct km_impl *impl, uint64_t ridx, uint64_t ridy)
{
    struct bkt *bktx, *bkty, *tmp;

    if (swappct == 0 || tdmax == 1)
        return;

    bktx = bkt_get(ridx);
    bkty = bkt_get(ridy);

    if (bktx->lock > bkty->lock) {
        tmp = bktx;
        bktx = bkty;
        bkty = tmp;
    }

    bkt_wlock(bktx);

    if (bktx->lock != bkty->lock)
        bkt_wlock(bkty);
}

bool
chk_pair_trylock(struct km_impl *impl, uint64_t ridx, uint64_t ridy)
{
    struct bkt *bktx, *bkty, *tmp;

    if (swappct == 0 || tdmax == 1)
        return true;

    bktx = bkt_get(ridx);
    bkty = bkt_get(ridy);

    if (bktx->lock > bkty->lock) {
        tmp = bktx;
        bktx = bkty;
        bkty = tmp;
    }

    if (0 != bkt_trywlock(bktx))
        return false;

    if (bktx->lock != bkty->lock) {
        if (0 != bkt_trywlock(bkty)) {
            bkt_wunlock(bktx);
            return false;
        }
    }

    return true;
}

void
chk_pair_unlock(struct km_impl *impl, uint64_t ridx, uint64_t ridy)
{
    struct bkt *bktx, *bkty;

    if (swappct == 0 || tdmax == 1)
        return;

    bktx = bkt_get(ridx);
    bkty = bkt_get(ridy);

    bkt_wunlock(bktx);

    if (bktx->lock != bkty->lock)
        bkt_wunlock(bkty);
}

hse_err_t
chk_verify(struct km_inst *inst, struct km_rec *r)
{
    struct km_impl *impl = inst->impl;
    struct chk *    chk;

    if (r->rid >= impl->recmax) {
        eprint("%s: invalid rid %lu >= recmax %lu\n", __func__, r->rid, impl->recmax);
        abort();
    }

    if (!impl->chk)
        return 0;

    chk = &impl->chk[r->rid];

    if (r->hash != chk->hash64) {
        if (impl->kvs || mongo) {
            inst->fmt = "chkfile hash mismatch: %s";
            return EINVAL;
        }

        if ((r->hash & 0xffffffff) != chk->hash32) {
            inst->fmt = "chkfile hash mismatch: %s";
            return EINVAL;
        }
    }

    return 0;
}

void
hash_update(struct km_rec *r)
{
    uint64_t hash[2];

    r->hash = 0;

    murmur3_128(r, sizeof(*r) + r->vlen, hash);

    r->hash = hash[0];
}

void
chk_update(struct km_impl *impl, struct km_rec *r, bool reset_hash)
{
    struct chk *chk;

    if (reset_hash)
        hash_update(r);

    /* If you get a SIGBUS here during init ensure you have
     * at least 16G of free space in /var/tmp.
     */
    if (impl->chk) {
        chk = &impl->chk[r->rid];
        chk->vlen = r->vlen;

        if (impl->kvs || mongo) {
            chk->hash64 = r->hash;
        } else {
            chk->mbid = r->mbid;
        }
        chk->hash32 = r->hash;

        if (keybinary)
            chk->flags |= CHK_F_KEYBINARY;
    }
}

void
chk_init(struct km_impl *impl, uint64_t recmax)
{
    struct stat sb;

    int   oflags = O_RDWR;
    int   mflags, prot;
    bool  needmap;
    off_t length;
    int   fd;
    int   rc;

    if (mongo) {
        snprintf(chk_path, sizeof(chk_path), "%s/%s-mongodb-%s", cf_dir, progname, impl->kvsname);
    } else {
        char buf[128], *pc = buf;

        strlcpy(buf, impl->mpname, sizeof(buf));
        while (*pc) {
            if (!isalnum(*pc))
                *pc = '-';
            ++pc;
        }

        snprintf(chk_path, sizeof(chk_path), "%s/%s-%s%s%s",
                 cf_dir, progname, buf,
                 impl->kvsname ? "-" : "",
                 impl->kvsname ?: "");
    }

    if (recmax > 0)
        oflags |= O_CREAT | O_TRUNC;

    fd = open(chk_path, oflags, 0600);
    if (-1 == fd) {
        eprint("%s: open(%s): %s\n", __func__, chk_path, strerror(errno));
        exit(EX_NOINPUT);
    }

    if (recmax > 0) {
        length = sizeof(struct chk) * recmax;
        rc = ftruncate(fd, length);
    } else {
        rc = fstat(fd, &sb);
        length = sb.st_size;
    }

    if (rc) {
        eprint("%s: unable to %s check file %s: %s\n",
               __func__, recmax > 0 ? "create" : "open",
               chk_path, strerror(errno));
        exit(EX_OSERR);
    }

    impl->recmax = length / sizeof(struct chk);

    /* Ensure length is an integral number of chk objects.
     */
    if (impl->recmax * sizeof(struct chk) != length) {
        eprint("%s: invalid check file length: %s\n", __func__, chk_path);
        abort();
    }

    prot = PROT_READ | PROT_WRITE;
    mflags = MAP_SHARED | MAP_POPULATE;

    impl->chk = mmap(NULL, length, prot, mflags, fd, 0);

    if (impl->chk == MAP_FAILED) {
        eprint("%s: mmap: %s\n", __func__, strerror(errno));
        exit(EX_OSERR);
    }

    /* Set the keybinary flag in the first chk record on create, and
     * retrieve it from the first record when re-opening a pre-
     * existing chk file.
     */
    if (keybinary && oflags & O_CREAT)
        impl->chk[0].flags = CHK_F_KEYBINARY;
    keybinary = !!(impl->chk->flags & CHK_F_KEYBINARY);

    /* Backends that cannot fabricate keys from record IDs require the
     * mapped check file into which they store their rid-to-key mappings.
     */
    needmap = !(mongo || impl->kvsname);

    if (!needmap && (impl->recmax > chk_recmax || !recverify)) {
        munmap(impl->chk, length);
        impl->chk = NULL;
    }

    close(fd);
}

void
chk_destroy(struct km_impl *impl)
{
    unlink(chk_path);
}

static void *rec_head;

void
km_rec_alloc_cmn(struct km_inst *inst, void **rp1, void **rp2)
{
    char  errbuf[128];
    void *r;
    int   i;

    td_lock();
    if (!rec_head) {
        r = super_alloc(secsz * tdmax * 2);
        if (!r) {
            eprint("%s: rec_alloc failed: %s\n",
                   __func__, strerror_r(errno, errbuf, sizeof(errbuf)));
            exit(EX_OSERR);
        }

        rec_head = r;

        for (i = 0; i < tdmax * 2; ++i, r += secsz)
            *(void **)r = r + secsz;
    }

    if (rp1) {
        r = rec_head;
        rec_head = r ? *(void **)r : NULL;
        *rp1 = r;
    }

    if (rp2) {
        r = rec_head;
        rec_head = r ? *(void **)r : NULL;
        *rp2 = r;
    }
    td_unlock();
}

void
km_rec_free_locked(void *r)
{
    *(void **)r = rec_head;
    rec_head = r;
}

int
km_rec_keygen_cmn(void *key, uint64_t rid)
{
    int len;

    if (keyfmt)
        return snprintf(key, KM_REC_KEY_MAX, keyfmt, rid, rid, rid);

    if (keybinary) {
        len = keybinmax;
        if (len > keybinmin)
            len = keybinmin + (rid % (keybinmax - keybinmin + 1));

        *(uint64_t *)key = rid;

        return len;
    }

    /* Fast uint to string.
     */
    const uint base = 10;
    uint64_t   value = rid;
    char *     right = key;
    char *     left;

    do {
        uint64_t tmp = value;

        value /= base;
        *right++ = '0' + tmp - value * base;
    } while (value > 0);

    len = right - (char *)key;
    if (len >= KM_REC_KEY_MAX) {
        eprint("%s: key buf overflow: len=%d keysz=%d keyfmt=%s rid=%lu\n",
               __func__, len, KM_REC_KEY_MAX, keyfmt, rid);
        abort();
    }

    *right-- = '\000';

    left = key;
    while (left < right) {
        char tmp = *right;

        *right-- = *left;
        *left++ = tmp;
    }

    return len;
}

void
km_rec_init_cmn(struct km_inst *inst, struct km_rec *r, uint64_t rid, const struct timeval *tv)
{
    struct km_impl *impl = inst->impl;
    char *          key = (char *)r + secsz - KM_REC_KEY_MAX;

    memset(r, 0, sizeof(*r));

    r->rid = rid;
    r->rid0 = rid;
    r->klen = km_rec_keygen_cmn(key, rid);
    r->vlen = 0;

    if (impl->vlenmax > 0) {
        void *src = randbuf + (rid % randbufsz);

        r->vlen = impl->vlenmin + (rid % impl->vlendiv);
        memmove(r->data, src, r->vlen);
        r->data[r->vlen] = '\000';
    }
}

hse_err_t
km_rec_verify_cmn(struct km_inst *inst, struct km_rec *r)
{
    uint64_t hash[2];
    uint64_t save;

    if (r->vlen > KM_REC_VLEN_MAX)
        abort();

    save = r->hash;
    r->hash = 0;

    murmur3_128(r, sizeof(*r) + r->vlen, hash);

    r->hash = hash[0];

    if (r->hash != save) {
        inst->fmt = "computed hash mismatch: %s";

        return EINVAL;
    }

    return 0;
}

void
km_rec_print_cmn(struct km_inst *inst, struct km_rec *r, const char *fmt, hse_err_t err)
{
    struct km_impl *impl = inst->impl;
    static int      once;
    char            ebuf[128];
    char            vbuf[128];
    u64             chk_hash;
    char *          dst;
    int             i;

    if (!once++) {
        printf(
            "%7s %7s %17s %17s %5s %9s %16s %-32s\n",
            "RID",
            "RID0",
            "HASH",
            "CHK_HASH",
            "KLEN",
            "VLEN",
            "MBID",
            "VALUE");
    }

    chk_hash = 0;
    if (impl->chk && r->rid < impl->recmax) {
        struct chk *chk = &impl->chk[r->rid];

        if (impl->kvs || mongo)
            chk_hash = chk->hash64;
        else
            chk_hash = chk->hash32;
    }

    ebuf[0] = '\000';
    if (err && fmt)
        snprintf(ebuf, sizeof(ebuf), "%ld", err);

    dst = vbuf;
    for (i = 0; i < 32 && i < r->vlen; ++i) {
        const char tab[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        *dst++ = tab[(r->data[i] >> 4) & 0x0f];
        *dst++ = tab[r->data[i] & 0x0f];
    }
    *dst = '\000';

    printf(
        "%7lu %7lu %17lx %17lx %5u %9u %16lx %-32s %s\n",
        r->rid,
        r->rid0,
        r->hash,
        chk_hash,
        r->klen,
        r->vlen,
        r->mbid,
        vbuf,
        ebuf);
}

void
km_rec_swap_cmn(struct km_inst *inst, struct km_rec *x, struct km_rec *y)
{
    struct km_impl *impl = inst->impl;

    char *   xkey = (char *)x + secsz - KM_REC_KEY_MAX;
    char *   ykey = (char *)y + secsz - KM_REC_KEY_MAX;
    uint64_t mbidx = x->mbid;
    uint64_t mbidy = y->mbid;
    uint64_t ridx = x->rid;
    uint64_t ridy = y->rid;

    x->rid = ridy;
    x->mbid = mbidy;
    x->klen = km_rec_keygen_cmn(xkey, ridy);
    x->vlen = 0;

    if (impl->vlenmax > 0) {
        void *src = randbuf + (xrand32() % randbufsz);

        x->vlen = impl->vlenmin + (xrand32() % impl->vlendiv);
        memmove(x->data, src, x->vlen);
    }

    y->rid = ridx;
    y->mbid = mbidx;
    y->klen = km_rec_keygen_cmn(ykey, ridx);
    y->vlen = 0;

    if (impl->vlenmax > 0) {
        void *src = randbuf + (xrand32() % randbufsz);

        y->vlen = impl->vlenmin + (xrand32() % impl->vlendiv);
        memmove(y->data, src, y->vlen);
    }

    inst->stats.swap++;
}

hse_err_t
km_rec_get_kvs(struct km_inst *inst, struct km_rec *r, uint64_t rid)
{
    struct km_impl *impl = inst->impl;
    char *          key = (char *)r + secsz - KM_REC_KEY_MAX;
    size_t          klen, vlen;
    hse_err_t          err;
    u64             rc;
    bool            found;
    u64             ns;

    if (rid >= impl->recmax)
        abort();

    ns = km_op_latency_init(inst->impl, OP_KVS_GET);

    inst->stats.op = OP_KVS_GET;
    inst->stats.get++;

    r->rid = -1;
    r->vlen = -1;

    klen = km_rec_keygen_cmn(key, rid);
    vlen = 0;

    rc = hse_kvs_get(impl->kvs, inst->flags, inst->txn, key, klen, &found, r, secsz, &vlen);
    if (rc) {
        inst->fmt = "hse_kvs_get: %s";
        return rc;
    }

    if (!found) {
        inst->fmt = "record not found: %s";
        return ENOENT;
    }

    if (r->rid != rid) {
        if (c0putval >= sizeof(r->rid)) {
            eprint("%s: corrupt value: (r->rid %lu != rid %lu)\n", __func__, r->rid, rid);
            abort();
        }

        /* If (c0putval < 8) then we must trust that the value
         * data we got back from hse_kvs_get() is valid.
         */
        r->rid = rid;
    }

    if (recverify) {
        inst->stats.op = OP_VERIFY;

        if (vlen < sizeof(*r)) {
            eprint("%s: invalid record size %zu (should be at least %zu)\n",
                   __func__, vlen, sizeof(*r));
            abort();
        }

        err = chk_verify(inst, r);
        if (err)
            return err;

        err = km_rec_verify(inst, r);
        if (err)
            return err;
    }

    inst->stats.getbytes += vlen;

    km_op_latency_record(inst, OP_KVS_GET, ns);

    return 0;
}

hse_err_t
km_rec_put_kvs(struct km_inst *inst, struct km_rec *r)
{
    struct km_impl *impl = inst->impl;
    char *          key = (char *)r + secsz - KM_REC_KEY_MAX;
    size_t          vlen;
    u64             rc;
    u64             ns;

    if (r->rid >= impl->recmax)
        abort();

    ns = km_op_latency_init(inst->impl, OP_KVS_PUT);

    /*
     * A transaction updates chk only when the puts succeed and the
     * transaction commits successfully.
     */
    if (!inst->txn)
        chk_update(impl, r, true);
    else
        hash_update(r);

    vlen = sizeof(*r) + r->vlen;
    vlen = min_t(size_t, vlen, c0putval);

    inst->stats.op = OP_KVS_PUT;
    inst->stats.put++;
    inst->stats.putbytes += vlen;

    rc = hse_kvs_put(impl->kvs, inst->flags, inst->txn, key, r->klen, r, vlen);

    if (!rc)
        km_op_latency_record(inst, OP_KVS_PUT, ns);

    return rc;
}

hse_err_t
km_rec_del_kvs(struct km_inst *inst, uint64_t rid)
{
    struct km_impl *impl = inst->impl;
    char            key[KM_REC_KEY_MAX];
    size_t          klen;
    u64             rc;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_DEL);

    if (keybinmax > 16)
        memset(key, 0, keybinmax);

    klen = km_rec_keygen_cmn(key, rid);

    inst->stats.op = OP_KVS_DEL;
    inst->stats.del++;
    inst->stats.putbytes += klen;

    rc = hse_kvs_delete(impl->kvs, inst->flags, inst->txn, key, klen);

    if (!rc)
        km_op_latency_record(inst, OP_KVS_DEL, ns);

    return rc;
}

hse_err_t
km_rec_get_ds(struct km_inst *inst, struct km_rec *r, uint64_t rid)
{
    struct km_impl *impl = inst->impl;
    struct iovec    iov[2];
    hse_err_t          err;
    uint64_t        mbid;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_GET);

    if (rid >= impl->recmax)
        abort();

    /* Poison the buffer to make read corruption detection easier...
     */
    r->rid = -1;
    r->mbid = -1;

    if (!impl->chk)
        return EINVAL;

    inst->stats.op = OP_MB_READ;
    inst->stats.get++;
    inst->stats.getbytes += secsz;

    iov[0].iov_base = r;
    iov[0].iov_len = secsz;

    mbid = impl->chk[rid].mbid;

    err = merr_to_hse_err(mpool_mblock_read(impl->ds, mbid, iov, 1, 0));
    if (err) {
        eprint("%s: mpool_mblock_read(0x%lx): rid=%lu mbid=%lx err=%lx\n",
               __func__, mbid, (ulong)rid, (ulong)mbid, err);
        return err;
    }

    if (r->rid != rid || r->mbid != mbid) {
        eprint(
            "%s: corrupt mblock: "
            "(r->rid %lu != rid %lu) || "
            "(r->mbid %lx != mbid %lx)\n",
            __func__,
            r->rid,
            rid,
            r->mbid,
            mbid);
        abort();
    }

    if (recverify) {
        inst->stats.op = OP_VERIFY;

        err = chk_verify(inst, r);
        if (err)
            return err;

        err = km_rec_verify(inst, r);
        if (err)
            return err;
    }

    km_op_latency_record(inst, OP_KVS_GET, ns);

    return 0;
}

hse_err_t
km_rec_put_ds(struct km_inst *inst, struct km_rec *r)
{
    struct km_impl *    impl = inst->impl;
    struct mblock_props props;

    struct iovec iov[2];
    uint64_t     nmbid;
    uint64_t     ombid;
    hse_err_t       err;
    u64          ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_PUT);

    if (r->rid >= impl->recmax)
        abort();

    inst->stats.op = OP_MB_ALLOC;
    inst->stats.alloc++;

    err = merr_to_hse_err(mpool_mblock_alloc(impl->ds, mclass, &nmbid, &props));
    if (err)
        return err;

    nmbid = props.mpr_objid;
    ombid = r->mbid;

    if (ombid > 0) {
        inst->stats.op = OP_MB_DELETE;
        inst->stats.del++;

        err = merr_to_hse_err(mpool_mblock_delete(impl->ds, ombid));
        if (err) {
            eprint("%s: mbdelete %lx failed: %lx\n", __func__, ombid, err);
        }
    }

    r->mbid = nmbid;
    chk_update(impl, r, true);

    iov[0].iov_base = r;
    iov[0].iov_len = secsz;

    inst->stats.op = OP_MB_WRITE;
    inst->stats.put++;
    inst->stats.putbytes += secsz;

    err = merr_to_hse_err(mpool_mblock_write(impl->ds, nmbid, iov, 1));
    if (err) {
        eprint("%s: mbwrite %lx failed: %lx\n", __func__, r->mbid, err);
        return err;
    }

    if (r->rid >= impl->recmax || r->mbid != nmbid)
        abort();

    inst->stats.op = OP_MB_COMMIT;
    inst->stats.commit++;

    err = merr_to_hse_err(mpool_mblock_commit(impl->ds, nmbid));
    if (err) {
        eprint("%s: mbcommit %lx failed: %lx\n", __func__, nmbid, err);
        return err;
    }

    km_op_latency_record(inst, OP_KVS_PUT, ns);

    return 0;
}

hse_err_t
km_rec_del_ds(struct km_inst *inst, uint64_t rid)
{
    struct km_impl *impl = inst->impl;
    uint64_t        mbid;
    hse_err_t          err;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_DEL);

    if (!impl->chk)
        return EINVAL;

    inst->stats.op = OP_MB_DELETE;
    inst->stats.del++;

    mbid = impl->chk[rid].mbid;
    if (mbid == 0)
        return EINVAL;

    err = merr_to_hse_err(mpool_mblock_delete(impl->ds, mbid));

    km_op_latency_record(inst, OP_KVS_DEL, ns);

    return err;
}

hse_err_t
km_rec_get_dev(struct km_inst *inst, struct km_rec *r, uint64_t rid)
{
    struct km_impl *impl = inst->impl;
    hse_err_t          err;
    off_t           offset;
    ssize_t         cc;
    int             fd;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_GET);

    if (rid >= impl->recmax)
        abort();

    r->rid = -1;

    if (!impl->chk)
        return EINVAL;

    inst->stats.op = OP_MB_READ;
    inst->stats.get++;
    inst->stats.getbytes += secsz;

    offset = impl->chk[rid].offset;

    fd = (intptr_t)impl->ds;

    cc = pread(fd, r, secsz, offset);
    if (cc != secsz)
        return cc == -1 ? errno : EIO;

    if (r->rid != rid || r->offset != offset) {
        eprint(
            "%s: corrupt block: "
            "(r->rid %lu != rid %lu) || "
            "(r->offset %ld != offset %ld)\n",
            __func__,
            r->rid,
            rid,
            r->offset,
            offset);
        abort();
    }

    if (recverify) {
        inst->stats.op = OP_VERIFY;

        err = chk_verify(inst, r);
        if (err)
            return err;

        err = km_rec_verify(inst, r);
        if (err)
            return err;
    }

    km_op_latency_record(inst, OP_KVS_GET, ns);

    return 0;
}

hse_err_t
km_rec_put_dev(struct km_inst *inst, struct km_rec *r)
{
    struct km_impl *impl = inst->impl;
    ssize_t         cc;
    int             fd;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_PUT);

    if (r->rid >= impl->recmax)
        abort();

    inst->stats.op = OP_MB_ALLOC;
    inst->stats.alloc++;

    r->offset = r->rid * vebsz;

    chk_update(impl, r, true);

    inst->stats.op = OP_MB_WRITE;
    inst->stats.put++;
    inst->stats.putbytes += secsz;

    fd = (intptr_t)impl->ds;

    cc = pwrite(fd, r, secsz, r->offset);
    if (cc != secsz)
        return cc == -1 ? errno : EIO;

    if (r->rid >= impl->recmax)
        abort();

    km_op_latency_record(inst, OP_KVS_PUT, ns);

    return 0;
}

hse_err_t
km_rec_del_dev(struct km_inst *inst, uint64_t rid)
{
    u64 ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_DEL);

    inst->stats.op = OP_MB_DELETE;
    inst->stats.del++;

    km_op_latency_record(inst, OP_KVS_DEL, ns);

    return 0;
}

void
rec_to_bson(struct km_rec *r, bson_t *doc)
{
    bson_append_binary(doc, "meta", 4, BSON_SUBTYPE_BINARY, (void *)r, sizeof(*r));

    if (r->vlen > 0) {
        const char *name = fieldnamev;
        const uint8_t *src = r->data;
        int namelen = fieldnamew_min;
        int i = fieldcount;
        size_t srclen;

        /* If (fieldlength == 0) then r->vlen can vary from record to record.
         * Otherwise, each field is fixed size.
         */
        srclen = fieldlength ?: r->vlen;

        while (i-- > 0) {
            bson_append_binary(doc, name, namelen, BSON_SUBTYPE_BINARY, src, srclen);

            name += fieldnamew_max;
            if (name[namelen])
                ++namelen;

            src += fieldlength;
        }
    }
}

void
bson_to_rec(const bson_t *doc, struct km_rec *r)
{
    const uint8_t *vptr;
    bson_iter_t iter;
    uint32_t vlen;

    if (!bson_iter_init(&iter, doc))
        abort();

    if (!bson_iter_find(&iter, "meta"))
        abort();

    bson_iter_binary(&iter, NULL, &vlen, &vptr);
    memcpy(r, vptr, vlen);

    if (r->vlen > 0) {
        const char *name = fieldnamev;
        uint8_t *dst = r->data;

        while (bson_iter_find(&iter, name)) {
            bson_iter_binary(&iter, NULL, &vlen, &vptr);
            memcpy(dst, vptr, vlen);

            name += fieldnamew_max;
            dst += fieldlength;
        }
    }
}

uint
rid2cid(uint64_t rid)
{
    return (rid >> cidshift) & MONGO_COLLECTION_MASK;
}

hse_err_t
km_rec_get_mongo(struct km_inst *inst, struct km_rec *r, uint64_t rid)
{
    struct km_impl  *impl = inst->impl;
    char            *key = (char *)r + secsz - KM_REC_KEY_MAX;
    size_t           klen, vlen;
    uint             retries;
    uint             cid;
    const bson_t    *doc;
    mongoc_cursor_t *cursor;
    hse_err_t           err;
    u64              ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_GET);

    if (rid >= impl->recmax)
        abort();

    inst->stats.op = OP_KVS_GET;
    retries = 3;

  again:
    r->rid = -1;
    r->vlen = -1;

    klen = km_rec_keygen_cmn(key, rid);
    vlen = 0;

    bson_append_utf8(&inst->query, "_id", 3, key, klen);

    cid = rid2cid(rid);

    cursor = mongoc_collection_find_with_opts(
        inst->collectionv[cid], &inst->query, &inst->ropts, NULL);

    if (mongoc_cursor_next(cursor, &doc))
        bson_to_rec(doc, r);

    if (mongoc_cursor_error(cursor, &inst->error)) {
        eprint("%s: cursor failure: (r->rid %lu != rid %lu): %s\n",
               __func__, r->rid, rid, inst->error.message);
        abort();
    }

    mongoc_cursor_destroy(cursor);
    bson_reinit(&inst->query);

    /* since mongoc does not set vlen like hse_kvs_get */
    vlen = sizeof(*r) + r->vlen;

    if (r->rid != rid) {
        if (c0putval >= sizeof(r->rid)) {
            eprint("%s: corrupt value: (r->rid %lu != rid %lu)\n", __func__, r->rid, rid);
            abort();
        }

        r->rid = rid;
    }

    if (recverify) {
        inst->stats.op = OP_VERIFY;

        /* possibly remove since vlen is being set explicity  */
        if (vlen < sizeof(*r)) {
            eprint("%s: invalid record size %zu (should be at least %zu)\n",
                   __func__, vlen, sizeof(*r));
            abort();
        }

        /* TODO: Sometimes mongo returns a document that mismatches the hash
         * in the check record.  Retrying seems to resolve the issue, but we
         * need to figure this out...
         */
        err = chk_verify(inst, r);
        if (err) {
            if (mongo && retries-- > 0) {
                usleep(100000);
                goto again;
            }

            return err;
        }

        err = km_rec_verify(inst, r);
        if (err)
            return err;
    }

    inst->stats.get++;
    inst->stats.getbytes += vlen;

    km_op_latency_record(inst, OP_KVS_GET, ns);

    return 0;
}

hse_err_t
km_rec_put_mongo(struct km_inst *inst, struct km_rec *r)
{
    struct km_impl *impl = inst->impl;
    char           *key = (char *)r + secsz - KM_REC_KEY_MAX;
    bson_t         *opts;
    uint            cid;
    bool            rc;
    u64             ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_PUT);

    if (r->rid >= impl->recmax)
        abort();

    inst->stats.op = OP_KVS_PUT;
    inst->stats.put++;
    inst->stats.putbytes += sizeof(*r) + r->vlen;

    chk_update(impl, r, true);

    bson_append_utf8(&inst->query, "_id", 3, key, r->klen);

    rec_to_bson(r, &inst->update);

    opts = &inst->wopts_wcmin;
    if (wcmaj > 0 && xrand64() % WCMAJSCALE < wcmaj)
        opts = &inst->wopts_wcmaj;

    cid = rid2cid(r->rid);

    rc = mongoc_collection_replace_one(
        inst->collectionv[cid], &inst->query, &inst->update, opts, NULL, &inst->error);

    if (!rc)
        eprint("%s: replace rid %lu failed%s\n", __func__, r->rid, inst->error.message);

    bson_reinit(&inst->update);
    bson_reinit(&inst->query);

    km_op_latency_record(inst, OP_KVS_PUT, ns);

    return rc ? 0 : EINVAL;
}

hse_err_t
km_rec_del_mongo(struct km_inst *inst, uint64_t rid)
{
    char       key[KM_REC_KEY_MAX];
    size_t     klen;
    uint       cid;
    bool       rc;
    u64        ns;

    ns = km_op_latency_init(inst->impl, OP_KVS_DEL);

    klen = km_rec_keygen_cmn(key, rid);

    inst->stats.op = OP_KVS_DEL;
    inst->stats.del++;
    inst->stats.putbytes += klen;

    bson_append_utf8(&inst->query, "_id", 3, key, klen);

    cid = rid2cid(rid);

    rc = mongoc_collection_delete_many(
        inst->collectionv[cid], &inst->query, NULL, NULL, &inst->error);

    if (!rc)
        eprint("%s: delete rid %lu failed: %s\n", __func__, rid, inst->error.message);

    bson_reinit(&inst->query);

    km_op_latency_record(inst, OP_KVS_DEL, ns);

    return rc ? 0 : EINVAL;
}

hse_err_t
km_open_kvs(struct km_impl *impl)
{
    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;
    u64              rc;
    struct svec *    kv_oparms = kvs_txn ? &kv_oparms_txn : &kv_oparms_notxn;

    if (impl->kvdb || impl->kvs)
        return 0;

    rc = hse_kvdb_open(impl->mpname, db_oparms.strc, db_oparms.strv, &kvdb);
    if (rc)
        return rc;

    rc = hse_kvdb_kvs_open(kvdb, impl->kvsname, kv_oparms->strc, kv_oparms->strv, &kvs);
    if (rc) {
        hse_kvdb_close(kvdb);
        return rc;
    }

    impl->kvdb = kvdb;
    impl->kvs = kvs;

    return rc;
}

hse_err_t
km_close_kvs(struct km_impl *impl)
{
    u64 rc = 0;

    if (stayopen)
        return 0;

    if (sigint < 3)
        rc = hse_kvdb_close(impl->kvdb);

    impl->kvs = NULL;
    impl->kvdb = NULL;

    return rc;
}

hse_err_t
km_open_ds(struct km_impl *impl)
{
    struct mpool *ds = NULL;
    struct mpool_rparams params = {0};
    merr_t err;

    if (impl->ds)
        return 0;

    if (secsz != roundup(secsz, 4096)) {
        eprint("%s: secsz must be 4096-byte aligned\n", __func__);
        return EINVAL;
    }

    for (int i = 0; i < MP_MED_COUNT; i++) {
        if (mclass == i) {
            strlcpy(params.mclass[i].path, impl->mpname, sizeof(params.mclass[i].path));
            break;
        }
    }

    err = mpool_open(impl->mpname, &params, O_RDWR, &ds);
    if (err)
        return merr_to_hse_err(err);

    impl->ds = ds;

    return err;
}

hse_err_t
km_close_ds(struct km_impl *impl)
{
    merr_t err;
    void *ds;

    if (stayopen)
        return 0;

    ds = impl->ds;
    impl->ds = NULL;

    err = mpool_close(ds);
    if (err)
        return merr_to_hse_err(err);

    return 0;
}

hse_err_t
km_open_dev(struct km_impl *impl)
{
    int fd;

    if (impl->ds)
        return 0;

    if (secsz != roundup(secsz, 512)) {
        eprint("%s: secsz must be 512-byte aligned\n", __func__);
        return EINVAL;
    }

    if (vebsz != roundup(vebsz, 512)) {
        eprint("%s: vebsz must be 512-byte aligned\n", __func__);
        return EINVAL;
    }

    if (vebsz < secsz) {
        eprint("%s: vebsz must greater than secsz\n", __func__);
        return EINVAL;
    }

    fd = open(impl->mpname, dev_oflags);
    if (-1 == fd)
        return errno;

    if (fd == 0)
        abort();

    impl->ds = (void *)(intptr_t)fd;

    return 0;
}

hse_err_t
km_close_dev(struct km_impl *impl)
{
    int fd;

    if (stayopen)
        return 0;

    fd = (intptr_t)impl->ds;
    impl->ds = NULL;

    return close(fd);
}

hse_err_t
km_open_mongo(struct km_impl *impl)
{
    bson_error_t     error;
    mongoc_client_t *client;
    bson_t           command;
    bson_t           reply;
    bool             ok;

    if (impl->client_pool)
        return 0;

    impl->active_uri = mongoc_uri_new_with_error(impl->mpname, &error);
    if (!impl->active_uri) {
        eprint("%s: mongoc_uri_new() failed: %s\n", __func__, error.message);
        return EINVAL;
    }

    impl->client_pool = mongoc_client_pool_new(impl->active_uri);
    if (!impl->active_uri) {
        eprint("%s: mongoc_client_pool_new() failed\n", __func__);
        mongoc_uri_destroy(impl->active_uri);
        impl->active_uri = NULL;
        return EINVAL;
    }

    mongoc_client_pool_set_error_api(impl->client_pool, 2);
    mongoc_client_pool_max_size(impl->client_pool, tdmax + 1);

    client = mongoc_client_pool_pop(impl->client_pool);
    if (!client) {
        eprint("%s: mongoc_client_pool_pop() failed\n", __func__);
        mongoc_client_pool_destroy(impl->client_pool);
        impl->client_pool = NULL;
        mongoc_uri_destroy(impl->active_uri);
        impl->active_uri = NULL;
        return EINVAL;
    }

    bson_init(&reply);
    bson_init(&command);
    BSON_APPEND_INT32(&command, "ping", 1);

    ok = mongoc_client_command_simple(client, "admin", &command, NULL, &reply, &error);
    if (ok) {
        mongoc_collection_t *collection;
        char collname[16];
        int64_t total;
        int retries = 15;
        int i;

      retry:
        total = 0;

        for (i = 0; i < collectionc; ++i) {
            bson_t query = BSON_INITIALIZER;
            int64_t n;

            snprintf(collname, sizeof(collname), "kmt%d", i);

            /* mongoc_client_get_collection() performs an implicit collection create...
             */
          again:
            collection = mongoc_client_get_collection(client, impl->kvsname, collname);
            if (!collection) {
                eprint("%s: unable to get collection %s\n",
                       __func__, collname);
                exit(EX_OSERR);
            }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            n = mongoc_collection_count_with_opts(
                collection, MONGOC_QUERY_NONE, &query, 0, 0, NULL, NULL, &error);
#pragma GCC diagnostic pop

            if (n == -1) {
                eprint("%s: unable to count collection %s: %s\n",
                       __func__, collname, error.message);
                exit(EX_OSERR);
            }

            /* Drop the collection in initmode if it's not empty...
             */
            if (initmode && n > 0) {
                eprint("%s: dropping preexisting collection %s with %ld records...\n",
                       __func__, collname, n);

                ok = mongoc_collection_drop(collection, &error);
                if (!ok) {
                    eprint("%s: drop collection %s failed: %s\n",
                           __func__, collname, error.message);
                }

                mongoc_collection_destroy(collection);

                /* Recreate the collection while we're single threaded to avoid
                 * a race in spawn_main()...
                 */
                ok = true;
                goto again;
            }

            mongoc_collection_destroy(collection);

            total += n;
        }

        /* TODO: mongoc_collection_count_with_opts() is not guaranteed to return
         * the correct count.  Use mongoc_collection_count_documents() when it
         * becomes available...
         */
        if (!initmode && total != impl->recmax) {
            if (retries-- > 0) {
                eprint("%s: record count mismatch (expected %lu, got %ld), retrying...\n",
                       __func__, impl->recmax, total);

                usleep(1000 * 1000);
                goto retry;
            }

            eprint("%s: record count mismatch (expected %lu, got %ld), continuing...\n",
                   __func__, impl->recmax, total);
        }
    }

    mongoc_client_pool_push(impl->client_pool, client);
    bson_destroy(&command);
    bson_destroy(&reply);

    if (!ok) {
        eprint("%s: ping %s failed: %s\n", __func__, impl->mpname, error.message);

        mongoc_client_pool_destroy(impl->client_pool);
        impl->client_pool = NULL;

        mongoc_uri_destroy(impl->active_uri);
        impl->active_uri = NULL;

        return EINVAL;
    }

    return 0;
}

hse_err_t
km_close_mongo(struct km_impl *impl)
{
    if (stayopen)
        return 0;

    mongoc_client_pool_destroy(impl->client_pool);
    impl->client_pool = NULL;

    mongoc_uri_destroy(impl->active_uri);
    impl->active_uri = NULL;

    return 0;
}

/* If (keydist > 0) we hand out the next keydist sized chunk of record
 * IDs on each request.  Otherwise, we divide the entire record ID space
 * evenly amongst all threads.
 */
void
td_range(struct km_inst *inst, uint64_t *startp, uint64_t *stopp)
{
    struct km_impl *impl = inst->impl;

    if (keydist > 0) {
        *stopp = atomic64_add_return(keydist, &impl->keydistchunk);
        *startp = *stopp - keydist;
    } else {
        uint64_t chunk;

        chunk = impl->recmax / impl->tdmax;
        if (impl->recmax % impl->tdmax)
            ++chunk;
        *startp = inst->tid * chunk;
        *stopp = *startp + chunk;
    }

    if (*stopp > impl->recmax)
        *stopp = impl->recmax;
}

void
td_init(struct km_inst *inst)
{
    struct timeval tv_init;
    struct km_rec *r;

    char     td_name[16];
    uint64_t start, stop;
    uint64_t rid;
    hse_err_t   err;

    snprintf(td_name, sizeof(td_name), "%s_init_%u", progname, inst->tid);
    pthread_setname_np(inst->td, td_name);

    gettimeofday(&tv_init, NULL);

    strcpy(inst->mode, "init");
    xrand_init(inst->tid ^ seed);
    err = 0;

    km_rec_alloc(inst, &r, NULL);

    while (1) {
        td_range(inst, &start, &stop);
        if (start >= stop)
            break;

        for (rid = start; rid < stop && !sigint; ++rid) {
            if (sysbench)
                km_rec_get(inst, r, rid);

            km_rec_init(inst, r, rid, &tv_init);

            err = km_rec_put(inst, r);
            if (err) {
                inst->fmt = "km_rec_put failed: %s";
                break;
            }

            inst->stats.op = OP_RUN;
        }
    }

    inst->stats.op = OP_EXIT;
    inst->err = err;

    td_lock();
    km_rec_free_locked(r);
    inst->next = td_exited_head;
    td_exited_head = inst;
    ++sigusr2;
    td_unlock();
}

void
td_check(struct km_inst *inst)
{
    char            td_name[16];
    struct km_impl *impl;
    struct km_rec * r;
    struct chk *    chk;
    hse_err_t          err;

    uint64_t start, stop;
    uint64_t rid;

    snprintf(td_name, sizeof(td_name), "%s_check_%u", progname, inst->tid);
    pthread_setname_np(inst->td, td_name);

    strcpy(inst->mode, "check");
    impl = inst->impl;
    chk = c0putval >= sizeof(*r) ? impl->chk : NULL;
    err = 0;

    xrand_init(inst->tid ^ seed);
    km_rec_alloc(inst, &r, NULL);

    while (!sigint) {
        td_range(inst, &start, &stop);
        if (start >= stop)
            break;

        for (rid = start; rid < stop && !sigint; ++rid) {
            err = km_rec_get(inst, r, rid);

            if (chk && r->rid == rid) {
                struct chk *p = chk + r->rid;

                if (p->cnt < 128 && (p->hash64 == r->hash || p->hash32 == (r->hash & 0xffffffff)))
                    ++p->cnt;

                if (r->rid == r->rid0)
                    p->flags |= CHK_F_INPLACE;
            }

            if (verbosity > 2)
                km_rec_print(inst, r, inst->fmt, err);
            else if (err && !chk)
                break;

            inst->stats.op = OP_RUN;
            err = 0;
        }
    }

    inst->stats.op = OP_EXIT;
    inst->err = err;

    td_lock();
    km_rec_free_locked(r);
    inst->next = td_exited_head;
    td_exited_head = inst;
    ++sigusr2;
    td_unlock();
}

void
td_check_init(struct km_impl *impl)
{
    uint64_t rid;

    if (!impl->chk)
        return;

    for (rid = 0; rid < impl->recmax; ++rid) {
        impl->chk[rid].cnt = 0;
        impl->chk[rid].flags &= ~CHK_F_INPLACE;
    }
}

void
td_check_fini(struct km_impl *impl)
{
    uint64_t nmissing, ndups, nswapped;
    uint64_t rid;

    if (!impl->chk || sigint)
        return;

    nmissing = 0;
    nswapped = 0;
    ndups = 0;

    for (rid = 0; rid < impl->recmax; ++rid) {
        if (impl->chk[rid].cnt > 1)
            ++ndups;
        else if (impl->chk[rid].cnt == 0)
            ++nmissing;
        if (!(impl->chk[rid].flags & CHK_F_INPLACE))
            ++nswapped;
        impl->chk[rid].cnt = 0;
        impl->chk[rid].flags &= ~CHK_F_INPLACE;
    }

    if (verbosity > 1 || nmissing > 0 || ndups > 0)
        printf(
            "%s: total=%lu nmissing=%lu ndups=%lu nswapped=%lu\n",
            __func__,
            impl->recmax,
            nmissing,
            ndups,
            nswapped);

    if (nmissing > 0 || ndups > 0)
        _exit(EX_SOFTWARE);
}

void
td_destroy(struct km_inst *inst)
{
    struct km_impl *impl;

    char     td_name[16];
    uint64_t start, stop;
    uint64_t rid;
    hse_err_t   err;
    int      nerrs;

    snprintf(td_name, sizeof(td_name), "%s_destroy_%u", progname, inst->tid);
    pthread_setname_np(inst->td, td_name);

    strcpy(inst->mode, "del");
    impl = inst->impl;
    nerrs = 0;
    err = 0;
    xrand_init(inst->tid ^ seed);

    while (1) {
        td_range(inst, &start, &stop);
        if (start >= stop)
            break;

        for (rid = start; rid < stop && !sigint; ++rid) {
            err = km_rec_del(inst, rid);
            if (err) {
                inst->fmt = "km_rec_del failed: %s";
                ++nerrs;
            }

            inst->stats.op = OP_RUN;
        }
    }

    if (nerrs > 0)
        eprint("%s: tid %u: range %lu - %lu, nerrs %d\n", __func__, inst->tid, start, stop, nerrs);

    inst->stats.op = OP_EXIT;
    inst->err = err;

    chk_destroy(impl);

    td_lock();
    inst->next = td_exited_head;
    td_exited_head = inst;
    ++sigusr2;
    td_unlock();
}

void
td_test(struct km_inst *inst)
{
    char                   td_name[16];
    struct km_rec *        recx, *recy;
    uint64_t               ridx, ridy;
    struct km_impl *       impl;
    struct hse_kvdb_txn *  txn;
    struct km_lor          lor;
    hse_err_t                 err;
    int                    rc;

    snprintf(td_name, sizeof(td_name), "%s_test_%u", progname, inst->tid);
    pthread_setname_np(inst->td, td_name);

    strcpy(inst->mode, "test");
    impl = inst->impl;
    lor = km_lor;
    txn = NULL;
    err = 0;

    xrand_init(inst->tid ^ seed);
    km_rec_alloc(inst, &recx, &recy);

    if (swaptxn && inst->impl->kvdb) {
        txn = hse_kvdb_txn_alloc(impl->kvdb);
        if (txn) {
            inst->flags = 0;
            inst->txn = txn;
        } else {
            inst->fmt = "txn alloc failed: %s";
            err = ENOMEM;
        }
    }

    /* Constrain threads by tid to a successively larger fraction
     * of the record ID space.
     */
    if (lor.constrain) {
        lor.range = (lor.range * (inst->tid + 1)) / impl->tdmax;
        lor.range = max_t(typeof(lor.range), 1, lor.range);
    }

    while (!sigalrm && !sigint && !err) {
        bool locked = false;

        inst->stats.op = OP_RUN;

        if (++lor.opscnt > lor.opsmax) {
            lor.base = xrand64() % lor.range;
            lor.opscnt = 0;
        }

        ridx = lor.base + (xrand64() % lor.span);
        ridy = lor.base + (xrand64() % lor.span);

        if (ridx == ridy)
            continue;

        if (swapexcl) {
            inst->stats.op = OP_LOCK;
            if (!chk_pair_trylock(impl, ridx, ridy))
                continue;

            locked = true;
        }

        if (txn) {
            inst->stats.op = OP_TXN_BEGIN;
            inst->stats.begin++;

            rc = hse_kvdb_txn_begin(impl->kvdb, txn);
            if (rc) {
                inst->fmt = "txn begin failed: %s";
                err = rc;
                goto unlock;
            }
        }

        err = km_rec_get(inst, recx, ridx);
        if (err) {
            inst->fmt = inst->fmt ?: "get 1 failed: %s";
            goto unlock;
        }

        err = km_rec_get(inst, recy, ridy);
        if (err) {
            inst->fmt = inst->fmt ?: "get 2 failed: %s";
            goto unlock;
        }

        if (swappct == 0 || (xrand32() % KM_SWAPPCT_MODULUS) >= swappct) {
            if (txn)
                hse_kvdb_txn_abort(impl->kvdb, txn);
            goto unlock;
        }

        km_rec_swap(inst, recx, recy);

        err = km_rec_put(inst, recx);
        if (err) {
            if (hse_err_to_errno(err) == ECANCELED && txn) {
                inst->stats.op = OP_TXN_ABORT;
                inst->stats.abort++;

                hse_kvdb_txn_abort(impl->kvdb, txn);
                err = 0;
            } else {
                inst->fmt = inst->fmt ?: "put 1 failed: %s";
            }
            goto unlock;
        }

        err = km_rec_put(inst, recy);
        if (err) {
            if (hse_err_to_errno(err) == ECANCELED && txn) {
                inst->stats.op = OP_TXN_ABORT;
                inst->stats.abort++;

                hse_kvdb_txn_abort(impl->kvdb, txn);
                err = 0;
            } else {
                inst->fmt = inst->fmt ?: "put 2 failed: %s";
            }
            goto unlock;
        }

        if (txn) {
            if (!locked) {
                inst->stats.op = OP_LOCK;
                chk_pair_lock(impl, ridx, ridy);
                locked = true;
            }

            inst->stats.op = OP_TXN_COMMIT;
            inst->stats.commit++;

            rc = hse_kvdb_txn_commit(impl->kvdb, txn);
            if (rc) {
                inst->fmt = "txn commit failed: %s";
                err = rc;
                goto unlock;
            }

            chk_update(inst->impl, recx, false);
            chk_update(inst->impl, recy, false);
        }

    unlock:
        if (locked) {
            inst->stats.op = OP_UNLOCK;
            chk_pair_unlock(impl, ridx, ridy);
        }
    }

    if (txn) {
        hse_kvdb_txn_abort(impl->kvdb, txn);
        hse_kvdb_txn_free(impl->kvdb, txn);
        inst->txn = NULL;
    }

    inst->stats.op = OP_EXIT;
    inst->err = err;

    td_lock();
    km_rec_free_locked(recx);
    km_rec_free_locked(recy);
    inst->next = td_exited_head;
    td_exited_head = inst;
    ++sigusr2;
    td_unlock();
}

void
status(
    struct km_impl *impl,
    struct km_inst *instv,
    struct timeval *tv_start,
    struct timeval *tv_prev,
    time_t          mark)
{
    static int      hdrcnt;
    static const int syncus_header_width =
        6; /* 6 is the length of the SYNCUS column header below */
    struct timeval  tv_now, tv_diff, tv_delta, tv_usrsys;
    struct km_inst *instv_end, *inst;
    struct rusage   rusage;

    int    width_gpd, width_pds, width_igpd, width_ipds;
    int    width_td, width_secs, width_sync_us;
    ulong  get_total, iget_total;
    ulong  getbytes_total, igetbytes_total;
    ulong  put_total, iput_total;
    ulong  putbytes_total, iputbytes_total;
    ulong  del_total, idel_total;
    ulong  swap_total, iswap_total;
    ulong  begin_total, ibegin_total;
    ulong  commit_total, icommit_total;
    ulong  abort_total, iabort_total;
    ulong  total_ms, usrsys;
    long   avg_sync_latency_us = 0;
    time_t msecs;
    int    nthreads;
    bool   show, txn;
    char   errmsg[128];

    gettimeofday(&tv_now, NULL);

    timersub(&tv_now, tv_prev, &tv_delta);
    msecs = tv_delta.tv_sec * 1000 + tv_delta.tv_usec / 1000;

    if (mark > msecs)
        return;

    timersub(&tv_now, tv_start, &tv_diff);
    total_ms = tv_diff.tv_sec * 1000000 + tv_diff.tv_usec;
    total_ms /= 1000;

    getrusage(RUSAGE_SELF, &rusage);
    timeradd(&rusage.ru_utime, &rusage.ru_stime, &tv_usrsys);
    usrsys = (tv_usrsys.tv_sec * 1000000 + tv_usrsys.tv_usec) / 1000000,

    get_total = iget_total = 0;
    getbytes_total = igetbytes_total = 0;
    put_total = iput_total = 0;
    putbytes_total = iputbytes_total = 0;
    del_total = idel_total = 0;
    swap_total = iswap_total = 0;
    begin_total = ibegin_total = 0;
    commit_total = icommit_total = 0;
    abort_total = iabort_total = 0;

    instv_end = instv + impl->tdmax;
    inst = instv;

    width_gpd = 12;
    width_igpd = 9;
#ifdef XKMT
    width_gpd += 1;
    width_igpd += 1;
#endif

    width_pds = width_gpd;
    width_ipds = width_igpd;

    width_secs = (total_ms > 999999) ? 9 : 7;

    width_td = (impl->tdmax > 99) ? 4 : 2;
    if (verbosity > 1)
        width_td = 8;

    const long iters = atomic64_read(&impl->km_sync_latency.km_sync_iterations);
    if (iters != 0) {
        avg_sync_latency_us =
            atomic64_read(&impl->km_sync_latency.km_total_sync_latency_us) / iters;
    }

    width_sync_us = snprintf(NULL, 0, "%*ld", syncus_header_width, avg_sync_latency_us);
    width_sync_us = width_sync_us >= syncus_header_width ? width_sync_us : syncus_header_width;

    txn = swaptxn && testmode;
    show = headers && (verbosity > 1 || mark == 0 || ++hdrcnt >= 60);
    if (show) {
        printf(
            "\n%-6s %*s %6s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %6s %*s %*s %s %s\n",
            "MODE",
            width_td, "TD",
            "OP",
            8, "tGETMB",
            7, "tPUTMB",
            width_gpd, txn ? "tBEGIN" : mongo ? "tFIND" : "tGET",
            width_pds, txn ? "tCOMMIT" : mongo ? "tUPSERT" : "tPUT",
            width_pds, txn ? "tABORT" : mongo ? "tDELETE" : "tDEL",
            width_igpd, txn ? "iBEGIN" : mongo ? "iFIND" : "iGET",
            width_ipds, txn ? "iCOMMIT" : mongo ? "iUPSERT" : "iPUT",
            width_ipds, txn ? "iABORT" : mongo ? "iDELETE" : "iDEL",
            width_pds, xstats ? "MINFLT" : "tSWAPS",
            width_ipds, xstats ? "MAJFLT" : "iSWAPS",
            "USRSYS",
            width_sync_us, "SYNCUS",
            width_secs, "MSECS",
            xstats ? "ELAPSED" : "DATE",
            "");
        hdrcnt = 0;
    }

    errmsg[0] = '\000';
    nthreads = 0;

    while (inst < instv_end) {
        ulong get_now, put_now, del_now, swap_now;
        ulong iget_now, iput_now, idel_now, iswap_now;
        ulong begin_now, ibegin_now;
        ulong commit_now, icommit_now;
        ulong abort_now, iabort_now;
        ulong getbytes_now, putbytes_now;

        get_now = inst->stats.get;
        getbytes_now = inst->stats.getbytes;
        put_now = inst->stats.put;
        putbytes_now = inst->stats.putbytes;
        del_now = inst->stats.del;
        swap_now = inst->stats.swap;
        begin_now = inst->stats.begin;
        commit_now = inst->stats.commit;
        abort_now = inst->stats.abort;

        get_total += get_now;
        getbytes_total += getbytes_now;
        put_total += put_now;
        putbytes_total += putbytes_now;
        del_total += del_now;
        swap_total += swap_now;
        begin_total += begin_now;
        commit_total += commit_now;
        abort_total += abort_now;

        iget_now = get_now - inst->stats.oget;
        iget_total += iget_now;
        igetbytes_total += (getbytes_now - inst->stats.ogetbytes);

        iput_now = put_now - inst->stats.oput;
        iput_total += iput_now;
        iputbytes_total += (putbytes_now - inst->stats.oputbytes);

        idel_now = del_now - inst->stats.odel;
        idel_total += idel_now;

        iswap_now = swap_now - inst->stats.oswap;
        iswap_total += iswap_now;

        ibegin_now = begin_now - inst->stats.obegin;
        ibegin_total += ibegin_now;

        icommit_now = commit_now - inst->stats.ocommit;
        icommit_total += icommit_now;

        iabort_now = abort_now - inst->stats.oabort;
        iabort_total += iabort_now;

        if (inst->err && inst->fmt) {
            char errbuf[128];

            hse_err_to_string(inst->err, errbuf, sizeof(errbuf), NULL);
            snprintf(errmsg, sizeof(errmsg), inst->fmt, errbuf);
            inst->fmt = NULL;
        }

        if (verbosity > 1 || errmsg[0]) {
            printf(
                "%-6s %*u %6s %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %6lu %*s %*lu %ld "
                "%s\n",
                instv->mode,
                width_td, inst->tid,
                op2txt[inst->stats.op],
                8, getbytes_now / (1024 * 1024),
                7, putbytes_now / (1024 * 1024),
                width_gpd, txn ? begin_now : get_now,
                width_pds, txn ? commit_now : put_now,
                width_pds, txn ? abort_now : del_now,
                width_igpd, txn ? ibegin_now : iget_now,
                width_ipds, txn ? icommit_now : iput_now,
                width_ipds, txn ? iabort_now : idel_now,
                width_pds, xstats ? rusage.ru_minflt : swap_total,
                width_ipds, xstats ? rusage.ru_majflt : iswap_total,
                usrsys,
                width_sync_us, "N/A",
                width_secs, total_ms,
                tv_now.tv_sec - (xstats ? tv_init.tv_sec : 0),
                errmsg);

            errmsg[0] = '\000';
        }

        inst->stats.oget = get_now;
        inst->stats.oput = put_now;
        inst->stats.odel = del_now;
        inst->stats.oswap = swap_now;
        inst->stats.obegin = begin_now;
        inst->stats.ocommit = commit_now;
        inst->stats.oabort = abort_now;

        if (inst->stats.op != OP_EXIT)
            ++nthreads;

        ++inst;
    }

    printf(
        "%-6s %*d %6s %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %*lu %6lu %*ld %*lu %ld\n",
        instv->mode,
        width_td, nthreads,
        "all",
        8, getbytes_total / (1024 * 1024),
        7, putbytes_total / (1024 * 1024),
        width_gpd, txn ? begin_total : get_total,
        width_pds, txn ? commit_total : put_total,
        width_pds, txn ? abort_total : del_total,
        width_igpd, txn ? ibegin_total : iget_total,
        width_ipds, txn ? icommit_total : iput_total,
        width_ipds, txn ? iabort_total : idel_total,
        width_pds, xstats ? rusage.ru_minflt : swap_total,
        width_ipds, xstats ? rusage.ru_majflt : iswap_total,
        usrsys,
        width_sync_us, avg_sync_latency_us,
        width_secs, total_ms,
        tv_now.tv_sec - (xstats ? tv_init.tv_sec : 0));

    if (mark >= 1000)
        fflush(stdout);

    *tv_prev = tv_now;
}

void
latency_init(struct km_latency *lat, int count)
{
    int i;

    /* Calling hdr_init with minimum value as 1, maximum value
     * as 10 seconds and significant figures as 3.
     */
    for (i = 0; i < KMT_LAT_REC_CNT; i++) {
        hdr_init(1, 10UL * 1000 * 1000 * 1000, 3, &lat[i].km_histogram);
        atomic64_set(&lat[i].km_samples, 0);
        atomic64_set(&lat[i].km_samples_err, 0);
    }
}

void
latency_finish(struct km_latency *lat, int count)
{
    int i;
    for (i = 0; i < KMT_LAT_REC_CNT; i++) {
        if (lat[i].km_histogram)
            hdr_close(lat[i].km_histogram);
    }
}

void
latency_aggregate(struct km_latency *to, struct km_latency *from, int count)
{
    int i;

    for (i = 0; i < KMT_LAT_REC_CNT; i++) {
        if (to[i].km_histogram && from[i].km_histogram) {
            td_lock();
            hdr_add(to[i].km_histogram, from[i].km_histogram);
            td_unlock();
        }
        atomic64_add(atomic64_read(&from[i].km_samples), &to[i].km_samples);
        atomic64_add(atomic64_read(&from[i].km_samples_err), &to[i].km_samples_err);
    }
}

void *
spawn_main(void *arg)
{
    static atomic_t workers;
    struct km_inst *inst = arg;
    char            collname[16];
    int             i;

    if (mongo) {
        inst->client = mongoc_client_pool_pop(inst->impl->client_pool);
        if (!inst->client)
            abort();

        for (i = 0; i < collectionc; ++i) {
            snprintf(collname, sizeof(collname), "kmt%d", i);

            inst->collectionv[i] =
                mongoc_client_get_collection(inst->client, inst->impl->kvsname, collname);

            if (!inst->collectionv[i]) {
                eprint("%s: get collection %s failed\n", __func__, collname);
                exit(EX_OSERR);
            }
        }

        while (i < MONGO_COLLECTIONS_MAX) {
            inst->collectionv[i] = inst->collectionv[i % collectionc];
            ++i;
        }

        bson_init(&inst->query);
        bson_init(&inst->update);

        bson_init(&inst->ropts);
        BSON_APPEND_INT64(&inst->ropts, "limit", 1);
        BSON_APPEND_INT64(&inst->ropts, "batchSize", 1);
        BSON_APPEND_BOOL(&inst->ropts, "singleBatch", true);

        inst->wcmin = mongoc_write_concern_new();
        if (testmode && !wcmin_given)
            mongoc_write_concern_set_w(inst->wcmin, min_t(uint, wcmin, 1));
        else
            mongoc_write_concern_set_w(inst->wcmin, wcmin);

        if (wcmaj > 0) {
            inst->wcmaj = mongoc_write_concern_new();
            mongoc_write_concern_set_wmajority(inst->wcmaj, 60000);
        }

        bson_init(&inst->wopts_wcmin);
        BSON_APPEND_BOOL(&inst->wopts_wcmin, "validate", false);
        if (initmode)
            BSON_APPEND_BOOL(&inst->wopts_wcmin, "upsert", true);
        if (mongoc_write_concern_is_acknowledged(inst->wcmin))
            BSON_APPEND_BOOL(&inst->wopts_wcmin, "bypassDocumentValidation", true);
        mongoc_write_concern_append(inst->wcmin, &inst->wopts_wcmin);

        bson_init(&inst->wopts_wcmaj);
        BSON_APPEND_BOOL(&inst->wopts_wcmaj, "validate", false);
        if (initmode)
            BSON_APPEND_BOOL(&inst->wopts_wcmaj, "upsert", true);
        mongoc_write_concern_append(inst->wcmaj, &inst->wopts_wcmaj);
    }

    atomic_inc(&workers);

    inst->func(inst);

    if (mongo) {
        for (i = 0; i < collectionc; ++i)
            mongoc_collection_destroy(inst->collectionv[i]);

        mongoc_client_pool_push(inst->impl->client_pool, inst->client);

        mongoc_write_concern_destroy(inst->wcmaj);
        mongoc_write_concern_destroy(inst->wcmin);
        bson_destroy(&inst->wopts_wcmaj);
        bson_destroy(&inst->wopts_wcmin);
        bson_destroy(&inst->ropts);
        bson_destroy(&inst->update);
        bson_destroy(&inst->query);

        inst->wcmin = NULL;
        inst->wcmaj = NULL;
    }

    if (0 == atomic_dec_return(&workers))
        kill(getpid(), SIGALRM);

    pthread_exit(NULL);
}

void
print_latency(struct km_impl *impl, const char *mode)
{
    int                   i;
    char                  hdr[1024];
    bool                  print_hdr = true;
    struct hdr_histogram *histogram;

    snprintf(
        hdr,
        1024,
        "%-9s %8s %8s %10s %10s %10s %10s %10s %10s %10s %10s "
        "%10s %10s",
        "LATMODE",
        "PHASE",
        "OP",
        "SAMPLES",
        "SAMPLES_ERR",
        "MIN_us",
        "MAX_us",
        "AVG_us",
        "L90_us",
        "L95_us",
        "L99_us",
        "L99.9_us",
        "L99.99_us");

    for (i = 0; i < KMT_LAT_REC_CNT; i++) {
        unsigned long min, max, avg, lt90, lt95, lt99, lt999, lt9999;

        histogram = impl->km_latency[i].km_histogram;
        if (!hdr_max(histogram))
            continue;

        if (print_hdr) {
            printf("\n%s\n", hdr);
            print_hdr = false;
        }

        min = hdr_min(histogram);
        max = hdr_max(histogram);
        avg = hdr_mean(histogram);
        lt90 = hdr_value_at_percentile(histogram, 90.0);
        lt95 = hdr_value_at_percentile(histogram, 95.0);
        lt99 = hdr_value_at_percentile(histogram, 99.0);
        lt999 = hdr_value_at_percentile(histogram, 99.9);
        lt9999 = hdr_value_at_percentile(histogram, 99.99);

        printf(
            "%-9s %8s %8s %10ld %10ld %10ld %10ld %10ld %10ld "
            "%10ld %10ld %10ld %10ld\n",
            "slatency",
            mode,
            op2txt[OP_KVS_GET + i],
            atomic64_read(&impl->km_latency[i].km_samples),
            atomic64_read(&impl->km_latency[i].km_samples_err),
            min,
            max,
            avg,
            lt90,
            lt95,
            lt99,
            lt999,
            lt9999);
    }
}

#ifndef XKMT
void *
periodic_sync(void *arg)
{
    struct timespec timeout = {
        .tv_sec = (sync_timeout_ms * 1000000) / 1000000,
        .tv_nsec = (sync_timeout_ms * 1000000) % 1000000
    };
    struct km_impl *impl = arg;
    sigset_t sigmask;
    hse_err_t err;
    uint64_t ns;
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

        ns = get_time_ns();
        err = hse_kvdb_sync(impl->kvdb);
        ns = get_time_ns() - ns;

        if (err) {
            char errbuf[128];

            hse_err_to_string(err, errbuf, sizeof(errbuf), NULL);
            eprint("%s: failed to sync kvdb: %s\n", __func__, errbuf);
            continue;
        }

        atomic64_inc(&impl->km_sync_latency.km_sync_iterations);
        atomic64_add(ns / 1000, &impl->km_sync_latency.km_total_sync_latency_us);
    }

    pthread_exit(NULL);
}
#endif

void
spawn(struct km_impl *impl, void (*run)(struct km_inst *), uint runmax, time_t mark)
{
    struct itimerval itv_guard;
    struct timeval   tv_start, tv_prev;
    struct km_inst * instv;
    struct timespec  timeout;
    sig_atomic_t     osigusr2;
    struct pollfd    fds;
    char errbuf[128];
    hse_err_t err;

#ifndef XKMT
    pthread_t        sync_thread;
#endif

    sigset_t sigmask_block;
    sigset_t sigmask_none;
    sigset_t sigmask_old;
    char     td_name[16];
    int      nthreads;
    int      nerrs;
    int      rc;
    int      i;
    char     mode[32];

    snprintf(td_name, sizeof(td_name), "%s_spawn", progname);
    pthread_setname_np(pthread_self(), td_name);

    instv = aligned_alloc(4096, roundup(sizeof(*instv) * impl->tdmax, 4096));
    if (!instv) {
        eprint("%s: malloc instv failed: %s\n", __func__, strerror(errno));
        exit(EX_OSERR);
    }

    memset(instv, 0, sizeof(*instv) * impl->tdmax);
    nthreads = impl->tdmax;
    nerrs = 0;

    for (i = 0; i < impl->tdmax; ++i)
        strcpy(instv[i].mode, "open");

    gettimeofday(&tv_start, NULL);
    tv_prev = tv_start;

    if (verbosity > 1 || nerrs > 0 || mark > 0)
        status(impl, instv, &tv_start, &tv_prev, 0);

    kvs_txn = swaptxn && run == td_test;

    err = km_open(impl);
    if (err) {
        hse_err_to_string(err, errbuf, sizeof(errbuf), NULL);
        eprint("%s: km_open failed: %s\n", __func__, errbuf);
        exit(EX_NOINPUT);
    }

    gettimeofday(&tv_prev, NULL);

    sigemptyset(&sigmask_none);
    sigemptyset(&sigmask_block);
    sigaddset(&sigmask_block, SIGINT);
    sigaddset(&sigmask_block, SIGALRM);
    sigprocmask(SIG_BLOCK, &sigmask_block, &sigmask_old);

    sigusr2 = osigusr2 = 0;
    sigalrm = 0;
    sigint = 0;

    setpriority(PRIO_PROCESS, 0, 0);

    atomic64_set(&impl->keydistchunk, 0);

    /* Spawn all worker threads...
     */
    for (i = 0; i < impl->tdmax; ++i) {
        struct km_inst *inst = instv + i;

        inst->ops = impl->km_rec_ops;
        inst->stats.op = OP_START;
        inst->impl = impl;
        inst->func = run;
        inst->tid = i;

        if (latency)
            latency_init(inst->latency, KMT_LAT_REC_CNT);

        rc = pthread_create(&inst->td, NULL, spawn_main, inst);
        if (rc) {
            inst->fmt = "pthread_create: %s";
            inst->stats.op = OP_EXIT;
            inst->err = merr(rc);
            --nthreads;
            ++nerrs;
            sleep(1);
            continue;
        }
    }

#ifndef XKMT
    if (testmode && sync_timeout_ms > 0) {
        rc = pthread_create(&sync_thread, NULL, periodic_sync, impl);
        if (rc) {
            eprint("%s: pthread_create failed for sync thread: %s\n",
                   __func__, strerror_r(rc, errbuf, sizeof(errbuf)));
            ++nerrs;
        }
    }
#endif

    fds.fd = isatty(0) ? 0 : -1;
    fds.events = POLLIN;

    if (runmax > 0) {
        timerclear(&itv_guard.it_value);
        timerclear(&itv_guard.it_interval);
        itv_guard.it_value.tv_sec = runmax;
        setitimer(ITIMER_REAL, &itv_guard, NULL);
    }

    setpriority(PRIO_PROCESS, 0, -1);

    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    if (mark > 0) {
        timeout.tv_sec = mark / 1000;
        timeout.tv_nsec = (mark % 1000) * 1000 * 1000;
    }

    /* Sleep in this loop until all worker threads have exited.
     * Print status every 'mark' seconds and/or on demand each
     * time stdin becomes readable.
     */
    while (nthreads > 0) {
        if (sigusr2 > osigusr2) {
            struct km_inst *inst;
            void *          val;

            td_lock();
            inst = td_exited_head;
            td_exited_head = NULL;
            osigusr2 = sigusr2;
            td_unlock();

            /* Reap exited threads...
             */
            while (inst) {
                pthread_join(inst->td, &val);
                if (inst->err)
                    ++nerrs;

                if (latency) {
                    latency_aggregate(inst->impl->km_latency, inst->latency, KMT_LAT_REC_CNT);
                    latency_finish(inst->latency, KMT_LAT_REC_CNT);
                }

                inst = inst->next;
                --nthreads;
            }

            continue;
        }

        rc = ppoll(&fds, 1, &timeout, &sigmask_none);
        if (-1 == rc)
            continue;

        if (fds.revents) {
            char    ttybuf[128];
            ssize_t cc;

            cc = read(fds.fd, ttybuf, sizeof(ttybuf));
            if (cc > 0) {
                switch (ttybuf[0]) {
                case 'm':
                    malloc_stats();
                    break;

                default:
                    status(impl, instv, &tv_start, &tv_prev, -1);
                    break;
                }
            } else {
                if (cc == 0)
                    kill(getpid(), SIGINT);
                fds.fd = -1;
            }
            continue;
        }

        if (mark == 0) {
            ++sigusr2;
            continue;
        }

        status(impl, instv, &tv_start, &tv_prev, mark);
    }

#ifndef XKMT
    if (testmode && sync_timeout_ms > 0) {
        pthread_kill(sync_thread, SIGUSR1);
        pthread_join(sync_thread, NULL);
    }
#endif

    if (runmax > 0) {
        timerclear(&itv_guard.it_value);
        setitimer(ITIMER_REAL, &itv_guard, NULL);
    }

    sigprocmask(SIG_SETMASK, &sigmask_old, NULL);

    snprintf(mode, sizeof(mode), "%s", instv[0].mode);

    if (verbosity > 1 || nerrs > 0 || mark > 0) {
        for (i = 0; i < impl->tdmax; ++i)
            strcpy(instv[i].mode + 1, "close");

        status(impl, instv, &tv_start, &tv_prev, -1);
    }

    km_close(impl);

    if (verbosity > 1 || nerrs > 0 || mark > 0) {
        for (i = 0; i < impl->tdmax; ++i)
            strcpy(instv[i].mode + 1, "exit");

        status(impl, instv, &tv_start, &tv_prev, -1);
    }

    if (latency)
        print_latency(impl, mode);

    free(instv);

    if (nerrs > 0)
        _exit(EX_SOFTWARE);
}

struct km_impl km_impl_kvs = {
    .km_open    = km_open_kvs,
    .km_close   = km_close_kvs,

    .km_rec_ops = {
        .km_rec_alloc   = km_rec_alloc_cmn,
        .km_rec_init    = km_rec_init_cmn,
        .km_rec_swap    = km_rec_swap_cmn,
        .km_rec_get     = km_rec_get_kvs,
        .km_rec_put     = km_rec_put_kvs,
        .km_rec_del     = km_rec_del_kvs,
    },

    .vlenmax_default = 16,
    .vlenmax = 1024 * 1024 - sizeof(struct km_rec),
};

struct km_impl km_impl_ds = {
    .km_open    = km_open_ds,
    .km_close   = km_close_ds,

    .km_rec_ops = {
        .km_rec_alloc   = km_rec_alloc_cmn,
        .km_rec_init    = km_rec_init_cmn,
        .km_rec_swap    = km_rec_swap_cmn,
        .km_rec_get     = km_rec_get_ds,
        .km_rec_put     = km_rec_put_ds,
        .km_rec_del     = km_rec_del_ds,
    },

    .vlenmax_default = 128,
    .vlenmax = KM_REC_SZ_MAX - sizeof(struct km_rec),
};

struct km_impl km_impl_dev = {
    .km_open    = km_open_dev,
    .km_close   = km_close_dev,

    .km_rec_ops = {
        .km_rec_alloc   = km_rec_alloc_cmn,
        .km_rec_init    = km_rec_init_cmn,
        .km_rec_swap    = km_rec_swap_cmn,
        .km_rec_get     = km_rec_get_dev,
        .km_rec_put     = km_rec_put_dev,
        .km_rec_del     = km_rec_del_dev,
    },

    .vlenmax_default = 128,
    .vlenmax = KM_REC_SZ_MAX - sizeof(struct km_rec),
};

struct km_impl km_impl_mongo = {
    .km_open    = km_open_mongo,
    .km_close   = km_close_mongo,

    .km_rec_ops = {
        .km_rec_alloc   = km_rec_alloc_cmn,
        .km_rec_init    = km_rec_init_cmn,
        .km_rec_swap    = km_rec_swap_cmn,
        .km_rec_get     = km_rec_get_mongo,
        .km_rec_put     = km_rec_put_mongo,
        .km_rec_del     = km_rec_del_mongo,
    },

    .vlenmax_default = 1024,  /* possible to test 16MB MongoDB limit? */
    .vlenmax = KM_REC_SZ_MAX - sizeof(struct km_rec),
};

__attribute__((format(printf, 1, 2))) void
syntax(const char *fmt, ...)
{
    char    msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

ulong
cvt_strtoul(
#if __GNUC__ > 4
    const char *restrict str,
    char **restrict      endp,
#else
    const char *str,
    char **     endp,
#endif
    const struct suftab *suftab)
{
    long double val;
    const char *pc;
    char *      end;

    errno = 0;
    val = strtold(str, &end);

    if (!errno && end != str && *end && suftab) {
        pc = strchr(suftab->list, tolower(*end));
        if (pc) {
            val *= *(suftab->mult + (pc - suftab->list));
            ++end;
        }
    }

    if (val < 0) {
        errno = errno ?: ERANGE;
        val = 0;
    } else if (val > ULONG_MAX) {
        errno = errno ?: ERANGE;
        val = ULONG_MAX;
    }

    if (endp)
        *endp = end;

    return val;
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
    int   n, rc;

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

        if (0 == strcmp(name, "directio")) {
            dev_oflags &= ~O_DIRECT;
            if (0 == strcasecmp(value, "true") || cvt_strtoul(value, &end, &suftab_iec) > 0)
                dev_oflags |= O_DIRECT;
        } else if (0 == strcmp(name, "secsz")) {
            secsz = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "vebsz")) {
            vebsz = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "oom_score_adj")) {
            vebsz = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "adj")) {
            vebsz = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "c0putval")) {
            c0putval = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "keydist")) {
            keydist = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "fieldcount")) {
            fieldcount = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "fieldlength")) {
            fieldlength = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "cidshift")) {
            cidshift = cvt_strtoul(value, &end, &suftab_iec);
            if (cidshift > 63)
                errno = EINVAL;
        } else if (0 == strcmp(name, "lor")) {
            n = sscanf(value, "%lu:%lu:%lu", &km_lor.span, &km_lor.opsmax, &km_lor.constrain);
            if (n != 3 && !errno)
                errno = EINVAL;
        } else if (0 == strcmp(name, "vrunlen") || 0 == strcmp(name, "rvalrunlen")) {
            vrunlen = cvt_strtoul(value, &end, &suftab_iec);
            vrunlen = clamp_t(uint, vrunlen, 1, 1024);
        } else if (0 == strcmp(name, "swapexcl")) {
            swapexcl = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "sysbench")) {
            sysbench = cvt_strtoul(value, &end, &suftab_iec);
        } else if (0 == strcmp(name, "wcmin")) {
            wcmin = cvt_strtoul(value, &end, &suftab_iec);
            wcmin_given = true;
        } else if (0 == strcmp(name, "wcmajprob")) {
            wcmajprob = strtod(value, &end);
        } else if (0 == strcmp(name, "mclass")) {
            mclass = strtoul(value, &end, 0);
            mclass = mclass == 1 ? MP_MED_STAGING : MP_MED_CAPACITY;
        } else {
            eprint("%s property '%s' ignored\n", valid ? "unhandled" : "invalid", name);
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
oom_score_adj_set(int adj)
{
    char  path[PATH_MAX];
    FILE *fp;

    if (adj < -1000 || adj > 1000)
        return;

    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", getpid());

    fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%d", adj);
        fclose(fp);
    }
}

void
usage(struct km_impl *impl)
{
    printf("usage: %s [options] <device> [kvs_param=value ...]\n", progname);
    printf("usage: %s -h [-v]\n", progname);

    printf("-B kbinsz   use kbinsz length binary keys\n");
    printf("-b          use 8-byte binary keys\n");
    printf("-C cfdir    config file directory\n");
    printf("-c          verify/check testbed\n");
    printf("-D          destroy testbed\n");
    printf("-f keyfmt   specify key format for snprintf\n");
    printf("-H          suppress headers\n");
    printf("-h          print this help list\n");
    printf("-i recmax   initialize testbed\n");
    printf("-j jobs     specify max number of jobs\n");
    printf("-l vlenmax  specify value length\n");
    printf("-L          print latency of operations in microseconds\n");
    printf("-m mark     print status every 'mark' milliseconds\n");
    printf("-O          keep kvs/dataset open between phases\n");
    printf("-o props    set one or more kmt properties\n");
    printf("-p count    partition into multiple collections\n");
    printf("-R          disable read verification\n");
    printf("-S seed     specify seed for initstate()\n");
    printf("-s mark     print status every 'mark' seconds\n");
    printf("-T swsecs   like -t, but with kvdb transactions\n");
    printf("-t swsecs   run swap test for 'swsecs' seconds\n");
    printf("-v          increase verbosity\n");
    printf("-w wpct     write percentage: wpct = 100*w/(w+r), 0 <= wpct <= 50\n");
    printf("-x          show extended statistics\n");
    printf("-y sync     kvdb sync interval (milliseconds)\n");
    printf("<device>    <kvdbhome> <kvsname>, /dev/<devname>, mpool:<kvdbhome>, mongodb://<url>\n");
    printf("\n");

    if (verbosity < 1) {
        printf("Use -hv for more detail\n\n");
        return;
    }

    printf("KMT DEFAULTS:\n");
    printf("  NAME           VALUE  DESCRIPTION\n");
    printf("  cfdir      %9s config file directory\n", cf_dir);
    printf("  chk_sz     %9zu  sizeof(struct chk)\n", sizeof(struct chk));
    printf("  jobs       %9u  max jobs\n", impl->tdmax);
    printf("  kbinsz     %9zu  min binary key length\n", keybinmax);
    printf("  kbinsz     %9zu  max binary key length\n", keybinmax);
    printf("  km_rec_sz  %9zu  sizeof(struct km_rec)\n", sizeof(struct km_rec));
    printf("  recmax     %9zu  max records\n", impl->recmax);
    printf("  vlenmin    %9zu  value length min\n", impl->vlenmin);
    printf("  vlenmax    %9zu  value length max\n", impl->vlenmax);
    printf("  wpct       %9d  write percentage\n", (int)wpctf);
    printf("\n");

    printf("KMT PROPERTIES:\n");
    printf("  NAME            VALUE  DESCRIPTION\n");
    printf("  adj         %10d  set oom_score_adjust\n", oom_score_adj);
    printf("  cidshift    %10u  bits to right-shift rid to obtain collection ID\n", cidshift);
    printf("  c0putval    %10u  c0 ingest test value length\n", c0putval);
    printf("  directio    %10u  enable/disable directIO\n", !!(dev_oflags & O_DIRECT));
    printf("  fieldcount  %10u  like ycsb fieldcount, mongo mode only\n", fieldcount);
    printf("  fieldlength %10u  like ycsb fieldlength, mongo mode only\n", fieldlength);
    printf("  keydist     %10zu  0: recmax/jobs, >0: in keydist chunks\n", keydist);
    printf("  lor           %lu:%lu:%u  set locality of reference [span:opsmax:constrain]\n",
           (ulong)km_lor.span, (ulong)km_lor.opsmax, (uint)km_lor.constrain);
    printf("  vrunlen     %10u  derandomize values every runlen bytes\n", vrunlen);
    printf("  secsz       %10zu  set device/mpool mode r/w size\n", secsz);
    printf("  swapexcl    %10u  disable exclusive record swapping\n", swapexcl);
    printf("  sysbench    %10u  enable sysbench load semantics\n", sysbench);
    printf("  vebsz       %10zu  set device mode r/w offset between records\n", vebsz);
    printf("  wcmin       %10d  set minimum mongod write concern\n", wcmin);
    printf("  wcmajprob   %10.3f  probability to use majority write concern\n", wcmajprob);
    printf("  sync_ms     %10lu  kvdb sync interval (milliseconds)\n", sync_timeout_ms);
    printf("  mclass      %10d  media class in mpool mode - 0: cap, 1: stg \n", mclass);
    printf("\n");

    printf("SIZEOF:\n");
    printf("  pthread_spinlock_t:   %zu\n", sizeof(pthread_spinlock_t));
    printf("  pthread_rwlock_t:     %zu\n", sizeof(pthread_rwlock_t));
    printf("  pthread_mutex_t:      %zu\n", sizeof(pthread_mutex_t));
    printf("  pthread_cond_t:       %zu\n", sizeof(pthread_cond_t));
    printf("  struct km_impl:       %zu\n", sizeof(struct km_impl));
    printf("  struct km_inst:       %zu\n", sizeof(struct km_inst));
    printf("  struct km_rec:        %zu\n", sizeof(struct km_rec));
    printf("  struct chk:           %zu\n", sizeof(struct chk));
    printf("  bson_t:               %zu\n", sizeof(bson_t));
    printf("  sem_t:                %zu\n", sizeof(sem_t));
    printf("\n");

    printf("EXAMPLES:\n");
    printf("  init:     %s -i 123456 mpool:/mnt/kvdb1\n", progname);
    printf("  test:     %s -t60 -j32 -s10 mpool:/mnt/kvdb1\n", progname);
    printf("  check:    %s -c -j32 mpool:/mnt/kvdb1\n", progname);
    printf("  destroy:  %s -D mpool:/mnt/kvdb1\n", progname);
    printf("  combo:    %s -i 123456 -t60 -cD -j32 mpool:/mnt/kvdb1\n", progname);
    printf("  device:   %s -i 393216 -t60 -bcDR -j768 -w0 -s1 /dev/nvme0n1p1\n", progname);
    printf("  kvs:      %s -i 128 -t60 -bcD -j48 -w50 -s1 /mnt/kvdb/kvdb1 kvs1\n", progname);
    printf("  mongo:    %s -i8m -t1m -cDx -j32 -p8 -s1 mongodb://localhost:27017\n", progname);
    printf("  xkmt:    xkmt -i 128 -t60 -bcDOR -j48 -w0 -s1\n");
    printf("\n");
}

int
main(int argc, char **argv)
{
    struct km_impl *impl;

#ifndef XKMT
    char errbuf[128];
    hse_err_t err;
#endif

    bool   init, check, test, destroy, help;
    char * mpname, *kvsname;
    size_t vlenmin, vlenmax;
    uint   swsecs;
    time_t mark;
    int    rc, c;
    float  swappctf;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    gettimeofday(&tv_init, NULL);

    impl = &km_impl_kvs;

    secsz = PAGE_SIZE;

    init = test = check = destroy = help = false;
    seed = tv_init.tv_usec;
    swsecs = INT_MAX;
    vlenmax = ULONG_MAX;
    vlenmin = 0;
    headers = true;
    recmax = 0;
    tdmax = 1;
    mark = 0;

    mpname = kvsname = NULL;
    xrand_init(seed);

    while (1) {
        char *errmsg, *end;

        c = getopt(argc, argv, ":B:bC:cDd:f:Hhi:j:KkLl:Mm:Oo:p:RS:s:T:t:vW:w:xy:");
        if (-1 == c)
            break;

        errmsg = end = NULL;
        errno = 0;

        switch (c) {
        case 'B':
            keybinmax = cvt_strtoul(optarg, &end, &suftab_iec);
            keybinmin = keybinmax;
            if (*end == ':')
                keybinmax = cvt_strtoul(end + 1, &end, &suftab_iec);
            if (keybinmin > KM_REC_KEY_MAX)
                keybinmin = KM_REC_KEY_MAX;
            if (keybinmax > KM_REC_KEY_MAX)
                keybinmax = KM_REC_KEY_MAX;
            if (keybinmin < 8)
                keybinmin = 8;
            if (keybinmax < keybinmin)
                keybinmax = keybinmin;
            errmsg = "invalid binary key length";
            keybinary = true;
            break;

        case 'b':
            keybinary = true;
            break;

        case 'C':
            chk_recmax = 1024 * 1024 * 1024;
            cf_dir = optarg;
            break;

        case 'c':
            check = true;
            break;

        case 'D':
            destroy = true;
            break;

        case 'f':
            keyfmt = optarg;
            break;

        case 'H':
            headers = false;
            break;

        case 'h':
            help = true;
            break;

        case 'i':
            recmax = cvt_strtoul(optarg, &end, &suftab_iec);
            if (recmax < 2)
                recmax = 2;
            errmsg = "invalid max record count";
            init = true;
            break;

        case 'j':
            tdmax = strtol(optarg, &end, 0);
            errmsg = "invalid max jobs count";
            break;

        case 'k': /* deprecated */
            break;

        case 'l':
            vlenmax = cvt_strtoul(optarg, &end, &suftab_iec);
            vlenmin = vlenmax;
            if (*end == ':')
                vlenmax = cvt_strtoul(end + 1, &end, &suftab_iec);
            if (vlenmax < vlenmin)
                vlenmax = vlenmin;
            errmsg = "invalid value length";
            break;

        case 'L':
            latency = true;
            break;

        case 'M': /* deprecated */
            break;

        case 'm':
            mark = cvt_strtoul(optarg, &end, &suftab_time_t);
            errmsg = "invalid mark";
            break;

        case 'O':
            stayopen = true;
            break;

        case 'o':
            rc = prop_decode(optarg, ",", NULL);
            if (rc)
                exit(EX_USAGE);
            break;

        case 'p':
            collectionc = strtoul(optarg, &end, 0);
            break;

        case 'R':
            recverify = false;
            break;

        case 'S':
            seed = cvt_strtoul(optarg, &end, &suftab_iec);
            errmsg = "invalid seed";
            xrand_init(seed);
            break;

        case 's':
            mark = cvt_strtoul(optarg, &end, &suftab_time_t);
            mark *= 1000;
            errmsg = "invalid mark";
            break;

        case 'T':
            swaptxn = true;
            /* FALLTHROUGH */

        case 't':
            swsecs = cvt_strtoul(optarg, &end, &suftab_time_t);
            if (swsecs < 1)
                swsecs = INT_MAX;
            errmsg = "invalid test run time";
            test = true;
            break;

        case 'v':
            ++verbosity;
            break;

        case 'w':
            wpctf = strtof(optarg, &end);
            if (wpctf < 0 || wpctf > 50)
                errno = EINVAL;
            errmsg = "invalid write percentage";
            break;

        case 'x':
            xstats = true;
            break;

        case 'y':
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
            eprint("option -%c ignored", c);
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

#ifdef XKMT
    mpname = strdup(progname);
    if (!mpname) {
        syntax("strdup(%s) failed", argv[0]);
        exit(EX_OSERR);
    }
#else

    if (argc > 0) {
		mpname = strdup(argv[0]);
		optind = 1;

		if (0 == strncmp(mpname, "/dev/", 5)) {
			impl = &km_impl_dev;
		} else if (0 == strncmp(mpname, "mongodb://", 10)) {
			impl = &km_impl_mongo;
			mongo = 1;

			kvsname = strchr(mpname + strlen("mongodb://"), '/');
			if (kvsname)
				*kvsname++ = '\000';

			if (!kvsname || !strlen(kvsname)) {
				syntax("%s does not specify target database", mpname);
				exit(EX_USAGE);
			}
		} else if (0 == strncmp(mpname, "mpool:", 6)) {
			impl = &km_impl_ds;
			impl->mpname = mpname + 6;
		} else {
			if (argc < 2) {
				syntax("missing kvs name");
				exit(EX_USAGE);
			}

			kvsname = argv[1];
			optind = 2;

			rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, NULL);
			if (rc) {
				eprint("pg_create failed: %s\n", strerror(rc));
				exit(EX_OSERR);
			}

			rc = pg_parse_argv(pg, argc, argv, &optind);
			switch (rc) {
            case 0:
				break;

            case EINVAL:
                eprint("missing group name (e.g. %s) before parameter %s\n",
					   PG_KVDB_OPEN, argv[optind]);
                exit(EX_USAGE);
                break;

            default:
                eprint("error processing parameter %s: %s\n", argv[optind], strerror(rc));
                exit(EX_OSERR);
                break;
			}

			rc = svec_append_pg(&db_oparms, pg, "perfc_enable=0", PG_KVDB_OPEN, NULL);
			if (rc) {
				eprint("unable to append kvdb-oparms params: %s\n", strerror(rc));
				exit(EX_OSERR);
			}

			rc = svec_append_pg(&kv_oparms_txn, pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
			if (rc) {
				eprint("unable to append kvs-oparms txn params: %s\n", strerror(rc));
				exit(EX_OSERR);
			}

			rc = svec_append_pg(&kv_oparms_notxn, pg, PG_KVS_OPEN, "transactions_enable=0", NULL);
			if (rc) {
				eprint("unable to append kvs-oparms notxn params: %s\n", strerror(rc));
				exit(EX_OSERR);
			}
		}

		if (argc > optind) {
			syntax("extraneous argument '%s'", argv[optind]);
			exit(EX_USAGE);
		}
    }
#endif

    if (!impl->mpname)
        impl->mpname = mpname;
    impl->kvsname = kvsname;
    impl->tdmax = tdmax;

    /* Convert write percent (wpctf) to swap percent (swappctf).
     * Let:
     *   R == total number of reads
     *   W == total number of writes
     *
     * Kmt's read/write logic is: read two entries and 'swappct' percent
     * of the time, write the same two entries (i.e., swap them).
     * Thus, swappct works out to be the ratio of writes to reads:
     *
     *   swappctf = W / R
     *
     * The write percent is:
     *
     *   wpctf = 100 * W / (W + R)
     *
     * To convert from wpctf to swappctf, substitue swappct*R for W in
     * the wpctf equation:
     *
     *   wpctf = 100 * swappctf*R / (swappctf*R + R)
     *
     * Solving for swappctf yeilds:
     *
     *   swappctf = wpctf / (100 - wpctf)
     */
    assert(0 <= wpctf && wpctf <= 50);
    swappctf = wpctf / (100.0 - wpctf);

    /* now convert to a more efficiently usable representation */
    swappct = (KM_SWAPPCT_MODULUS * swappctf);

    if (c0putval < sizeof(struct km_rec))
        recverify = false;

    if (vlenmax >= ULONG_MAX)
        vlenmax = impl->vlenmax_default;
    vlenmax = min_t(size_t, vlenmax, impl->vlenmax);

    if (mongo) {
        int i;

        if (keybinary) {
            keybinary = false;
            ++mongo;
        }

        wcmaj = wcmajprob * WCMAJSCALE;

        if (collectionc > MONGO_COLLECTIONS_MAX) {
            eprint("%s: limiting to %u collections", __func__, MONGO_COLLECTIONS_MAX);
            collectionc = MONGO_COLLECTIONS_MAX;
        }

        if (fieldcount < 2) {
            fieldcount = 1;
        } else if (fieldlength == 0) {
            fieldlength = vlenmax / fieldcount;
            if (fieldlength == 0) {
                syntax("too many fields for length %zu", vlenmax);
                exit(EX_USAGE);
            }
        }

        if (fieldlength > 0) {
            vlenmax = fieldlength * fieldcount;
            vlenmin = vlenmax;
        }

        if (fieldcount > fieldcount_max) {
            syntax("fieldcount must be less than %u", fieldcount_max);
            exit(EX_USAGE);
        }

        if (fieldlength > impl->vlenmax / fieldcount) {
            syntax("field (length * count) must be less than %lu", impl->vlenmax);
            exit(EX_USAGE);
        }

        /* Build a table of field names to avoid having to call snprintf
         * fieldcount times for each put operation...
         */
        fieldnamew_min = snprintf(NULL, 0, fieldname_fmt, 0);
        fieldnamew_max = snprintf(NULL, 0, fieldname_fmt, fieldcount);
        fieldnamew_max = roundup(fieldnamew_max + 1, 8);

        fieldnamev = aligned_alloc(128, (fieldcount + 1) * fieldnamew_max);
        if (!fieldnamev)
            abort();

        for (i = 0; i < fieldcount; ++i) {
            int n;

            n = snprintf(fieldnamev + fieldnamew_max * i, fieldnamew_max, fieldname_fmt, i);
            if (n < fieldnamew_min || n >= fieldnamew_max)
                abort();
        }
        fieldnamev[fieldnamew_max * i] = '\000';
    }

    impl->vlenmax = min_t(size_t, vlenmax, impl->vlenmax);
    impl->vlenmin = min_t(size_t, vlenmin, impl->vlenmax);
    impl->vlendiv = impl->vlenmax - impl->vlenmin + 1;

    if (secsz < impl->vlenmax + (KM_REC_SZ_MAX - KM_REC_VLEN_MAX))
        secsz = ALIGN(impl->vlenmax + (KM_REC_SZ_MAX - KM_REC_VLEN_MAX), PAGE_SIZE);

    if (help) {
        usage(impl);
        exit(0);
    }

    if (!(init || test || check || destroy)) {
        syntax("one or more of -i, -t, -c, -D is required");
        exit(EX_USAGE);
    }

    if (argc < 1) {
        syntax("insufficient arguments for mandatory parameters");
        exit(EX_USAGE);
    }

#ifdef XKMT
    if (!init) {
        syntax("-i is always required in XKMT mode");
        exit(EX_USAGE);
    }
#else
    err = hse_init(0, NULL);
    if (err) {
        hse_err_to_string(err, errbuf, sizeof(errbuf), NULL);
        eprint("%s: failed to initialize kvdb: %s\n", __func__, errbuf);
        exit(EX_OSERR);
    }
#endif

    pthread_spin_init(&td_exited_lock, PTHREAD_PROCESS_PRIVATE);

    if ((init || test) && impl->vlenmax > 0) {
        char *p, *end;

        /* Construct the buffer of randomness such that we can
         * start from any offset from randbuf and access up to
         * vlenmax valid bytes.
         */
        randbufsz = roundup(impl->vlenmax, PAGE_SIZE) * 2;

        randbuf = aligned_alloc(PAGE_SIZE, randbufsz);
        if (!randbuf) {
            eprint("%s: malloc(%zu) randbuf failed\n", __func__, randbufsz);
            exit(EX_OSERR);
        }

        end = randbuf + randbufsz;
        p = randbuf;

        if (vrunlen > 0) {
            char c; /* ASCII value that won't prevent data loss when stored as UTF-8 */

            c = xrand64() & 0x7F; /* ASCII range */
            if (c < '0')
                c += '0';

            while (p < end) {
                if ((uintptr_t)p % vrunlen == 0) {
                    c = xrand64() & 0x7F; /* ASCII range */
                    if (c < '0')
                        c += '0';
                }
                *p++ = c;
            }
        } else {
            while (p < end) {
                *(long *)p = xrand64();
                p += sizeof(long);
            }
        }

        randbufsz /= 2;
    }

    bkt_init();
    chk_init(impl, recmax);

    if (keyfmt) {
        char key1[KM_REC_KEY_MAX * 2] = {};
        char key2[KM_REC_KEY_MAX * 2] = {};
        int  len1, len2;

        if (keybinary) {
            syntax("option -f excludes -b and -B");
            exit(EX_USAGE);
        }

        len1 = km_rec_keygen_cmn(key1, impl->recmax - 1);

        if (len1 < 1 || len1 > KM_REC_KEY_MAX) {
            syntax("key format yields key (%s) longer than %d bytes", key1, KM_REC_KEY_MAX);
            exit(EX_USAGE);
        }

        len2 = km_rec_keygen_cmn(key2, 0);
        if (len1 == len2 && 0 == memcmp(key1, key2, len1)) {
            syntax("key format yields identical keys (%s) for 0 and recmax", key1);
            exit(EX_USAGE);
        }
    }

    if (swappct > 0) {
        if (impl->tdmax > impl->recmax / 2)
            impl->tdmax = impl->recmax / 2;
        if (impl->tdmax > BKTLOCK_MAX / 2)
            impl->tdmax = BKTLOCK_MAX / 2;
    }

    km_lor.span = clamp_t(u64, km_lor.span, 32, impl->recmax - 1);
    km_lor.range = impl->recmax - km_lor.span + 1;

    signal_reliable(SIGALRM, sigalrm_isr);
    signal_reliable(SIGUSR1, sigusr1_isr);
    signal_reliable(SIGINT, sigint_isr);
    signal_reliable(SIGHUP, SIG_IGN);

    oom_score_adj_set(oom_score_adj);

    if (mongo)
        mongoc_init();

    if (latency)
        latency_init(impl->km_latency, KMT_LAT_REC_CNT);

    if (init) {
        initmode = true;

        spawn(impl, td_init, 0, mark);
        if (sigint) {
            destroy = true;
            goto sigint;
        }

        initmode = false;
    }

    /* Clear the transient bits in the check file.  As a bonus,
     * this should warm up the page cache such that it reduces
     * some of the startup noise in test mode.
     */
    if (test || check)
        td_check_init(impl);

    if (test) {
        bool orecverify = recverify;

        recverify = swapexcl && recverify;
        testmode = true;

        spawn(impl, td_test, swsecs, mark);

        recverify = orecverify;
        testmode = false;
    }

    if (check && !sigint) {
        spawn(impl, td_check, 0, mark);
        td_check_fini(impl);
    }

    if (destroy && !sigint)
        spawn(impl, td_destroy, 0, mark);

sigint:
    if (sigint) {
        if (destroy)
            chk_destroy(impl);
        signal(SIGINT, SIG_DFL);
        kill(getpid(), SIGINT);
        _exit(1);
    }

    if (stayopen) {
        stayopen = false;
        km_close(impl);
    }

    /* For valgrind...
     */
    super_free(g.bktlock, g.bktlocksz);
    free(fieldnamev);
    free(randbuf);
    free(mpname);

    if (latency)
        latency_finish(impl->km_latency, KMT_LAT_REC_CNT);

    if (mongo)
        mongoc_cleanup();

    svec_reset(&db_oparms);
    svec_reset(&kv_oparms_notxn);
    svec_reset(&kv_oparms_txn);

    pg_destroy(pg);

#ifndef XKMT
    hse_fini();
#endif

    return 0;
}
