/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/compiler.h>
#include <hse_util/string.h>
#include <hse_util/hse_err.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/atomic.h>
#include <hse_util/logging.h>
#include <hse_util/xrand.h>
#include <hse_util/keycmp.h>
#include <hse_util/seqno.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/storage.h>

#include <util/src/bonsai_tree_pvt.h>

#include <hse_ut/framework.h>

#include <sysexits.h>

#define BONSAI_TREE_CLIENT_VERIFY

#if defined(LIBURCU_QSBR) || defined(LIBURCU_BP)
#define BONSAI_RCU_REGISTER()
#define BONSAI_RCU_UNREGISTER()
#else
#define BONSAI_RCU_REGISTER()       rcu_register_thread()
#define BONSAI_RCU_UNREGISTER()     rcu_unregister_thread()
#endif

#ifdef LIBURCU_QSBR
#define BONSAI_RCU_QUIESCE()        rcu_quiescent_state()
#else
#define BONSAI_RCU_QUIESCE()
#endif

#define ALLOC_LEN_MAX 1344

enum bonsai_alloc_mode {
    HSE_ALLOC_MALLOC = 0,
    HSE_ALLOC_CURSOR = 1,
};

static struct cheap *cheap;

static enum bonsai_alloc_mode allocm = HSE_ALLOC_CURSOR;

/* [HSE_REVISIT] Need to replace these constants, macros. */
#define HSE_CORE_TOMB_REG ((void *)~0x1UL)
#define HSE_CORE_TOMB_PFX ((void *)~0UL)

struct bonsai_root *   broot;
static int             induce_alloc_failure;
unsigned int           key_begin = 0;
unsigned int           key_end = 7 * 1024 * 1024;
static int             stop_producer_threads;
static int             stop_consumer_threads;
static unsigned int    key_current = 1;
static int             num_consumers = 4;
static int             num_producers = 4;
static int             runtime_insecs = 10;
static int             random_number;
static size_t          key_size = 10;
static size_t          val_size = 100;
static pthread_mutex_t mtx;

static thread_local struct xrand xr;

static void
bonsai_xrand_init(uint64_t seed64)
{
    u32 seed32 = seed64;

    if (seed64 == 0) {
        seed32 = get_cycles();
        seed64 = (get_cycles() << 32) | seed32;
    }

    seed32 = seed32 ^ (seed64 >> 32);

    xrand_init(&xr, seed32);
}

static uint64_t
bonsai_xrand(void)
{
    return xrand64(&xr);
}

static void
bonsai_client_insert_callback(
    void *                cli_rock,
    enum bonsai_ior_code *code,
    struct bonsai_kv *    kv,
    struct bonsai_val *   new_val,
    struct bonsai_val **  old_val,
    uint                  height)
{
    struct bonsai_val * old;
    struct bonsai_val **prevp;

    uintptr_t seqnoref;

    assert(rcu_read_ongoing());

    if (IS_IOR_INS(*code)) {
            assert(new_val == NULL);
            kv->bkv_valcnt++;
            return;
    }

    assert(IS_IOR_REPORADD(*code));
    assert(new_val);

    /* Search for an existing value with the given seqnoref */
    prevp = &kv->bkv_values;
    SET_IOR_ADD(*code);

    seqnoref = new_val->bv_seqnoref;

    old = rcu_dereference(kv->bkv_values);
    assert(old);

    while (old) {
        if (seqnoref == old->bv_seqnoref) {
            SET_IOR_REP(*code);
            break;
        }

        if (seqnoref_gt(seqnoref, old->bv_seqnoref))
            break;

        prevp = &old->bv_next;
        old = rcu_dereference(old->bv_next);
    }

    if (IS_IOR_REP(*code)) {
        /* in this case we'll just replace the old list element */
        new_val->bv_next = rcu_dereference(old->bv_next);
        *old_val = old;
    } else if (HSE_SQNREF_ORDNL_P(seqnoref)) {
        /* slot the new element just in front of the next older one */
        new_val->bv_next = old;
        kv->bkv_valcnt++;
    } else {
        /* rewind & slot the new element at the front of the list */
        prevp = &kv->bkv_values;
        new_val->bv_next = *prevp;
        kv->bkv_valcnt++;
    }

    /* Publish the new value node.  New readers will see the new node,
     * while existing readers may continue to use the old node until
     * the end of the current grace period.
     */
    rcu_assign_pointer(*prevp, new_val);
}

static int
cmpKey(const void *p1, const void *p2)
{
    const struct bonsai_skey *skp1 = p1;
    const struct bonsai_skey *skp2 = p2;

    return key_full_cmp(&skp1->bsk_key_imm, skp1->bsk_key, &skp2->bsk_key_imm, skp2->bsk_key);
}

static u64
decrement_key(u64 key, int numeric)
{
    if (numeric)
        return key - 1;
    else
        return ((key & 0x00ffffffffffffff) | 0x2000000000000000);
}

static u64
increment_key(u64 key, int numeric)
{
    if (numeric)
        return key + 1;
    else
        return ((key & 0x00ffffffffffffff) | 0x7b00000000000000);
}

void
init_tree(struct bonsai_root **tree, enum bonsai_alloc_mode allocm)
{
    merr_t err;

    cheap = NULL;
    *tree = NULL;

    if (allocm == HSE_ALLOC_CURSOR) {
        while (1) {
            cheap = cheap_create(16, 1024 * MB);
            if (cheap)
                break;

            usleep(USEC_PER_SEC);
        }
    }

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, tree);
    if (err)
        abort();
}

/*
 * c0's callback to pick the right value from the value list, based on
 * sequence numbers.
 */
static struct bonsai_val *
findValue(struct bonsai_kv *kv, u64 view_seqno, uintptr_t seqnoref)
{
    struct bonsai_val *val_ge, *val;
    u64                diff_ge, diff;

    diff_ge = ULONG_MAX;
    val_ge = NULL;

    for (val = rcu_dereference(kv->bkv_values); val; val = rcu_dereference(val->bv_next)) {
        diff = seqnoref_ext_diff(view_seqno, val->bv_seqnoref);
        if (diff < diff_ge) {
            diff_ge = diff;
            val_ge = val;
        }

        if (!seqnoref) {
            if (diff_ge == 0)
                break;
            continue;
        }

        if (seqnoref == val->bv_seqnoref)
            return val;

        diff = seqnoref_diff(seqnoref, val->bv_seqnoref);
        if (diff < diff_ge) {
            diff_ge = diff;
            val_ge = val;
        }
    }

    return val_ge;
}

static struct bonsai_val *
findPfxValue(struct bonsai_kv *kv, uintptr_t seqnoref)
{
    struct bonsai_val *val;

    val = kv->bkv_values;
    while (val) {
        if (val->bv_value == HSE_CORE_TOMB_PFX) {
            if ((val->bv_seqnoref == seqnoref) || seqnoref_ge(seqnoref, val->bv_seqnoref))
                break;
        }
        val = rcu_dereference(val->bv_next);
    }

    return val;
}

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *tci = info->ti_coll;
    int c;

    bonsai_xrand_init(0);

    BONSAI_RCU_REGISTER();

    optind = 1;

    while (-1 != (c = getopt(tci->tci_argc - tci->tci_optind, tci->tci_argv + tci->tci_optind, ":cm"))) {
        switch (c) {
        case 'c':
            allocm = HSE_ALLOC_CURSOR;
            break;

        case 'm':
            allocm = HSE_ALLOC_MALLOC;
            break;

        case '?':
            fprintf(stderr, "%s: invalid option -%c\n", tci->tci_argv[0], optopt);
            exit(EX_USAGE);

        case ':':
            fprintf(stderr, "%s: option -%c requires a parameter\n", tci->tci_argv[0], optopt);
            exit(EX_USAGE);

        default:
            fprintf(stderr, "%s: option '-%c' ignored\n", tci->tci_argv[0], c);
            break;
        }
    }

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    BONSAI_RCU_UNREGISTER();

    return 0;
}

int
no_fail_pre(struct mtf_test_info *info)
{
    bonsai_xrand_init(0);

    return 0;
}

int
no_fail_post(struct mtf_test_info *info)
{
    return 0;
}

static void
bonsai_client_wait_for_test_completion(void)
{
    u_long stop = get_time_ns() + (runtime_insecs * NSEC_PER_SEC);

    usleep(runtime_insecs * USEC_PER_SEC);

    while (get_time_ns() < stop)
        usleep(1000);
}

static void *
bonsai_client_producer(void *arg)
{
    unsigned long *val = NULL;
    unsigned int *key;
    merr_t         err = 0;
    int i;

    struct bonsai_skey skey = { 0 };
    struct bonsai_sval sval = { 0 };

    /*
     * Register is not required for BP. For QSBR, it is required only for
     * clients.
     */
    BONSAI_RCU_REGISTER();

    bonsai_xrand_init(0);

    key = calloc(1, roundup(key_size, sizeof(*key)));
    if (!key)
        goto exit;

    assert(val_size >= key_size);

    val = calloc(1, val_size);
    if (!val)
        goto exit;

    while (!stop_producer_threads) {
        for (i = key_begin; i < key_end; i++) {
            if (random_number == 0)
                *key = htobe32(i);
            else
                *key = htobe32(bonsai_xrand());

            *val = *key;

            bn_skey_init(key, key_size, 0, 0, &skey);
            bn_sval_init(val, val_size, HSE_ORDNL_TO_SQNREF(*val), &sval);

            pthread_mutex_lock(&mtx);

            rcu_read_lock();
            err = bn_insert_or_replace(broot, &skey, &sval);
            rcu_read_unlock();

            if (merr_errno(err) == 0) {
                __sync_synchronize();
                key_current = i;
            }
            pthread_mutex_unlock(&mtx);

            if (err) {
                assert(merr_errno(err) != EEXIST);
                break;
            }

            if (stop_producer_threads)
                break;

            if ((bonsai_xrand() % 128) < 13)
                usleep(1);
        }

        if (err) {
            log_errx("bn_insert %u/%u result @@e", err, i, key_current);
            break;
        }
    }

exit:

    BONSAI_RCU_UNREGISTER();

    free(key);
    free(val);

    pthread_exit((void *)(long)merr_errno(err));
}

struct lcp_test_arg {
    pthread_barrier_t *fbarrier;
    uint               tid;
};

static void *
bonsai_client_lcp_test(void *arg)
{
    int                i;
    uint               tid;
    merr_t             err = 0;
    char               key[KI_DLEN_MAX + 36];
    unsigned long      val;
    pthread_barrier_t *fbarrier;

    struct lcp_test_arg *p = (struct lcp_test_arg *)arg;

    fbarrier = p->fbarrier;
    tid = p->tid;

    struct bonsai_skey skey = { 0 };
    struct bonsai_sval sval = { 0 };

#ifdef BONSAI_TREE_CLIENT_VERIFY
    uint lcp, bounds;
#endif

    /*
     * Register is not required for BP. For QSBR, it is required only for
     * clients.
     */
    BONSAI_RCU_REGISTER();

    memset(key, 'a', KI_DLEN_MAX + 27);

    /*
     * Insert keys of the same length (KI_DLEN_MAX + 27).
     * The last byte is replaced with a..z.
     * Each key is inserted with a unique value to identify the keynum, skidx.
     */
    for (i = 0; i < 26; i++) {
        val = (u64)i << 32 | tid;

        key[KI_DLEN_MAX + 26] = 'a' + i;

        bn_skey_init(key, KI_DLEN_MAX + 27, 0, tid, &skey);
        bn_sval_init(&val, sizeof(val), HSE_ORDNL_TO_SQNREF(val), &sval);

        pthread_mutex_lock(&mtx);
        rcu_read_lock();
        err = bn_insert_or_replace(broot, &skey, &sval);
        rcu_read_unlock();
        pthread_mutex_unlock(&mtx);

        key[KI_DLEN_MAX + 26] = 'a';

        if (err) {
            log_errx("lcp_test bn_insert %u result @@e", err, i);
            assert(!err);
        }
    }

    pthread_barrier_wait(fbarrier);

    while (!stop_producer_threads)
        usleep(1000);

#ifdef BONSAI_TREE_CLIENT_VERIFY
    bounds = atomic_read(&broot->br_bounds);

    lcp = (bounds > 0) ? (bounds - 1) : 0;

    for (i = 0; i < 26; i++) {
        struct bonsai_skey          skey = { 0 };
        struct bonsai_kv *          kv = NULL;
        struct bonsai_val *         v;
        unsigned long               val;
        bool                        found HSE_MAYBE_UNUSED;
        const struct key_immediate *ki HSE_MAYBE_UNUSED;

        key[KI_DLEN_MAX + 26] = 'a' + i;

        bn_skey_init(key, KI_DLEN_MAX + 27, 0, tid, &skey);
        ki = &skey.bsk_key_imm;

        rcu_read_lock();
        found = bn_find(broot, &skey, &kv);
        assert(found);

        v = rcu_dereference(kv->bkv_values);
        memcpy(&val, v->bv_value, sizeof(val));
        assert(val == ((u64)i << 32 | tid));

        key[KI_DLEN_MAX + 26] = 'a';

        if (lcp > 0) {
            assert(key_immediate_cmp(ki, &kv->bkv_key_imm) == S32_MIN);
            assert(memcmp(key, kv->bkv_key, lcp) == 0);
        }
        rcu_read_unlock();
    }

    for (i = 1; i < KI_DLEN_MAX + 27; i++) {
        struct bonsai_skey skey = { 0 };
        struct bonsai_kv * kv = NULL;
        bool               found HSE_MAYBE_UNUSED;

        bn_skey_init(key, i, 0, tid, &skey);

        rcu_read_lock();
        found = bn_find(broot, &skey, &kv);
        assert(!found);
        rcu_read_unlock();
    }

    for (i = KI_DLEN_MAX + 28; i < sizeof(key); i++) {
        struct bonsai_skey skey = { 0 };
        struct bonsai_kv * kv = NULL;
        bool               found HSE_MAYBE_UNUSED;

        bn_skey_init(key, i, 0, tid, &skey);

        rcu_read_lock();
        found = bn_find(broot, &skey, &kv);
        assert(!found);
        rcu_read_unlock();
    }
#endif

    BONSAI_RCU_UNREGISTER();

    pthread_exit((void *)(long)merr_errno(err));
}

static void *
bonsai_client_consumer(void *arg)
{
    struct bonsai_skey skey = { 0 };
    struct bonsai_kv * kv = NULL;

    unsigned int    key_last;
    unsigned int   *key;
    bool            found = true;
    int             i;

    key = calloc(1, roundup(key_size, sizeof(*key)));
    if (!key)
        goto exit;

    BONSAI_RCU_REGISTER();

    while (!stop_consumer_threads) {
        __sync_synchronize();
        key_last = key_current;

        for (i = 1; i <= key_last; i++) {
            *key = htobe32(i);
            bn_skey_init(key, key_size, 0, 0, &skey);

            rcu_read_lock();
            found = bn_find(broot, &skey, &kv);
            rcu_read_unlock();

            if (stop_consumer_threads)
                break;

            if (!found) {
                log_err("key %u not found", i);
                break;
            }
        }

        BONSAI_RCU_QUIESCE();

        sched_yield();
    }

#ifdef BONSAI_TREE_DEBUG
    log_info("Stopped consumer ... last key %u", i);
#endif

    BONSAI_RCU_UNREGISTER();
    free(key);

exit:
    pthread_exit(found ? (void *)0 : (void *)-1);
}

static int
bonsai_client_multithread_test(enum bonsai_alloc_mode allocm)
{
    pthread_t *consumer_tids;
    pthread_t *producer_tids;
    void *     ret;
    int        rc, i;

#ifdef BONSAI_TREE_CLIENT_VERIFY
    struct bonsai_skey skey;
    struct bonsai_kv *kvnext, *kv;

    unsigned int *key;
    merr_t         err;
    bool           found;

    key = calloc(1, roundup(key_size, sizeof(*key)));
    if (!key) {
        rc = ENOMEM;
        goto exit;
    }
#endif

    cheap = NULL;

    if (allocm == HSE_ALLOC_CURSOR) {
        cheap = cheap_create(16, 1 * GB);
        if (!cheap)
            return -1;
    }

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, &broot);
    if (err) {
        log_err("Bonsai tree create failed");
        return err;
    }

    rc = pthread_mutex_init(&mtx, NULL);
    assert(rc == 0);

    consumer_tids = malloc(num_consumers * sizeof(*consumer_tids));
    assert(consumer_tids);

    producer_tids = malloc(num_producers * sizeof(*producer_tids));
    assert(producer_tids);

    /* Create an rcu callback thread for each cpu.
     */
    rc = create_all_cpu_call_rcu_data(0);
    assert(rc == 0);

    for (i = 0; i < num_producers; i++) {
        rc = pthread_create(&producer_tids[i], NULL, bonsai_client_producer, NULL);
        assert(rc == 0);
    }

    for (i = 0; i < num_consumers; i++) {
        rc = pthread_create(&consumer_tids[i], NULL, bonsai_client_consumer, NULL);
        assert(rc == 0);
    }

    bonsai_client_wait_for_test_completion();

    stop_consumer_threads = 1;
    for (i = 0; i < num_consumers; i++) {
        rc = pthread_join(consumer_tids[i], &ret);
        assert(rc == 0);
    }

    stop_producer_threads = 1;
    for (i = 0; i < num_producers; i++) {
        rc = pthread_join(producer_tids[i], &ret);
        assert(rc == 0);
    }

#ifdef BONSAI_TREE_DEBUG
    log_info("Before teardown noded added %ld removed %ld", client.bnc_add, client.bnc_del);
#endif

    rcu_barrier();

#ifdef BONSAI_TREE_CLIENT_VERIFY
    rcu_read_lock();
    kvnext = rcu_dereference(broot->br_kv.bkv_next);

    for (i = 1; i < key_current; i++) {
        *key = htobe32(i);
        bn_skey_init(key, key_size, 0, 0, &skey);

        found = bn_find(broot, &skey, &kv);

        if (!found) {
            if (random_number)
                continue;

            log_err("Key %u (%x) not found", i, *key);
            rc = ENOENT;
            break;
        }

        /* Verify that the first key_current items are in order.
         */
        if (kvnext != kv) {
            log_err("Key %u (%x) not found in sorted list", i, *key);
            rc = EINVAL;
            break;
        }

        kvnext = rcu_dereference(kvnext->bkv_next);
    }

    /* Check to see if forw/back lists have the same number
     * of items.  They may have more items than key_current
     * because key_current isn't the max number of items
     * in the tree.
     */
    if (!err) {
        int j = 0, k = 0;

        kvnext = rcu_dereference(broot->br_kv.bkv_next);

        while (kvnext != &broot->br_kv) {
            kvnext = rcu_dereference(kvnext->bkv_next);
            ++j;
        }

        kvnext = rcu_dereference(broot->br_kv.bkv_prev);

        while (kvnext != &broot->br_kv) {
            kvnext = rcu_dereference(kvnext->bkv_prev);
            ++k;
        }

        log_debug("%d %d %d, key_current %d, rand %d",
                  i, j, k, key_current, random_number);
        assert(j == k);
    }

    bn_traverse(broot);
    rcu_read_unlock();
#endif

#ifdef BONSAI_TREE_DEBUG
    log_info("Tree height %d", bn_height_get(broot.br_root));
#endif

    bn_destroy(broot);
    broot = NULL;

    free_all_cpu_call_rcu_data();

    cheap_destroy(cheap);
    cheap = NULL;

    pthread_mutex_destroy(&mtx);

    free(producer_tids);
    free(consumer_tids);

#ifdef BONSAI_TREE_CLIENT_VERIFY
    free(key);
#endif

exit:
    return rc;
}

static int
bonsai_client_singlethread_test(enum bonsai_alloc_mode allocm)
{
    merr_t        err;
    int           i;
    unsigned long tmpkey = 9999999;
    size_t        tmpkey_len = sizeof(tmpkey);
    bool          found;

    static unsigned long a[] = { 300, 1,   2,   3,   4,   3,   2,  1,  5,  6,  7,   8,
                                 303, 302, 1,   2,   3,   4,   5,  99, 1,  2,  3,   4,
                                 5,   99,  200, 1,   2,   3,   4,  5,  99, 1,  2,   3,
                                 4,   5,   99,  299, 301, 1,   2,  3,  4,  5,  99,  7,
                                 8,   9,   13,  14,  15,  99,  20, 30, 40, 50, 101, 150,
                                 500, 100, 600, 5,   99,  200, 1,  2,  3,  4,  5,   99 };
    struct bonsai_skey   skey = { 0 };
    struct bonsai_sval   sval = { 0 };
    struct bonsai_kv *   kv = NULL;

    cheap = NULL;

    if (allocm == HSE_ALLOC_CURSOR) {
        cheap = cheap_create(16, 64 * MB);
        if (!cheap)
            return -1;
    }

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, &broot);
    if (err) {
        log_errx("Bonsai tree create failed: @@e", err);
        return err;
    }

    i = 0;
    do {
        for (; i < NELEM(a); i++) {
            bn_skey_init(&a[i], sizeof(a[i]), 0, 0, &skey);
            bn_sval_init(&a[i], sizeof(a[i]), HSE_ORDNL_TO_SQNREF(a[i]), &sval);

            rcu_read_lock();
            err = bn_insert_or_replace(broot, &skey, &sval);
            rcu_read_unlock();

            if (err) {
                log_errx("Inserting %ld result %d: @@e", err, a[i], merr_errno(err));
                assert(merr_errno(err) != EEXIST);
                break;
            }
        }

    } while (merr_errno(err) == ENOMEM);

    for (i = i - 1; i >= 0; i--) {
        struct bonsai_val *v;
        u64                val;

        /* Initialize Key */
        bn_skey_init(&a[i], sizeof(a[i]), 0, 0, &skey);

        rcu_read_lock();
        found = bn_find(broot, &skey, &kv);
        if (!found) {
            rcu_read_unlock();
            log_err("Finding %ld result %d", a[i], found);
            break;
        }

        v = rcu_dereference(kv->bkv_values);
        memcpy(&val, v->bv_value, sizeof(val));
        assert(a[i] == val);

        rcu_read_unlock();
    }

    bn_skey_init(&tmpkey, tmpkey_len, 0, 0, &skey);

    rcu_read_lock();
    found = bn_find(broot, &skey, &kv);
    assert(found == false);

    bn_traverse(broot);
    rcu_read_unlock();

    bn_destroy(broot);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;

    return 0;
}

MTF_MODULE_UNDER_TEST(bonsai_tree_test);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    bonsai_tree_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST(bonsai_tree_test, misc)
{
    merr_t err;

    err = bn_create(NULL, NULL, NULL, &broot);
    ASSERT_NE(err, 0);

    err = bn_create(NULL, bonsai_client_insert_callback, NULL, NULL);
    ASSERT_NE(err, 0);

    cheap = cheap_create(16, 4 * MB);
    ASSERT_NE(cheap, NULL);

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, &broot);
    ASSERT_EQ(err, 0);

    bn_destroy(broot);
    broot = NULL;

    bn_destroy(NULL);

    cheap_destroy(cheap);
    cheap = NULL;
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, short_tree, no_fail_pre, no_fail_post)
{
    const int maxvals = 12345;
    const int maxkeys = 64;
    struct bonsai_skey skey;
    struct bonsai_sval sval;
    uintptr_t seqno;
    merr_t err;
    int i;

    err = bn_create(NULL, bonsai_client_insert_callback, NULL, &broot);
    ASSERT_EQ(err, 0);

    /* Load the first six or so levels of the tree such that each key
     * has many values.
     */
    for (i = 0; i < maxvals; ++i) {
        uint64_t key = i % maxkeys;
        uint64_t val = i;

        bn_skey_init(&key, sizeof(key), 0, 0, &skey);

        seqno = HSE_ORDNL_TO_SQNREF(i);
        bn_sval_init(&val, sizeof(val), seqno, &sval);

        rcu_read_lock();
        err = bn_insert_or_replace(broot, &skey, &sval);
        rcu_read_unlock();

        ASSERT_EQ(0, err);
    }

    /* Check that the values from the last 16 inserts are what we expect.
     */
    for (i = maxvals - maxkeys; i < maxvals; ++i) {
        struct bonsai_kv *kv = NULL;
        struct bonsai_val* v;
        uint64_t key = i % maxkeys;
        uint64_t val = i;
        bool b;

        bn_skey_init(&key, sizeof(key), 0, 0, &skey);
        seqno = HSE_ORDNL_TO_SQNREF(i);

        b = bn_find(broot, &skey, &kv);
        ASSERT_NE(false, b);

        v = rcu_dereference(kv->bkv_values);

        ASSERT_NE(NULL, v);
        ASSERT_EQ(seqno, v->bv_seqnoref);
        ASSERT_EQ(sizeof(val), bonsai_val_vlen(v));

        ASSERT_EQ(0, memcmp(&val, v->bv_value, sizeof(val)));
    }

    bn_destroy(broot);
    broot = NULL;
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, insdel, no_fail_pre, no_fail_post)
{
    uint ninserted = 0, ndeleted = 0;
    struct bonsai_root *tree;
    struct bonsai_skey skey;
    struct bonsai_sval sval;
    uintptr_t seqno;
    size_t intreec;
    bool *intreev;
    merr_t err;
    uint i, j;
    bool b;

    init_tree(&tree, allocm);

    intreec = 128 * 1024 + 1;

    intreev = calloc(intreec, sizeof(*intreev));
    ASSERT_NE(NULL, intreev);

    for (i = 1; i < intreec; i *= 2) {
        uint itermax = max_t(uint, i * 5, 128 * 1024);
        uint maxkeys = i;
        uint64_t tstart;

        tstart = get_time_ns();

        /* Randomly insert/delete keys...
         */
        for (j = 0; j < itermax; ++j) {
            uint64_t key = xrand64_tls() % maxkeys;

            bn_skey_init(&key, sizeof(key), 0, 0, &skey);

            rcu_read_lock();
            if (intreev[key]) {
                err = bn_delete(tree, &skey);
                ASSERT_EQ(0, err);

                intreev[key] = false;
                ++ndeleted;
            } else {
                uint64_t val = key;

                seqno = HSE_ORDNL_TO_SQNREF(i);
                bn_sval_init(&val, sizeof(val), seqno, &sval);

                err = bn_insert_or_replace(tree, &skey, &sval);
                ASSERT_EQ(0, err);

                intreev[key] = true;
                ++ninserted;
            }

            /* Double-check intreev[key] roughly 3% of the time...
             */
            if (xrand64_tls() % (1u << 20) < (3 * (1u << 20) / 100)) {
                struct bonsai_kv *kv = NULL;
                uint64_t val = key;

                b = bn_find(tree, &skey, &kv);
                ASSERT_EQ(intreev[key], b);
                if (b)
                    ASSERT_EQ(val, *(uint64_t *)kv->bkv_values->bv_value);
            }
            rcu_read_unlock();
        }

        tstart = get_time_ns() - tstart;

        rcu_read_lock();
        bn_traverse(tree);
        rcu_read_unlock();

        log_info("%7u: height %2u %2u, ins %6u, del %6u, %lu ns/insdel\n",
                 maxkeys, tree->br_height,
                 tree->br_root ? tree->br_root->bn_height : 0,
                 ninserted, ndeleted, tstart / itermax);

        /* Remove all the keys that we think are in the tree...
         */
        for (j = 0; j < maxkeys; ++j) {
            uint64_t key = j;

            if (!intreev[key])
                continue;

            bn_skey_init(&key, sizeof(key), 0, 0, &skey);

            rcu_read_lock();
            err = bn_delete(tree, &skey);
            ASSERT_EQ(0, err);

            intreev[key] = false;
            rcu_read_unlock();
        }

        /* Tree should be empty...
         */
        rcu_read_lock();
        ASSERT_EQ(NULL, rcu_dereference(tree->br_root));
        ASSERT_EQ(&tree->br_kv, rcu_dereference(tree->br_kv.bkv_next));
        ASSERT_EQ(&tree->br_kv, rcu_dereference(tree->br_kv.bkv_prev));
        rcu_read_unlock();
    }

    bn_destroy(tree);
    free(intreev);

    cheap_destroy(cheap);
    cheap = NULL;
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, basic_single_threaded, no_fail_pre, no_fail_post)
{
    ASSERT_EQ(0, bonsai_client_singlethread_test(allocm));
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, producer_test, no_fail_pre, no_fail_post)
{
    key_begin = 1;
    key_current = 0;
    stop_producer_threads = 0;
    stop_consumer_threads = 0;
    num_consumers = 0;
    num_producers = 1;
    ASSERT_EQ(0, bonsai_client_multithread_test(allocm));

#ifdef BONSAI_TREE_DEBUG
    log_info("Run time %d seconds consumers %d producers %d last key %ld",
             runtime_insecs,
             num_consumers,
             num_producers,
             key_current);
#endif
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, lcp_test, no_fail_pre, no_fail_post)
{
    int        rc;
    int        i;
    const int  num_skidx = 64;
    pthread_t *producer_tids;

    void *              ret;
    pthread_barrier_t   final_barrier;
    struct lcp_test_arg args[num_skidx];
    merr_t              err;

    cheap = cheap_create(16, 64 * MB);
    ASSERT_NE(cheap, NULL);

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, &broot);
    ASSERT_EQ(err, 0);

    rc = pthread_mutex_init(&mtx, NULL);
    ASSERT_EQ(rc, 0);

    producer_tids = malloc(num_skidx * sizeof(*producer_tids));
    ASSERT_NE(producer_tids, NULL);

    stop_producer_threads = 0;

    pthread_barrier_init(&final_barrier, NULL, num_skidx + 1);

    for (i = 0; i < num_skidx; i++) {
        args[i].tid = i;
        args[i].fbarrier = &final_barrier;
        rc = pthread_create(&producer_tids[i], NULL, bonsai_client_lcp_test, &args[i]);
        ASSERT_EQ(rc, 0);
    }

    /* Wait until all the skidx threads are done inserting their keys */
    pthread_barrier_wait(&final_barrier);

    bn_finalize(broot);

    /* lcp must be zero since the keys have different skidx values */
    ASSERT_EQ(atomic_read(&broot->br_bounds), 1);

    stop_producer_threads = 1;
    for (i = 0; i < num_skidx; i++) {
        rc = pthread_join(producer_tids[i], &ret);
        ASSERT_EQ(rc, 0);
    }

    bn_destroy(broot);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = cheap_create(16, 64 * MB);
    ASSERT_NE(cheap, NULL);

    err = bn_create(cheap, bonsai_client_insert_callback, NULL, &broot);
    ASSERT_EQ(err, 0);

    stop_producer_threads = 0;

    /* Repeat the test with a bonsai tree containing keys for just one skidx. */
    pthread_barrier_init(&final_barrier, NULL, 2);

    args[0].tid = num_skidx + 1;
    args[0].fbarrier = &final_barrier;
    rc = pthread_create(&producer_tids[0], NULL, bonsai_client_lcp_test, &args[0]);
    ASSERT_EQ(rc, 0);

    pthread_barrier_wait(&final_barrier);

    bn_finalize(broot);

    /* lcp must be set this time around */
    ASSERT_GT(atomic_read(&broot->br_bounds), 1 + KI_DLEN_MAX);

    stop_producer_threads = 1;
    rc = pthread_join(producer_tids[0], &ret);
    ASSERT_EQ(rc, 0);

    bn_destroy(broot);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;

    pthread_mutex_destroy(&mtx);

    free(producer_tids);
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, producer_manyconsumer_test, no_fail_pre, no_fail_post)
{
    key_begin = 1;
    key_current = 0;
    stop_producer_threads = 0;
    stop_consumer_threads = 0;
    num_consumers = 32;
    num_producers = 1;
    ASSERT_EQ(0, bonsai_client_multithread_test(allocm));
}

MTF_DEFINE_UTEST_PREPOST(
    bonsai_tree_test,
    manyproducer_manyconsumer_test,
    no_fail_pre,
    no_fail_post)
{
    key_begin = 1;
    key_current = 0;
    stop_producer_threads = 0;
    stop_consumer_threads = 0;
    num_consumers = 32;
    num_producers = 8;
    runtime_insecs = 30;
    ASSERT_EQ(0, bonsai_client_multithread_test(allocm));
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, random_key_test, no_fail_pre, no_fail_post)
{
    key_begin = 1;
    key_current = 0;
    random_number = 1;
    stop_producer_threads = 0;
    stop_consumer_threads = 0;
    num_consumers = 0;
    num_producers = 1;
    runtime_insecs = 10;
    ASSERT_EQ(0, bonsai_client_multithread_test(allocm));
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, odd_key_size_test, no_fail_pre, no_fail_post)
{
    key_begin = 1;
    key_current = 0;
    induce_alloc_failure = 0;
    stop_producer_threads = 0;
    stop_consumer_threads = 0;
    key_size = 7;
    random_number = 0;
    num_consumers = 0;
    num_producers = 1;
    runtime_insecs = 10;
    ASSERT_EQ(0, bonsai_client_multithread_test(allocm));
}

/* Test the key weight algorithms by creating keys of identical bytes
 * of different lengths.  Only tests edge condition bytes that seem
 * most likely to cause problems.
 */
void
bonsai_weight_test(enum bonsai_alloc_mode allocm, struct mtf_test_info *lcl_ti)
{
    u8                  list[] = { 0, 1, 2, 127, 128, 129, 253, 254, 255 };
    const int           maxlen = 37;
    struct bonsai_root *tree;
    uintptr_t           seqno;
    int                 i, j;
    struct bonsai_skey  skey = { 0 };
    struct bonsai_sval  sval = { 0 };
    struct bonsai_kv *  kv = NULL;
    struct bonsai_val * v;
    merr_t              err;

    init_tree(&tree, allocm);

    for (i = 0; i < NELEM(list); ++i) {
        for (j = 1; j < maxlen; ++j) {
            u8 key[maxlen];

            memset(key, list[i], j);
            bn_skey_init(&key, j, 0, 0, &skey);

            seqno = HSE_ORDNL_TO_SQNREF(3);
            bn_sval_init(key, j, seqno, &sval);

            rcu_read_lock();
            err = bn_insert_or_replace(tree, &skey, &sval);
            rcu_read_unlock();

            ASSERT_EQ(0, err);
        }
    }

    for (i = 0; i < NELEM(list); ++i) {
        for (j = 1; j < maxlen; ++j) {
            u8 key[maxlen];
            bool b;

            memset(key, list[i], j);

            seqno = HSE_ORDNL_TO_SQNREF(3);

            bn_skey_init(&key, j, 0, 0, &skey);

            rcu_read_lock();
            b = bn_find(tree, &skey, &kv);
            ASSERT_NE(b, false);

            v = kv->bkv_values;

            ASSERT_NE(NULL, v);
            ASSERT_EQ(seqno, v->bv_seqnoref);
            ASSERT_EQ(j, bonsai_val_vlen(v));
            ASSERT_EQ(0, memcmp(key, v->bv_value, j));
            rcu_read_unlock();
        }
    }

    bn_destroy(tree);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;
}

/* Create a bunch of unique keys, each with three different values (i.e.,
 * with different sequence numbers).  For half the keys, check to see that
 * the higher and lower values still exist and are valid.
 */
void
bonsai_basic_test(enum bonsai_alloc_mode allocm, struct mtf_test_info *lcl_ti)
{
    const int           LEN = 1024 * 1024;
    struct bonsai_root *tree;
    uintptr_t           op_seqno;
    uintptr_t           seqnoref;
    int                 i;
    struct bonsai_skey  skey = { 0 };
    struct bonsai_sval  sval = { 0 };
    struct bonsai_kv *  kv = NULL;
    merr_t              err;
    bool                found;

    init_tree(&tree, allocm);

    for (i = 0; i < LEN; ++i) {
        u64 key = i % 2 ? i : -i;

        op_seqno = 3;
        seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);

        bn_skey_init(&key, sizeof(key), 0, 234, &skey);
        bn_sval_init(&key, sizeof(key), seqnoref, &sval);

        rcu_read_lock();
        err = bn_insert_or_replace(tree, &skey, &sval);
        rcu_read_unlock();

        ASSERT_EQ(0, err);

        op_seqno = 1;
        seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);
        sval.bsv_seqnoref = seqnoref;

        rcu_read_lock();
        err = bn_insert_or_replace(tree, &skey, &sval);
        rcu_read_unlock();

        op_seqno = 2;
        seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);
        sval.bsv_seqnoref = seqnoref;

        rcu_read_lock();
        err = bn_insert_or_replace(tree, &skey, &sval);
        rcu_read_unlock();
    }

    for (i = 0; i < LEN / 2; ++i) {
        struct bonsai_val *v;
        u64                key;
        u64                val;

        key = i % 2 ? i : -i;
        v = NULL;
        op_seqno = 1;
        bn_skey_init(&key, sizeof(key), 0, 234, &skey);

        rcu_read_lock();
        found = bn_find(tree, &skey, &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        v = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, v);
        ASSERT_EQ(op_seqno, HSE_SQNREF_TO_ORDNL(v->bv_seqnoref));
        ASSERT_EQ(sizeof(key), bonsai_val_vlen(v));
        memcpy((char *)&val, v->bv_value, sizeof(val));
        ASSERT_EQ(key, val);
        rcu_read_unlock();

        op_seqno = 3;

        rcu_read_lock();
        found = bn_find(tree, &skey, &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        v = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, v);
        ASSERT_EQ(op_seqno, HSE_SQNREF_TO_ORDNL(v->bv_seqnoref));
        ASSERT_EQ(sizeof(key), bonsai_val_vlen(v));
        memcpy((char *)&val, v->bv_value, sizeof(val));
        ASSERT_EQ(key, val);
        rcu_read_unlock();
    }

    bn_destroy(tree);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;
}

/* Update each value of a single multi-valued key many times, then verify
 * the final result.
 */
void
bonsai_update_test(enum bonsai_alloc_mode allocm, struct mtf_test_info *lcl_ti)
{
    const int           MAX_VALUES = 17;
    const int           LEN = 4003 * MAX_VALUES;
    u64                 op_seqno;
    uintptr_t           seqnoref;
    u64                 value;
    u64                 key;
    int                 i;
    merr_t              err;
    bool                found;
    struct bonsai_root *tree;
    struct bonsai_skey  skey = { 0 };
    struct bonsai_sval  sval = { 0 };
    struct bonsai_kv *  kv = NULL;

    init_tree(&tree, allocm);

    key = 0x900dcafe;
    value = 0;

    for (i = 0; i < LEN; ++i) {
        op_seqno = i % MAX_VALUES;
        seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);
        ++value;

        bn_skey_init(&key, sizeof(key), 0, 23, &skey);
        bn_sval_init(&value, sizeof(value), seqnoref, &sval);

        rcu_read_lock();
        err = bn_insert_or_replace(tree, &skey, &sval);
        rcu_read_unlock();

        ASSERT_EQ(0, err);
    }

    for (i = 0; i < MAX_VALUES; ++i) {
        struct bonsai_val *v;
        u64                val;

        op_seqno = i;

        rcu_read_lock();

        found = bn_find(tree, &skey, &kv);

        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);

        v = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, v);

        ASSERT_EQ(op_seqno, HSE_SQNREF_TO_ORDNL(v->bv_seqnoref));
        ASSERT_EQ(sizeof(value), bonsai_val_vlen(v));
        memcpy((char *)&val, v->bv_value, sizeof(val));
        ASSERT_EQ(LEN - MAX_VALUES + i + 1, val);
        rcu_read_unlock();
    }

    bn_destroy(tree);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;
}

void
bonsai_original_test(enum bonsai_alloc_mode allocm, struct mtf_test_info *lcl_ti)
{
    enum { LEN = 5 };
    struct bonsai_root *tree;
    u64                 keys[LEN];
    struct bonsai_skey  skeys[LEN];
    struct bonsai_skey  skey = { 0 };
    struct bonsai_sval  sval = { 0 };
    int                 i;
    int                 numeric = 0;
    u64                 op_seqno = 343;
    uintptr_t           seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);
    merr_t              err;
    bool                finalize = false;
    bool                found;

    init_tree(&tree, allocm);

    for (i = 0; i < LEN; ++i) {
        u64 key;

        /* Ensure keys are unique and non-consecutive. */
        key = (i << 16) | (bonsai_xrand() & 0xffff);
        if (!numeric)
            key |= 0x6100000000000000;

        keys[i] = key;
        bn_skey_init(&keys[i], sizeof(keys[i]), 0, bonsai_xrand() % 256, &skeys[i]);
        bn_sval_init(&keys[i], sizeof(keys[i]), seqnoref, &sval);

        rcu_read_lock();
        err = bn_insert_or_replace(tree, &skeys[i], &sval);
        rcu_read_unlock();

        ASSERT_EQ(0, err);
    }

    qsort(skeys, LEN, sizeof(struct bonsai_skey), cmpKey);

again:
    for (i = 0; i < LEN; ++i) {
        u64                 key, key0;
        u32                 sz = sizeof(key);
        struct bonsai_kv *  kv;
        struct bonsai_val * pval;
        struct bonsai_skey *next;
        u16                 sid;

        kv = NULL;
        key0 = *(u64 *)skeys[i].bsk_key;

        /* Assumes no two keys are consecutive */
        sid = key_immediate_index(&skeys[i].bsk_key_imm);
        key = decrement_key(key0, numeric);
        bn_skey_init(&key, sizeof(key), 0, sid, &skey);

        rcu_read_lock();
        found = bn_find(tree, &skey, &kv);
        ASSERT_NE(true, found);
        ASSERT_EQ(NULL, kv);

        kv = NULL;
        found = bn_find(tree, &skeys[i], &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        pval = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, pval);
        ASSERT_EQ(0, memcmp(skeys[i].bsk_key, pval->bv_value, sz));

        kv = NULL;
        key = increment_key(key0, numeric);
        bn_skey_init(&key, sizeof(key), 0, sid, &skey);
        found = bn_find(tree, &skey, &kv);
        ASSERT_NE(true, found);
        ASSERT_EQ(NULL, kv);

        kv = NULL;
        key = decrement_key(key0, numeric);
        bn_skey_init(&key, sizeof(key), 0, sid, &skey);
        found = bn_find(tree, &skey, &kv);
        ASSERT_NE(true, found);
        ASSERT_EQ(NULL, kv);

        next = i < LEN - 1 ? (struct bonsai_skey *)&skeys[i + 1] : NULL;

        kv = NULL;
        found = bn_findGE(tree, &skeys[i], &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        pval = findValue(kv, op_seqno, 0);
        ASSERT_EQ(0, memcmp(skeys[i].bsk_key, pval->bv_value, sz));

        kv = NULL;
        key = increment_key(key0, numeric);
        bn_skey_init(&key, sizeof(key), 0, sid, &skey);

        found = bn_findGE(tree, &skey, &kv);
        if (!found) {
            ASSERT_EQ(NULL, next);
        } else {
            ASSERT_EQ(true, found);
            ASSERT_NE(NULL, kv);
            pval = findValue(kv, op_seqno, 0);
            ASSERT_EQ(0, memcmp(next->bsk_key, pval->bv_value, sz));
        }

        next = i > 0 ? (struct bonsai_skey *)&skeys[i - 1] : NULL;

        kv = NULL;
        found = bn_findLE(tree, &skeys[i], &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        pval = findValue(kv, op_seqno, 0);
        ASSERT_EQ(0, memcmp(skeys[i].bsk_key, pval->bv_value, sz));

        kv = NULL;
        key = decrement_key(key0, numeric);
        bn_skey_init(&key, sizeof(key), 0, sid, &skey);

        found = bn_findLE(tree, &skey, &kv);
        if (!found) {
            ASSERT_EQ(NULL, next);
        } else {
            ASSERT_EQ(true, found);
            ASSERT_NE(NULL, kv);
            pval = findValue(kv, op_seqno, 0);
            ASSERT_EQ(0, memcmp(next->bsk_key, pval->bv_value, sz));
        }

        rcu_read_unlock();
    }

    if (!finalize) {
        bn_finalize(tree);
        finalize = true;
        goto again;
    }

    bn_destroy(tree);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, weight, no_fail_pre, no_fail_post)
{
    bonsai_weight_test(HSE_ALLOC_MALLOC, lcl_ti);
    bonsai_weight_test(HSE_ALLOC_CURSOR, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, basic, no_fail_pre, no_fail_post)
{
    bonsai_basic_test(HSE_ALLOC_MALLOC, lcl_ti);
    bonsai_basic_test(HSE_ALLOC_CURSOR, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, update, no_fail_pre, no_fail_post)
{
    bonsai_update_test(HSE_ALLOC_MALLOC, lcl_ti);
    bonsai_update_test(HSE_ALLOC_CURSOR, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, original, no_fail_pre, no_fail_post)
{
    bonsai_original_test(HSE_ALLOC_MALLOC, lcl_ti);
    bonsai_original_test(HSE_ALLOC_CURSOR, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(bonsai_tree_test, complicated, no_fail_pre, no_fail_post)
{
    enum { LEN = 349 };
    u64                 keys[LEN], ord_vals[LEN], key, value;
    u64                 op_seqno;
    uintptr_t           seqnoref;
    struct bonsai_root *tree;
    struct bonsai_val * pval;
    u32                 sz = sizeof(key);
    int                 i, j, rand_num;
    int                 MAX_VALUES_PER_KEY;
    merr_t              err;
    bool                found;

    struct bonsai_skey skey = { 0 };
    struct bonsai_sval sval = { 0 };
    struct bonsai_kv * kv;

    bonsai_xrand_init(0);

    MAX_VALUES_PER_KEY = 1;

    skey.bsk_key = &key;

again:
    init_tree(&tree, HSE_ALLOC_CURSOR);

    for (i = 0; i < LEN; ++i) {
        rand_num = (i << 16) | (bonsai_xrand() & 0xffff);
        key = rand_num | 0x6100000000000000;
        keys[i] = key;
        bn_skey_init(&key, sizeof(key), 0, 143, &skey);
        ord_vals[i] = (rand_num >> 2) + MAX_VALUES_PER_KEY;

        for (j = 1; j <= MAX_VALUES_PER_KEY; j++) {
            if (j % 2)
                op_seqno = ord_vals[i] + j;
            else
                op_seqno = ord_vals[i] - j;

            seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);
            sval.bsv_seqnoref = seqnoref;
            sval.bsv_xlen = 0;

            rcu_read_lock();
            if (op_seqno % 200 == 0) {
                sval.bsv_val = HSE_CORE_TOMB_REG;

                err = bn_insert_or_replace(tree, &skey, &sval);
                ASSERT_EQ(0, err);
            } else if (op_seqno % 500 == 0) {
                sval.bsv_val = HSE_CORE_TOMB_PFX;

                err = bn_insert_or_replace(tree, &skey, &sval);
                ASSERT_EQ(0, err);
            } else {
                value = key - op_seqno;
                sval.bsv_val = (void *)&value;
                sval.bsv_xlen = sizeof(value);

                err = bn_insert_or_replace(tree, &skey, &sval);
                ASSERT_EQ(0, err);
            }
            rcu_read_unlock();
        }
    }

    for (i = 0; i < LEN; ++i) {

        key = keys[i];
        bn_skey_init(&key, sizeof(key), 0, 143, &skey);

        for (j = MAX_VALUES_PER_KEY; j >= 1; j--) {
            if (j % 2)
                op_seqno = ord_vals[i] + j;
            else
                op_seqno = ord_vals[i] - j;

            seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno);

            value = key - op_seqno;

            rcu_read_lock();

            kv = NULL;
            found = bn_find(tree, &skey, &kv);
            ASSERT_EQ(true, found);
            ASSERT_NE(NULL, kv);
            pval = findValue(kv, op_seqno, 0);
            ASSERT_NE(NULL, pval);

            if (op_seqno % 200 == 0) {
                ASSERT_EQ(HSE_CORE_TOMB_REG, pval->bv_value);
                ASSERT_EQ(0, bonsai_val_vlen(pval));
            } else if (op_seqno % 500 == 0) {
                uintptr_t lcl_seqnoref;

                ASSERT_EQ(HSE_CORE_TOMB_PFX, pval->bv_value);
                ASSERT_EQ(0, bonsai_val_vlen(pval));

                lcl_seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno + 2);
                kv = NULL;
                found = bn_find(tree, &skey, &kv);
                ASSERT_EQ(true, found);
                ASSERT_NE(NULL, kv);
                pval = findPfxValue(kv, lcl_seqnoref);
                ASSERT_NE(NULL, pval);
                ASSERT_EQ(
                    HSE_SQNREF_TO_ORDNL(lcl_seqnoref) - 2, HSE_SQNREF_TO_ORDNL(pval->bv_seqnoref));

                lcl_seqnoref = HSE_ORDNL_TO_SQNREF(op_seqno - 2);
                kv = NULL;
                found = bn_find(tree, &skey, &kv);
                ASSERT_EQ(true, found);
                ASSERT_NE(NULL, kv);
                pval = findPfxValue(kv, lcl_seqnoref);
                ASSERT_EQ(NULL, pval);
            } else {
                ASSERT_EQ(0, memcmp((void *)&value, pval->bv_value, sz));
                ASSERT_EQ(op_seqno, HSE_SQNREF_TO_ORDNL(pval->bv_seqnoref));
                ASSERT_EQ(bonsai_val_vlen(pval), sz);
            }
            rcu_read_unlock();
        }

        if (MAX_VALUES_PER_KEY < 8)
            continue;

        rcu_read_lock();
        op_seqno = ord_vals[i];
        kv = NULL;
        found = bn_find(tree, &skey, &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        pval = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, pval);

        /* The insertion loop above produces a collection of values
         * for the key that are almost centered around op_seqno.
         * Those that are larger start at op_seqno + 1 and go up by 2.
         * Those that are smaller start at op_seqno - 2 and go down by
         * 2. As a result, the value we find should have a sequence
         * number that is 2 smaller than op_seqno.
         */
        ASSERT_EQ(op_seqno - 2, HSE_SQNREF_TO_ORDNL(pval->bv_seqnoref));

        if (ord_vals[i] > MAX_VALUES_PER_KEY) {
            /* If we have enough room, then we know that the
             * smallest sequence number for this key is larger
             * than:
             *       ord_vals[i] - MAX_VALUES_PER_KEY - 1
             */
            op_seqno = ord_vals[i] - MAX_VALUES_PER_KEY - 1;
            kv = NULL;
            found = bn_find(tree, &skey, &kv);
            ASSERT_EQ(true, found);
            ASSERT_NE(NULL, kv);
            pval = findValue(kv, op_seqno, 0);
            ASSERT_EQ(NULL, pval);
        }

        /* Similarly we know that the largest sequence number for this
         * key is smaller than:
         *       ord_vals[i] + MAX_VALUES_PER_KEY
         */
        op_seqno = ord_vals[i] + MAX_VALUES_PER_KEY;
        kv = NULL;
        found = bn_find(tree, &skey, &kv);
        ASSERT_EQ(true, found);
        ASSERT_NE(NULL, kv);
        pval = findValue(kv, op_seqno, 0);
        ASSERT_NE(NULL, pval);

        /* W/o changing op_seqno, we know that if the
         * MAX_VALUES_PER_KEY is even then the first delta was on
         * the "+j" side of the insert branch. In that case
         * ord_vals[i] + MAX_VALUES_PER_KEY will be the precise
         * sequence number in the collection of values. Otherwise
         * it will be one larger.
         */
        if (MAX_VALUES_PER_KEY % 2)
            ASSERT_EQ(op_seqno, HSE_SQNREF_TO_ORDNL(pval->bv_seqnoref));
        else
            ASSERT_EQ(op_seqno - 1, HSE_SQNREF_TO_ORDNL(pval->bv_seqnoref));

        rcu_read_unlock();
    }

    bn_destroy(tree);
    broot = NULL;

    cheap_destroy(cheap);
    cheap = NULL;

    if (++MAX_VALUES_PER_KEY < 131)
        goto again;
}

#if 0
/* TODO: Fix me...
 */
static void
set_kv(struct bonsai_kv *k, void *key, size_t len, bool is_ptomb)
{
    k->bkv_flags = 0;
    k->bkv_key_imm.ki_klen = len;
    memcpy(k->bkv_key, key, k->bkv_key_imm.ki_klen);
    if (is_ptomb)
        k->bkv_flags |= BKV_FLAG_PTOMB;
}

#define max_cmp(key1, key1_is_pt, key2, key2_is_pt, res) \
    do {                                                 \
        struct bonsai_kv *kv1, *kv2;                     \
        int               rc;                            \
                                                         \
        kv1 = calloc(1, sizeof(*kv1) + ALLOC_LEN_MAX);   \
        kv2 = calloc(1, sizeof(*kv2) + ALLOC_LEN_MAX);   \
        set_kv(kv1, key1, strlen(key1), key1_is_pt);     \
        set_kv(kv2, key2, strlen(key2), key2_is_pt);     \
                                                         \
        rc = bn_kv_cmp_rev(kv1, kv2);                    \
                                                         \
        if (res < 0)                                     \
            ASSERT_LT(rc, 0);                            \
        else if (res > 0)                                \
            ASSERT_GT(rc, 0);                            \
        else                                             \
            ASSERT_EQ(rc, 0);                            \
        free(kv1);                                       \
        free(kv2);                                       \
    } while (0)

MTF_DEFINE_UTEST(bonsai_tree_test, bn_kv_cmp_test)
{
    /* result (last arg) -
     *  1 : key2 > key1
     * -1 : key1 > key2
     *  0 : key1 == key2
     */
    /* two keys - normal */
    max_cmp("ab1234", false, "ab34", false, 1);
    max_cmp("ab34", false, "ab1234", false, -1);

    max_cmp("ab1234", false, "ab", false, -1);
    max_cmp("ab", false, "ab1234", false, 1);

    /* key w/ ptomb, where keylen > ptomblen */
    max_cmp("ab1234", false, "ab", true, 1);
    max_cmp("ab", true, "ab1234", false, -1);

    /* key w/ ptomb, where keylen < ptomblen */
    max_cmp("a", false, "ab", true, 1);
    max_cmp("ab", true, "a", false, -1);

    /* two ptombs */
    max_cmp("ab", true, "ac", true, 1);

    /* matching key and ptomb */
    max_cmp("ab", true, "ab", false, -1);
    max_cmp("ab", false, "ab", true, 1);
}
#endif

MTF_END_UTEST_COLLECTION(bonsai_tree_test);
