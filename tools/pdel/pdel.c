#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hse/hse.h>

#include <hse_util/hse_params_helper.h>

#include <tools/common.h>

#define PFXLEN          2
#define NUM_PFX         4
#define THREADS_PER_PFX 16
#define NUM_THREADS     (NUM_PFX * THREADS_PER_PFX)

char *progname;

struct opt {
    uint64_t count;
    size_t   klen;
    bool     sync;
    bool     txn;
    bool     rev;
    bool     upd;
    bool     load;
    int      help;
} opt;

struct test {
    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;
} test;

struct thread_info {
    pthread_t tid;
    char      pfx[HSE_KVS_MAX_PFXLEN];
    uint64_t  start;
    uint64_t  end;
};

void *
put_keys(void *arg)
{
    struct thread_info *ti = arg;
    uint8_t             key[HSE_KVS_KLEN_MAX];
    int                 rc;
    uint64_t            i;
    uint8_t *           suffix = key + PFXLEN;
    size_t              suffix_len = opt.klen - PFXLEN;
    char                one = '1';

    memcpy(key, ti->pfx, PFXLEN);

    for (i = ti->start; i < ti->end; i++) {
        sprintf((char *)suffix, "%0*lu", (int)suffix_len, i);
        rc = hse_kvs_put(test.kvs, 0, key, opt.klen, &one, 1);
        if (rc)
            fatal(rc, "hse_kvs_put failed");
    }

    return 0;
}

static int
cursor_create(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            pfx,
    size_t                  pfxlen,
    struct hse_kvs_cursor **cur)
{
    int rc, attempts = 5;

try_again:
    rc = (*cur) ? hse_kvs_cursor_update(*cur, os)
                : hse_kvs_cursor_create(test.kvs, os, pfx, PFXLEN, cur);

    if (rc != EAGAIN)
        return rc;

    if (attempts-- == 0)
        return rc;

    printf("Retrying cursor create\n");
    sleep(1);
    goto try_again;
}

static int errs;

void *
verify_keys(void *arg)
{
    char *                 pfx = (char *)arg;
    uint64_t               i, found;
    struct hse_kvs_cursor *cur;
    uint8_t                kbuf[HSE_KVS_KLEN_MAX];
    uint8_t *              suffix = kbuf + PFXLEN;
    size_t                 suffix_len = opt.klen - PFXLEN;
    uint64_t               last;
    int                    first;
    int                    second;
    int                    rc;
    char *                 key, *val;
    size_t                 klen, vlen;
    struct hse_kvdb_opspec os;
    size_t                 tot_keys = 2 * opt.count;
    bool                   eof;

    first = second = 0;
    if (strncmp(pfx, "AA", PFXLEN) == 0)
        first = second = 1;
    else if (strncmp(pfx, "AB", PFXLEN) == 0)
        second = 1;
    else if (strncmp(pfx, "AD", PFXLEN) == 0)
        first = second = 1;

    if (opt.rev) {
        int tmp;

        tmp = first;
        first = second;
        second = tmp;
    }

    HSE_KVDB_OPSPEC_INIT(&os);

    memcpy(kbuf, pfx, PFXLEN);

    if (opt.rev)
        os.kop_flags |= HSE_KVDB_KOP_FLAG_REVERSE;

    cur = 0; /* this will create a new cursor as opposed to updating one */
    rc = cursor_create(test.kvs, &os, pfx, PFXLEN, &cur);
    if (rc)
        fatal(rc, "pfx %s: cannot create cursor", pfx);

    if (!first && !second) {
        bool eof;

        rc = hse_kvs_cursor_read(
            cur, 0, (const void **)&key, &klen, (const void **)&val, &vlen, &eof);
        if (rc)
            fatal(rc, "pfx %s: read failure", pfx);

        if (!eof)
            fprintf(
                stderr,
                "pfx %s: Expected no keys. Found "
                "some\n",
                pfx);
        hse_kvs_cursor_destroy(cur);

        return 0;
    }

    found = 0;
    last = opt.count;
    if (first) {
        for (i = 0; i < last; i++) {
            size_t idx = i;

            if (opt.rev)
                idx = tot_keys - i - 1;

            sprintf((char *)suffix, "%0*lu", (int)suffix_len, idx);

            rc = hse_kvs_cursor_read(
                cur, 0, (const void **)&key, &klen, (const void **)&val, &vlen, &eof);
            if (rc)
                fatal(rc, "pfx %s: read failure", pfx);
            if (eof) {
                fprintf(stderr, " error : Premature eof\n");
                break;
            }

            if (klen != opt.klen)
                fprintf(stderr, "pfx: %s: (i) klen mismatch\n", pfx);

            if (memcmp(kbuf, key, klen) != 0) {
                errs++;
                fprintf(
                    stderr,
                    "pfx: %s: (i) key mismatch: %s\t"
                    "expected %s\n",
                    pfx,
                    key,
                    kbuf);
                return 0;
            }

            found++;
        }

        if (found != opt.count) {
            errs++;
            fprintf(stderr, "pfx %s: phase i: expected %lu found %lu\n", pfx, opt.count, found);
        }
    }

    if (opt.upd) {
        rc = cursor_create(test.kvs, &os, pfx, PFXLEN, &cur);
        if (rc)
            fatal(rc, "pfx %s: cannot update cursor", pfx);

        rc = hse_kvs_cursor_seek(cur, 0, kbuf, first ? opt.klen : PFXLEN, 0, 0);
        if (rc)
            fatal(rc, "pfx %s: cannot seek cursor", pfx);
        if (first) {
            rc = hse_kvs_cursor_read(
                cur, 0, (const void **)&key, &klen, (const void **)&val, &vlen, &eof);
            if (rc)
                fatal(rc, "pfx %s: read failure", pfx);
        }
    }

    found = 0;
    last = tot_keys;
    if (second) {
        for (i = opt.count; i < last; i++) {
            int    rc;
            size_t idx = i;

            if (opt.rev)
                idx = tot_keys - i - 1;

            sprintf((char *)suffix, "%0*lu", (int)suffix_len, idx);

            rc = hse_kvs_cursor_read(
                cur, 0, (const void **)&key, &klen, (const void **)&val, &vlen, &eof);
            if (rc)
                fatal(rc, "pfx %s: read failure", pfx);
            if (eof) {
                fprintf(stderr, " error : Premature eof\n");
                break;
            }

            if (klen != opt.klen)
                fprintf(stderr, "pfx: %s: (ii) klen mismatch\n", pfx);

            if (memcmp(kbuf, key, klen) != 0) {
                errs++;
                fprintf(
                    stderr,
                    "pfx: %s: (ii) key mismatch: %s\t"
                    "expected %s\n",
                    pfx,
                    key,
                    kbuf);
                return 0;
            }

            found++;
        }

        if (found != opt.count) {
            errs++;
            fprintf(stderr, "pfx %s: phase ii: expected %lu found %lu\n", pfx, opt.count, found);
        }
    }

    hse_kvs_cursor_destroy(cur);

    return 0;
}

void
verify_kvs(struct thread_info *ti)
{
    int       i;
    pthread_t tid[NUM_PFX];

    for (i = 0; i < NUM_PFX; i++) {
        int pfxid = i * THREADS_PER_PFX;

        printf("Verifying %2s\n", ti[pfxid].pfx);
        pthread_create(&tid[i], 0, verify_keys, ti[pfxid].pfx);
    }

    for (i = 0; i < NUM_PFX; i++)
        pthread_join(tid[i], 0);
}

int
usage(void)
{
    printf(
        "%s [options] <kvdb> <kvs>\n"
        "options:\n"
        "-c keys  number of keys used in each phase\n"
        "-k klen  key length to use\n"
        "-l       load keys\n"
        "-s       sync after phase 1\n"
        "-t       use transactions\n"
        "-u       update cursor between the 2 phases\n",
        progname);

    return 1;
}

void
do_params(int *argc, char ***argv, struct hse_params *params)
{
    int idx = optind;

    hse_params_set(params, "kvdb.perfc_enable", "0");

    if (hse_parse_cli(*argc - idx, *argv + idx, &idx, 0, params))
        rp_usage();

    *argc -= idx;
    *argv += idx;
    optind = 0;
}

int
main(int argc, char **argv)
{
    int                    i, rc;
    char *                 mpname, *kvsname;
    struct thread_info     ti[NUM_THREADS] = {};
    char                   c;
    uint64_t               stride;
    struct hse_kvdb_txn *  txn = 0;
    struct hse_kvdb_opspec op;
    struct hse_params *    params;

    opt.count = 1000;
    opt.klen = 10;
    opt.sync = false;
    opt.load = false;

    progname = basename(argv[0]);

    while ((c = getopt(argc, argv, "lhc:k:rstu")) != -1) {
        switch (c) {
            case 's':
                opt.sync = true;
                break;
            case 'k':
                opt.klen = (unsigned)strtoul(optarg, 0, 0);
                break;
            case 'c':
                opt.count = (unsigned)strtoull(optarg, 0, 0);
                break;
            case 't':
                opt.txn = true;
                break;
            case 'r':
                opt.rev = true;
                break;
            case 'u':
                opt.upd = true;
                break;
            case 'l':
                opt.load = true;
                break;
            case 'h': /* fallthru */
            default:
                opt.help++;
                break;
        }
    }

    if (opt.help)
        return usage();

    rc = hse_kvdb_init();
    if (rc)
        fatal(rc, "failed to initialize kvdb");

    HSE_KVDB_OPSPEC_INIT(&op);

    hse_params_create(&params);

    do_params(&argc, &argv, params);

    mpname = argv[optind++];
    kvsname = argv[optind++];

    if (opt.klen <= PFXLEN)
        return 1;

    if (pow(10, (opt.klen - PFXLEN)) < opt.count) {
        fprintf(
            stderr,
            "suffix len (keylen - pfxlen) too short to "
            "accommodate %lu keys\n",
            opt.count);
        return 1;
    }

    if (opt.count % NUM_THREADS != 0)
        fatal(EINVAL, "count should be a multiple of thread count(64)");

    rc = hse_kvdb_open(mpname, params, &test.kvdb);
    if (rc)
        fatal(rc, "hse_kvdb_open failed");

    rc = hse_kvdb_kvs_open(test.kvdb, kvsname, params, &test.kvs);
    if (rc)
        fatal(rc, "hse_kvdb_kvs_open failed");

    if (opt.txn) {
        txn = hse_kvdb_txn_alloc(test.kvdb);
        if (!txn)
            fatal(ENOMEM, "cannot allocate a txn");
    }

    stride = opt.count / THREADS_PER_PFX;
    /* thread setup */
    for (i = 0; i < NUM_THREADS; i++) {
        memset(ti[i].pfx, 'A', PFXLEN);
        ti[i].pfx[PFXLEN - 1] = 'A' + (i / THREADS_PER_PFX);

        ti[i].start = (i % THREADS_PER_PFX) * stride;
        ti[i].end = ti[i].start + stride;
    }

    if (opt.txn) {
        rc = hse_kvdb_txn_begin(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn begin failed");

        op.kop_txn = txn;
    }

    rc = hse_kvs_prefix_delete(test.kvs, &op, "AA", PFXLEN, 0);
    if (rc)
        fatal(rc, "could not delete prefix %s\n", "AA");

    if (opt.txn) {
        rc = hse_kvdb_txn_commit(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn commit failed");
    }

    /* Phase I */
    fprintf(stdout, "Loading. Phase I...\n");
    for (i = 0; i < NUM_THREADS; i++) {
        rc = pthread_create(&ti[i].tid, 0, put_keys, &ti[i]);
        if (rc)
            fatal(rc, "pthread_create failed");
    }

    for (i = 0; i < NUM_THREADS; i++)
        pthread_join(ti[i].tid, 0);

    if (opt.sync)
        hse_kvdb_sync(test.kvdb);

    if (opt.txn) {
        rc = hse_kvdb_txn_begin(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn begin failed");

        op.kop_txn = txn;
    }

    rc = hse_kvs_prefix_delete(test.kvs, &op, "AB", PFXLEN, 0);
    if (rc)
        fatal(rc, "could not delete prefix AB\n");

    if (opt.txn) {
        rc = hse_kvdb_txn_commit(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn commit failed");
    }

    for (i = 0; i < NUM_THREADS; i++) {
        ti[i].start += opt.count;
        ti[i].end += opt.count;
    }

    /* Phase II */
    fprintf(stdout, "Loading. Phase II...\n");
    for (i = 0; i < NUM_THREADS; i++) {
        rc = pthread_create(&ti[i].tid, 0, put_keys, &ti[i]);
        if (rc)
            fatal(rc, "pthread_create failed");
    }

    for (i = 0; i < NUM_THREADS; i++)
        pthread_join(ti[i].tid, 0);

    if (opt.txn) {
        rc = hse_kvdb_txn_begin(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn begin failed");

        op.kop_txn = txn;
    }

    rc = hse_kvs_prefix_delete(test.kvs, &op, "AC", PFXLEN, 0);
    if (rc)
        fatal(rc, "could not delete prefix AC\n");

    if (opt.txn) {
        rc = hse_kvdb_txn_commit(test.kvdb, txn);
        if (rc)
            fatal(rc, "txn commit failed");
    }

    /* Verify */

    if (!opt.load) {
        fprintf(stdout, "Verifying keys...\n");
        verify_kvs(ti);
    }

    if (errs)
        printf("err\n");

    hse_kvdb_txn_free(test.kvdb, txn);
    hse_kvdb_close(test.kvdb);

    hse_params_destroy(params);

    hse_kvdb_fini();

    return 0;
}
