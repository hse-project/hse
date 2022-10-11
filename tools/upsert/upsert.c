/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sysexits.h>
#include <pthread.h>

#include <hse_util/mutex.h>
#include <hse_util/atomic.h>

#include <hse/hse.h>
#include <hse/experimental.h>

#include <xoroshiro.h>

#include <hse/cli/param.h>

#include "kvs_helper.h"

const char *key_suffix = "AA";
size_t key_sfxlen;

const char *progname;
volatile bool completed;
atomic_int completed_cnt;

atomic_long opcnt;

enum run_mode {
	MODE_PFX_PROBE = 0,
	MODE_POINT_GET,
	MODE_CURSOR,
	MODE_CNT,
};

struct opts {
	uint64_t      nkeys;
	uint64_t      stride;
	unsigned int  nthreads;
	unsigned int  laps;
	enum run_mode mode;
} opts = {
	.nkeys = 1000 * 1000 * 1000,
	.stride = 100,
	.nthreads = 32,
	.laps = 3,
	.mode = MODE_PFX_PROBE,
};

struct _test_ctx {
    struct mutex lock;
    uint64_t     startidx;
    unsigned int curr_lap;
} test_ctx;

struct probe_ctx {
    char kbuf[HSE_KVS_KEY_LEN_MAX];
    char vbuf[HSE_KVS_VALUE_LEN_MAX];
    size_t klen;
    size_t vlen;
};

bool
(*probe)(struct hse_kvs *, struct probe_ctx *);

bool
point_get(struct hse_kvs *kvs, struct probe_ctx *pc)
{
    hse_err_t err;
    bool found;

    err = hse_kvs_get(kvs, 0, 0, pc->kbuf, pc->klen, &found,
                      pc->vbuf, sizeof(pc->vbuf), &pc->vlen);
    if (err)
        fatal(err, "Point get failed");

    return found;
}

bool
prefix_probe(struct hse_kvs *kvs, struct probe_ctx *pc)
{
    hse_err_t err;
    enum hse_kvs_pfx_probe_cnt found;

    err = hse_kvs_prefix_probe(kvs, 0, 0, pc->kbuf, pc->klen - key_sfxlen, &found,
                               pc->kbuf, sizeof(pc->kbuf), &pc->klen,
                               pc->vbuf, sizeof(pc->vbuf), &pc->vlen);
    if (err)
        fatal(err, "Prefix probe failed");

    return (found != HSE_KVS_PFX_FOUND_ZERO);
}

bool
cursor_probe(struct hse_kvs *kvs, struct probe_ctx *pc)
{
    hse_err_t err;
    struct hse_kvs_cursor *c;
    bool eof;

    err = hse_kvs_cursor_create(kvs, 0, 0, 0, 0, &c);
    if (err)
        fatal(err, "Cursor create failed");

    err = hse_kvs_cursor_seek(c, 0, pc->kbuf, pc->klen - key_sfxlen, 0, 0);
    if (err)
        fatal(err, "Cursor seek failed");

    err = hse_kvs_cursor_read_copy(c, 0, pc->kbuf, sizeof(pc->kbuf), &pc->klen,
                                   pc->vbuf, sizeof(pc->vbuf), &pc->vlen, &eof);
    if (err)
        fatal(err, "Cursor read failed");

    hse_kvs_cursor_destroy(c);

    return !eof;
}

void
upsert(void *arg)
{
    struct kh_thread_arg *targ = arg;
    hse_err_t err = 0;
    unsigned int curr_lap HSE_MAYBE_UNUSED;
    unsigned long ops = 0;
    char tname[32];

    while (1) {
        uint64_t start, end;

        mutex_lock(&test_ctx.lock);

        start = test_ctx.startidx;
        end = start + opts.stride;

        if (test_ctx.curr_lap == opts.laps) {
            mutex_unlock(&test_ctx.lock);
            break;
        }

        test_ctx.startidx = end;
        curr_lap = test_ctx.curr_lap;

        if (test_ctx.startidx > opts.nkeys) {
            test_ctx.startidx = 0;
            end = opts.nkeys;

            test_ctx.curr_lap++;
        }

        mutex_unlock(&test_ctx.lock);

        snprintf(tname, sizeof(tname), "upsert-%lu", start);
        pthread_setname_np(pthread_self(), tname);

        for (uint64_t i = start; i < end; i++) {
            struct probe_ctx pc;
            bool found;

            pc.klen = snprintf(pc.kbuf, sizeof(pc.kbuf), "key.%032lu%s", i, key_suffix);

            found = probe(targ->kvs, &pc);
            if (!found) {
                pc.vlen = snprintf(pc.vbuf, sizeof(pc.vbuf), "val.%032lu", i);
                assert(curr_lap == 0);
            }

            err = hse_kvs_put(targ->kvs, 0, 0, pc.kbuf, pc.klen, pc.vbuf, pc.vlen);
            if (err)
                fatal(err, "Put failure");

            if (++ops % 128 == 0) {
                atomic_add(&opcnt, ops);
                ops = 0;
            }
        }
    }

    atomic_add(&opcnt, ops);

    if (atomic_inc_return(&completed_cnt) == opts.nthreads)
        completed = true;
}

void
print_stats(void *arg)
{
    uint32_t second = 0;
    uint64_t curr_opcnt, last_opcnt = 0;

    pthread_setname_np(pthread_self(), __func__);

    while (!completed) {
        curr_opcnt = atomic_read(&opcnt);

        if (second++ % 20 == 0) {
            printf("\n%8s %12s %8s %8s\n", "seconds", "opcnt", "ops/s", "lap");
        }

        printf("%8u %12lu %8lu %8u\n", second, curr_opcnt, curr_opcnt - last_opcnt, test_ctx.curr_lap);

        last_opcnt = curr_opcnt;
        usleep(999 * 1000);
    }
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
        "-c nkeys   Number of keys\n"
        "-h         Print help\n"
        "-j nth     Number of threads\n"
        "-l laps    Insert all keys $laps times\n"
        "-m mode    Mode (default=0)\n"
        "             0: Use prefix probe\n"
        "             1: Use point get\n"
        "             2: Use cursor\n"
        "-s stride  Batch size of keys processed by each thread\n"
        "-Z config  Path to global config file\n"
        , progname);

    printf("\n");
}

int
main(int argc, char **argv)
{
	struct parm_groups *pg = 0;
	struct svec hse_gparms = { 0 };
	struct svec kvdb_oparms = { 0 };
	struct svec kvs_cparms = { 0 };
	struct svec kvs_oparms = { 0 };
    const char *kvdbhome, *kvsname, *config = NULL;
    char sfx_param_buf[32];
    int c, rc;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

    while ((c = getopt(argc, argv, ":c:hj:l:m:s:Z:")) != -1) {
        char *errmsg = NULL, *end = NULL;

        errno = 0;
        switch (c) {
        case 'c':
            opts.nkeys = strtoul(optarg, &end, 0);
            errmsg = "invalid number of keys";
            break;
        case 'h':
            usage();
            exit(0);
        case 'j':
            opts.nthreads = strtoul(optarg, &end, 0);
            errmsg = "invalid number of threads";
            break;
        case 'l':
            opts.laps = strtoul(optarg, &end, 0);
            errmsg = "invalid number of laps";
            break;
        case 'm':
            opts.mode = strtoul(optarg, &end, 0);
            errmsg = "invalid mode";

            if (opts.mode < 0 || opts.mode > MODE_CNT)
                errno = EINVAL;
            else if (opts.mode == MODE_PFX_PROBE)
                probe = prefix_probe;
            else if (opts.mode == MODE_POINT_GET)
                probe = point_get;
            else if (opts.mode == MODE_CURSOR)
                probe = cursor_probe;
            else
                errno = EINVAL;

            break;
        case 's':
            opts.stride = strtoul(optarg, &end, 0);
            errmsg = "invalid stride count";
            break;
        case 'Z':
            config = optarg;
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

    if (argc - optind < 2)
        fatal(0, "missing required parameter\nuse -h for help");

    kvdbhome = argv[optind++];
    kvsname = argv[optind++];

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

    snprintf(sfx_param_buf, sizeof(sfx_param_buf), "kvs_sfx_len=%lu", strlen(key_suffix));
    rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, sfx_param_buf, NULL);
    if (rc) {
        fprintf(stderr, "svec_append_pg failed: %d", rc);
        exit(EX_USAGE);
    }

    atomic_set(&completed_cnt, 0);
    mutex_init(&test_ctx.lock);
    key_sfxlen = strlen(key_suffix);

    kh_init(config, kvdbhome, &hse_gparms, &kvdb_oparms);

    for (unsigned int i = 0; i < opts.nthreads; i++)
        kh_register_kvs(kvsname, 0, &kvs_cparms, &kvs_oparms, &upsert, NULL);

    kh_register(0, &print_stats, NULL);

    kh_wait();
    kh_fini();

    svec_reset(&hse_gparms);
    svec_reset(&kvdb_oparms);
    svec_reset(&kvs_cparms);
    svec_reset(&kvs_oparms);
    pg_destroy(pg);

	return 0;
}
