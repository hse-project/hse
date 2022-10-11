/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <endian.h>
#include <errno.h>
#include <stdio.h>
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

#define SFX "AA"

const char *progname;
volatile bool completed;
int completed_cnt = 0;

atomic_long opcnt;

enum run_mode {
	MODE_PFX_PROBE,
	MODE_POINT_GET,
	MODE_CURSOR,
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
    unsigned int laps;
} test_ctx;

void
upsert(void *arg)
{
    struct kh_thread_arg *targ = arg;
    char kbuf[HSE_KVS_KEY_LEN_MAX] = { 0 };
    char vbuf[HSE_KVS_VALUE_LEN_MAX] = { 0 };
    hse_err_t err = 0;
    unsigned int laps;
    unsigned long ops = 0;
    uint32_t sfxlen = strlen(SFX);

    while (1) {
        uint64_t start, end;

        mutex_lock(&test_ctx.lock);

        start = test_ctx.startidx;
        test_ctx.startidx = end = start + opts.stride;

        laps = test_ctx.laps;
        if (laps == opts.laps) {
            mutex_unlock(&test_ctx.lock);
            break;
        }

        if (test_ctx.startidx > opts.nkeys) {
            test_ctx.startidx = 0;
            end = opts.nkeys;

            test_ctx.laps++;
        }

        mutex_unlock(&test_ctx.lock);

        for (uint64_t i = start; i < end; i++) {
            size_t klen, vlen;

            klen = snprintf(kbuf, sizeof(kbuf), "key.%032lu%s", i, SFX);

            // TODO Gaurav: Do something with vbuf

#if 0
            {
                bool found;
                err = hse_kvs_get(targ->kvs, 0, 0, kbuf, klen, &found, vbuf, sizeof(vbuf), &vlen);
                if (!found)
                    vlen = snprintf(vbuf, sizeof(vbuf), "val.%032lu", i);
            }
#endif
#if 1
            {
                enum hse_kvs_pfx_probe_cnt found;
                char kbuf_out[HSE_KVS_KEY_LEN_MAX] = { 0 };
                size_t klen_out;

                err = hse_kvs_prefix_probe(targ->kvs, 0, 0, kbuf, klen - sfxlen, &found,
                                           kbuf_out, sizeof(kbuf_out), &klen_out,
                                           vbuf, sizeof(vbuf), &vlen);
                if (found == HSE_KVS_PFX_FOUND_ZERO)
                    vlen = snprintf(vbuf, sizeof(vbuf), "val.%032lu", i);

                assert(found != HSE_KVS_PFX_FOUND_ZERO || laps == 0);
            }
#endif
#if 0
            {
                struct hse_kvs_cursor *c;

                err = hse_kvs_cursor_create(targ->kvs, 0, 0, 0, 0, &c);
                if (err)
                    fatal(err, "Cursor create failed");

                err = hse_kvs_cursor_seek(c, 0, kbuf, klen, 0, 0);
                if (err)
                    fatal(err, "Cursor seek failed");

                const void *k, *v;
                bool eof;

                err = hse_kvs_cursor_read(c, 0, &k, &klen, &v, &vlen, &eof);
                if (err)
                    fatal(err, "Cursor read failed");

                if (eof)
                    vlen = snprintf(vbuf, sizeof(vbuf), "val.%032lu", i);

                assert(!eof || laps == 0);

                hse_kvs_cursor_destroy(c);
            }
#endif

            if (err)
                fatal(err, "Get failure");

            err = hse_kvs_put(targ->kvs, 0, 0, kbuf, klen, vbuf, vlen);
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

    while (!completed) {
        curr_opcnt = atomic_read(&opcnt);

        if (second++ % 20 == 0) {
            printf("\n%8s %12s %8s %8s\n", "seconds", "opcnt", "ops/s", "lap");
        }

        printf("%8u %12lu %8lu %8u\n", second, curr_opcnt, curr_opcnt - last_opcnt, test_ctx.laps);

        last_opcnt = curr_opcnt;
        usleep(999 * 1000);
    }
}

int
main(int argc, char **argv)
{
	struct parm_groups *pg = 0;
	struct svec hse_gparms = { 0 };
	struct svec kvdb_oparms = { 0 };
	struct svec kvs_cparms = { 0 };
	struct svec kvs_oparms = { 0 };
    const char *kvdbhome, *kvsname;
    char sfx_param_buf[32];
    int rc;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

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

    snprintf(sfx_param_buf, sizeof(sfx_param_buf), "kvs_sfx_len=%lu", strlen(SFX));
    rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, sfx_param_buf, NULL);
    if (rc) {
        fprintf(stderr, "svec_append_pg failed: %d", rc);
        exit(EX_USAGE);
    }

    // TODO Gaurav: Replace NULL with -Z config's config

    mutex_init(&test_ctx.lock);
    kh_init(NULL, kvdbhome, &hse_gparms, &kvdb_oparms);

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
