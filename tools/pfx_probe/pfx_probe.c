/*
 * Copyright (C) 2018 Micron Technology, Inc.  All rights reserved.
 */

#include <endian.h>
#include <getopt.h>
#include <libgen.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse_util/timing.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>

#include <xoroshiro/xoroshiro.h>

#include "common.h"
#include "kvs_helper.h"

const char *progname;

struct opts {
	uint npfx;
	uint ncore;
	uint nsfx;
	uint threads;
	uint duration;
	bool use_cursors;
	bool use_gets;
	bool skip_load;
} opts = {
	.npfx = 4,
	.ncore = 100,
	.nsfx = 2,
	.threads = 6,
	.use_cursors = false,
	.use_gets = false,
	.skip_load = false,
	.duration = 30,
};

struct thread_info {
	uint64_t pfx;
	uint64_t core;
	uint64_t sfx;
	uint64_t seed;
};

#define VLEN 1024

enum phase {
	LOAD_PHASE,
	READ_PHASE,
};
enum phase phase;
uint64_t total_puts;
atomic64_t completed_puts;

int err;

static _Thread_local uint64_t xrand_state[2] HSE_ALIGNED(16);

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

void
loader(void *arg)
{
	struct thread_arg  *ta = arg;
	struct thread_info *ti = ta->arg;
	char key[sizeof(ti->pfx) + sizeof(ti->core) + sizeof(ti->sfx)];
	char val[VLEN];
	uint64_t *p, *c, *s;
	int  i, j;
	size_t plen;
        u64 rc;

	rc = hse_kvs_prefix_delete(ta->kvs, 0, 0, 0, &plen);
        if (err)
            fatal(rc, "prefix delete failed");

	if (plen != sizeof(ti->pfx))
		fatal(EINVAL, "kvs must have a pfxlen = %lu", sizeof(ti->pfx));

	memset(val, 0xa1, sizeof(val));

	p = (void *)key;
	c = p + 1;
	s = c + 1;

	*p = htobe64(ti->pfx);
	for (i = 0; i < ti->core; i++) {
		*c = htobe64(i);
		for (j = 0; j < ti->sfx; j++) {
			*s = htobe64(j);
			rc = hse_kvs_put(ta->kvs, 0, key, sizeof(key),
				     val, sizeof(val));
			if (rc)
				fatal(rc, "put failure");

			atomic64_inc(&completed_puts);
		}
	}
}

bool killthreads = false;

atomic64_t rd_count;
atomic64_t rd_time;

enum hse_kvs_pfx_probe_cnt
_pfx_probe(
	struct hse_kvs *kvs,
	void           *pfx,
	size_t          pfxlen,
	void           *kbuf,
	size_t          kbufsz,
	void           *vbuf,
	size_t          vbufsz)
{
	size_t      klen, vlen;
	u64         rc;
	uint64_t    start, dt;

	enum hse_kvs_pfx_probe_cnt  pc;

	start = get_time_ns();

	if (opts.use_cursors) {
		struct hse_kvs_cursor *c;
		const void *k, *v;
		bool eof;

		/* cursor over the hard prefix */
		c = kh_cursor_create(kvs, 0, pfx, 2*sizeof(uint64_t));

		/* seek to soft prefix */
		kh_cursor_seek(c, pfx, pfxlen);

		eof = kh_cursor_read(c, &k, &klen, &v, &vlen);
		if (!eof && memcmp(k, pfx, pfxlen))
			eof = true;
		if (eof) {
			pc = HSE_KVS_PFX_FOUND_ZERO;
			goto done;
		}
		eof = kh_cursor_read(c, &k, &klen, &v, &vlen);
		if (!eof && memcmp(k, pfx, pfxlen))
			eof = true;
		if (eof) {
			pc = HSE_KVS_PFX_FOUND_ONE;
			goto done;
		}

		pc = HSE_KVS_PFX_FOUND_MUL;
done:
		kh_cursor_destroy(c);
	} else if (opts.use_gets) {
		bool found;
		char key[3 * sizeof(uint64_t)] = {0};

		memcpy(key, pfx, pfxlen);

		pc = HSE_KVS_PFX_FOUND_ZERO;
		rc = hse_kvs_get(kvs, 0, key, sizeof(key), &found,
				 vbuf, vbufsz, &vlen);
		if (found)
			pc = HSE_KVS_PFX_FOUND_ONE;
		if (rc)
			fatal(rc, "get failure");
	} else {

		rc = hse_kvs_prefix_probe_exp(kvs, 0, pfx, pfxlen, &pc,
					      kbuf, kbufsz, &klen,
					      vbuf, vbufsz, &vlen);
		if (rc)
			fatal(rc, "prefix probe failure");
	}

	dt = get_time_ns() - start;

	atomic64_inc(&rd_count);
	atomic64_add(dt, &rd_time);

	return pc;
}

void
reader(void *arg)
{
	struct thread_arg  *ta = arg;
	char pfxbuf[2 * sizeof(uint64_t)];
	uint64_t *p, *c;

	xrand_init(ta->seed);

	p = (void *)pfxbuf;
	c = p + 1;

	while (!killthreads) {
		char        kbuf[HSE_KVS_KLEN_MAX] = {0};
		char        vbuf[VLEN];
		uint64_t    pfx, core;

		enum hse_kvs_pfx_probe_cnt pc HSE_MAYBE_UNUSED;

		pfx = xrand() % opts.npfx;
		core = 0;
		if (pfx % 5 > 1)
			core = xrand() % (opts.ncore / 2);

		*p = htobe64(pfx);
		*c = htobe64(core);

		pc = _pfx_probe(ta->kvs, (void *)pfxbuf, sizeof(pfxbuf),
			       kbuf, sizeof(kbuf), vbuf, sizeof(vbuf));

		if (pfx % 5 == 0 && pc != HSE_KVS_PFX_FOUND_ZERO) {
			killthreads = true;
			err = 1;
			printf("pfx %lu expected %d matches %d\n", pfx, 0, pc);
		} else if (pfx % 5 == 1 && pc != HSE_KVS_PFX_FOUND_ONE) {
			killthreads = true;
			err = 1;
			printf("pfx %lu expected %d matches %d\n", pfx, 1, pc);
		} else if (pfx % 5 > 1 && pc != HSE_KVS_PFX_FOUND_MUL) {
			killthreads = true;
			err = 1;
			printf("pfx %lu expected %d matches %d\n", pfx, 2, pc);
		}
	}
}

void
syncme(void *arg)
{
	struct thread_arg  *ta = arg;

	while (!killthreads) {
		hse_kvdb_sync(ta->kvdb);

		usleep(100 * 1000);
	}
}

void
print_stats(void *arg)
{
	uint second = 0;
	uint64_t last_dt = 0;
	uint64_t last_cnt = 0;

	usleep(999 * 1000);

	while (!killthreads) {
		uint64_t dt = atomic64_read(&rd_time);
		uint64_t cnt = atomic64_read(&rd_count) ?: 1;
		uint64_t load_pct = 100;

		if (second % 20 == 0)
			printf("\n%8s %6s %9s %12s\n",
			       "seconds", "load", "reads", "time/probe");

		++second;
		if (phase == LOAD_PHASE) {
			load_pct = atomic64_read(&completed_puts) * 100;
			load_pct /= total_puts ?: 1;
		}

		printf("%8u %5lu%% %9lu %12lu\n",
		       second, load_pct, cnt,
		       (dt - last_dt)/(1 + cnt - last_cnt));
		usleep(999 * 1000);

		last_dt = dt;
		last_cnt = cnt;
	}
}

void
usage(void)
{
	printf(
		"usage: %s [options] kvdb kvs [param=value]\n"
		"-c nvar  Number of core (middle portion of key) variations "
		"per hard prefix\n"
		"-d secs  Duration of run (in seconds)\n"
		"-g       Use gets (in addition to -v)\n"
		"-j jobs  Number of threads\n"
		"-p npfx  Hard prefixes\n"
		"-s nsfx  Suffixes per soft prefix\n"
		"-v       Only verify (default: use hse_kvs_prefix_probe)\n"
		"-x       Use cursors (in addition to -v)\n"
		, progname);

	printf("\n");
	exit(0);
}

int
main(
	int       argc,
	char    **argv)
{
	struct hse_params  *params;
	const char         *mpool, *kvs;
	struct thread_info *ti;
	char                c;
	int                 i;

	progname = basename(argv[0]);
        xrand_init(time(NULL));

	while ((c = getopt(argc, argv, "gvxd:j:p:c:s:")) != -1) {
		errno = 0;
		switch (c) {
		case 'p':
			opts.npfx = strtoul(optarg, 0, 0);
			break;
		case 'c':
			opts.ncore = strtoul(optarg, 0, 0);
			break;
		case 's':
			opts.nsfx = strtoul(optarg, 0, 0);
			if (opts.nsfx < 3)
				fatal(EINVAL, "nsfx must be at least 3");
			break;
		case 'j':
			opts.threads = strtoul(optarg, 0, 0);
			break;
		case 'x':
			opts.use_cursors = true;
			break;
		case 'g':
			opts.use_gets = true;
			break;
		case 'v':
			opts.skip_load = true;
			break;
		case 'd':
			opts.duration = strtoul(optarg, 0, 0);
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}

	hse_params_create(&params);

	kh_rparams(&argc, &argv, params);
	if (argc != 2) {
		hse_params_destroy(params);
		fatal(EINVAL, "Incorrect number of arguments");
	}

	mpool = argv[0];
	kvs   = argv[1];

	kh_init(mpool, params);

	kh_register(0, KH_FLAG_DETACH, 0, syncme, 0);
	kh_register(0, KH_FLAG_DETACH, 0, print_stats, 0);

	if (opts.skip_load)
		goto skip_load;

	ti = malloc(opts.npfx * sizeof(*ti));
	if (!ti)
		fatal(ENOMEM, "no mem");

	printf("Loading %lu keys ...\n", total_puts);

	phase = LOAD_PHASE;
	for (i = 0; i < opts.npfx; i++) {
		ti[i].pfx = i;
		ti[i].core = opts.ncore;
		ti[i].seed = xrand();

		switch (i % 5) {
		case 0:
			ti[i].sfx = 0;
			break;
		case 1:
			ti[i].sfx = 1;
			break;
		default:
			ti[i].sfx = opts.nsfx;
			break;
		}

		total_puts += ti[i].core * ti[i].sfx;
	}

	for (i = 0; i < opts.npfx; i++)
		kh_register(kvs, 0, params, loader, &ti[i]);
	kh_wait();

	free(ti);

skip_load:
	phase = READ_PHASE;
	for (i = 0; i < opts.threads; i++)
		kh_register(kvs, 0, params, reader, 0);

	sleep(opts.duration);
	killthreads = true;
	kh_wait();

	kh_fini();

	hse_params_destroy(params);

	return err;
}
