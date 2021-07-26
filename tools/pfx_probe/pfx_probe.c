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

#include <cli/param.h>

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

static thread_local uint64_t xrand_state[2] HSE_ALIGNED(16);

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

	rc = hse_kvs_prefix_delete(ta->kvs, 0, NULL, 0, 0, &plen);
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
			rc = hse_kvs_put(ta->kvs, 0, NULL, key, sizeof(key),
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
		c = kh_cursor_create(kvs, 0, NULL, pfx, sizeof(uint64_t));

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
        uint64_t *s;

		memcpy(key, pfx, pfxlen);
        s = (uint64_t *)(key + pfxlen);

		pc = HSE_KVS_PFX_FOUND_ZERO;
		rc = hse_kvs_get(kvs, 0, NULL, key, sizeof(key), &found,
				 vbuf, vbufsz, &vlen);
		if (rc)
			fatal(rc, "get failure");
		if (found)
			pc = HSE_KVS_PFX_FOUND_ONE;

        *s = htobe64(1);
		rc = hse_kvs_get(kvs, 0, NULL, key, sizeof(key), &found,
				 vbuf, vbufsz, &vlen);
		if (rc)
			fatal(rc, "get failure");
		if (found)
			pc = HSE_KVS_PFX_FOUND_MUL;
	} else {

		rc = hse_kvs_prefix_probe(kvs, 0, NULL, pfx, pfxlen, &pc,
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
		char        kbuf[HSE_KVS_KEY_LEN_MAX] = {0};
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
			printf("pfx %lu expected %d found %d\n", pfx, 0, pc);
		} else if (pfx % 5 == 1 && pc != HSE_KVS_PFX_FOUND_ONE) {
			killthreads = true;
			err = 1;
			printf("pfx %lu expected %d found %d\n", pfx, 1, pc);
		} else if (pfx % 5 > 1 && pc != HSE_KVS_PFX_FOUND_MUL) {
			killthreads = true;
			err = 1;
			printf("pfx %lu expected %d found %d\n", pfx, 2, pc);
		}
	}
}

void
syncme(void *arg)
{
	struct thread_arg  *ta = arg;

	while (!killthreads) {
		hse_kvdb_sync(ta->kvdb, 0);

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
	struct parm_groups *pg = NULL;
	struct svec         hse_gparms = { 0 };
	struct svec         db_oparms = { 0 };
	struct svec         kv_cparms = { 0 };
	struct svec         kv_oparms = { 0 };
	const char         *mpool, *kvs;
	struct thread_info *ti;
	char                c;
	int                 i;
	int                 rc;

	progname = basename(argv[0]);
        xrand_init(time(NULL));

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

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


	if (argc - optind < 2) {
		fprintf(stderr, "missing required parameters");
		exit(EX_USAGE);
	}

	mpool = argv[optind++];
	kvs   = argv[optind++];

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
	rc = rc ?: svec_append_pg(&db_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kv_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kv_oparms, pg, PG_KVS_OPEN, NULL);
	if (rc)
		fatal(rc, "svec_append_pg failed");

	kh_init(mpool, &hse_gparms, &db_oparms);

	kh_register(KH_FLAG_DETACH, syncme, NULL);
	kh_register(KH_FLAG_DETACH, print_stats, NULL);

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
		kh_register_kvs(kvs, 0, &kv_cparms, &kv_oparms, loader, &ti[i]);
	kh_wait();

	free(ti);

skip_load:
	phase = READ_PHASE;
	for (i = 0; i < opts.threads; i++)
		kh_register_kvs(kvs, 0, &kv_cparms, &kv_oparms, reader, 0);

	sleep(opts.duration);
	killthreads = true;
	kh_wait();

	kh_fini();

    svec_reset(&db_oparms);
    svec_reset(&kv_cparms);
    svec_reset(&kv_oparms);

	pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&db_oparms);
	svec_reset(&kv_cparms);
	svec_reset(&kv_oparms);

	return err;
}
