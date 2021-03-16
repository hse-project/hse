/*
 * Copyright (C) 2018 Micron Technology, Inc.  All rights reserved.
 *
 * This test emulates the behavior of a capped kvs.
 *
 * This test consists of
 * 1. Writer threads: add keys to the kvs
 * 2. Reader threads: read keys from the kvs  in the same order in which they
 *                    were added.
 * 3. pfx del thread: This thread maintains a cap of a certain number of
 *                    prefixes in the kvs
 * 4. sync thread:    This thread sleeps for a second and then syncs the
 *                    contents on the kvdb to media.
 *
 * Each writer thread performs the following operations in a loop:
 *   1. picks up a global prefix and a global suffix and constructs its key.
 *   2. In a txn, puts this key into the kvs.
 *
 * All writer threads atomically increment and read the suffix thus ensuring
 * that the kvs contains all unique keys.
 * The set of writer threads has one leader which is reponsible for updating
 * the prefix.
 *
 * Each reader thread performs the following operations in a loop:
 *   1. create a cursor
 *   2. seek cursor just past the last-read-key
 *   3. read until eof or until we have a batch size worth of data
 *   4. record the last-read-key and destroy the cursor
 *
 */

#include <endian.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>
#include <hse_util/time.h>
#include <hse_util/timing.h>

#include "common.h"
#include "kvs_helper.h"

HSE_ALIGNED(SMP_CACHE_BYTES)
static atomic64_t  pfx = ATOMIC64_INIT(1);

HSE_ALIGNED(SMP_CACHE_BYTES)
static atomic64_t  sfx = ATOMIC64_INIT(1);

HSE_ALIGNED(SMP_CACHE_BYTES)
static uint64_t    last_del;

pthread_barrier_t   put_barrier1;
pthread_barrier_t   put_barrier2;

char *progname;

static int  err;
static volatile bool killthreads;
static volatile bool exit_puts;

struct opts {
	ulong batch;
	uint chunk;
	uint cap;
	uint put_threads;
	uint cur_threads;
	uint headstart;
	uint duration;
	bool verify;
} opts = {
	.batch = ULONG_MAX,
	.chunk = 2000,
	.cap = 10,
	.put_threads = 64,
	.cur_threads = 1,
	.duration = (30 * 60),
	.verify = false,
};


struct thread_info {
	HSE_ALIGNED(SMP_CACHE_BYTES)
	int           idx;
	atomic64_t    ops;
};

struct thread_info *g_ti;

void
pdel(void *arg)
{
	struct thread_arg *targ = arg;
	struct hse_kvdb_txn    *txn = hse_kvdb_txn_alloc(targ->kvdb);
	struct hse_kvdb_opspec  os;
	int rc;

	if (!txn)
		fatal(ENOMEM, "Failed to allocate resources for txn");

	pthread_setname_np(pthread_self(), __func__);

	HSE_KVDB_OPSPEC_INIT(&os);
	os.kop_txn = txn;

	while (!killthreads) {
		char      key[sizeof(uint64_t)];
		size_t    kvs_plen;
		uint64_t  curr_safe;
		uint64_t  curr;
		uint64_t *p;

		/* Compute how many entries is it safe to delete */
		curr = atomic64_read(&pfx);
		curr_safe = curr > opts.cap ? curr - opts.cap : 0;
		if (last_del >= curr_safe) {
			sleep(3);
			continue;
		}

		/* delete a prefix */

		p = (uint64_t *)key;
		*p = htobe64(last_del + 1);

		hse_kvdb_txn_begin(targ->kvdb, txn);
		rc = hse_kvs_prefix_delete(targ->kvs, &os,
				       key, sizeof(*p),
				       &kvs_plen);
		if (rc) {
			killthreads = 1;
			fprintf(stderr, "prefix delete failure. "
				"KVS pfxlen = %lu. Must be %lu\n",
				kvs_plen, sizeof(key));
			err = 1;
		}

		hse_kvdb_txn_commit(targ->kvdb, txn);
		last_del++;
	}
}

#define VLEN 1024

void
txput(void *arg)
{
	struct thread_arg *targ = arg;
	struct thread_info *ti = targ->arg;
	struct hse_kvdb_txn    *txn;
	struct hse_kvdb_opspec  os;
	uint64_t *p = 0; /* prefix */
	uint64_t *s = 0; /* suffix */
	int rc;
	uint32_t added;
	bool leader = ti->idx == 0;

	char key[2 * sizeof(uint64_t)];
	char val[VLEN] = { 0xfe };

	pthread_setname_np(pthread_self(), __func__);

	if (0 == getpriority(PRIO_PROCESS, 0))
		setpriority(PRIO_PROCESS, 0, 1);

	p = (uint64_t *)key;
	s = (uint64_t *)(key + sizeof(*p));

	txn = hse_kvdb_txn_alloc(targ->kvdb);
	if (!txn)
		fatal(ENOMEM, "Failed to allocate resources for txn");

	HSE_KVDB_OPSPEC_INIT(&os);
	os.kop_txn = txn;

	added = 0;
	while (!exit_puts) {
		*p = htobe64(atomic64_read(&pfx));       /* prefix */
		*s = htobe64(atomic64_inc_return(&sfx)); /* suffix */

		rc = hse_kvdb_txn_begin(targ->kvdb, txn);
		if (rc)
			fatal(rc, "Failed to begin txn");

		rc = hse_kvs_put(targ->kvs, &os, key, sizeof(key),
			     val, sizeof(val));
		if (rc)
			fatal(rc, "Failed to put key");

		atomic64_inc(&ti->ops);
		if (!err) {
			rc = hse_kvdb_txn_commit(targ->kvdb, txn);
			if (rc)
				fatal(rc, "Failed to commit txn");
			added++;
		} else {
			rc = hse_kvdb_txn_abort(targ->kvdb, txn);
			if (rc)
				fatal(rc, "Failed to abort txn");
		}

		if (killthreads || added == opts.chunk) {

			added = 0;
			rc = pthread_barrier_wait(&put_barrier1);

			if (leader) {
				atomic64_inc(&pfx);
				if (killthreads)
					exit_puts = true;
			}

			pthread_barrier_wait(&put_barrier2);
		}
	}

	hse_kvdb_txn_free(targ->kvdb, txn);
}

void
syncme(void *arg)
{
	struct thread_arg *targ = arg;

	pthread_setname_np(pthread_self(), __func__);

	while (!killthreads) {
		sleep(1);

		hse_kvdb_sync(targ->kvdb);
	}
}

void
print_stats(void *arg)
{
	uint32_t     second = 0;
	uint64_t     puts_last, reads_last;
	uint64_t     puts, reads;
	uint64_t     start;
	long         minflt = 0;
	long         majflt = 0;
	int          i;
	unsigned int keys_per_pfx = opts.chunk * opts.put_threads;

	puts_last = reads_last = 0;

	start = get_time_ns();
	while (!killthreads) {
		struct thread_info *t = &g_ti[0];
		struct rusage       rusage;
		uint64_t            dt;
		double              lag;
		unsigned int        pfx_lag;

		usleep(999 * 1000);
		getrusage(RUSAGE_SELF, &rusage);

		puts = reads = 0;
		for (i = 0; i < opts.put_threads; i++) {
			puts += atomic64_read(&t->ops);
			++t;
		}

		for (i = 0; i < opts.cur_threads; i++) {
			reads += atomic64_read(&t->ops);
			++t;
		}

		/* All readers must read each and every put.
		 */
		reads /= (opts.cur_threads ?: 1);

		pfx_lag = (puts - reads) / keys_per_pfx;

		lag = (puts - reads) / (reads - reads_last + 0.000001);
		if (lag > 99999)
			lag = 99999.99;

		dt = get_time_ns() - start;
		if (second % 20 == 0)
			printf("\n%8s %8s %8s %10s %10s %8s %8s %8s %8s %8s %8s\n",
			       "seconds", "cpfx", "dpfx", "puts",
			       "reads", "lag", "pfxLag", "pRate", "rRate",
			       "majflt", "minflt");

		printf("%8lu %8lu %8lu %10lu %10lu %8.2lf %8u %8lu %8lu %8ld %8ld\n",
		       dt / NSEC_PER_SEC,
		       atomic64_read(&pfx), last_del,
		       puts, reads, lag, pfx_lag,
		       puts - puts_last, reads - reads_last,
		       rusage.ru_majflt - majflt,
		       rusage.ru_minflt - minflt);
		fflush(stdout);

		reads_last = reads;
		puts_last = puts;

		majflt = rusage.ru_majflt;
		minflt = rusage.ru_minflt;
		second++;
	}
}

void
reader(void *arg)
{
	struct thread_arg  *targ = arg;
	struct thread_info *ti = targ->arg;
	struct hse_kvdb_opspec  os;
	struct hse_kvs_cursor  *c;
	uint32_t            cnt;
	bool                eof = false;
	uint64_t            klast[2] = { 0 };
	const void         *key, *val;
	const uint64_t     *key64;
	size_t              klen, vlen;
	int                 rc;

	pthread_setname_np(pthread_self(), __func__);

	HSE_KVDB_OPSPEC_INIT(&os);
	os.kop_txn = hse_kvdb_txn_alloc(targ->kvdb);

	while (!killthreads) {
		uint64_t last_safe_pfx = atomic64_read(&pfx) - 1;

		rc = hse_kvdb_txn_begin(targ->kvdb, os.kop_txn);
		if (rc)
			fatal(rc, "Failed to begin txn");

		/* [MU_REVISIT] Consider adding an option to replace
		 * destroy-create-seek with an update to test positional
		 * stability
		 */
		rc = hse_kvs_cursor_create(targ->kvs, &os, NULL, 0, &c);
		if (rc)
			fatal(rc, "hse_kvs_cursor_create failure");

		if (klast[0]) {
			klen = 0;

			rc = hse_kvs_cursor_seek(c, NULL, klast, sizeof(klast),
					&key, &klen);
			if (rc)
				fatal(rc, "hse_kvs_cursor_seek failure");

			if (klen != sizeof(klast) || memcmp(klast, key, klen)) {
				key64 = key;

				fatal(ENOENT, "Lost capped position at seek: "
				      "expected %lu-%lu found %lu-%lu "
				      "last del %lu",
				      be64toh(klast[0]), be64toh(klast[1]),
				      key ? be64toh(key64[0]) : 0,
				      key ? be64toh(key64[1]) : 0,
				      last_del);
			}

			rc = hse_kvs_cursor_read(c, NULL, &key, &klen,
					     &val, &vlen, &eof);
			if (rc)
				fatal(rc, "Failed to read from the cursor");
		}

		eof = false;
		cnt = 0;

		while (cnt < opts.batch) {
			rc = hse_kvs_cursor_read(c, NULL, &key, &klen,
					     &val, &vlen, &eof);
			if (rc)
				fatal(rc, "Failed to read from the cursor");
			key64 = key;
			if (eof || be64toh(key64[0]) > last_safe_pfx)
				break;

			if (opts.verify && klast[0]) {
				uint64_t found[2], last[2];

				found[0] = be64toh(key64[0]);
				found[1] = be64toh(key64[1]);
				last[0]  = be64toh(klast[0]);
				last[1]  = be64toh(klast[1]);

				if (!(found[1] == 1 + last[1] ||
				    (found[1] == 0 && found[0] == 1 + last[0])))
					fatal(EINVAL, "Found unexpected key\n");
			}

			klast[0] = key64[0];
			klast[1] = key64[1];

			if (++cnt % 1024 == 0) {
				atomic64_add(1024, &ti->ops);
				if (killthreads)
					break;
			}
		}

        /* Abort txn: This was a read-only txn */
        rc = hse_kvdb_txn_abort(targ->kvdb, os.kop_txn);
        if (rc)
            fatal(rc, "Failed to abort txn");

		atomic64_add(cnt % 1024, &ti->ops);

		hse_kvs_cursor_destroy(c);
	}

    hse_kvdb_txn_free(targ->kvdb, os.kop_txn);
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
		"-b bsz  Reader batch size\n"
		"-c csz  Chunk size per writer thread\n"
		"-d dur  Duration of run (in seconds)\n"
		"-h      Print this help menu\n"
		"-j wtd  Number of writer threads\n"
		"-m pfx  How many most recent prefixes to keep alive\n"
		"-s sec  Headstart for put threads (in seconds)\n"
		"-t rtd  Number of reader threads\n"
		"-v      Verify data\n"
		, progname);

	printf("\nDescription:\n");
	printf("Number of kv-pairs per prefix = "
		"chunk_size * number_of_put_threads\n");
	printf("Each cursor thread will read a max of 'batch size' "
		"(set using the '-b' option) kv-pairs before it updates the "
		"cursor and continues reading. The default value (0) will let "
		"it read to EOF\n");
	printf("\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	struct hse_params  *params;
	const char         *mpool, *kvs;
	size_t              sz;
	uint                i;
	char                c;

	progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":vhb:c:j:t:m:s:d:")) != -1) {
		char *errmsg, *end;

		errmsg = end = 0;
		errno = 0;
		switch (c) {
		case 'b':
			opts.batch = strtoul(optarg, &end, 0);
			errmsg = "invalid batch size";
			break;
		case 'c':
			opts.chunk = strtoul(optarg, &end, 0);
			errmsg = "invalid chunk size";
			break;
		case 'j':
			opts.put_threads = strtoul(optarg, &end, 0);
			errmsg = "invalid writer thread count";
			break;
		case 't':
			opts.cur_threads = strtoul(optarg, &end, 0);
			errmsg = "invalid reader thread count";
			break;
		case 'm':
			opts.cap = strtoul(optarg, &end, 0);
			errmsg = "invalid data size cap";
			break;
		case 's':
			opts.headstart = strtoul(optarg, &end, 0);
			errmsg = "invalid headstart";
			break;
		case 'd':
			opts.duration = strtoul(optarg, &end, 0);
			errmsg = "invalid duration";
			break;
		case 'v':
			opts.verify = true;
			break;
		case '?':
			syntax("invalid option -%c", optopt);
			exit(EX_USAGE);
		case ':':
			syntax("option -%c requires a parameter", optopt);
			exit(EX_USAGE);
		case 'h':
			usage();
			exit(0);
		default:
			fprintf(stderr, "option -%c ignored\n", c);
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

	hse_params_create(&params);
	hse_params_set(params, "kvs.enable_transactions", "1");

	kh_rparams(&argc, &argv, params);
	if (argc != 2) {
		syntax("insufficient arguments for mandatory parameters");
		hse_params_destroy(params);
		exit(EX_USAGE);
	}

	mpool = argv[0];
	kvs   = argv[1];

	sz = (opts.put_threads + opts.cur_threads) * sizeof(*g_ti);

	g_ti = aligned_alloc(SMP_CACHE_BYTES, sz);
	if (!g_ti) {
		hse_params_destroy(params);
		fatal(ENOMEM, "Allocation failed");
	}
	memset(g_ti, 0, sz);

	kh_init(mpool, params);

	pthread_barrier_init(&put_barrier1, NULL, opts.put_threads);
	pthread_barrier_init(&put_barrier2, NULL, opts.put_threads);

	for (i = 0; i < opts.put_threads; i++) {
		g_ti[i].idx = i;
		atomic64_set(&g_ti[i].ops, 0);
		kh_register(kvs, 0, params, &txput, &g_ti[i]);
	}

	if (opts.headstart) {
		printf("%d second headstart...\n", opts.headstart);
		sleep(opts.headstart);
	}

	for (i = 0; i < opts.cur_threads; i++) {
		int j = i + opts.put_threads;

		g_ti[j].idx = i;
		atomic64_set(&g_ti[j].ops, 0);
		kh_register(kvs, 0, params, &reader, &g_ti[j]);
	}

	if (opts.cap)
		kh_register(kvs, 0, params, &pdel, 0);

	kh_register(0, 0, 0, &print_stats, 0);
	kh_register(0, 0, 0, &syncme, 0);

	/* run time */
	while (!killthreads && opts.duration--)
		sleep(1);

	killthreads = true;

	kh_wait();

	pthread_barrier_destroy(&put_barrier1);
	pthread_barrier_destroy(&put_barrier2);

	kh_fini();

	hse_params_destroy(params);

	free(g_ti);

	return err;
}
