/*
 * Copyright (C) 2018 Micron Technology, Inc.  All rights reserved.
 *
 * This test loads a number of keys and uses multiple cursors to verify the
 * various ranges of the key space.
 *
 * The test launches multiple threads, and each thread:
 *   1. Creates its share of cursors.
 *   2. Loads its share of keys.
 *   3. Updates its cursors.
 *   4. With each cursor in this thread, read a portion of this thread's share
 *      of keys such that all cursors of a thread put together verify the keys
 *      inserted by that thread.
 */

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

#include <cli/param.h>

#include "kvs_helper.h"

static int  err;
static volatile bool killthreads;

struct opts {
	unsigned int threads;
	unsigned int count;
	unsigned int ncursor;
	bool load;
	int verify;
} opts = {
	.count   = 1000 * 1000 * 1000,
	.ncursor = 20000,
	.threads = 20,
	.load    = false,
	.verify  = 0,
};

struct thread_info {
	HSE_ALIGNED(SMP_CACHE_BYTES)
	int           start;
	int           end;
	int           num_cursors;
	atomic64_t    puts;
	atomic64_t    reads;
	atomic64_t    cursors;
};

struct thread_info *g_ti;

#define KLEN 64
#define VLEN 1024

void
do_things(void *arg)
{
	struct thread_arg *targ = arg;
	struct thread_info *ti = targ->arg;
	uint64_t *key = 0;
	uint i;
	hse_err_t err;
	struct hse_kvs_cursor *cursorv[ti->num_cursors];
	struct timespec pause = { .tv_nsec = 1000 * 100 };

	char kbuf[KLEN] = {0};
	char vbuf[VLEN];

	pthread_setname_np(pthread_self(), __func__);

	key = (uint64_t *)kbuf;
	memset(vbuf, 0x42, sizeof(vbuf));

	if (opts.verify) {
		uint num_cursors = ti->num_cursors;

		for (i = 0; i < num_cursors; i++) {
			int retries = 5;

			do {
				err = hse_kvs_cursor_create(targ->kvs, 0, NULL, 0, 0,
						       &cursorv[i]);
				if (hse_err_to_errno(err) == EAGAIN)
					nanosleep(&pause, 0);
			} while (hse_err_to_errno(err) == EAGAIN && retries-- > 0);

			if (err)
				fatal(err, "Failed to create cursor");

			atomic64_inc(&ti->cursors);
		}
	}

	if (opts.load) {
		struct hse_kvdb_txn *txn = hse_kvdb_txn_alloc(targ->kvdb);
		hse_kvdb_txn_begin(targ->kvdb, txn);
		i = ti->start;
		for (i = ti->start; i < ti->end; i++) {
			*key = htobe64(i); /* key */
			err = hse_kvs_put(targ->kvs, 0, txn, kbuf, sizeof(kbuf),
				     vbuf, sizeof(vbuf));
			if (err)
				fatal(err, "Put failed");

			atomic64_inc(&ti->puts);
		}
		hse_kvdb_txn_commit(targ->kvdb, txn);
		hse_kvdb_txn_free(targ->kvdb, txn);
	}

	if (opts.verify) {
		uint count;
		bool eof;
		uint num_cursors = ti->num_cursors;
		uint stride = (ti->end - ti->start) / num_cursors;

		for (i = 0; i < num_cursors; i++) {
			int retries = 5;

			do {
				err = hse_kvs_cursor_update_view(cursorv[i], 0);
				if (hse_err_to_errno(err) == EAGAIN)
					nanosleep(&pause, 0);
			} while (hse_err_to_errno(err) == EAGAIN && retries-- > 0);

			if (err)
				fatal(err, "Failed to update cursor");

		}

		for (i = 0; i < num_cursors; i++) {
			int j;
			uint start, end;

			start = ti->start + (i * stride);
			end = start + stride;

			*key = htobe64(start); /* seek key */
			err = hse_kvs_cursor_seek(cursorv[i], 0, kbuf,
						 sizeof(kbuf), 0, 0);
			if (err)
				fatal(err, "Failed to seek cursor");

			count = 0;
			if (i == num_cursors - 1)
				end = ti->end;

			for (j = start; j < end; j++) {
				const void  *cur_key, *cur_val;
				size_t       cur_klen, cur_vlen;

				err = hse_kvs_cursor_read(cursorv[i], 0,
						     &cur_key, &cur_klen,
						     &cur_val, &cur_vlen, &eof);
				if (err || eof)
					break;

				/* Verify if keys match */
				if (opts.verify > 1) {
					bool match;

					*key = htobe64(j); /* expected key */
					match = cur_klen == sizeof(kbuf) &&
					!memcmp(kbuf, cur_key, cur_klen);

					if (!match)
						fatal(ENOKEY, "key mismatch: "
						      "expected %d found %d", j,
						      be64toh(*(uint64_t *)
							      cur_key));

				}

				count++;
				atomic64_inc(&ti->reads);
			}

			if (err)
				fatal(err, "Cursor read failed");

			if (eof && count != (end - start))
				fatal(ENODATA,
				      "Cursor encountered premature eof. "
				      "Expected %u Got %u",
				      ti->end - ti->start, count);
		}

		for (i = 0; i < num_cursors; i++)
			hse_kvs_cursor_destroy(cursorv[i]);
	}
}

void
print_stats(void *arg)
{
	uint seconds = 0;

	while (!killthreads) {
		int i;
		uint tot_puts = 0;
		uint tot_reads = 0;
		uint tot_cursors = 0;

		for (i = 0; i < opts.threads; i++) {
			tot_puts += atomic64_read(&g_ti[i].puts);
			tot_reads += atomic64_read(&g_ti[i].reads);
			tot_cursors += atomic64_read(&g_ti[i].cursors);
		}

		printf("seconds %u cursors %u puts %u reads %u\n",
		       seconds, tot_cursors, tot_puts, tot_reads);
		sleep(1);
		++seconds;
	}
}

char *progname;

void
usage(void)
{
	printf(
		"usage: %s [options] kvdb kvs [param=value ...]\n"
		"-c keys  Number of keys\n"
		"-h       Print this help menu\n"
		"-j jobs  Number of threads\n"
		"-l       Run the load phase\n"
		"-r curs  Number of cursors\n"
		"-v       Run the exec phase\n"
		, progname);
}

void
syntax(const char *fmt, ...)
{
	char msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

int
main(int argc, char **argv)
{
	struct parm_groups *pg = NULL;
	struct svec         hse_gparms = {};
	struct svec         kvdb_oparms = {};
	struct svec         kvs_cparms = {};
	struct svec         kvs_oparms = {};
	const char         *mpool, *kvs;
	size_t              sz;
	uint                i, stride;
	char                c;
	uint                cur_per_thread;
	int                 rc;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

	while ((c = getopt(argc, argv, ":c:hj:lr:v")) != -1) {
		char *end, *errmsg;

		end = errmsg = 0;
		errno = 0;
		switch (c) {
		case 'c':
			opts.count = strtoul(optarg, &end, 0);
			errmsg = "invalid key count";
			break;
		case 'h':
			usage();
			exit(0);
		case 'j':
			opts.threads = strtoul(optarg, &end, 0);
			errmsg = "invalid thread count";
			break;
		case 'l':
			opts.load = true;
			break;
		case 'r':
			opts.ncursor = strtoul(optarg, &end, 0);
			errmsg = "invalid cursor count";
			break;
		case 'v':
			opts.verify++;
			break;
		case '?':
			syntax("invalid option -%c", optopt);
			exit(EX_USAGE);
		case ':':
			syntax("option -%c requires a parameter", optopt);
			exit(EX_USAGE);
		default:
			fprintf(stderr, "option -%c ignored\n", c);
			break;
		}

		if (errno && errmsg) {
			usage();
			exit(EX_USAGE);
		} else if (end && *end) {
			syntax("%s '%s'", errmsg, optarg);
			exit(EX_USAGE);
		}
	}

	if (argc - optind < 2) {
		syntax("missing required parameters");
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
	rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
	if (rc) {
		fprintf(stderr, "svec_append_pg failed: %d", rc);
		exit(EX_USAGE);
	}

	/* Load phase */
	sz = (opts.threads) * sizeof(*g_ti);

	g_ti = aligned_alloc(SMP_CACHE_BYTES, sz);
	if (!g_ti) {
		pg_destroy(pg);
		fatal(ENOMEM, "Allocation failed");
	}
	memset(g_ti, 0, sz);

	kh_init(mpool, &hse_gparms, &kvdb_oparms);

	kh_register(KH_FLAG_DETACH, &print_stats, NULL);
	sleep(1); /* wait for print_stats to detach itself */

	stride = opts.count / opts.threads;
	cur_per_thread = opts.ncursor / opts.threads;

	for (i = 0; i < opts.threads; i++) {
		g_ti[i].start = i * stride;
		g_ti[i].end   = g_ti[i].start + stride;
		atomic64_set(&g_ti[i].puts, 0);
		g_ti[i].num_cursors  = cur_per_thread;
		kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &do_things, &g_ti[i]);
	}

	kh_wait();

	sleep(1); /* allow detached threads to finish up */
	killthreads = true; /* for stats */

	kh_fini();

	pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

	free(g_ti);

	return err;
}
