#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse/hse.h>

#include <hse_util/arch.h>
#include <hse_util/compiler.h>

#include "common.h"
#include "kvs_helper.h"

int errcnt = 0;

struct opts {
	uint nthread;
	uint count;
	bool reverse;
} opts = {
	.nthread  = 64,
	.count    = 3000000,
	.reverse = false,
};

struct thread_info {
	HSE_ALIGNED(SMP_CACHE_BYTES)
	uint64_t start;
	uint64_t end;
} *g_ti;

#define VLEN 1024

void
do_work(void *arg)
{
	struct thread_arg  *targ = arg;
	struct thread_info *ti = targ->arg;
	struct hse_kvdb_opspec  os;
	int                 i;
	char                val[VLEN];
	char                key[sizeof(uint64_t)];
	uint64_t           *k = (void *)key;
	struct hse_kvs_cursor  *c;
	int                 rc, cnt;
	const void         *kdata, *vdata;
	size_t              klen, vlen;
	bool                eof = false;
	int                 attempts = 5;

    HSE_KVDB_OPSPEC_INIT(&os);

	os.kop_txn   = hse_kvdb_txn_alloc(targ->kvdb);

	memset(val, 0xfe, sizeof(val));

	hse_kvdb_txn_begin(targ->kvdb, os.kop_txn);
	for (i = ti->start; i < ti->end; i++) {
		*k = htobe64(i);

		rc = hse_kvs_put(targ->kvs, &os, key, sizeof(key),
			     val, sizeof(val));
		if (rc)
			fatal(rc, "Failed to put key");
	}

	if (opts.reverse) {
		*k = htobe64(ti->end - 1);
		os.kop_flags = HSE_KVDB_KOP_FLAG_REVERSE |
			       HSE_KVDB_KOP_FLAG_BIND_TXN;
	} else {
		*k = htobe64(ti->start);
		os.kop_flags = HSE_KVDB_KOP_FLAG_BIND_TXN;
	}

	do {
		rc = hse_kvs_cursor_create(targ->kvs, &os, 0, 0, &c);
	} while (rc == EAGAIN);

	if (rc)
		fatal(rc, "Failed to create cursor");

	hse_kvdb_txn_commit(targ->kvdb, os.kop_txn);
	hse_kvdb_txn_free(targ->kvdb, os.kop_txn);

	cnt = 0;

	sleep(1); /* allow KVMSes to be ingested */

	/* seek to beginning */
	do  {
		rc = hse_kvs_cursor_seek(c, 0, key, sizeof(key), &kdata, &klen);
		if (rc == EAGAIN)
			usleep(1000 * 1000);

	} while (rc == EAGAIN && attempts-- > 0);

	if (rc || klen != sizeof(key) || memcmp(key, kdata, sizeof(key)))
		fatal(rc ?: ENOKEY, "Seek: found unexpected key. "
		      "Expected %lu got %lu\n",
		      be64toh(*k),
		      be64toh(*(uint64_t *)kdata));

	for (i = ti->start; i < ti->end; i++) {
		rc = hse_kvs_cursor_read(c, 0, &kdata, &klen, &vdata,
					 &vlen, &eof);
		if (rc || eof)
			break;

		++cnt;
	}

	if (cnt < ti->end - ti->start) {
		fatal(ENOANO, "Found incorrect number of records: "
			      "Expected %lu Got %lu",
			      ti->end - ti->start, cnt);

		++errcnt;
	}

	rc = hse_kvs_cursor_destroy(c);
}

char *progname;

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
		"-c keys  Number of keys\n"
		"-j jobs  Number of threads\n"
		"-r       Use reverse cursors\n"
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
main(
	int       argc,
	char    **argv)
{
	struct hse_params  *params;
	const char         *mpool, *kvs;
	char                c;
	int                 i;

	progname = basename(argv[0]);

	while ((c = getopt(argc, argv, "c:hj:r")) != -1) {
		char *errmsg, *end;

		errmsg = end = 0;
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
			opts.nthread = strtoul(optarg, &end, 0);
			errmsg = "invalid thread count";
			break;
		case 'r':
			opts.reverse = true;
			break;
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

	kh_rparams(&argc, &argv, params);
	if (argc != 3) {
		syntax("Incorrect number of arguments");
		exit(EX_USAGE);
	}

	mpool = argv[0];
	kvs   = argv[1];

	kh_init(mpool, params);

	g_ti = malloc(sizeof(*g_ti) * opts.nthread);
	if (!g_ti)
		fatal(ENOMEM, "Failed to allocate resources for threads");

	for (i = 0; i < opts.nthread; i++) {
		uint64_t stride = opts.count / opts.nthread;
		bool     last = i == (opts.nthread - 1);

		g_ti[i].start = i * stride;
		g_ti[i].end   = g_ti[i].start + stride;
		g_ti[i].end  += last ? (opts.count % opts.nthread) : 0;
		kh_register(kvs, 0, params, &do_work, &g_ti[i]);
	}

	kh_wait();
	kh_fini();

	hse_params_destroy(params);

	free(g_ti);

	if (errcnt) {
		fprintf(stderr, "errcnt %d", errcnt);
		assert(0);
	}

	printf("Finished successfully\n");

	return errcnt;
}
