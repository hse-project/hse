/*
 * Copyright (C) 2018-2019 Micron Technology, Inc.  All rights reserved.
 */

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <hse_util/timing.h>

#include "common.h"
#include "kvs_helper.h"

struct opts {
	uint threads;
	uint count;
} opts = {
	.threads = 1,
	.count = 500000,
};

struct thread_info {
	uint64_t kidx;
};

void
txn_puts(
	void *arg)
{
	struct thread_arg *targ = arg;
	struct thread_info *ti = targ->arg;
	struct hse_kvdb_txn    *txn;
	char key[64] = {0};
	char val[1024];
	uint64_t *k; /* key */
	struct hse_kvdb_opspec os;
	uint64_t kid;
	int i, rc;

	memset(val, 0xfc, sizeof(val));
	k = (uint64_t *)key;

	txn = hse_kvdb_txn_alloc(targ->kvdb);
	if (!txn)
		fatal(ENOMEM, "Failed to allocate resources for txn");

	HSE_KVDB_OPSPEC_INIT(&os);
	os.kop_txn = txn;

	printf("Loading keys\n");
	hse_kvdb_txn_begin(targ->kvdb, txn);
	for (i = 0, kid = ti->kidx; i < opts.count; i++) {
		*k = htobe64(++kid);

		rc = hse_kvs_put(targ->kvs, &os, key, sizeof(key),
			     val, sizeof(val));
		if (rc)
			fatal(rc, "Put failure");
	}

	rc = hse_kvdb_txn_commit(targ->kvdb, txn);
	if (rc) {
		fatal(rc, "TX Commit failure");
		hse_kvdb_txn_abort(targ->kvdb, txn);
	}

	hse_kvdb_txn_free(targ->kvdb, txn);

	printf("Verifying keys\n");

	for (i = 0, kid = ti->kidx; i < opts.count; i++) {
		bool   found;
		size_t vlen;
		char   vbuf[1024];

		*k = htobe64(++kid);

		memset(vbuf, 0, sizeof(vbuf));
		rc = hse_kvs_get(targ->kvs, 0, key, sizeof(key), &found,
			     vbuf, sizeof(vbuf), &vlen);
		if (rc)
			fatal(rc, "Get failure");

		if (!found)
			fatal(ENOKEY, "Failed to get key %llu", kid);

		if (vlen != sizeof(vbuf) || memcmp(vbuf, val, vlen))
			fatal(ENOANO, "Found key %llu, val doesn't match");

	}
}

char *progname;

void
usage(void)
{
	printf(
		"usage: %s [options] kvdb kvs [param=value ...]\n"
		"-c keys   Number of keys per thread\n"
		"-j jobs   Number threads\n"
		, progname);
}

int
main(
	int       argc,
	char    **argv)
{
	struct hse_params  *params;
	const char         *mpool, *kvs;
	struct thread_info *ti;
	int i;
	char  c;

	progname = basename(argv[0]);

	while ((c = getopt(argc, argv, "hc:j:")) != -1) {
		char *errmsg = 0;

		errno = 0;
		switch (c) {
		case 'c':
			opts.count = strtoul(optarg, 0, 0);
			errmsg = "invalid key count";
			break;
		case 'j':
			opts.threads = strtoul(optarg, 0, 0);
			errmsg = "invalid number of threads";
			break;
		}

		if (errno && errmsg) {
			usage();
			exit(EX_USAGE);
		}
	}

	hse_params_create(&params);
	hse_params_set(params, "kvs.enable_transactions", "1");

	kh_rparams(&argc, &argv, params);
	if (argc != 2) {
		fprintf(stderr, "Incorrect number of arguments\n");
		usage();
		hse_params_destroy(params);
		exit(EX_USAGE);
	}

	mpool = argv[0];
	kvs   = argv[1];

	kh_init(mpool, params);

	ti = malloc(opts.threads * sizeof(*ti));
	if (!ti)
		fatal(ENOMEM, "Failed to allocate resources for threads");

	for (i = 0; i < opts.threads; i++) {
		ti[i].kidx = i * opts.count;
		kh_register(kvs, 0, params, &txn_puts, &ti[i]);
	}

	kh_wait();
	kh_fini();

	hse_params_destroy(params);

	free(ti);

	return 0;
}
