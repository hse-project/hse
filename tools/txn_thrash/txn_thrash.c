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

#include <cli/param.h>

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
	uint64_t kid;
	int i, rc;

	memset(val, 0xfc, sizeof(val));
	k = (uint64_t *)key;

	txn = hse_kvdb_txn_alloc(targ->kvdb);
	if (!txn)
		fatal(ENOMEM, "Failed to allocate resources for txn");

	printf("Loading keys\n");
	hse_kvdb_txn_begin(targ->kvdb, txn);
	for (i = 0, kid = ti->kidx; i < opts.count; i++) {
		*k = htobe64(++kid);

		rc = hse_kvs_put(targ->kvs, 0, txn, key, sizeof(key),
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
		rc = hse_kvs_get(targ->kvs, 0, NULL, key, sizeof(key), &found,
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
	struct parm_groups *pg = NULL;
	struct svec         hse_gparms = { 0 };
	struct svec         kvdb_oparms = { 0 };
	struct svec         kvs_cparms = { 0 };
	struct svec         kvs_oparms = { 0 };
	const char         *mpool, *kvs;
	struct thread_info *ti;
	int i, rc;
	char  c;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

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

	rc = pg_set_parms(pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
	if (rc)
		fatal(rc, "pg_set_parms");

	rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
	rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
	if (rc)
		fatal(rc, "failed to parse params\n");

	kh_init(mpool, &hse_gparms, &kvdb_oparms);

	ti = malloc(opts.threads * sizeof(*ti));
	if (!ti)
		fatal(ENOMEM, "Failed to allocate resources for threads");

	for (i = 0; i < opts.threads; i++) {
		ti[i].kidx = i * opts.count;
		kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &txn_puts, &ti[i]);
	}

	kh_wait();
	kh_fini();

	pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

	free(ti);

	return 0;
}
