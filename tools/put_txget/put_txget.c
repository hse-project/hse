/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc. All rights reserved.
 *
 * One  thread calls non-transactional PUTs in a loop. Each time w/ the same
 * key, but a different value.
 * Another thread repeatedly creates a transaction and reads the key twice with
 * a short sleep b/w the two reads.
 */

#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <cli/param.h>

#include "kvs_helper.h"

static int  err;
static bool killthreads;

void
put(void *arg)
{
	struct thread_arg *targ = arg;
	uint64_t p = 0;

	while (!killthreads) {
		p++;
		hse_kvs_put(targ->kvs, 0, NULL, "abc", 3, &p, sizeof(p));
	}

}

void
txget(void *arg)
{
	struct thread_arg  *targ = arg;
	struct hse_kvdb_txn    *txn = hse_kvdb_txn_alloc(targ->kvdb);
	uint64_t            val1, val2;
	bool                found;
	size_t              vlen;

	while (!killthreads) {
		val1 = val2 = 0;

		hse_kvdb_txn_begin(targ->kvdb, txn);
		hse_kvs_get(targ->kvs, 0, txn, "abc", 3, &found, &val1,
			sizeof(val1), &vlen);
		if (!found)
			continue;
		usleep(1000);
		hse_kvs_get(targ->kvs, 0, txn, "abc", 3, &found, &val2,
			sizeof(val2), &vlen);

		if (val1 != val2) {
			printf("Value mismatch: val1 = %lu, val2 = %lu\n",
			       val1, val2);
			killthreads = true;
			err = 1;
			return;
		}

		hse_kvdb_txn_abort(targ->kvdb, txn);
	}

	hse_kvdb_txn_free(targ->kvdb, txn);
}

int
main(int argc, char **argv)
{
	struct parm_groups *pg = NULL;
	struct svec         hse_gparms = { 0 };
	struct svec         kvdb_oparms = { 0 };
	struct svec         kvs_cparms = { 0 };
	struct svec         kvs_oparms = { 0 };
	const char *mpool;
	int rc = 0;

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

	if (argc - optind < 1) {
		fprintf(stderr, "missing required parameters\n");
		exit(EX_USAGE);
	}

	mpool = argv[optind++];

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

	if (optind < argc) {
		fprintf(stderr, "extraneous argument: %s", argv[optind]);
		exit(EX_USAGE);
	}

	rc = pg_set_parms(pg, PG_KVS_OPEN, "transactions.enabled=true", NULL);
	if (rc) {
		fprintf(stderr, "pg_set_parms failed");
		exit(EX_USAGE);
	}

	rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
	rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
	if (rc)
		fatal(rc, "failed to parse params\n");

	kh_init(mpool, &hse_gparms, &kvdb_oparms);

	kh_register_kvs("kvs1", 0, &kvs_cparms, &kvs_oparms, &txget, 0);
	kh_register_kvs("kvs1", 0, &kvs_cparms, &kvs_oparms, &put, 0);

	sleep(10);
	killthreads = true;
	kh_wait();

	kh_fini();

	pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

	return err;
}
