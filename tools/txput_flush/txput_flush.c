/*
 * Several threads call transactional PUTs in a loop. For a given thread, each
 * time w/ the same key, but a different value.
 * Another thread periodically flushes the kvdb.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sysexits.h>

#include <hse/hse.h>

#include <cli/param.h>

#include "kvs_helper.h"

static int  err;
static bool killthreads;

void
flush_kvs(void *arg)
{
	struct thread_arg *targ = arg;

	while (!killthreads) {
		hse_kvdb_flush(targ->kvdb);
		usleep(100*1000);
	}
}

void
txput(void *arg)
{
	struct thread_arg *targ = arg;
	struct hse_kvdb_txn    *txn = hse_kvdb_txn_alloc(targ->kvdb);
	uint idx;
	uint64_t  vidx;
	int rc;

	char val[8];
	char key[HSE_KVS_KLEN_MAX];
	uint *v = (uint *)val;
	uint *k = (uint *)key;

	idx = *(uint *)targ->arg;
	*k = htonl(idx);
	memset(key + sizeof(*k), 0xaf, sizeof(key) - sizeof(*k));

	vidx = 0;
	while (!killthreads) {
		hse_kvdb_txn_begin(targ->kvdb, txn);
		*v = htonl(vidx++);
		rc = hse_kvs_put(targ->kvs, 0, txn, key, sizeof(key),
			     val, sizeof(val));
		if (rc) {
			err = 1;
			killthreads = true;
		}
		hse_kvdb_txn_commit(targ->kvdb, txn);
	}

	hse_kvdb_txn_free(targ->kvdb, txn);
}

#define NUM_THREADS 64

int
main(int argc, char **argv)
{
	struct parm_groups *pg = NULL;
	struct svec         kvdb_oparms = {};
	struct svec         kvs_cparms = {};
	struct svec         kvs_oparms = {};
	const char *mpool, *kvs;
	uint idx[NUM_THREADS];
	uint i;
	int rc;

	rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

	if (argc < 2) {
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

	rc = svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, "transactions_enable=1", NULL);
	if (rc) {
		fprintf(stderr, "pg_set_parms failed");
		exit(EX_USAGE);
	}

	kh_init(mpool, &kvdb_oparms);

	/* frequent flushes */
	kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &flush_kvs, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		idx[i] = i;
		kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &txput, &idx[i]);
	}

	sleep(15);
	killthreads = true;
	kh_wait();

	kh_fini();

	pg_destroy(pg);

	return err;
}
