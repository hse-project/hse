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

#include <hse/hse.h>

#include "common.h"
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
	struct hse_kvdb_opspec  os;
	uint idx;
	uint64_t  vidx;
	int rc;

	char val[8];
	char key[HSE_KVS_KLEN_MAX];
	uint *v = (uint *)val;
	uint *k = (uint *)key;

	HSE_KVDB_OPSPEC_INIT(&os);

	idx = *(uint *)targ->arg;
	*k = htonl(idx);
	memset(key + sizeof(*k), 0xaf, sizeof(key) - sizeof(*k));
	os.kop_txn = txn;

	vidx = 0;
	while (!killthreads) {
		hse_kvdb_txn_begin(targ->kvdb, txn);
		*v = htonl(vidx++);
		rc = hse_kvs_put(targ->kvs, &os, key, sizeof(key),
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
	struct hse_params  *params;
	const char *mpool, *kvs;
	uint idx[NUM_THREADS];
	uint i;

	hse_params_create(&params);
	hse_params_set(params, "kvs.transactions_enable", "1");

	kh_rparams(&argc, &argv, params);
	if (argc != 2) {
		hse_params_destroy(params);
		fatal(EINVAL, "usage: %s <kvdb> <kvs> [rparams]",
		      basename(argv[0]));
	}

	mpool = argv[0];
	kvs   = argv[1];

	kh_init(mpool, params);

	/* frequent flushes */
	kh_register(kvs, 0, params, &flush_kvs, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		idx[i] = i;
		kh_register(kvs, 0, params, &txput, &idx[i]);
	}

	sleep(15);
	killthreads = true;
	kh_wait();

	kh_fini();

	hse_params_destroy(params);

	return err;
}
