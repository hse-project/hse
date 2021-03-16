/*
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

#include <hse/hse.h>

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
		hse_kvs_put(targ->kvs, 0, "abc", 3, &p, sizeof(p));
	}

}

void
txget(void *arg)
{
	struct thread_arg  *targ = arg;
	struct hse_kvdb_txn    *txn = hse_kvdb_txn_alloc(targ->kvdb);
	struct hse_kvdb_opspec  os;
	uint64_t            val1, val2;
	bool                found;
	size_t              vlen;

	HSE_KVDB_OPSPEC_INIT(&os);
	os.kop_txn = txn;

	while (!killthreads) {
		val1 = val2 = 0;

		hse_kvdb_txn_begin(targ->kvdb, txn);
		hse_kvs_get(targ->kvs, &os, "abc", 3, &found, &val1,
			sizeof(val1), &vlen);
		if (!found)
			continue;
		usleep(1000);
		hse_kvs_get(targ->kvs, &os, "abc", 3, &found, &val2,
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
	struct hse_params *params;
	const char *mpool;

	hse_params_create(&params);
	hse_params_set(params, "kvs.enable_transactions", "1");

	kh_rparams(&argc, &argv, params);
	if (argc != 1) {
		hse_params_destroy(params);
		fatal(EINVAL, "usage: %s [options] <kvdb> [rparams]",
		      basename(argv[0]));
	}

	mpool = argv[0];

	kh_init(mpool, params);

	kh_register("kvs1", 0, params, &txget, 0);
	kh_register("kvs1", 0, params, &put, 0);

	sleep(10);
	killthreads = true;
	kh_wait();

	kh_fini();

	hse_params_destroy(params);

	return err;
}
