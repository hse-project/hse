/*
 * This test creates several threads that call non-transactional PUTs on a loop.
 * One  thread that calls flush periodically on the KVDB.
 * And another thread that creates dummy transactions to bump up the kvdb seqno.
 */

#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <hse/hse.h>
#include <hse/hse_limits.h>

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
		usleep(10*1000);
	}
}

void
put(void *arg)
{
	struct thread_arg *targ = arg;
	uint64_t p = 0;
	int rc;

	char key[HSE_KVS_KLEN_MAX];

	memset(key, 0xaf, sizeof(key));
	while (!killthreads) {
		p++;
		rc = hse_kvs_put(targ->kvs, 0, key, sizeof(key), &p, sizeof(p));
		if (rc) {
			err = 1;
			killthreads = true;
		}
	}

}

void
seq_inc(void *arg)
{
	struct thread_arg  *targ = arg;
	struct hse_kvdb_txn    *txn = hse_kvdb_txn_alloc(targ->kvdb);

	while (!killthreads) {

		hse_kvdb_txn_begin(targ->kvdb, txn);
		hse_kvdb_txn_abort(targ->kvdb, txn);
	}

	hse_kvdb_txn_free(targ->kvdb, txn);
}

int
main(int argc, char **argv)
{
	struct hse_params  *params;
	const char *mpool;
	int i;

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

	/* frequent flushes */
	kh_register("kvs1", 0, params, &flush_kvs, 0);

	/* bump up seqno */
	kh_register("kvs1", 0, params, &seq_inc, 0);

	for (i = 0; i < 64; i++)
		kh_register("kvs1", 0, params, &put, 0);

	sleep(10);
	killthreads = true;
	kh_wait();

	kh_fini();

	hse_params_destroy(params);

	return err;
}
