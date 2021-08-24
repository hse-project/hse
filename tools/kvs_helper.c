/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2018-2019 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#include <bsd/string.h>
#include <hse/hse.h>
#include <hse/limits.h>

#include "kvs_helper.h"

struct test {
	struct hse_kvdb *kvdb;
} test;

struct kvs_info {
	char                name[HSE_KVS_NAME_LEN_MAX];
	struct hse_kvs     *hdl;
	struct kvs_info    *next;
};
struct kvs_info *k_head;

struct thread_info {
	pthread_t           tid;
	enum kh_flags       flags;
	kh_func            *func;
	struct thread_arg  *targ;
	struct thread_info *next;
	struct hse_kvs     *idx_kvs;
};
static struct thread_info *t_head, *t_detached;

/* caller processes cmdline options */
struct hse_kvdb *
kh_init(
	const char  *config,
	const char  *kvdb_home,
	struct svec *hse_gparms,
	struct svec *kvdb_oparms)
{
	hse_err_t err;

	err = hse_init(config, hse_gparms->strc, hse_gparms->strv);
	if (err) {
		fatal(err, "hse_init failed");
	}

	err = hse_kvdb_open(kvdb_home, kvdb_oparms->strc, kvdb_oparms->strv, &test.kvdb);
	if (err) {
		fatal(err, "hse_kvdb_open failed");
	}

	t_head = t_detached = NULL;
	k_head = NULL;

	return test.kvdb;
}

void
kh_fini(void)
{
	void *next;

	/* [MU_REVISIT] make sure all threads have finished */

	while (t_head) {
		next = t_head->next;
		free(t_head);
		t_head = next;
	}

	while (t_detached) {
		next = t_detached->next;
		free(t_detached);
		t_detached = next;
	}

	while (k_head) {
		next = k_head->next;
		hse_kvdb_kvs_close(k_head->hdl);
		free(k_head);
		k_head = next;
	}

	hse_kvdb_close(test.kvdb);

	hse_fini();
}

void
kh_wait(void)
{
	void *next;

	while (t_head) {
		next = t_head->next;
		pthread_join(t_head->tid, 0);
		free(t_head);
		t_head = next;
	}
}

void
kh_wait_all(void)
{
	void *next;

	kh_wait();
	while (t_detached) {
		next = t_detached->next;
		pthread_join(t_detached->tid, 0);
		free(t_detached);
		t_detached = next;
	}
}

static void *
threadfunc(
	void *arg)
{
	struct thread_info *ti = arg;

	ti->func(ti->targ);

	pthread_exit(NULL);
}

struct hse_kvs *
kh_get_kvs(
	const char           *name,
	struct svec          *cparms,
	struct svec          *oparms)
{
	hse_err_t err;
	struct kvs_info *ki;

	/* if already opened, return handle */
	for (ki = k_head; ki; ki = ki->next) {
		if (strncmp(name, ki->name, sizeof(ki->name)) == 0)
			return ki->hdl;
	}

	ki = malloc(sizeof(*ki));
	if (!ki) {
		fatal(ENOMEM, "cannot allocate memory for kvs\n");
	}

	strlcpy(ki->name, name, sizeof(ki->name));

	err = hse_kvdb_kvs_open(test.kvdb, name, oparms->strc, oparms->strv, &ki->hdl);
	if (hse_err_to_errno(err) == EBUSY) {
		fatal(err, "hse_kvdb_kvs_open failed");
	} else if (err) {
		err = hse_kvdb_kvs_create(test.kvdb, name, cparms->strc, cparms->strv);
		if (err) {
			free(ki);
			fatal(err, "hse_kvdb_kvs_create failed");
		}

		err = hse_kvdb_kvs_open(test.kvdb, name, oparms->strc, oparms->strv, &ki->hdl);
		if (err) {
			/* [MU_REVISIT] add kvs_drop here */
			free(ki);
			fatal(err, "hse_kvdb_kvs_open failed");
		}

	}

	/* add to list */
	ki->next = k_head;
	k_head   = ki;

	return ki->hdl;
}

int
kh_register_kvs(
	const char           *kvs,
	enum kh_flags         flags,
	struct svec          *kvs_cparms,
	struct svec          *kvs_oparms,
	kh_func              *func,
	void                 *arg)
{
	struct thread_info *ti;
	int rc;

	/* [MU_REVISIT] The thread should wait for a call like kh_run() to start
	 * all threads. This function should only prep the threads.
	 */

	ti = malloc(sizeof(struct thread_arg) + sizeof(*ti));
	if (!ti) {
		fatal(ENOMEM, "kvs_helper: cannot allocate memory for threads");
	}

	ti->func = func;
	ti->next = 0;

	ti->targ       = (struct thread_arg *)(ti + 1);
	ti->targ->arg  = arg;
	ti->targ->kvdb = test.kvdb;
	ti->targ->kvs  = kvs ? kh_get_kvs(kvs, kvs_cparms, kvs_oparms) : 0;
	ti->flags      = flags;

again:
	rc = pthread_create(&ti->tid, 0, threadfunc, ti);
	if (rc) {
		if (rc == EAGAIN) {
			usleep(1000);
			goto again;
		}

		fatal(rc, "kvs_helper: cannot create thread");
	}

	if (ti->flags & KH_FLAG_DETACH) {
		ti->next = t_detached;
		t_detached = ti;
	} else {
		ti->next = t_head;
		t_head = ti;
	}

	return 0;
}

int
kh_register(
	enum kh_flags         flags,
	kh_func              *func,
	void                 *arg)
{
	return kh_register_kvs(NULL, flags, NULL, NULL, func, arg);
}

int
kh_register_multiple(
	int           kvs_cnt,
	const char  **kvs_vec,
	int           num_threads,
	void        **argv,
	kh_func      *func)
{
	/* iteratively register the function w/ all args and assign to KVSes
	 * in a round-robin fashion (maybe other variations can be added later;
	 * see longtest)
	 */
	return -ENOTSUP;
}

/* cursor helper functions */
struct hse_kvs_cursor *
kh_cursor_create(
	struct hse_kvs *     kvs,
	unsigned int         flags,
	struct hse_kvdb_txn *txn,
	void *               pfx,
	size_t               pfxlen)
{
	struct hse_kvs_cursor *cur;
	hse_err_t              err;
	int                    attempts = 5;

retry:
	if (attempts-- == 0)
		fatal(err, "cursor create failed");

	err = hse_kvs_cursor_create(kvs, flags, txn, pfx, pfxlen, &cur);
	if (err) {
		if (hse_err_to_errno(err) == EAGAIN) {
			usleep(10*1000);
			goto retry;
		}

		fatal(err, "cursor create failed");
	}

	return cur;
}

void
kh_cursor_update_view(
	struct hse_kvs_cursor *cur,
	unsigned int           flags)
{
	hse_err_t err;

	err = hse_kvs_cursor_update_view(cur, flags);
	if (err)
		fatal(err, "cursor update failed");
}

void
kh_cursor_seek(
	struct hse_kvs_cursor    *cur,
	void                 *key,
	size_t                klen)
{
	hse_err_t          err;
	const void        *fkey;
	size_t             fklen;

	err = hse_kvs_cursor_seek(cur, 0, key, klen, &fkey, &fklen);
	if (err)
		fatal(err, "cursor seek failed");
}

void
kh_cursor_seek_limited(
	struct hse_kvs_cursor    *cur,
	void                 *from,
	size_t                from_len,
	void                 *to,
	size_t                to_len)
{
	hse_err_t          err;
	const void        *fkey;
	size_t             fklen;

	err = hse_kvs_cursor_seek_range(cur, 0, from, from_len, to, to_len,
				   &fkey, &fklen);
	if (err)
		fatal(err, "cursor seek failed");
}

bool
kh_cursor_read(
	struct hse_kvs_cursor    *cur,
	const void          **key,
	size_t               *klen,
	const void          **val,
	size_t               *vlen)
{
	bool eof;
	hse_err_t err;

	err = hse_kvs_cursor_read(cur, 0, key, klen, val, vlen, &eof);
	if (err)
		fatal(err, "cursor read failed");

	return eof;
}

void
kh_cursor_destroy(
	struct hse_kvs_cursor    *cur)
{
	hse_err_t err;

	err = hse_kvs_cursor_destroy(cur);
	if (err)
		fatal(err, "cursor destroy failed");
}
