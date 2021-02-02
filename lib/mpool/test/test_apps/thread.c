// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>

#include "thread.h"

volatile enum thread_state thread_state = NOT_STARTED;

void thread_wait_for_start(struct thread_args *targs)
{

	/* Wait for starting flag */
	pthread_mutex_lock(targs->start_mutex);
	atomic_dec(targs->start_cnt);
	while (thread_state == NOT_STARTED)
		pthread_cond_wait(targs->start_line, targs->start_mutex);
	pthread_mutex_unlock(targs->start_mutex);
}


merr_t
thread_create(
	int                 thread_cnt,
	thread_func_t       func,
	struct thread_args *targs,
	struct thread_resp *tresp)
{
	pthread_t         *thread;
	pthread_attr_t    *attr;
	pthread_cond_t     start_line = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t    start_mutex = PTHREAD_MUTEX_INITIALIZER;
	atomic_t           start_cnt;
	int                still_to_start;
	int                i, rc;

	if (!targs || !tresp) {
		fprintf(stderr, "%s: targs and/or tresp not passed in\n", __func__);
		return merr(EINVAL);
	}

	/* Prep thread(s) */
	thread = calloc(thread_cnt, sizeof(*thread));
	attr = calloc(thread_cnt, sizeof(*attr));
	if (!thread || !attr) {
		fprintf(stderr, "%s: Unable to allocate memory for thread data\n", __func__);
		return merr(ENOMEM);
	}

	atomic_set(&start_cnt, thread_cnt);

	for (i = 0; i < thread_cnt; i++) {

		pthread_attr_init(&attr[i]);

		targs[i].instance = i;
		targs[i].start_mutex = &start_mutex;
		targs[i].start_line = &start_line;
		targs[i].start_cnt = &start_cnt;

		rc = pthread_create(&thread[i], &attr[i], func,
			(void *)&targs[i]);
		if (rc != 0) {
			fprintf(stderr, "%s pthread_create failed\n", __func__);
			return merr(rc);
		}
	}

	while ((still_to_start = atomic_read(&start_cnt)) != 0)
		;

	pthread_mutex_lock(&start_mutex);
	thread_state = STARTED;
	pthread_cond_broadcast(&start_line);
	pthread_mutex_unlock(&start_mutex);

	for (i = 0; i < thread_cnt; i++) {
		pthread_join(thread[i], (void **)&tresp[i].resp);

		pthread_attr_destroy(&attr[i]);
	}
	thread_state = NOT_STARTED;

	free(attr);
	free(thread);

	return 0;
}
