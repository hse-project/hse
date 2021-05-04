/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PIDFILE_PIDFILE_H
#define HSE_PIDFILE_PIDFILE_H

#include <limits.h>

#include <bsd/libutil.h>

#define PIDFILE_NAME "hse.pid"

struct pidfile {
	pid_t pid;
	struct {
		char path[PATH_MAX];
	} socket;
};

int
pidfile_serialize(struct pidfh *pfh, const struct pidfile *content);

int
pidfile_deserialize(const char *home, struct pidfile *content);

#endif
