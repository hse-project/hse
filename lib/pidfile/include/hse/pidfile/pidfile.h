/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_PIDFILE_PIDFILE_H
#define HSE_PIDFILE_PIDFILE_H

#include <limits.h>

#include <bsd/libutil.h>
#include <sys/un.h>

#include <hse/error/merr.h>

#define PIDFILE_ALIAS_LEN_MAX 32
#define PIDFILE_NAME          "kvdb.pid"

struct pidfile {
    pid_t pid;
    char alias[PIDFILE_ALIAS_LEN_MAX];
    struct {
        char socket_path[sizeof(((struct sockaddr_un *)NULL)->sun_path)];
    } rest;
};

merr_t
pidfile_serialize(struct pidfh *pfh, const struct pidfile *content);

merr_t
pidfile_deserialize(const char *home, struct pidfile *content);

#endif
