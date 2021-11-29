/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "stress_util.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <hse/experimental.h>

int DEBUG = 0;

static const char *       level_names[] = { "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
static pthread_t          g_thread_id;
static struct timer_node *g_head;
static const int          MAX_PARAMS = 10;

#define MAX_TIMER_COUNT 1000

long long
current_timestamp_ms()
{
    struct timeval te;
    long long      milliseconds;

    gettimeofday(&te, NULL);
    milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000;

    return milliseconds;
}

void
log_print(int level, const char *fmt, ...)
{
    char       buf[32];
    va_list    args;
    time_t     t = time(NULL);
    struct tm *lt = localtime(&t);
    int        n;

    n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", lt);
    assert(n > 0);
    n = n; /* unused */

    printf("[%s %-5s] ", buf, level_names[level]);

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
}

void
gen_kvs_ext_name(char *dest, size_t dest_size, const char *base_kvs_name, long int txn, int rank)
{
    int n;

    n = snprintf(dest, dest_size, "%s_r%d_t%ld", base_kvs_name, rank, txn);
    assert(n < dest_size);
    n = n; /* unused */
}

void
fillrandom(char *dest, size_t dest_size)
{
    /* This does NOT null terminate the data; caller must do so if needed */
    int               n = 0;
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

    if (dest_size > 0) {
        int l = (int)(sizeof(charset) - 1);

        for (n = 0; n < dest_size; n++) {
            dest[n] = charset[rand() % l];
        }
    }
}

void
generate_record(
    char *      key_buf,
    size_t      key_buf_size,
    char *      val_buf,
    size_t      val_buf_size,
    int         key_len,
    int         val_len,
    const char *val_data,
    long        key_idx)
{
    int n;

    assert(val_len <= val_buf_size);
    assert(key_len <= key_buf_size);
    assert(key_len > 0);

    // size param to snprintf includes terminating null byte
    n = snprintf(key_buf, key_buf_size, "%0*ld", key_len - 1, key_idx);
    assert(n < key_buf_size);
    n = n; /* unused */

    if (val_len > key_len) {
        int val_pfx_len = val_len - key_len;

        memcpy(val_buf, val_data, val_pfx_len);

        // key string includes terminating null byte
        memcpy(val_buf + val_pfx_len, key_buf, key_len);
    } else {
        strncpy(val_buf, val_data, val_buf_size - 1);
        val_buf[val_buf_size - 1] = '\0';
    }
}
int
create_or_open_kvs(
    struct hse_kvdb *kvdb,
    const char *     kvs_name,
    struct hse_kvs **kvs_out,
    int              transactions_enable)
{
    struct hse_kvs *kvs;
    hse_err_t       err;
    int             status = 0;
    const char *    paramv[MAX_PARAMS];
    int             paramc = 0;
    char            msg[100];

    if (transactions_enable) {
        paramv[paramc] = "transactions.enabled=true";
        paramc++;
    }

    log_info("opening kvs \"%s\"", kvs_name);

    err = hse_kvdb_kvs_open(kvdb, kvs_name, paramc, paramv, &kvs);

    if (hse_err_to_errno(err) == ENOENT) {
        log_info("kvs \"%s\" does not exist, creating it", kvs_name);

        err = hse_kvdb_kvs_create(kvdb, kvs_name, 0, NULL);

        if (err) {
            status = hse_err_to_errno(err);
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvdb_kvs_create: error=%d msg=\"%s\" kvs_name=\"%s\"", status, msg, kvs_name);
            goto errout;
        } else {
            log_debug("hse_kvdb_kvs_create: success kvs_name=\"%s\"", kvs_name);
        }

        err = hse_kvdb_kvs_open(kvdb, kvs_name, paramc, paramv, &kvs);
    }

    if (err) {
        status = hse_err_to_errno(err);
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_kvs_open: error=%d msg=\"%s\" kvs_name=\"%s\"", status, msg, kvs_name);
        goto errout;
    } else {
        log_debug("hse_kvdb_kvs_open: success kvs_name=\%s\"", kvs_name);
    }

    *kvs_out = kvs;

errout:
    return status;
}

int
create_or_open_kvdb_and_kvs(
    char *            kvdb_home,
    char *            kvs_name,
    struct hse_kvdb **kvdb_out,
    struct hse_kvs ** kvs_out,
    bool              drop,
    int               wal_disable,
    int               transactions_enable)
{
    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;
    hse_err_t        err;
    clock_t          t1, t2;
    int              status;
    char             msg[100];
    const char *     paramv[MAX_PARAMS];
    int              paramc = 0;

    paramc = 0;
    status = 0;

    if (wal_disable) {
        paramv[paramc] = "durability.enabled=false";
        paramc++;
    }

    if (drop) {
        log_info("drop kvdb at \"%s\"", kvdb_home);

        t1 = clock();
        err = hse_kvdb_drop(kvdb_home);
        t2 = clock();

        if (err && hse_err_to_errno(err) != ENOENT) {
            status = hse_err_to_errno(err);
            hse_strerror(err, msg, sizeof(msg));
            log_error("hse_kvdb_drop: error=%d msg=\"%s\"");
            goto errout;
        } else if (err == 0) {
            log_info("kvdb drop time elapsed: %f seconds", (double)(t2 - t1) / CLOCKS_PER_SEC);
        }
    }

    log_info("open kvdb at \"%s\"", kvdb_home);

    t1 = clock();
    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    t2 = clock();

    if (hse_err_to_errno(err) == ENOENT) {
        log_info("kvdb \"%s\" does not exist, creating it", kvdb_home);

        err = hse_kvdb_create(kvdb_home, 0, NULL);

        if (err) {
            status = hse_err_to_errno(err);
            hse_strerror(err, msg, sizeof(msg));
            log_error("hse_kvdb_make: error=%d msg=\"%s\"", status, msg);
            goto errout;
        }

        err = hse_kvdb_open(kvdb_home, paramc, paramv, &kvdb);
    }

    if (err) {
        status = hse_err_to_errno(err);
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_open: error=%d msg=\"%s\"", status, msg);
        goto errout;
    }

    log_info("kvdb open time elapsed: %f seconds", (double)(t2 - t1) / CLOCKS_PER_SEC);

    print_storage_info(kvdb);

    kvs = NULL;

    t1 = clock();
    status = create_or_open_kvs(kvdb, kvs_name, &kvs, transactions_enable);
    t2 = clock();

    log_info("kvs open time elapsed: %f seconds", (double)(t2 - t1) / CLOCKS_PER_SEC);

    if (status) {
        goto errout;
    }

    *kvs_out = kvs;
    *kvdb_out = kvdb;

errout:
    return status;
}

void
print_storage_info(struct hse_kvdb *kvdb)
{
    hse_err_t              err;
    struct hse_mclass_info info;
    char                   buf[256];

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        err = hse_kvdb_mclass_info_get(kvdb, i, &info);
        if (err) {
            hse_strerror(err, buf, sizeof(buf));
            log_error("hse_kvdb_storage_info_get: errno=%d msg=\"%s\"", hse_err_to_errno(err), buf);
        } else {
            log_info("%s: allocated_bytes=%ld used_bytes=%ld", hse_mclass_name_get(i),
                info.mi_allocated_bytes, info.mi_used_bytes);
        }
    }
}

int
timer_start(
    unsigned int        interval,
    time_handler        handler,
    t_timer             type,
    void *              user_data,
    struct timer_node **node_out)
{
    struct timer_node *new_node = NULL;
    struct itimerspec  new_value;
    int                rc;

    new_node = (struct timer_node *)malloc(sizeof(struct timer_node));

    if (new_node == NULL)
        return 1;

    new_node->callback = handler;
    new_node->user_data = user_data;
    new_node->interval = interval;
    new_node->type = type;

    new_node->fd = timerfd_create(CLOCK_REALTIME, 0);

    if (new_node->fd == -1) {
        free(new_node);
        return 1;
    }

    new_value.it_value.tv_sec = interval;
    new_value.it_value.tv_nsec = 0;

    if (type == TIMER_PERIODIC)
        new_value.it_interval.tv_sec = interval;
    else
        new_value.it_interval.tv_sec = 0;

    new_value.it_interval.tv_nsec = 0;

    rc = timerfd_settime(new_node->fd, 0, &new_value, NULL);

    if (rc) {
        free(new_node);
        return 1;
    }

    /*Inserting the timer node into the list*/
    new_node->next = g_head;
    g_head = new_node;

    *node_out = new_node;

    return 0;
}

int
timer_stop(struct timer_node *node)
{
    struct timer_node *tmp = NULL;
    int                rc;

    if (node == NULL)
        return 0;

    rc = close(node->fd);

    if (rc)
        return 1;

    if (node == g_head)
        g_head = g_head->next;

    tmp = g_head;

    while (tmp && tmp->next != node)
        tmp = tmp->next;

    if (tmp && tmp->next)
        tmp->next = tmp->next->next;

    free(node);

    return 0;
}

void
timer_finalize(void)
{
    while (g_head)
        timer_stop(g_head);

    pthread_cancel(g_thread_id);
    pthread_join(g_thread_id, NULL);
}

struct timer_node *
_get_timer_from_fd(int fd)
{
    struct timer_node *tmp = g_head;

    while (tmp) {
        if (tmp->fd == fd)
            return tmp;

        tmp = tmp->next;
    }
    return NULL;
}

void *
_timer_thread(void *data)
{
    struct pollfd      ufds[MAX_TIMER_COUNT] = { { 0 } };
    int                iMaxCount = 0;
    struct timer_node *tmp = NULL;
    int                read_fds = 0, i, s;
    uint64_t           exp;

    while (1) {
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        iMaxCount = 0;
        tmp = g_head;

        memset(ufds, 0, sizeof(struct pollfd) * MAX_TIMER_COUNT);
        while (tmp) {
            ufds[iMaxCount].fd = tmp->fd;
            ufds[iMaxCount].events = POLLIN;
            iMaxCount++;

            tmp = tmp->next;
        }
        read_fds = poll(ufds, iMaxCount, 100);

        if (read_fds <= 0)
            continue;

        for (i = 0; i < iMaxCount; i++) {
            if (ufds[i].revents & POLLIN) {
                s = read(ufds[i].fd, &exp, sizeof(uint64_t));

                if (s != sizeof(uint64_t))
                    continue;

                tmp = _get_timer_from_fd(ufds[i].fd);

                if (tmp && tmp->callback)
                    tmp->callback((size_t)tmp, tmp->user_data);
            }
        }
    }

    return NULL;
}

int
timer_initialize(void)
{
    int rc;

    rc = pthread_create(&g_thread_id, NULL, _timer_thread, NULL);

    return rc;
}
