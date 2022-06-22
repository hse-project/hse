/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef _STRESS_UTIL_H
#define _STRESS_UTIL_H

#include <stdlib.h>
#include <hse/hse.h>

extern int DEBUG;

enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

long long
current_timestamp_ms();
void
log_print(int level, const char *fmt, ...);
#define log_debug(...)                     \
    if (DEBUG) {                           \
        log_print(LOG_DEBUG, __VA_ARGS__); \
    }
#define log_info(...)  log_print(LOG_INFO, __VA_ARGS__)
#define log_warn(...)  log_print(LOG_WARN, __VA_ARGS__)
#define log_error(...) log_print(LOG_ERROR, __VA_ARGS__)
#define log_fatal(...) log_print(LOG_FATAL, __VA_ARGS__)

void
gen_kvs_ext_name(char *dest, size_t dest_size, const char *base_kvs_name, long int txn, int rank);
void
fillrandom(char *dest, size_t dest_size);

void
generate_record(
    char *      key_buf,
    size_t      key_buf_size,
    char *      val_buf,
    size_t      val_buf_size,
    int         key_len,
    int         val_len,
    const char *val_data,
    long        key_idx);

int
create_or_open_kvs(
    struct hse_kvdb *kvdb,
    const char *     kvs_name,
    struct hse_kvs **kvs_out,
    int              transactions_enable);

int
create_or_open_kvdb_and_kvs(
    char *            mpool_name,
    char *            kvs_name,
    struct hse_kvdb **kvdb_out,
    struct hse_kvs ** kvs_out,
    bool              drop,
    int               wal_disable,
    uint64_t          txn_timeout,
    int               transactions_enable);

void
print_storage_info(struct hse_kvdb *kvdb);

typedef void (*time_handler)(size_t timer_id, void *user_data);
typedef enum { TIMER_SINGLE_SHOT = 0, TIMER_PERIODIC } t_timer;
struct timer_node {
    int                fd;
    time_handler       callback;
    void *             user_data;
    unsigned int       interval;
    t_timer            type;
    struct timer_node *next;
};
int
timer_initialize(void);
void
timer_finalize(void);
int
timer_start(
    unsigned int        interval,
    time_handler        handler,
    t_timer             type,
    void *              user_data,
    struct timer_node **node_out);
int
timer_stop(struct timer_node *node);

#endif
