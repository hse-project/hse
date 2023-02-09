/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <bsd/string.h>
#include <sys/timerfd.h>

#include <hse/hse.h>

#include <hse/cli/program.h>
#include <hse/util/compiler.h>
#include <hse/util/err_ctx.h>

#include <hse/test/fixtures/scratch_directory.h>

#include "stress_util.h"

#define MAX_KEY_LEN HSE_KVS_KLEN_MAX
#define MAX_VAL_LEN 4096
#define MAX_THREAD  500
#define MAX_RETRY   20

typedef enum {
    MULTIPLE_CURSOR = 1,
    CURSOR_WITH_MULTIPLE_SYNC = 5,
    TRANSACTIONS = 6,
} test_mode;

extern int DEBUG;
atomic_int active_cursor_count;
atomic_int error_count;
atomic_int kvdb_sync_flag;
atomic_int verification_failure_count;

struct cursor_test_data {
    char kvdb_home[PATH_MAX];
    char *kvs_name;
    long int key_count;
    int val_size;
    int thread_count;
    int key_size;
    int wal_disable;
    int cursor_test;
    unsigned int sync_time;
    int rank;
    long int key_index;
    long int transaction_count;
    unsigned long txn_timeout;
    long int transaction_per_thread;
    long int cursor_count;
    long int key_count_per_thread;
    long int key_count_per_txn;
    long int key_count_per_cursor;
    long int cursor_count_per_thread;
    long int cursor_count_per_txn;
    struct hse_kvs *kvs;
    struct hse_kvdb *kvdb;
    char data[MAX_VAL_LEN];
};

struct cursor_list {
    struct hse_kvs_cursor *cursor;
    long int start;
    long int end;
    char *failed_key_index;
};

void
kvdb_sync_handler(size_t timer_id, void *user_data)
{
    struct hse_kvdb *kvdb = (struct hse_kvdb *)user_data;
    hse_err_t err;
    char msg[100];

    kvdb_sync_flag = 1;
    err = hse_kvdb_sync(kvdb, 0);
    kvdb_sync_flag = 0;

    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_sync: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
        return;
    }

    log_info("hse_kvdb_sync: success");
}

void
print_usage(void)
{
    printf("Usage: stress_cursor\n"
           " -b <key size>\n"
           " -c <key count>\n"
           " -C <kvdb_home>\n"
           " -d <cursor test id>\n"
           "     1 = multiple cursor\n"
           "     2 = cursor with multiple sync\n"
           "     3 = transactions\n"
           " -e <cursor_count>\n"
           " -j <sync_time>\n"
           " -n <kvs name>\n"
           " -o <thread_count>\n"
           " -r <wal_disable>\n"
           " -s <transaction count>\n"
           " -t <txn_timeout> (in milliseconds)\n"
           " -u <debug>\n"
           " -v <value_size>\n");
}

long int
get_first_key_index(long int key_count_per_thread, int thread_index)
{
    long int i, firstkey = 1, lastkey = 0;

    for (i = 0; i < thread_index; i++) {
        lastkey = firstkey + key_count_per_thread - 1;
        firstkey = lastkey + 1;
    }
    return firstkey;
}

void *
verify_cursor(struct cursor_test_data *info, struct cursor_list *cursor_list)
{
    long int i = 0, cursor_index;
    struct hse_kvs_cursor *cursor;
    const void *cur_key, *cur_val;
    size_t cur_klen, cur_vlen;
    char expected_key_buf[info->key_size];
    char expected_val_buf[info->val_size];
    bool eof = false;
    hse_err_t err;
    char msg[100];

    log_info(
        "begin %s: rank=%d key_index=%ld cursor_count_per_thread=%ld", __func__, info->rank,
        info->key_index, info->cursor_count_per_thread);

    if (error_count > 0 || verification_failure_count > 0)
        return NULL;

    for (cursor_index = 0; cursor_index < info->cursor_count_per_thread; cursor_index++) {
        cursor = cursor_list[cursor_index].cursor;

        for (i = cursor_list[cursor_index].start; i < cursor_list[cursor_index].end; i++) {
            generate_record(
                expected_key_buf, sizeof(expected_key_buf), expected_val_buf,
                sizeof(expected_val_buf), info->key_size, info->val_size, info->data, i);

            if (i == cursor_list[cursor_index].start) {
                if (DEBUG) {
                    log_debug(
                        "hse_kvs_cursor_seek: rank=%d cursor=%ld key_index=%ld key=\"%s\"",
                        info->rank, cursor_index, i, expected_key_buf);
                }

                err = hse_kvs_cursor_seek(cursor, 0, expected_key_buf, info->key_size, NULL, NULL);

                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvs_cursor_seek: errno=%d msg=\"%s\" "
                        "rank=%d expected_key=\"%s\"",
                        hse_err_to_errno(err), msg, info->rank, expected_key_buf);
                    ++error_count;
                    goto out;
                }
            }

            err = hse_kvs_cursor_read(cursor, 0, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_cursor_read: errno=%d msg=\"%s\" rank=%d cursor=%ld key_index=%ld",
                    hse_err_to_errno(err), msg, info->rank, cursor_index, i);
                ++error_count;
                goto out;
            } else if (DEBUG) {
                log_debug(
                    "hse_kvs_cursor_read: rank=%d cursor=%ld key_index=%ld key=\"%*s\"", info->rank,
                    cursor_index, i, (int)cur_klen, (char *)cur_key);
            }

            if (eof) {
                log_error(
                    "hse_kvs_cursor_read: unexpected eof rank=%d start=%ld end=%ld failed=%ld",
                    info->rank, cursor_list[cursor_index].start, cursor_list[cursor_index].end, i);
                ++verification_failure_count;
                goto out;
            }

            if (info->key_size != cur_klen || info->val_size != cur_vlen) {
                log_error(
                    "FAILED key length verification: "
                    "actual_key_len=%ld expected_key_len=%d",
                    cur_klen, info->key_size);
                ++verification_failure_count;
                goto out;
            } else if (info->val_size != cur_vlen) {
                log_error(
                    "FAILED value length verfication: "
                    "actual_val_len=%ld expected_val_len=%d",
                    cur_vlen, info->val_size);
                ++verification_failure_count;
                goto out;
            } else if (memcmp(expected_key_buf, cur_key, info->key_size) != 0) {
                log_error(
                    "FAILED key verification: start=%ld end=%ld i=%ld "
                    "key=\"%*s\" expected_key=\"%s\"",
                    cursor_list[cursor_index].start, cursor_list[cursor_index].end, i,
                    (int)cur_klen, (char *)cur_key, expected_key_buf);
                ++verification_failure_count;
                goto out;
            } else if (memcmp(expected_val_buf, cur_val, info->val_size) != 0) {
                log_error(
                    "FAILED value verification: start=%ld end=%ld i=%ld "
                    "key=\"%*s\" value=\"%*s\" expected_value=\"%s\"",
                    cursor_list[cursor_index].start, cursor_list[cursor_index].end, i,
                    (int)cur_klen, (char *)cur_key, (int)cur_vlen, (char *)cur_val,
                    expected_val_buf);
                ++verification_failure_count;
                goto out;
            }
        }
    }

out:
    log_info(
        "end %s: rank=%d key_index=%ld cursor_count_per_thread=%ld", __func__, info->rank,
        info->key_index, info->cursor_count_per_thread);

    return NULL;
}

void *
insert_key_fast(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;
    long int i, cursor_index;
    char key_buf[info->key_size];
    char val_buf[info->val_size];
    struct cursor_list cursor_table[info->cursor_count_per_thread];
    struct hse_kvs_cursor *CURSOR;
    int retry = 0;
    int tmp_errno;
    hse_err_t err;
    char msg[100];

    log_info(
        "begin %s: rank=%d key_index=%ld cursor_count_per_thread=%ld key_count_per_cursor=%ld",
        __func__, info->rank, info->key_index, info->cursor_count_per_thread,
        info->key_count_per_cursor);

    if (error_count > 0 || verification_failure_count > 0)
        return NULL;

    memset(cursor_table, 0, sizeof(cursor_table));

    for (i = 0; i < info->cursor_count_per_thread; i++) {
        tmp_errno = 0;
        retry = 0;

        do {
            if (DEBUG) {
                log_debug("hse_kvs_cursor_create: rank=%d cursor=%ld", info->rank, i);
            }

            err = hse_kvs_cursor_create(info->kvs, 0, NULL, NULL, 0, &CURSOR);
            tmp_errno = hse_err_to_errno(err);

            if (tmp_errno == EAGAIN)
                sleep(10);
            retry++;
        } while (retry < MAX_RETRY && tmp_errno == EAGAIN);

        if (tmp_errno) {
            hse_strerror(err, msg, sizeof(msg));
            log_fatal(
                "hse_kvs_cursor_create: errno=%d msg=\"%s\" retry=%d active_cursor_count=%d",
                tmp_errno, msg, retry, active_cursor_count);
            ++error_count;
            return NULL;
        }

        ++active_cursor_count;

        cursor_table[i].cursor = CURSOR;
        cursor_table[i].start = info->key_index + i * info->key_count_per_cursor;
        cursor_table[i].end = cursor_table[i].start + info->key_count_per_cursor - 1;

        if (DEBUG) {
            log_debug(
                "cursor_table: rank=%d cursor=%ld start=%ld end=%ld", info->rank, i,
                cursor_table[i].start, cursor_table[i].end);
        }
    }

    for (cursor_index = 0; cursor_index < info->cursor_count_per_thread; cursor_index++) {
        for (i = cursor_table[cursor_index].start; i <= cursor_table[cursor_index].end; i++) {
            generate_record(
                key_buf, sizeof(key_buf), val_buf, sizeof(val_buf), info->key_size, info->val_size,
                info->data, i);

            retry = 0;
            tmp_errno = 0;

            while (kvdb_sync_flag != 0)
                sleep(1);

            do {
                if (DEBUG) {
                    log_debug("hse_kvs_put: rank=%d cursor=%ld key=\"%s\"", info->rank, i, key_buf);
                }

                err = hse_kvs_put(
                    info->kvs, 0, NULL, key_buf, info->key_size, val_buf, info->val_size);
                tmp_errno = hse_err_to_errno(err);

                if (tmp_errno == EAGAIN)
                    sleep(10);
                retry++;
            } while (retry < MAX_RETRY && tmp_errno == EAGAIN);

            if (tmp_errno) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_put: errno=%d msg=\"%s\" retry=%d key=\"%s\"", tmp_errno, msg, retry,
                    key_buf);
                ++error_count;
                goto clean_up;
            }
        }
    }

    for (i = 0; i < info->cursor_count_per_thread; i++) {
        retry = 0;
        tmp_errno = 0;

        do {
            if (DEBUG) {
                log_debug("hse_kvs_cursor_update_view: rank=%d cursor=%ld", info->rank, i);
            }

            err = hse_kvs_cursor_update_view(cursor_table[i].cursor, 0);
            tmp_errno = hse_err_to_errno(err);

            if (tmp_errno == EAGAIN)
                sleep(10);
            retry++;
        } while (retry < MAX_RETRY && tmp_errno == EAGAIN);

        if (tmp_errno) {
            ++error_count;
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvs_cursor_update: errno=%d msg=\"%s\" retry=%d rank=%d idx=%ld", tmp_errno,
                msg, retry, info->rank, i);
            goto clean_up;
        }
    }

    verify_cursor(info, cursor_table);

clean_up:
    for (i = 0; i < info->cursor_count_per_thread; i++) {
        if (DEBUG) {
            log_debug("hse_kvs_cursor_destroy: rank=%d cursor=%ld", info->rank, i);
        }

        err = hse_kvs_cursor_destroy(cursor_table[i].cursor);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvs_cursor_destroy: errno=%d msg=\"%s\" rank=%d idx=%ld",
                hse_err_to_errno(err), msg, info->rank, i);
            ++error_count;
        }

        --active_cursor_count;
    }

    log_info(
        "end %s: rank=%d key_index=%ld cursor_count_per_thread=%ld key_count_per_cursor=%ld",
        __func__, info->rank, info->key_index, info->cursor_count_per_thread,
        info->key_count_per_cursor);

    return NULL;
}

void *
cursor_with_transactions(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;
    long int txn_idx, i;
    char key_buf[info->key_size];
    char val_buf[info->val_size];
    struct hse_kvdb_txn *txn = NULL;
    struct hse_kvdb_txn *txn_table[info->transaction_per_thread];
    struct hse_kvs_cursor *CURSOR;
    struct cursor_list cursor_table[info->cursor_count_per_thread];
    long int cursor_index, cursor_index_this_txn;
    long int cursor_key_index = info->key_index;
    int retry;
    hse_err_t err;
    int tmp_errno;
    char msg[100];

    log_info(
        "begin %s: rank=%d key_index=%ld transaction_per_thread=%ld key_count_per_cursor=%ld",
        __func__, info->rank, info->key_index, info->transaction_per_thread,
        info->key_count_per_cursor);

    if (error_count > 0 || verification_failure_count > 0)
        return NULL;

    memset(cursor_table, 0, sizeof(cursor_table));

    for (i = 0; i < info->cursor_count_per_thread; i++) {
        cursor_table[i].start = cursor_key_index + i * info->key_count_per_cursor;
        cursor_table[i].end = cursor_table[i].start + info->key_count_per_cursor;
        if (DEBUG) {
            log_debug(
                "cursor_table: i=%ld start=%ld end=%ld", i, cursor_table[i].start,
                cursor_table[i].end);
        }
    }

    cursor_index = 0;

    for (txn_idx = 0; txn_idx < info->transaction_per_thread; txn_idx++) {
        txn = hse_kvdb_txn_alloc(info->kvdb);
        txn_table[txn_idx] = txn;

        if (txn == NULL) {
            log_error("hse_kvdb_txn_alloc failed");
            ++error_count;
            break;
        }

        err = hse_kvdb_txn_begin(info->kvdb, txn);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error(
                "hse_kvdb_txn_begin: errno=%d msg=\"%s\" rank=%d txn=%ld", hse_err_to_errno(err),
                msg, info->rank, txn_idx);

            hse_kvdb_txn_free(info->kvdb, txn);
            if (DEBUG) {
                log_debug("hse_kvdb_txn_free: rank=%d cursor=%ld", info->rank, cursor_index);
            }

            ++error_count;
            goto clean_up;
        } else if (DEBUG) {
            log_debug("hse_kvdb_txn_begin: rank=%d txn=%ld addr=%p", info->rank, txn_idx, txn);
        }

        for (cursor_index_this_txn = 0; cursor_index_this_txn < info->cursor_count_per_txn;
             cursor_index_this_txn++)
        {
            for (i = cursor_table[cursor_index].start; i < cursor_table[cursor_index].end; i++) {
                generate_record(
                    key_buf, sizeof(key_buf), val_buf, sizeof(val_buf), info->key_size,
                    info->val_size, info->data, i);

                retry = 0;
                tmp_errno = 0;

                while (kvdb_sync_flag != 0)
                    sleep(1);

                do {
                    if (DEBUG) {
                        log_debug(
                            "hse_kvs_put: rank=%d txn=%ld cursor=%ld key_index=%ld key=\"%s\"",
                            info->rank, txn_idx, cursor_index, i, key_buf);
                    }

                    err = hse_kvs_put(
                        info->kvs, 0, txn, key_buf, info->key_size, val_buf, info->val_size);
                    tmp_errno = hse_err_to_errno(err);

                    if (tmp_errno == EAGAIN) {
                        log_info("hse_kvs_put: retry=%d key=\"%s\"", retry, key_buf);
                        sleep(10);
                    }
                    retry++;
                } while (retry < MAX_RETRY && tmp_errno == EAGAIN);

                if (tmp_errno) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvs_put: errno=%d msg=\"%s\" key=\"%s\" txn=%ld cursor_idx=%ld",
                        hse_err_to_errno(err), msg, key_buf, txn_idx, cursor_index);
                    ++error_count;
                    goto clean_up;
                }
            }

            retry = 0;
            tmp_errno = 0;

            do {
                if (DEBUG) {
                    log_debug(
                        "hse_kvs_cursor_create: rank=%d txn=%ld cursor=%ld", info->rank, txn_idx,
                        cursor_index);
                }

                err = hse_kvs_cursor_create(info->kvs, 0, txn, NULL, 0, &CURSOR);
                tmp_errno = hse_err_to_errno(err);
                if (tmp_errno == EAGAIN)
                    sleep(10);
                retry++;
            } while (retry < MAX_RETRY && tmp_errno == EAGAIN);

            if (tmp_errno) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_cursor_create: errno=%d msg=\"%s\" rank=%d", tmp_errno, msg,
                    info->rank);
                ++error_count;
                goto clean_up;
            }

            ++active_cursor_count;

            cursor_table[cursor_index].cursor = CURSOR;
            cursor_index++;
        } /* end for cursor_index_this_txn */
    }     /* end for txn */

    verify_cursor(info, cursor_table);

clean_up:
    for (i = 0; i < info->cursor_count_per_thread; i++) {
        if (NULL != cursor_table[i].cursor) {
            err = hse_kvs_cursor_destroy(cursor_table[i].cursor);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_cursor_destroy: errno=%d msg=\"%s\" rank=%d cursor_idx=%ld",
                    hse_err_to_errno(err), msg, info->rank, i);
                ++error_count;
            } else if (DEBUG) {
                log_debug("hse_kvs_cursor_destroy: rank=%d cursor=%ld", info->rank, i);
            }
        }

        --active_cursor_count;
    }

    for (i = 0; i < info->transaction_per_thread; i++) {
        txn = txn_table[i];
        if (NULL != txn) {
            err = hse_kvdb_txn_abort(info->kvdb, txn);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvdb_txn_abort: errno=%d msg=\"%s\" rank=%d cursor_idx=%ld txn_addr=%p",
                    hse_err_to_errno(err), msg, info->rank, i, txn);
                ++error_count;
            } else if (DEBUG) {
                log_debug(
                    "hse_kvdb_txn_abort: rank=%d cursor_idx=%ld txn_addr=%p", info->rank, i, txn);
            }

            hse_kvdb_txn_free(info->kvdb, txn);

            if (DEBUG) {
                log_debug(
                    "hse_kvdb_txn_free: rank=%d cursor_idx=%ld txn_addr=%p", info->rank, i, txn);
            }
        }
    }

    log_info(
        "end %s: rank=%d key_index=%ld key_count_per_cursor=%ld", __func__, info->rank,
        info->key_index, info->key_count_per_cursor);

    return NULL;
}

void *
get_cursor_test(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;

    if (info->cursor_test == TRANSACTIONS)
        return cursor_with_transactions;
    else
        return insert_key_fast;
}

const char *
get_test_name(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;

    if (info->cursor_test == TRANSACTIONS)
        return "cursor_with_transactions";
    else
        return "insert_key_fast";
}

void
spawn_threads(
    struct cursor_test_data *params,
    struct cursor_list *cursors,
    void *thread_fun,
    const char *fun_name)
{
    int proc = 0;
    int numberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t thread_info[MAX_THREAD];
    int thread;
    char buf[100];
    struct cursor_test_data args[MAX_THREAD];
    int rc;

    log_info("number of processors: %d", numberOfProcessors);
    log_info("spawning %d thread(s), fun_name=\"%s\"", params->thread_count, fun_name);

    for (thread = 0; thread < params->thread_count; thread++) {
        int rc, j;
        pthread_attr_t attr;
        cpu_set_t cpus;
        int n HSE_MAYBE_UNUSED;

        pthread_attr_init(&attr);

        params->rank = thread;
        params->key_index = get_first_key_index(params->key_count_per_thread, thread);

        memcpy(&args[thread], params, sizeof(struct cursor_test_data));
        memcpy(&args[thread].data, params->data, sizeof(params->data));

        CPU_ZERO(&cpus);
        CPU_SET(proc, &cpus);
        proc += 2;
        if (proc >= numberOfProcessors)
            proc = 0;

        rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
        if (rc != 0)
            log_fatal("pthread_attr_setaffinity_np: errno=%d", rc);

        pthread_create(&thread_info[thread], &attr, thread_fun, (void *)&args[thread]);

        pthread_attr_destroy(&attr);

        /* Check the actual affinity mask assigned to the thread */
        rc = pthread_getaffinity_np(thread_info[thread], sizeof(cpu_set_t), &cpus);
        if (rc != 0)
            log_fatal("pthread_getaffinity_np: errno=%d", rc);

        log_info("set returned by pthread_getaffinity_np() contained:");
        for (j = 0; j < CPU_SETSIZE; j++) {
            if (CPU_ISSET(j, &cpus)) {
                log_info("thread=%d cpu=%d", thread, j);
            }
        }

        n = snprintf(buf, sizeof(buf), "%s-%03d", fun_name, thread);
        assert(n < sizeof(buf));

        pthread_setname_np(thread_info[thread], buf);
    }

    for (thread = 0; thread < params->thread_count; thread++) {
        rc = pthread_join(thread_info[thread], NULL);
        if (rc)
            log_error("pthread_join: errno=%d", rc);
    }

    log_info(
        "completed wait for %d spawned thread(s), fun_name=\"%s\"", params->thread_count, fun_name);
}

long int
get_count_per_x(long int long_count, int x)
{
    long int count_per_x = long_count;

    if (long_count % x)
        count_per_x = long_count + (x - long_count % x);

    return count_per_x / x;
}

int
execute_test(struct cursor_test_data *params)
{
    struct hse_kvdb *kvdb;
    struct cursor_list cursor_list[200];
    struct timer_node *node;
    int status = 0;
    int tmp_errno;
    hse_err_t err;
    int timer_rc;
    char msg[100];

    srand(time(NULL));
    fillrandom(params->data, sizeof(params->data));

    params->key_count_per_thread = get_count_per_x(params->key_count, params->thread_count);
    params->cursor_count_per_thread = get_count_per_x(params->cursor_count, params->thread_count);
    params->key_count_per_cursor =
        get_count_per_x(params->key_count_per_thread, params->cursor_count_per_thread);

    if (params->cursor_test == TRANSACTIONS) {
        params->cursor_count_per_txn = params->cursor_count / params->transaction_count;
        params->transaction_per_thread =
            get_count_per_x(params->transaction_count, params->thread_count);
        params->key_count_per_txn =
            get_count_per_x(params->key_count_per_thread, params->transaction_per_thread);
    }

    /* C1 should be disabled for kvdb sync to work */
    if (params->cursor_test == CURSOR_WITH_MULTIPLE_SYNC)
        params->wal_disable = 1;

    tmp_errno = create_or_open_kvdb_and_kvs(
        params->kvdb_home, params->kvs_name, &kvdb, &params->kvs, true, params->wal_disable,
        params->txn_timeout, params->cursor_test == TRANSACTIONS ? 1 : 0);

    params->kvdb = kvdb;

    if (tmp_errno) {
        log_fatal("kvdb+kvs open failed: errno=%d", tmp_errno);
        return 1;
    }

    if (params->cursor_test == CURSOR_WITH_MULTIPLE_SYNC) {
        timer_rc = timer_initialize();
        if (timer_rc) {
            log_fatal("timer_initialize: status=%d", timer_rc);
            return 1;
        }

        timer_rc = timer_start(params->sync_time, kvdb_sync_handler, TIMER_PERIODIC, kvdb, &node);
        if (timer_rc) {
            log_fatal("timer_start: status=%d", timer_rc);
            return 1;
        }
    }

    spawn_threads(params, cursor_list, get_cursor_test(params), get_test_name(params));

    /* kill the process */
    if (params->cursor_test == CURSOR_WITH_MULTIPLE_SYNC) {
        timer_rc = timer_stop(node);

        if (timer_rc) {
            log_fatal("timer_stop: status=%d", timer_rc);
            status = 1;
        }

        timer_finalize();
        err = hse_kvdb_sync(kvdb, 0);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_error("hse_kvdb_sync: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
        } else if (DEBUG) {
            log_debug("hse_kvdb_sync");
        }
    }

    if (error_count > 0) {
        log_error("FAILED after %d error(s)", error_count);
        status = 1;
    } else if (verification_failure_count > 0) {
        log_error("FAILED after %d verification failure(s)", verification_failure_count);
        status = 1;
    } else
        log_info("PASSED verification");

    log_info("closing kvs \"%s\" in \"%s\"", params->kvs_name, params->kvdb_home);
    err = hse_kvdb_kvs_close(params->kvs);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_kvs_close: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
    }

    log_info("closing kvdb \"%s\"", params->kvdb_home);
    err = hse_kvdb_close(kvdb);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_close: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
    }

    return status;
}

int
main(int argc, char *argv[])
{
    int rc, option = 0;
    struct cursor_test_data para;
    hse_err_t err;

    memset(&para, 0, sizeof(para));

    para.kvs_name = "cursor_kvs";

    progname_set(argv[0]);

    while ((option = getopt(argc, argv, "b:c:C:d:e:j:n:n:o:r:s:t:u:v:")) != -1) {
        switch (option) {
        case 'b':
            para.key_size = atoi(optarg);
            break;

        case 'c':
            para.key_count = atoi(optarg);
            break;

        case 'C': {
            size_t n;

            n = strlcpy(para.kvdb_home, optarg, sizeof(para.kvdb_home));
            if (n >= sizeof(para.kvdb_home)) {
                fprintf(stderr, "KVDB home directory too long\n");
                return EX_USAGE;
            }

            break;
        }

        case 'd':
            para.cursor_test = atoi(optarg);
            break;

        case 'e':
            para.cursor_count = atoi(optarg);
            break;

        case 'j':
            para.sync_time = atoi(optarg);
            break;

        case 'n':
            para.kvs_name = optarg;
            break;

        case 'o':
            para.thread_count = atoi(optarg);
            break;

        case 'r':
            para.wal_disable = atoi(optarg);
            break;

        case 's':
            para.transaction_count = atoi(optarg);
            break;

        case 't':
            para.txn_timeout = atoll(optarg);
            break;

        case 'u':
            DEBUG = atoi(optarg);
            break;

        case 'v':
            para.val_size = atoi(optarg);
            break;

        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (argc == 1) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    if (para.kvdb_home[0] == '\0') {
        merr_t err;
        char buf[256];

        err = scratch_directory_setup(progname, para.kvdb_home, sizeof(para.kvdb_home));
        if (err) {
            fprintf(
                stderr, "%s: Failed to setup scratch directory: %s", progname,
                merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL));
            return EX_CANTCREAT;
        }
    }

    log_info("cursor_count                  = %ld", para.cursor_count);
    log_info("cursor_test                   = %d", para.cursor_test);
    log_info("debug                         = %d", DEBUG);
    log_info("key_count                     = %ld", para.key_count);
    log_info("key_size                      = %d", para.key_size);
    log_info("kvdb_home                     = \"%s\"", para.kvdb_home);
    log_info("kvs_name                      = \"%s\"", para.kvs_name);
    log_info("thread_count                  = %d", para.thread_count);
    log_info("transaction_count             = %ld", para.transaction_count);
    log_info("sync_time                     = %d", para.sync_time);
    log_info("val_size                      = %d", para.val_size);
    log_info("wal_disable                   = %d\n", para.wal_disable);

    assert(para.key_size > 0 || para.key_count > 0 || para.val_size > 0);

    if (para.key_count % para.thread_count) {
        para.key_count += para.thread_count - (para.key_count % para.thread_count);
        log_info("adjusted key_count to %ld", para.key_count);
    }

    if (para.cursor_count < para.thread_count) {
        para.cursor_count = para.thread_count;
        log_info("adjusted cursor_count to %ld", para.cursor_count);
    }

    if (para.cursor_test == TRANSACTIONS)
        if (para.thread_count > para.transaction_count) {
            para.thread_count = para.transaction_count;
            log_info("adjusted thread_count to %d", para.thread_count);
        }

    /* [HSE_REVISIT]: Re-evaluate options to make room for -c/--config */
    err = hse_init(NULL, 0, NULL);
    if (err) {
        log_fatal("hse_init: errno=%d", hse_err_to_errno(err));
        exit(EXIT_FAILURE);
    }

    rc = execute_test(&para);

    hse_fini();

    exit(rc);
}
