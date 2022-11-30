/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <bsd/string.h>

#include <hse/cli/program.h>
#include <hse/error/merr.h>
#include <hse/hse.h>
#include <hse/test/fixtures/scratch_directory.h>
#include <hse/util/compiler.h>
#include <hse/util/err_ctx.h>

#include "stress_util.h"

#define MAX_KEY_LEN 2048
#define MAX_VAL_LEN 4096
#define MAX_THREAD  500

typedef enum {
    NONE = 0,
    TXN_ENABLED = 1,
    INTERLEAVE_ABORTED_TXN = 2,
    KVS_PER_TXN = 4,
    TXN_TYPE_LAST
} txn_mode;

const char *test_names[] = { "NONE",       "TXN_ENABLED", "INTERLEAVE_ABORTED_TXN",
                             "DEPRECATED", "KVS_PER_TXN", "TXN_TYPE_LAST" };

extern int DEBUG;
atomic_int aborted_txn_found_count;
atomic_int active_cursor_count;
atomic_int error_count;
atomic_int verification_failure_count;

struct txn_info {
    struct hse_kvdb_txn *txn;
    struct hse_kvs *     kvs;
};

struct test_params {
    char             kvdb_home[PATH_MAX];
    char *           kvdb_name;
    char *           kvs_name;
    long int         key_count;
    int              val_size;
    int              thread_count;
    int              shutdown_type;
    int              sleep_after_load_ms;
    int              sync;
    int              key_size;
    int              transaction;
    int              variable_key_size;
    int              variable_val_size;
    int              wal_disable;
    int              transaction_count;
    long int         key_count_per_thread;
    long int         transactions_per_thread;
    struct hse_kvs * kvs;
    struct hse_kvdb *kvdb;
    int              rank;                   /* thread specific */
    long int         thread_start_key_index; /* thread specific */
    char             data[MAX_VAL_LEN];
    char             data2[MAX_VAL_LEN]; /* alternate data if -p and -q specified */
};

void
print_usage(void)
{
    printf("Usage: stress_wal\n"
           " -b <key size>\n"
           " -c <key count>\n"
           " -C <kvdb_home>\n"
           " -e <close after load>   0 = no 1 = yes\n"
           " -i <sync after load>    0 = no 1 = yes\n"
           " -o <thread_count>\n"
           " -n <kvs name>\n"
           " -p <variable_key_size>\n"
           " -q <variable_val_size>\n"
           " -r <wal_disable>        0 = no 1 = yes\n"
           " -s <transaction_count>\n"
           " -t <1 = transaction enabled\n"
           "     2 = transaction_abort_test\n"
           "     4 = kvs per transaction>\n"
           " -u <debug>              0 = no 1 = yes\n"
           " -v <value_size>\n"
           " -y <sleep ms after load>\n");
}

void *
do_inserts(void *args)
{
    struct test_params * params = (struct test_params *)args;
    long int             txn_idx, i, key_index_offset;
    long int             keys_per_txn;
    long int             transactions_per_thread;
    struct hse_kvdb_txn *txn;
    struct hse_kvs *     kvs;
    char                 kvs_name[31];
    int                  key_len;
    int                  val_len;
    char                 key_buf[MAX_KEY_LEN];
    char                 val_buf[MAX_VAL_LEN];
    hse_err_t            err;
    unsigned int         flags;
    char *               expected_val_data;
    char                 msg[100];
    int                  status;
    int                  transactions_enable;
    struct txn_info *txn_table;

    if (params->transaction) {
        transactions_enable = 1;
        transactions_per_thread = params->transactions_per_thread;
        keys_per_txn = params->key_count_per_thread / params->transactions_per_thread;
    } else {
        transactions_enable = 0;
        transactions_per_thread = 1;
        keys_per_txn = params->key_count_per_thread;
    }

    txn_table = calloc(transactions_per_thread, sizeof(*txn_table));
    if (!txn_table) {
        log_error("Failed to allocate memory");
        return NULL;
    }

    key_index_offset = params->thread_start_key_index;
    kvs = params->kvs;
    txn = NULL;
    txn_table[0].kvs = kvs;
    flags = 0;

    for (txn_idx = 0; txn_idx < transactions_per_thread; txn_idx++) {
        if (params->transaction == KVS_PER_TXN) {
            gen_kvs_ext_name(kvs_name, sizeof(kvs_name), params->kvs_name, txn_idx, params->rank);

            status = create_or_open_kvs(params->kvdb, kvs_name, &kvs, transactions_enable);

            if (status) {
                ++error_count;
                break;
            }

            txn_table[txn_idx].kvs = kvs;
        }

        if (params->transaction) {
            txn = hse_kvdb_txn_alloc(params->kvdb);
            if (txn == NULL) {
                log_error("hse_kvdb_txn_alloc failed");
                ++error_count;
                break;
            }

            err = hse_kvdb_txn_begin(params->kvdb, txn);
            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvdb_txn_begin: errno=%d msg=\"%s\" rank=%d txn=%ld",
                    hse_err_to_errno(err),
                    msg,
                    params->rank,
                    txn_idx);

                hse_kvdb_txn_free(params->kvdb, txn);
                log_debug("hse_kvdb_txn_free: rank=%d txn=%ld", params->rank, txn_idx);

                ++error_count;
                goto clean_up;
            } else {
                log_debug("hse_kvdb_txn_begin: rank=%d txn=%ld", params->rank, txn_idx);
            }

            txn_table[txn_idx].txn = txn;
        }

        for (i = key_index_offset; i < key_index_offset + keys_per_txn; i++) {
            if (params->variable_key_size == 0 || (i % 2) == 0) {
                key_len = params->key_size;
            } else {
                key_len = params->variable_key_size;
            }

            if (params->variable_val_size == 0 || (i % 2) == 0) {
                val_len = params->val_size;
                expected_val_data = params->data;
            } else {
                val_len = params->variable_val_size;
                expected_val_data = params->data2;
            }

            generate_record(
                key_buf,
                sizeof(key_buf),
                val_buf,
                sizeof(val_buf),
                key_len,
                val_len,
                expected_val_data,
                i);

            if (params->transaction) {
                err = hse_kvs_put(kvs, flags, txn, key_buf, key_len, val_buf, val_len);
                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvs_put: errno=%d msg=\"%s\" rank=%d txn=%ld key=\"%s\"",
                        hse_err_to_errno(err),
                        msg,
                        params->rank,
                        txn_idx,
                        key_buf);
                    ++error_count;
                    goto clean_up;
                } else {
                    log_debug(
                        "hse_kvs_put: rank=%d txn=%ld key=\"%s\"", params->rank, txn_idx, key_buf);
                }
            } else {
                err = hse_kvs_put(kvs, 0, NULL, key_buf, key_len, val_buf, val_len);
                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvs_put: errno=%d msg=\"%s\" rank=%d key=\"%s\"",
                        hse_err_to_errno(err),
                        msg,
                        params->rank,
                        key_buf);
                    ++error_count;
                    goto clean_up;
                } else {
                    log_debug("hse_kvs_put: rank=%d key=\"%s\"", params->rank, key_buf);
                }
            }
        }

        key_index_offset += keys_per_txn;
    }

clean_up:
    for (txn_idx = 0; txn_idx < transactions_per_thread; txn_idx++) {
        txn = txn_table[txn_idx].txn;
        kvs = txn_table[txn_idx].kvs;

        if (txn != NULL) {
            if (params->transaction == INTERLEAVE_ABORTED_TXN && (txn_idx % 2) == 0) {
                err = hse_kvdb_txn_abort(params->kvdb, txn);
                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvdb_txn_abort: errno=%d msg=\"%s\" rank=%d txn=%ld",
                        hse_err_to_errno(err),
                        msg,
                        params->rank,
                        txn_idx);
                    ++error_count;
                } else {
                    log_debug("hse_kvdb_txn_abort: rank=%d txn=%ld", params->rank, txn_idx);
                }
            } else {
                err = hse_kvdb_txn_commit(params->kvdb, txn);
                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvdb_txn_commit: errno=%d msg=\"%s\" rank=%d txn=%ld",
                        hse_err_to_errno(err),
                        msg,
                        params->rank,
                        txn_idx);
                    ++error_count;
                } else {
                    log_debug("hse_kvdb_txn_commit: rank=%d txn=%ld", params->rank, txn_idx);
                }
            }

            hse_kvdb_txn_free(params->kvdb, txn);
            log_debug("hse_kvdb_txn_free: rank=%d txn=%ld", params->rank, txn_idx);
        }

        if (kvs != NULL) {
            if (params->transaction == KVS_PER_TXN) {
                err = hse_kvdb_kvs_close(txn_table[txn_idx].kvs);
                if (err) {
                    hse_strerror(err, msg, sizeof(msg));
                    log_error(
                        "hse_kvdb_kvs_close: errno=%d msg=\"%s\" rank=%d txn=%ld",
                        hse_err_to_errno(err),
                        msg,
                        params->rank,
                        txn_idx);
                    ++error_count;
                } else {
                    log_info("hse_kvdb_kvs_close: rank=%d txn=%ld", params->rank, txn_idx);
                }
            }
        }
    }

    free(txn_table);

    return NULL;
}

void *
verify_records(void *args)
{
    struct test_params *params = (struct test_params *)args;
    long int            txn_idx, i, key_index_offset;
    long int            keys_per_txn;
    long int            transactions_per_thread;
    char                kvs_name[31];
    struct hse_kvs *    kvs;
    int                 key_len;
    int                 val_len;
    char                key_buf[MAX_KEY_LEN];
    char                val_buf[MAX_VAL_LEN];
    bool                found = false;
    size_t              vlen;
    hse_err_t           err;
    char                expected_key_buf[MAX_KEY_LEN];
    char                expected_val_buf[MAX_VAL_LEN];
    char *              expected_val_data;
    char                msg[100];

    key_index_offset = params->thread_start_key_index;
    kvs = params->kvs;

    if (params->transaction) {
        transactions_per_thread = params->transactions_per_thread;
        keys_per_txn = params->key_count_per_thread / params->transactions_per_thread;
    } else {
        transactions_per_thread = 1;
        keys_per_txn = params->key_count_per_thread;
    }

    for (txn_idx = 0; txn_idx < transactions_per_thread; txn_idx++) {
        if (params->transaction == KVS_PER_TXN) {
            gen_kvs_ext_name(kvs_name, sizeof(kvs_name), params->kvs_name, txn_idx, params->rank);

            err = hse_kvdb_kvs_open(params->kvdb, kvs_name, 0, NULL, &kvs);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvdb_kvs_open: errno=%d msg=\"%s\" kvs_name=\"%s\" rank=%d txn_idx=%ld",
                    hse_err_to_errno(err),
                    msg,
                    kvs_name,
                    params->rank,
                    txn_idx);
                ++error_count;
                break;
            } else {
                log_debug(
                    "hse_kvdb_kvs_open: kvs_name=\"%s\" rank=%d txn_idx=%ld",
                    kvs_name,
                    params->rank,
                    txn_idx);
            }
        }

        for (i = key_index_offset; i < key_index_offset + keys_per_txn; i++) {
            if (params->variable_key_size == 0 || (i % 2) == 0) {
                key_len = params->key_size;
                val_len = params->val_size;
                expected_val_data = params->data;
            } else {
                key_len = params->variable_key_size;
                val_len = params->variable_val_size;
                expected_val_data = params->data2;
            }

            generate_record(
                expected_key_buf,
                sizeof(expected_key_buf),
                expected_val_buf,
                sizeof(expected_val_buf),
                key_len,
                val_len,
                expected_val_data,
                i);

            err = hse_kvs_get(
                kvs, 0, NULL, expected_key_buf, key_len, &found, val_buf, val_len, &vlen);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvs_get: errno=%d msg=\"%s\" rank=%d txn_idx=%ld key_idx=%ld",
                    hse_err_to_errno(err),
                    msg,
                    params->rank,
                    txn_idx,
                    i);
                ++error_count;
                break;
            } else {
                log_debug(
                    "hse_kvs_get: rank=%d txn_idx=%ld key=\"%s\"",
                    params->rank,
                    txn_idx,
                    expected_key_buf);
            }

            if (params->transaction == INTERLEAVE_ABORTED_TXN) {
                bool should_find = ((txn_idx % 2) == 1);

                if (found && !should_find) {
                    log_error(
                        "hse_kvs_get: aborted txn key found rank=%d key_idx=%ld key=\"%s\"",
                        params->rank,
                        i,
                        expected_key_buf);
                    aborted_txn_found_count++;
                    break;
                } else if (!found && should_find) {
                    log_error(
                        "hse_kvs_get: key missing rank=%d key_idx=%ld key=\"%s\"",
                        params->rank,
                        i,
                        expected_key_buf);
                    verification_failure_count++;
                    break;
                } else if (!found && !should_find) {
                    /* skip remaining validation */
                    continue;
                };
            } else {
                if (!found) {
                    log_error(
                        "hse_kvs_get: key missing rank=%d key_idx=%ld key=\"%s\"",
                        params->rank,
                        i,
                        expected_key_buf);
                    verification_failure_count++;
                    break;
                }
            }

            if (val_len != vlen) {
                log_error(
                    "FAILED value length verfication: "
                    "actual_val_len=%ld expected_val_len=%d",
                    vlen,
                    params->val_size);
                ++verification_failure_count;
                break;
            } else if (memcmp(expected_val_buf, val_buf, val_len) != 0) {
                log_error(
                    "FAILED value verification: key_idx=%ld "
                    "key=\"%s\" value=\"%s\" expected_value=\"%s\"",
                    i,
                    key_buf,
                    val_buf,
                    expected_val_buf);
                ++verification_failure_count;
                break;
            }
        }

        if (params->transaction == KVS_PER_TXN) {
            err = hse_kvdb_kvs_close(kvs);

            if (err) {
                hse_strerror(err, msg, sizeof(msg));
                log_error(
                    "hse_kvdb_kvs_close: errno=%d msg=\"%s\" kvs_name=\"%s\" rank=%d txn_idx=%ld",
                    hse_err_to_errno(err),
                    msg,
                    kvs_name,
                    params->rank,
                    txn_idx);
                ++error_count;
            } else {
                log_debug(
                    "hse_kvdb_kvs_close: kvs_name=\"%s\" rank=%d txn_idx=%ld",
                    kvs_name,
                    params->rank,
                    txn_idx);
            }
        }

        if (error_count || verification_failure_count || aborted_txn_found_count)
            break;

        key_index_offset += keys_per_txn;
    }

    return NULL;
}

void
spawn_threads(struct test_params *params, void *thread_fun, char *fun_name)
{
    pthread_t          thread_info[MAX_THREAD];
    struct test_params args[MAX_THREAD];
    int                thread;
    char               buf[100];
    int                pthread_errno;

    log_info("spawning %d thread(s), fun_name=\"%s\"", params->thread_count, fun_name);

    for (thread = 0; thread < params->thread_count; thread++) {
        int n HSE_MAYBE_UNUSED;

        params->rank = thread;
        params->thread_start_key_index = (thread * params->key_count_per_thread) + 1;

        memcpy(&args[thread], params, sizeof(struct test_params));
        memcpy(&args[thread].data, params->data, sizeof(params->data));
        memcpy(&args[thread].data2, params->data2, sizeof(params->data2));

        pthread_create(&thread_info[thread], NULL, thread_fun, (void *)&args[thread]);

        n = snprintf(buf, sizeof(buf), "%s-%03d", fun_name, thread);
        assert(n < sizeof(buf));

        pthread_setname_np(thread_info[thread], buf);
    }

    for (thread = 0; thread < params->thread_count; thread++) {
        pthread_errno = pthread_join(thread_info[thread], NULL);
        if (pthread_errno)
            log_error("pthread_join: errno=%d", pthread_errno);
    }

    log_info(
        "completed wait for %d spawned thread(s), fun_name=\"%s\"", params->thread_count, fun_name);
}

int
do_sync(struct test_params *params)
{
    char      msg[100];
    hse_err_t err;

    log_info("begin sync kvdb \"%s\"", params->kvdb_home);

    err = hse_kvdb_sync(params->kvdb, 0);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_sync: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
        return 1;
    }

    log_info("hse_kvdb_sync: success");

    return 0;
}

int
do_close(struct test_params *params)
{
    char      msg[100];
    hse_err_t err;

    print_storage_info(params->kvdb);

    log_info("closing kvs \"%s\" in \"%s\"", params->kvs_name, params->kvdb_home);
    err = hse_kvdb_kvs_close(params->kvs);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_kvs_close: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
        return 1;
    }

    log_info("closing kvdb \"%s\"", params->kvdb_home);
    err = hse_kvdb_close(params->kvdb);
    if (err) {
        hse_strerror(err, msg, sizeof(msg));
        log_error("hse_kvdb_close: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
        return 1;
    }

    return 0;
}

int
execute_test(struct test_params *params, int argc, char *argv[])
{
    int       status;
    int       transactions_enable = 0;
    pid_t     pid;
    hse_err_t err;

    srand(time(NULL));
    fillrandom(params->data, sizeof(params->data));
    fillrandom(params->data2, sizeof(params->data2));

    params->key_count_per_thread = params->key_count / params->thread_count;
    params->transactions_per_thread = params->transaction_count / params->thread_count;
    transactions_enable = (params->transaction > 0) ? 1 : 0;

    log_info("key_count_per_thread          = %ld", params->key_count_per_thread);
    log_info("transactions_per_thread       = %ld", params->transactions_per_thread);

    pid = fork();

    if (pid == 0) {
        log_info("begin child process");

        /* [HSE_REVISIT]: Re-evaluate options to make room for -c/--config */
        err = hse_init(NULL, 0, NULL);
        if (err) {
            log_print(LOG_FATAL, "hse_init: errno=%d", hse_err_to_errno(err));
            exit(EXIT_FAILURE);
        }

        status = create_or_open_kvdb_and_kvs(
            params->kvdb_home,
            params->kvs_name,
            &params->kvdb,
            &params->kvs,
            true,
            params->wal_disable,
            0,
            transactions_enable);

        if (status)
            exit(EXIT_FAILURE);

        spawn_threads(params, do_inserts, "do_inserts");

        if (error_count)
            exit(EXIT_FAILURE);

        if (params->sync != 0) {
            status = do_sync(params);
            if (status)
                exit(EXIT_FAILURE);
        }

        if (params->shutdown_type != 0) {
            status = do_close(params);
            if (status)
                exit(EXIT_FAILURE);

            hse_fini();

            log_info("exiting child process normally");
        } else {
            print_storage_info(params->kvdb);

            if (params->sync == 0) {
                log_info(
                    "sleeping %d ms in order for wal related writes to flush and sync to disk",
                    params->sleep_after_load_ms);
                usleep(params->sleep_after_load_ms * 1000);
            }

            log_info("exiting child process with unclean shutdown!");
        }

        exit(EXIT_SUCCESS);
    }

    pid = wait(&status);

    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        log_error("child process failed\n");
        return 1;
    } else {
        log_info("child process completed\n");
    }

    /* [HSE_REVISIT]: Re-evaluate options to make room for -c/--config */
    err = hse_init(NULL, 0, NULL);
    if (err) {
        log_print(LOG_FATAL, "hse_init: errno=%d", hse_err_to_errno(err));
        exit(EXIT_FAILURE);
    }

    status = create_or_open_kvdb_and_kvs(
        params->kvdb_home,
        params->kvs_name,
        &params->kvdb,
        &params->kvs,
        false,
        params->wal_disable,
        0,
        transactions_enable);

    if (status) {
        return 1;
    }

    spawn_threads(params, verify_records, "verify_records");

    if (error_count > 0) {
        log_error("FAILED after %d error(s)", error_count);
        status = 1;
    } else if (verification_failure_count > 0) {
        log_error("FAILED after %d verification failure(s)", verification_failure_count);
        status = 1;
    } else if (aborted_txn_found_count > 0) {
        log_error(
            "FAILED after finding %d record(s) in aborted transaction", aborted_txn_found_count);
        status = 1;
    } else
        log_info("PASSED verification");

    status = do_close(params);

    hse_fini();

    return status;
}

int
validate_arguments(struct test_params *params)
{
    int status = 0;
    int tmp;
    int key_count = params->key_count;
    int thread_count = params->thread_count;
    int transaction_count = params->transaction_count;

    if (params->key_count <= 0) {
        log_error("key_count must be greater than 0");
        status = 1;
    }
    if (params->key_size <= 0) {
        log_error("key_size must be greater than 0");
        status = 1;
    }
    if (params->val_size <= 0) {
        log_error("val_size must be greater than 0");
        status = 1;
    }
    if (params->kvdb_home[0] == '\0') {
        log_error("kvdb_home is required");
        status = 1;
    }
    if (params->transaction < 0 || params->transaction >= TXN_TYPE_LAST) {
        log_error("invalid transaction option %d", params->transaction);
        status = 1;
    }
    if (params->thread_count > MAX_THREAD) {
        log_error("thread count must be less than or equal to %d", MAX_THREAD);
        status = 1;
    }

    if (status == 0) {
        if (params->transaction) {
            if (transaction_count < thread_count) {
                log_warn(
                    "increased transaction_count from %d to %d", transaction_count, thread_count);
                transaction_count = thread_count;
            } else if (transaction_count % thread_count > 0) {
                tmp = transaction_count + (thread_count - (transaction_count % thread_count));
                log_warn("increased transaction_count from %d to %d", transaction_count, tmp);
                transaction_count = tmp;
            }

            if (key_count < transaction_count) {
                log_warn("increased key_count from %d to %d", key_count, transaction_count);
                key_count = transaction_count;
            } else if (key_count % transaction_count > 0) {
                tmp = key_count + (transaction_count - (key_count % transaction_count));
                log_warn("increased key_count from %d to %d", key_count, tmp);
                key_count = tmp;
            }
        } else {
            if (key_count < thread_count) {
                log_warn("increased key_count from %d to %d", key_count, thread_count);
                key_count = thread_count;
            } else if (key_count % thread_count > 0) {
                tmp = key_count + (thread_count - (key_count % thread_count));
                log_warn("increased key_count from %d to %d", key_count, tmp);
                key_count = tmp;
            }
        }

        params->key_count = key_count;
        params->transaction_count = transaction_count;
    }

    return status;
}

int
main(int argc, char *argv[])
{
    int                option = 0;
    struct test_params params;
    int                status;

    memset(&params, 0, sizeof(params));
    params.kvs_name = "kvs1";
    params.sleep_after_load_ms = 200;

    progname_set(argv[0]);

    while ((option = getopt(argc, argv, "b:c:C:e:i:n:o:p:t:q:r:s:u:v:y:")) != -1) {
        switch (option) {
            case 'b':
                params.key_size = atoi(optarg);
                break;

            case 'c':
                params.key_count = atoi(optarg);
                break;

            case 'C': {
                size_t n;

                n = strlcpy(params.kvdb_home, optarg, sizeof(params.kvdb_home));
                if (n >= sizeof(params.kvdb_home)) {
                    fprintf(stderr, "KVDB home directory too long\n");
                    return EX_USAGE;
                }

                break;
            }

            case 'e':
                params.shutdown_type = atoi(optarg);
                break;

            case 'i':
                params.sync = atoi(optarg);
                break;

            case 'n':
                params.kvs_name = optarg;
                break;

            case 'o':
                params.thread_count = atoi(optarg);
                break;

            case 'p':
                params.variable_key_size = atoi(optarg);
                break;

            case 't':
                params.transaction = atoi(optarg);
                break;

            case 'q':
                params.variable_val_size = atoi(optarg);
                break;

            case 'r':
                params.wal_disable = atoi(optarg);
                break;

            case 's':
                params.transaction_count = atoi(optarg);
                break;

            case 'u':
                DEBUG = atoi(optarg);
                break;

            case 'v':
                params.val_size = atoi(optarg);
                break;

            case 'y':
                params.sleep_after_load_ms = atoi(optarg);
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

    if (params.kvdb_home[0] == '\0') {
        merr_t err;
        char buf[256];

        err = scratch_directory_setup(progname, params.kvdb_home, sizeof(params.kvdb_home));
        if (err) {
            fprintf(stderr, "%s: Failed to setup scratch directory: %s",
                progname, merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL));
            return EX_CANTCREAT;
        }
    }

    if (validate_arguments(&params)) {
        exit(EXIT_FAILURE);
    }

    log_info("debug                         = %d", DEBUG);
    log_info("key_count                     = %ld", params.key_count);
    log_info("key_size                      = %d", params.key_size);
    log_info("kvdb_home                     = \"%s\"", params.kvdb_home);
    log_info("kvs_name                      = \"%s\"", params.kvs_name);
    log_info("thread_count                  = %d", params.thread_count);
    log_info("transaction_count             = %d", params.transaction_count);
    log_info(
        "transaction                   = %d [%s]",
        params.transaction,
        test_names[params.transaction]);
    log_info("shutdown_type                 = %d", params.shutdown_type);
    log_info("sleep_after_load_ms           = %d", params.sleep_after_load_ms);
    log_info("sync                          = %d", params.sync);
    log_info("val_size                      = %d", params.val_size);
    log_info("variable_key_size             = %d", params.variable_key_size);
    log_info("variable_val_size             = %d", params.variable_val_size);
    log_info("wal_disable                   = %d\n", params.wal_disable);

    status = execute_test(&params, argc, argv);

    exit(status ? EXIT_FAILURE : EXIT_SUCCESS);
}
