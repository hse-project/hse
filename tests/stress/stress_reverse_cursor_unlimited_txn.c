/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
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

#define MAX_KEY_LEN HSE_KVS_KLEN_MAX
#define MAX_VAL_LEN 4096
#define MAX_THREAD  500
#define MAX_RETRY   20

extern int  DEBUG;
atomic_int  error_count;
atomic_int  verification_failure_count;
atomic_long aborted_txn_count;
atomic_long committed_txn_count;
atomic_long inserted_record_count;
atomic_long queries_count;

struct cursor_test_data {
    char             kvdb_home[PATH_MAX];
    char *           kvs_name;
    long int         key_count;
    int              val_size;
    int              point_insertion_thread_count;
    int              cursor_read_thread_count;
    int              txn_size;
    int              cursor_sleep_time;
    int              key_format;
    int              key_size;
    int              wal_disable;
    int              rank;
    long int         start;
    long int         end;
    long int         tot_key_count;
    long int         key_count_per_thread;
    struct hse_kvs * kvs;
    struct hse_kvdb *kvdb;
    char             data[MAX_VAL_LEN];
};

void
print_usage(void)
{
    printf("Usage: stress_reverse_cursor_unlimited_txn\n"
           " -a <records_per_txn>\n"
           " -b <key size>\n"
           " -c <key count>\n"
           " -C <kvdb_home>\n"
           " -d <cursor read thread count>\n"
           " -e <cursor_read_sleep_time ms>\n"
           " -o <point_insertion_thread_count>\n"
           " -r <wal_disable>\n"
           " -u <debug>\n"
           " -v <value_size\n");
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
cursor_read(void *args)
{
    struct cursor_test_data *info = args;
    long int                 i = 0;
    struct hse_kvs_cursor *  CURSOR;
    const void *             cur_key, *cur_val;
    size_t                   cur_klen, cur_vlen;
    bool                     eof = false;
    char                     expected_key_buf[info->key_size];
    char                     expected_val_buf[info->val_size];
    hse_err_t                hse_err;
    char                     msg[100];

    log_info("begin %s", __func__);

    if (error_count > 0 || verification_failure_count > 0)
        goto out;

    hse_err = hse_kvs_cursor_create(info->kvs, HSE_CURSOR_CREATE_REV, NULL, NULL, 0, &CURSOR);

    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_print(
            LOG_ERROR,
            "hse_kvs_cursor_create: errno=%d msg=\"%s\" rank=%d",
            hse_err_to_errno(hse_err),
            msg,
            info->rank);
        ++error_count;
        goto out;
    } else if (DEBUG) {
        log_debug("hse_kvs_cursor_create: rank=%d", info->rank);
    }

    for (i = info->end - 1; i >= info->start; i--) {
        generate_record(
            expected_key_buf,
            sizeof(expected_key_buf),
            expected_val_buf,
            sizeof(expected_val_buf),
            info->key_size,
            info->val_size,
            info->data,
            i);

        if (i == info->end - 1) {
            hse_err = hse_kvs_cursor_seek(
                CURSOR, 0, expected_key_buf, info->key_size, NULL, NULL);

            if (hse_err) {
                hse_strerror(hse_err, msg, sizeof(msg));
                log_print(
                    LOG_ERROR,
                    "hse_kvs_cursor_seek: errno=%d msg=\"%s\" "
                    "rank=%d key_index=%ld key=\"%s\"",
                    hse_err_to_errno(hse_err),
                    msg,
                    info->rank,
                    i,
                    expected_key_buf);
                ++error_count;
                break;
            } else if (DEBUG) {
                log_print(
                    LOG_DEBUG,
                    "hse_kvs_cursor_seek: rank=%d key_index=%ld key=\"%s\"",
                    info->rank,
                    i,
                    expected_key_buf);
            }
        }

        hse_err = hse_kvs_cursor_read(
            CURSOR, 0, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

        if (hse_err) {
            hse_strerror(hse_err, msg, sizeof(msg));
            log_print(
                LOG_ERROR,
                "hse_kvs_cursor_read: errno=%d msg=\"%s\" rank=%d key_index=%ld",
                hse_err_to_errno(hse_err),
                msg,
                info->rank,
                i);
            ++error_count;
            break;
        } else if (DEBUG) {
            log_print(
                LOG_DEBUG,
                "hse_kvs_cursor_read: rank=%d key_index=%ld key=\"%*s\"",
                info->rank,
                i,
                (int)cur_klen,
                (char *)cur_key);
        }

        if (eof) {
            log_print(
                LOG_ERROR,
                "hse_kvs_cursor_read: unexpected eof rank=%d start=%ld end=%ld failed=%ld",
                info->rank,
                info->start,
                info->end,
                i);
            ++verification_failure_count;
            break;
        }

        if (info->key_size != cur_klen || info->val_size != cur_vlen) {
            log_print(
                LOG_ERROR,
                "FAILED key length verification: "
                "actual_key_len=%ld expected_key_len=%d",
                cur_klen,
                info->key_size);
            ++verification_failure_count;
            break;
        } else if (info->val_size != cur_vlen) {
            log_print(
                LOG_ERROR,
                "FAILED value length verfication: "
                "actual_val_len=%ld expected_val_len=%d",
                cur_vlen,
                info->val_size);
            ++verification_failure_count;
            break;
        } else if (memcmp(expected_key_buf, cur_key, info->key_size) != 0) {
            log_print(
                LOG_ERROR,
                "FAILED key verification: start=%ld end=%ld i=%ld "
                "key=\"%*s\" expected_key=\"%s\"",
                info->start,
                info->end,
                i,
                (int)cur_klen,
                (char *)cur_key,
                expected_key_buf);
            ++verification_failure_count;
            break;
        } else if (memcmp(expected_val_buf, cur_val, info->val_size) != 0) {
            log_print(
                LOG_ERROR,
                "FAILED value verification: start=%ld end=%ld i=%ld "
                "key=\"%*s\" value=\"%*s\" expected_value=\"%s\"",
                info->start,
                info->end,
                i,
                (int)cur_klen,
                (char *)cur_key,
                (int)cur_vlen,
                (char *)cur_val,
                expected_val_buf);
            ++verification_failure_count;
            break;
        }

        ++queries_count;
    }

    if (info->cursor_sleep_time > 0) {
        sleep(info->cursor_sleep_time / 1000);
    }

    hse_err = hse_kvs_cursor_destroy(CURSOR);

    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_print(
            LOG_ERROR,
            "hse_kvs_cursor_destroy: errno=%d msg=\"%s\" rank=%d",
            hse_err_to_errno(hse_err),
            msg,
            info->rank);
        ++error_count;
    } else if (DEBUG) {
        log_debug("hse_kvs_cursor_destroy: rank=%d", info->rank);
    }

out:
    log_info("end %s", __func__);

    return NULL;
}

void *
point_insertion(void *args)
{
    struct cursor_test_data *info = (struct cursor_test_data *)args;
    struct hse_kvdb_txn *    txn;
    long int                 i = 0;
    long int                 txn_size_idx = 0;
    char                     key_buf[info->key_size];
    char                     val_buf[info->val_size];
    int                      retry = 0;
    hse_err_t                err;
    char                     msg[100];

    log_print(
        LOG_INFO,
        "begin %s: rank=%d start=%ld end=%ld",
        __func__,
        info->rank,
        info->start,
        info->end);

    if (error_count > 0 || verification_failure_count > 0)
        goto out;

    txn = hse_kvdb_txn_alloc(info->kvdb);

    if (txn == NULL) {
        log_error("hse_kvdb_txn_alloc failed");
        ++error_count;
        goto out;
    }

    for (i = info->start; i < info->end; i++) {
        err = hse_kvdb_txn_begin(info->kvdb, txn);

        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_print(
                LOG_ERROR, "hse_kvdb_txn_begin: errno=%d msg=\"%s\"", hse_err_to_errno(err), msg);
            ++error_count;
            goto out2;
        } else if (DEBUG) {
            log_debug("hse_kvdb_txn_begin: rank=%d i=%ld", info->rank, i);
        }

        txn_size_idx = 0;

        while (txn_size_idx < info->txn_size) {
            if (i + txn_size_idx >= info->end)
                goto commit;

            generate_record(
                key_buf,
                sizeof(key_buf),
                val_buf,
                sizeof(val_buf),
                info->key_size,
                info->val_size,
                info->data,
                i + txn_size_idx);

            do {
                err = hse_kvs_put(
                    info->kvs,
                    0,
                    txn,
                    key_buf,
                    sizeof(key_buf),
                    val_buf,
                    sizeof(val_buf));

                if (hse_err_to_errno(err) == EAGAIN) {
                    sleep(10);
                    retry++;
                } else if (hse_err_to_errno(err) == ECANCELED) {
                    err = hse_kvdb_txn_abort(info->kvdb, txn);
                    ++aborted_txn_count;

                    if (err) {
                        hse_strerror(err, msg, sizeof(msg));
                        log_print(
                            LOG_ERROR,
                            "hse_kvdb_txn_abort: errno=%d msg=\"%s\"",
                            hse_err_to_errno(err),
                            msg);
                        ++error_count;
                        goto out2;
                    }

                    srand(time(0));
                    sleep((rand() % 10) / 1000);
                    err = hse_kvdb_txn_begin(info->kvdb, txn);

                    if (err) {
                        hse_strerror(err, msg, sizeof(msg));
                        log_print(
                            LOG_ERROR,
                            "hse_kvdb_txn_begin: errno=%d msg=\"%s\"",
                            hse_err_to_errno(err),
                            msg);
                        ++error_count;
                        goto out2;
                    }
                    txn_size_idx = -1;
                } else if (err) {
                    ++error_count;

                    hse_strerror(err, msg, sizeof(msg));
                    log_print(
                        LOG_ERROR,
                        "hse_kvs_put: errno=%d msg=\"%s\" key=\"%s\"",
                        hse_err_to_errno(err),
                        msg,
                        key_buf);

                    err = hse_kvdb_txn_abort(info->kvdb, txn);

                    if (err) {
                        hse_strerror(err, msg, sizeof(msg));
                        log_print(
                            LOG_ERROR,
                            "hse_kvdb_txn_abort: errno=%d msg=\"%s\" i=%ld",
                            hse_err_to_errno(err),
                            msg,
                            i);
                        ++error_count;
                        goto out2;
                    } else if (DEBUG) {
                        log_debug("hse_kvdb_txn_abort: i=%ld", i);
                    }

                    ++aborted_txn_count;
                    goto out2;
                } else if (DEBUG) {
                    log_debug("hse_kvs_put: rank=%d key=\"%s\"", info->rank, key_buf);
                }
            } while (retry < MAX_RETRY && hse_err_to_errno(err) == EAGAIN);

            txn_size_idx++;
        }

    commit:
        err = hse_kvdb_txn_commit(info->kvdb, txn);
        if (err) {
            hse_strerror(err, msg, sizeof(msg));
            log_print(
                LOG_ERROR,
                "hse_kvdb_txn_commit: error=%d msg=\"%s\" rank=%d",
                hse_err_to_errno(err),
                msg,
                info->rank);

            ++error_count;
            goto out2;
        } else if (DEBUG) {
            log_debug("hse_kvdb_txn_abort: rank=%d i=%ld", info->rank, i);
        }

        ++committed_txn_count;
        inserted_record_count += txn_size_idx;

        i = i + txn_size_idx - 1;
    }

out2:
    hse_kvdb_txn_free(info->kvdb, txn);
    if (DEBUG) {
        log_debug("hse_kvdb_txn_free: rank=%d", info->rank);
    }

out:
    log_print(LOG_INFO, "end %s: rank=%d start=%ld end=%ld", __func__, info->rank, info->start,
        info->end);

    return NULL;
}

long int
get_count_per_x(long int long_count, int x)
{
    long int count_per_x = long_count;

    if (long_count % x)
        count_per_x = long_count + (x - long_count % x);

    return count_per_x / x;
}

void
spawn_threads(struct cursor_test_data *params, void *thread_fun, char *fun_name)
{
    pthread_t               thread_info[MAX_THREAD];
    int                     thread;
    char                    buf[100];
    struct cursor_test_data args[MAX_THREAD];
    int                     thread_count = 0;
    int                     rc;

    if (strcmp(fun_name, "point_insertion") == 0)
        thread_count = params->point_insertion_thread_count;
    else
        thread_count = params->cursor_read_thread_count;

    log_info("spawning %d thread(s), fun_name=\"%s\"", thread_count, fun_name);

    for (thread = 0; thread < thread_count; thread++) {
        int n HSE_MAYBE_UNUSED;

        params->key_count_per_thread = get_count_per_x(params->key_count, thread_count);
        params->rank = thread;
        params->start = get_first_key_index(params->key_count_per_thread, thread);
        params->end = params->start + params->key_count_per_thread;

        memcpy(&args[thread], params, sizeof(struct cursor_test_data));
        memcpy(&args[thread].data, params->data, sizeof(params->data));

        pthread_create(&thread_info[thread], NULL, thread_fun, (void *)&args[thread]);

        n = snprintf(buf, sizeof(buf), "%s-%03d", fun_name, thread);
        assert(n < sizeof(buf));

        pthread_setname_np(thread_info[thread], buf);
    }

    for (thread = 0; thread < thread_count; thread++) {
        rc = pthread_join(thread_info[thread], NULL);
        if (rc)
            log_error("pthread_join: errno=%d", rc);
    }

    log_print(
        LOG_INFO,
        "completed wait for %d spawned thread(s), fun_name=\"%s\"",
        thread_count,
        fun_name);
}

int
execute_test(struct cursor_test_data *params)
{
    struct hse_kvdb *kvdb;
    int              status;
    int              result;
    hse_err_t        hse_err;
    char             msg[100];

    result = 0;

    srand(time(NULL));
    fillrandom(params->data, sizeof(params->data));

    status = create_or_open_kvdb_and_kvs(
        params->kvdb_home, params->kvs_name, &kvdb, &params->kvs, true, params->wal_disable, 0, 1);

    if (status) {
        log_fatal("kvdb+kvs open failed: errno=%d", status);
        return 1;
    }

    params->kvdb = kvdb;

    spawn_threads(params, point_insertion, "point_insertion");

    if (error_count > 0) {
        result = 1;
        log_error("FAILED after %d error(s)", error_count);
    } else if (verification_failure_count > 0) {
        result = 1;
        log_error("FAILED after %d verification failure(s)", verification_failure_count);
    }

    spawn_threads(params, cursor_read, "cursor_read");

    sleep(2);

    if (error_count > 0) {
        result = 1;
        log_error("FAILED after %d error(s)", error_count);
    } else if (verification_failure_count > 0) {
        result = 1;
        log_error("FAILED after %d verification failure(s)", verification_failure_count);
    } else
        log_info("PASSED verification");

    log_info("closing kvs \"%s/%s\"", params->kvdb_home, params->kvs_name);
    hse_err = hse_kvdb_kvs_close(params->kvs);
    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_print(
            LOG_ERROR, "hse_kvdb_kvs_close: errno=%d msg=\"%s\"", hse_err_to_errno(hse_err), msg);
    }

    log_info("closing kvdb \"%s\"", params->kvdb_home);
    hse_err = hse_kvdb_close(kvdb);
    if (hse_err) {
        hse_strerror(hse_err, msg, sizeof(msg));
        log_print(
            LOG_ERROR, "hse_kvdb_close: errno=%d msg=\"%s\"\n", hse_err_to_errno(hse_err), msg);
    }

    return result;
}

int
main(int argc, char *argv[])
{
    int                     option, status;
    struct cursor_test_data para;
    hse_err_t               hse_err;

    memset(&para, 0, sizeof(para));

    para.kvs_name = "kvs1";

    progname_set(argv[0]);

    while ((option = getopt(argc, argv, "a:b:c:C:d:e:o:r:u:v:")) != -1) {
        switch (option) {
            case 'a':
                para.txn_size = atoi(optarg);
                break;

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
                para.cursor_read_thread_count = atoi(optarg);
                break;

            case 'e':
                para.cursor_sleep_time = atoi(optarg);
                break;

            case 'o':
                para.point_insertion_thread_count = atoi(optarg);
                break;

            case 'r':
                para.wal_disable = atoi(optarg);
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
            fprintf(stderr, "%s: Failed to setup scratch directory: %s",
                progname, merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL));
            return EX_CANTCREAT;
        }
    }

    assert(para.key_size > 0 || para.key_count > 0 || para.val_size > 0);

    if (para.key_count % para.point_insertion_thread_count) {
        para.key_count += para.point_insertion_thread_count -
                          (para.key_count % para.point_insertion_thread_count);
        log_print(
            LOG_INFO, "adjusted key_count to %ld due to insertion thread count\n", para.key_count);
    }

    log_info("debug                         = %d", DEBUG);
    log_info("cursor_read_thread_count      = %d", para.cursor_read_thread_count);
    log_info("cursor_sleep_time             = %d", para.cursor_sleep_time);
    log_info("key_count                     = %ld", para.key_count);
    log_info("key_size                      = %d", para.key_size);
    log_info("kvdb_home                    = \"%s\"", para.kvdb_home);
    log_info("point_insertion_thread_count  = %d", para.point_insertion_thread_count);
    log_info("txn_size                      = %d", para.txn_size);
    log_info("val_size                      = %d", para.val_size);
    log_info("wal_disable                   = %d", para.wal_disable);

    /* [HSE_REVISIT]: Re-evaluate options to make room for -c/--config */
    hse_err = hse_init(NULL, 0, NULL);
    if (hse_err) {
        log_fatal("hse_init: errno=%d", hse_err_to_errno(hse_err));
        exit(EXIT_FAILURE);
    }

    status = execute_test(&para);

    hse_fini();

    exit(status);
}
