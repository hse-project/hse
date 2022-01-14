/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_REST_API_H
#define HSE_PLATFORM_REST_API_H

#include <microhttpd.h>

#include <hse_util/hse_err.h>

#define REST_VERSION_MAJOR 0
#define REST_VERSION_MINOR 1

#define REST_URL_LEN_MAX PATH_MAX

#define URL_KLEN_MAX 32
#define URL_VLEN_MAX 128

enum rest_url_flags {
    URL_FLAG_NONE = 0,
    URL_FLAG_BINVAL = 1 << 1,
    URL_FLAG_EXACT =
        1 << 2, /* Whether the registered route should match exactly with the requested route */
};

struct kv_iter;

/**
 * struct conn_info -
 * @resp_fd: write response to this fd
 * @data:    uploaded data, if any
 * @data_sz: size of data
 * @buf:     ptr to a buffer that will exist for the duration of this session
 * @buf_sz:  size of @buf
 */
struct conn_info {
    int         resp_fd;
    const char *data;
    size_t *    data_sz;
    char *      buf;
    size_t      buf_sz;
};

/* arguments passed as key-value pairs as part of URI */
struct rest_kv {
    char *key;
    char *value;
};

struct rest_kv *
rest_kv_next(struct kv_iter *iter);

size_t
rest_kv_count(struct kv_iter *iter);

typedef merr_t
rest_get_t(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context);

typedef merr_t
rest_put_t(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context);

merr_t
rest_server_start(const char *sock_path);

void
rest_server_stop(void);

void
rest_init(void);
void
rest_destroy(void);

merr_t
rest_url_register(
    void *              context,
    enum rest_url_flags flags,
    rest_get_t *        get_func,
    rest_put_t *        put_func,
    const char *        fmt,
    ...);

merr_t
rest_url_deregister(const char *fmt, ...);

/**
 * rest_write_safe() - Check if the fd is available for writing and only then
 *                     write
 * @fd:   write fd of pipe
 * @buf:  buffer to write to fd
 * @sz:   size of buf
 *
 * Returns: Number of bytes written, or -errno if there's an error.
 */
ssize_t
rest_write_safe(int fd, const char *buf, size_t sz);

#endif /* HSE_PLATFORM_REST_API_H */
