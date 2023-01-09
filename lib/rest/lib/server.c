/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bsd/string.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <event2/thread.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse/rest/headers.h>
#include <hse/rest/method.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/util/assert.h>
#include <hse/util/compiler.h>
#include <hse/util/err_ctx.h>
#include <hse/util/event_counter.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/rest/server.h>

#include "response.h"
#include "status.h"

#define REST_ROUTE_MASK (REST_ENDPOINT_EXACT)

struct server {
    bool initialized;
    pthread_t thread;
    struct evhttp *handle;
    struct event_base *base;
    struct sockaddr_un addr;
    struct list_head endpoints;
    struct mutex endpoints_lock;
};

struct endpoint {
    char path[PATH_MAX];
    unsigned int flags;
    rest_handler *handlers[REST_METHOD_COUNT];
    void *ctx;
    struct list_head entry;
};

static struct server server;

static enum rest_method
evhttp_cmd_type_to_rest_method(const enum evhttp_cmd_type cmd)
{
    switch (cmd) {
    case EVHTTP_REQ_GET:
        return REST_METHOD_GET;
    case EVHTTP_REQ_POST:
        return REST_METHOD_POST;
    case EVHTTP_REQ_PUT:
        return REST_METHOD_PUT;
    case EVHTTP_REQ_DELETE:
        return REST_METHOD_DELETE;
    case EVHTTP_REQ_HEAD:
    case EVHTTP_REQ_OPTIONS:
    case EVHTTP_REQ_TRACE:
    case EVHTTP_REQ_CONNECT:
    case EVHTTP_REQ_PATCH:
        break;
    }

    abort();
}

static const char *
evhttp_cmd_type_to_string(const enum evhttp_cmd_type cmd)
{
    switch (cmd) {
    case EVHTTP_REQ_GET:
        return "GET";
    case EVHTTP_REQ_POST:
        return "POST";
    case EVHTTP_REQ_HEAD:
        return "HEAD";
    case EVHTTP_REQ_PUT:
        return "PUT";
    case EVHTTP_REQ_DELETE:
        return "DELETE";
    case EVHTTP_REQ_OPTIONS:
        return "OPTIONS";
    case EVHTTP_REQ_TRACE:
        return "TRACE";
    case EVHTTP_REQ_CONNECT:
        return "CONNECT";
    case EVHTTP_REQ_PATCH:
        return "PATCH";
    }

    abort();
}

static void
send_error(
    struct evhttp_request *const req,
    const enum rest_status status,
    const char *const detail,
    const merr_t origin)
{
    const char *reason;
    struct evbuffer *evbuf;
    struct evkeyvalq *headers;

    reason = status_to_reason(status);
    evbuf = evhttp_request_get_output_buffer(req);
    headers = evhttp_request_get_output_headers(req);

    evhttp_add_header(headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_PROBLEM_JSON);
    evbuffer_add_printf(evbuf, RFC7807_FMT, reason, status, detail, merr_file(origin),
        merr_lineno(origin), merr_errno(origin));

    evhttp_send_reply(req, (int)status, reason, NULL);
}

static void
handle_request(struct evhttp_request *const req, const struct endpoint *const endpoint)
{
    int rc;
    char *resp_data;
    const char *query;
    size_t req_data_len;
    size_t resp_data_len;
    char *req_data = NULL;
    struct evkeyvalq params;
    enum rest_status status;
    struct rest_request hreq;
    enum evhttp_cmd_type cmd;
    struct evbuffer *req_body;
    struct rest_response hresp;
    const struct evhttp_uri *uri;
    struct evkeyvalq *resp_headers;
    struct evbuffer *resp_body = NULL;
    const struct evkeyvalq *req_headers;

    cmd = evhttp_request_get_command(req);
    uri = evhttp_request_get_evhttp_uri(req);
    query = evhttp_uri_get_query(uri);
    req_headers = evhttp_request_get_input_headers(req);
    resp_headers = evhttp_request_get_output_headers(req);

    if (!endpoint->handlers[evhttp_cmd_type_to_rest_method(cmd)]) {
        send_error(req, REST_STATUS_METHOD_NOT_ALLOWED, "Method for endpoint does not exist",
            merr(ENOENT));
        return;
    }

    if (query) {
        rc = evhttp_parse_query_str(query, &params);
        if (rc == -1) {
            send_error(req, REST_STATUS_BAD_REQUEST, "Invalid query string", merr(EINVAL));
            return;
        }
    }

    req_body = evhttp_request_get_input_buffer(req);
    req_data_len = evbuffer_get_length(req_body);
    if (req_data_len > 0) {
        ssize_t len;

        req_data = malloc((req_data_len + 1) * sizeof(*req_data));
        if (ev(!req_data)) {
            send_error(req, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory", merr(ENOMEM));
            return;
        }
        req_data[req_data_len] = '\0';

        len = evbuffer_copyout(req_body, req_data, req_data_len + 1);
        if (len == -1) {
            free(req_data);
            send_error(req, REST_STATUS_INTERNAL_SERVER_ERROR, "Failed to copy data out of buffer",
                merr(EBADE));
            return;
        }
    }

    hreq.rr_matched = endpoint->path;
    hreq.rr_actual = evhttp_uri_get_path(uri);
    hreq.rr_headers = (struct rest_headers *)req_headers;
    hreq.rr_params = query ? (struct rest_params *)&params : NULL;
    hreq.rr_data = req_data;
    hreq.rr_data_len = req_data_len;

    hresp.rr_headers = (struct rest_headers *)resp_headers;
    hresp.rr_stream = open_memstream(&resp_data, &resp_data_len);
    if (ev(!hresp.rr_stream)) {
        free(req_data);
        send_error(req, REST_STATUS_INTERNAL_SERVER_ERROR, "Failed to open memory stream",
            merr(ENOSTR));
        return;
    }

    status = endpoint->handlers[evhttp_cmd_type_to_rest_method(cmd)](&hreq, &hresp, endpoint->ctx);
    assert(status >= 100 && status < 600);
    fflush(hresp.rr_stream);

    if (query) {
        evhttp_clear_headers(&params);
        memset(&params, 0, sizeof(params));
    }
    free(req_data);
    hreq.rr_data = NULL;

    if (resp_data_len > 0) {
        resp_body = evbuffer_new();
        if (ev(!resp_body)) {
            send_error(req, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory", merr(ENOMEM));
            return;
        }

        rc = evbuffer_add(resp_body, resp_data, resp_data_len);
        if (ev(rc == -1)) {
            send_error(req, REST_STATUS_INTERNAL_SERVER_ERROR, "Failed to copy data to buffer",
                merr(EBADE));
            return;
        }
    }

    fclose(hresp.rr_stream);
    free(resp_data);

    evhttp_send_reply(req, (int)status, status_to_reason(status), resp_body);

    if (resp_body)
        evbuffer_free(resp_body);
}

void
on_exact_request(struct evhttp_request *const req, void *const arg)
{
    enum evhttp_cmd_type cmd;
    const struct endpoint *endpoint;

    INVARIANT(req);
    INVARIANT(arg);

    cmd = evhttp_request_get_command(req);

    log_debug("REST request received: %s %s", evhttp_cmd_type_to_string(cmd),
        evhttp_request_get_uri(req));

    endpoint = arg;

    handle_request(req, endpoint);
}

void
on_inexact_request(struct evhttp_request *const req, void *const arg)
{
    const char *path;
    enum evhttp_cmd_type cmd;
    const struct evhttp_uri* uri;
    const struct endpoint *endpoint = NULL;

    cmd = evhttp_request_get_command(req);
    uri = evhttp_request_get_evhttp_uri(req);
    path = evhttp_uri_get_path(uri);

    log_debug("REST request received: %s %s", evhttp_cmd_type_to_string(cmd),
        evhttp_request_get_uri(req));

    list_for_each_entry(endpoint, &server.endpoints, entry) {
        size_t path_len;

        path_len = strlen(endpoint->path);

        /* We wouldn't be in this function if the EXACT flag was passed. */
        if (endpoint->flags & REST_ENDPOINT_EXACT)
            continue;

        if (strncmp(path, endpoint->path, path_len) == 0 && ((path[path_len] == '/' &&
                path[path_len + 1] != '\0') || path[path_len] == '\0'))
            break;
    }

    if (!endpoint) {
        send_error(req, REST_STATUS_NOT_FOUND, "Endpoint does not exist", merr(ENOENT));
        return;
    }

    handle_request(req, endpoint);
}

merr_t
rest_server_add_endpoint(
    const unsigned int flags,
    rest_handler *handlers[static REST_METHOD_COUNT],
    void *const ctx,
    const char *const path_fmt,
    ...)
{
    int rc;
    va_list args;
    merr_t err = 0;
    const struct endpoint *e;
    struct endpoint *endpoint = NULL;

    if (!server.initialized)
        return merr(EINVAL);

    if (flags & ~REST_ROUTE_MASK || !handlers || !path_fmt || strlen(path_fmt) == 0)
        return merr(EINVAL);

    mutex_lock(&server.endpoints_lock);

    endpoint = malloc(sizeof(*endpoint));
    if (ev(!endpoint)) {
        err = merr(ENOMEM);
        goto out;
    }

    va_start(args, path_fmt);
    rc = vsnprintf(endpoint->path, sizeof(endpoint->path), path_fmt, args);
    va_end(args);
    if (rc >= sizeof(endpoint->path)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }

    /* Check for duplicate endpoints */
    list_for_each_entry(e, &server.endpoints, entry) {
        if (ev(strcmp(e->path, endpoint->path) == 0)) {
            err = merr(ENOTUNIQ);
            goto out;
        }
    }

    list_add_tail(&endpoint->entry, &server.endpoints);

    endpoint->flags = flags;
    memcpy(endpoint->handlers, handlers, sizeof(endpoint->handlers));
    endpoint->ctx = ctx;

    if (endpoint->flags & REST_ENDPOINT_EXACT) {
        rc = evhttp_set_cb(server.handle, endpoint->path, on_exact_request, endpoint);
        if (rc < 0) {
            err = merr(ECONNREFUSED);
            goto out;
        }
    }

out:
    if (err)
        free(endpoint);

    mutex_unlock(&server.endpoints_lock);

    return err;
}

merr_t
rest_server_remove_endpoint(const char *const path_fmt, ...)
{
    int rc;
    va_list args;
    merr_t err = 0;
    bool deleted = false;
    struct endpoint *endpoint;
    char path[sizeof(((struct endpoint *)NULL)->path)];

    if (!server.initialized)
        return 0;

    va_start(args, path_fmt);
    rc = vsnprintf(path, sizeof(path), path_fmt, args);
    va_end(args);
    if (ev(rc >= sizeof(path)))
        return merr(ENAMETOOLONG);

    mutex_lock(&server.endpoints_lock);

    list_for_each_entry(endpoint, &server.endpoints, entry) {
        if (strcmp(endpoint->path, path) == 0) {
            deleted = true;

            list_del(&endpoint->entry);
            if (endpoint->flags & REST_ENDPOINT_EXACT) {
                rc = evhttp_del_cb(server.handle, path);
                if (ev(rc))
                    err = merr(EINVAL);
            }

            /* endpoint is invalidated beyond this point */
            free(endpoint);
            endpoint = NULL;

            break;
        }
    }

    if (!deleted) {
        err = merr(ENOENT);
        goto out;
    }

out:
    mutex_unlock(&server.endpoints_lock);

    return err;
}

static void *
run_server(void *const arg)
{
    sigset_t sigset;
    int rc HSE_MAYBE_UNUSED;

    rc = sigfillset(&sigset);
    assert(rc == 0);
    rc = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    assert(rc == 0);
    rc = pthread_setname_np(pthread_self(), "hse_rest_server");
    assert(rc == 0);

    rc = event_base_dispatch(server.base);
    assert(rc == 0);

    return NULL;
}

merr_t
rest_server_start(const char *const socket_path)
{
    size_t n HSE_MAYBE_UNUSED;
    int rc;
    bool mutex_initialized = false;
    merr_t err = 0;
    struct evconnlistener *listener = NULL;
    struct evhttp_bound_socket *sock = NULL;

    if (ev(!socket_path))
        return merr(EINVAL);

    if (ev(server.initialized))
        return 0;

    /* In case the program exited inadvertently on the last run,
     * remove the socket.
     */
    unlink(socket_path);

    server.addr.sun_family = AF_UNIX;
    n = strlcpy(server.addr.sun_path, socket_path, sizeof(server.addr.sun_path));
    assert(n < sizeof(server.addr.sun_path));

    INIT_LIST_HEAD(&server.endpoints);

    evthread_use_pthreads();

#ifdef LIBEVENT_DEBUG
    event_enable_debug_logging(EVENT_DBG_ALL);
#endif

    server.base = event_base_new();
    if (ev(!server.base)) {
        err = merr(ECONNABORTED);
        goto out;
    }

    server.handle = evhttp_new(server.base);
    if (ev(!server.handle)) {
        err = merr(ECONNABORTED);
        goto out;
    }

    evhttp_set_allowed_methods(server.handle, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_PUT |
        EVHTTP_REQ_DELETE);

    listener = evconnlistener_new_bind(server.base, NULL, NULL,
        LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr *)&server.addr, sizeof(server.addr));
    if (ev(!listener)) {
        err = merr(ECONNABORTED);
        goto out;
    }

    sock = evhttp_bind_listener(server.handle, listener);
    if (ev(!sock)) {
        err = merr(ECONNABORTED);
        goto out;
    }

    evhttp_set_gencb(server.handle, on_inexact_request, NULL);

    mutex_init(&server.endpoints_lock);
    mutex_initialized = true;

    rc = pthread_create(&server.thread, NULL, run_server, NULL);
    if (ev(rc)) {
        err = merr(rc);
        goto out;
    }

    server.initialized = true;

out:
    if (err) {
        if (listener)
            evconnlistener_free(listener);
        if (server.handle) {
            evhttp_free(server.handle);
            server.handle = NULL;
        }
        if (server.base) {
            event_base_free(server.base);
            server.base = NULL;
        }
        if (mutex_initialized)
            mutex_destroy(&server.endpoints_lock);
    }

    return err;
}

void
rest_server_stop(void)
{
    if (!server.initialized)
        return;

    event_base_loopexit(server.base, NULL);
    pthread_join(server.thread, NULL);
    evhttp_free(server.handle);
    event_base_free(server.base);
    mutex_destroy(&server.endpoints_lock);
    libevent_global_shutdown();

    memset(&server, 0, sizeof(server));
}
