/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/minmax.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/delay.h>
#include <hse_util/workqueue.h>
#include <hse_util/event_counter.h>

#include <hse_util/rest_api.h>
#include <hse_util/spinlock.h>
#include <hse_util/mutex.h>
#include <hse_util/string.h>
#include <hse_util/table.h>

#include <hse/version.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/select.h>
#include <poll.h>

#define SESSIONS_PER_THREAD 5
#define NUM_THREADS 3
#define MAX_SESSIONS (SESSIONS_PER_THREAD * NUM_THREADS)
#define WQ_THREADS 5

#ifndef MHD_HTTP_NOT_ACCEPTABLE
#define MHD_HTTP_NOT_ACCEPTABLE MHD_HTTP_METHOD_NOT_ACCEPTABLE
#endif

#ifndef MHD_HTTP_TOO_MANY_REQUESTS
#define MHD_HTTP_TOO_MANY_REQUESTS 429
#endif

#define KV_PAIR_MAX 16

enum {
    URL_GET = 1,
    URL_PUT = 2,
};

struct kv_iter {
    merr_t        err;
    int           pos;
    size_t        len;
    struct table *kv_tab;
};

struct url_desc {
    char                name[REST_URL_LEN_MAX];
    void *              context;
    rest_get_t *        get_handler;
    rest_put_t *        put_handler;
    enum rest_url_flags url_flags;
    atomic_t            refcnt;
};

struct thread_arg {
    struct work_struct work;
    struct url_desc *  udesc;
    const char *       path;
    struct kv_iter     iter;
    struct conn_info * ci;
    int                op;
    atomic_t           busy;
};

/**
 * struct session - identifies one client session/request
 * @resp_pipe:   Pipe for communication between url handler function (get/put)
 *               and the rest server's response callback (rest_response_cb)
 * @response:    MHD response object
 * @targ:        argument to url handler thread
 * @enqueued:    whether work was enqueued
 * @ci:          connection information for the handler
 * @refcnt:      reference count
 * @slot:        ptr to session table slot
 * @magic:       used for sanity checking
 * @buf:         Scratch space for handlers to use for the session duration
 */
struct session {
    int                  resp_pipe[2];
    struct MHD_Response *response;
    struct thread_arg    targ;
    int                  enqueued;
    struct conn_info     ci;
    atomic_t             refcnt;
    struct session **    slot;
    void *               magic;
    char                 buf[4096];
};

struct rest {
    spinlock_t      sessions_lock;
    struct session *sessions[MAX_SESSIONS];

    HSE_ALIGNED(SMP_CACHE_BYTES) struct mutex url_tab_lock;
    struct table *url_tab; /* table of rest URLs */

    HSE_ALIGNED(SMP_CACHE_BYTES) struct workqueue_struct *url_hdlr_wq;
    struct MHD_Daemon *monitor_daemon;

    int  sockfd;
    char sock_name[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

static struct rest rest;

/* [HSE_REVISIT] This lib is designed to work under the constraint that a process
 * will have only one KVDB open at a time.
 */

static merr_t
string_validate(const char *str, size_t max)
{
    /* does string contain invalid characters ?
     * i.e. char outside [:-_/.A-Za-z0-9]
     */
    while (*str && max-- > 0) {
        if (!isalnum(*str) && *str != '_' && *str != '-' && *str != '.' && *str != '/' &&
            *str != ':') {
            hse_log(HSE_ERR "rest, bad request: %s", str);
            return merr(ev(EINVAL));
        }
        ++str;
    }

    if (*str)
        return merr(ev(ENAMETOOLONG));

    return 0;
}

/**
 * rest_kv_next() - get next key/value pair from url query
 *
 * Give this example query string:
 *
 *    "test?key1=value1&key2=value2&key2=value2"
 *
 * rest_kv_next() would iterate over the the following pairs:
 *
 *    < "key1", "value1" >
 *    < "key2", "value2" >
 *    < "key3", "value3" >
 *
 * Notes:
 *  - keys and values are percent decoded by libmicrohttpd before
 *    they are seen by HSE. So a url with "%61%62%63=%31%32%33" would
 *    be seen as "abc=123".
 */
struct rest_kv *
rest_kv_next(struct kv_iter *iter)
{
    if (!iter || iter->pos >= iter->len)
        return 0;

    return table_at(iter->kv_tab, iter->pos++);
}

size_t
rest_kv_count(struct kv_iter *iter)
{
    return iter ? iter->len : 0;
}

void
rest_init(void)
{
    if (ev(rest.url_tab))
        return;

    rest.url_tab = table_create(10, sizeof(struct url_desc), true);
    mutex_init(&rest.url_tab_lock);
    rest.sockfd = -1;
}

void
rest_destroy(void)
{
    if (!rest.url_tab)
        return;

    mutex_lock(&rest.url_tab_lock);
    table_destroy(rest.url_tab);
    rest.url_tab = NULL;
    mutex_unlock(&rest.url_tab_lock);

    mutex_destroy(&rest.url_tab_lock);
}

merr_t
rest_url_register(
    void *              context,
    enum rest_url_flags url_flags,
    rest_get_t *        get_func,
    rest_put_t *        put_func,
    char *              fmt,
    ...)
{
    struct url_desc *ud;
    int              i, len, ret;
    char             name[REST_URL_LEN_MAX];
    va_list          ap;
    merr_t           err;

    if (ev(!fmt || !rest.url_tab))
        return merr(EINVAL);

    if (ev(!get_func && !put_func))
        return merr(EINVAL);

    /* construct url */
    va_start(ap, fmt);
    ret = vsnprintf(name, sizeof(name), fmt, ap);
    va_end(ap);

    if (ev(ret >= sizeof(name)))
        return merr(ENAMETOOLONG);

    err = string_validate(name, REST_URL_LEN_MAX);
    if (ev(err))
        return err;

    /* add a unique entry to the table */
    mutex_lock(&rest.url_tab_lock);
    len = table_len(rest.url_tab);

    for (i = 0; i < len; i++) {
        ud = table_at(rest.url_tab, i);

        if (strncmp(name, ud->name, sizeof(ud->name)) == 0) {
            mutex_unlock(&rest.url_tab_lock);
            return 0; /* this entry exists; do nothing */
        }
    }

    ud = table_append(rest.url_tab);
    if (ud) {
        strlcpy(ud->name, name, sizeof(ud->name));
        ud->context = context;
        ud->url_flags = url_flags;
        ud->get_handler = get_func;
        ud->put_handler = put_func;
        atomic_set(&ud->refcnt, 0);
    }
    mutex_unlock(&rest.url_tab_lock);

    ev(!ud);

    return ud ? 0 : merr(ENOMEM);
}

merr_t
rest_url_deregister(char *fmt, ...)
{
    char             name[REST_URL_LEN_MAX];
    va_list          ap;
    int              i, len;
    struct url_desc *match = 0;

    if (!fmt || !rest.url_tab)
        return merr(ev(EINVAL));

    /* construct url */
    va_start(ap, fmt);
    vsnprintf(name, sizeof(name), fmt, ap);
    va_end(ap);

    mutex_lock(&rest.url_tab_lock);
    len = table_len(rest.url_tab);

    for (i = 0; i < len; i++) {
        struct url_desc *ud = table_at(rest.url_tab, i);

        if (strcmp(name, ud->name) == 0) {

            ud->name[0] = '\000';
            match = ud;
            break;
        }
    }
    mutex_unlock(&rest.url_tab_lock);

    if (match) {
        while (atomic_read(&match->refcnt) > 0)
            msleep(100);

        match->get_handler = match->put_handler = match->context = 0;
        return 0;
    }

    return merr(ev(ENOENT));
}

static merr_t
kv_iter_init(struct kv_iter *iter)
{
    memset(iter, 0, sizeof(*iter));

    iter->kv_tab = table_create(KV_PAIR_MAX, sizeof(struct rest_kv), true);
    if (ev(!iter->kv_tab))
        return merr(ENOMEM);

    iter->len = iter->pos = 0;

    return 0;
}

#if (MHD_VERSION >= 0x00097002)
static enum MHD_Result
#else
static int
#endif
extract_kv_pairs(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
    struct session *    session = cls;
    struct kv_iter *    iter;
    struct rest_kv *    kv;
    enum rest_url_flags url_flags;
    merr_t              err;

    assert(session->magic == session);

    iter = &session->targ.iter;
    assert(iter->err == 0);

    url_flags = session->targ.udesc->url_flags;

    if (!key) {
        iter->err = merr(ev(EINVAL));
        return MHD_NO;
    }

    /* check if by adding the current kv-pair we exceed the limit */
    if (table_len(iter->kv_tab) + 1 > KV_PAIR_MAX) {
        iter->err = merr(ev(E2BIG));
        return MHD_NO;
    }

    /* Keys are values are precent-decoded before we get here.
     * Verify keys are simple ascii strings.  Values can be binary
     * so there is no validation we can do.  Note: due to
     * limitations of MHD_get_connection_values(), binary 0x00 is
     * not handled correctly. Recent libmicrohttpd releases
     * provide a new API, MHD_get_connection_values_n(), which
     * allows proper support of binary 0x00 in URL parameters.
     */

    err = string_validate(key, URL_KLEN_MAX);
    if (err) {
        iter->err = ev(err);
        return MHD_NO;
    }

    if (value) {

        if (ev(strlen(value) > URL_VLEN_MAX)) {
            iter->err = merr(EINVAL);
            return MHD_NO;
        }

        if ((url_flags & URL_FLAG_BINVAL) == 0) {
            err = string_validate(value, URL_VLEN_MAX);
            if (err) {
                iter->err = ev(err);
                return MHD_NO;
            }
        }
    }

    kv = table_append(iter->kv_tab);
    if (!kv) {
        iter->err = merr(ev(ENOMEM));
        return MHD_NO;
    }

    kv->key = kv->value = 0;

    kv->key = strdup(key);
    if (!kv->key) {
        iter->err = merr(ev(ENOMEM));
        return MHD_NO;
    }

    if (value) {
        kv->value = strdup(value);
        if (!kv->value) {
            iter->err = merr(ev(ENOMEM));
            free(kv->key);
            kv->key = 0;
            return MHD_NO;
        }
    }

    iter->len++;

    return MHD_YES;
}

static void
kv_free(void *arg)
{
    struct rest_kv *kv = arg;

    free(kv->key);
    free(kv->value);
}

static void
kv_tab_free(struct table *tab)
{
    table_apply(tab, kv_free);
    table_destroy(tab);
}

static void
rest_session_release(struct session *s)
{
    int rc HSE_MAYBE_UNUSED;

    assert(s->magic == s);

    if (atomic_dec_return(&s->refcnt) > 0)
        return;

    s->magic = (void *)0x0badcafe0badcafe;

    spin_lock(&rest.sessions_lock);
    if (s->slot && *s->slot == s)
        *s->slot = NULL;
    s->slot = NULL;
    spin_unlock(&rest.sessions_lock);

    if (s->targ.iter.kv_tab) {
        kv_tab_free(s->targ.iter.kv_tab);
        s->targ.iter.kv_tab = 0;
    }

    /* To ensure that we don't close a re-purposed desciptor
     * this is the only place that we close the descriptors
     * we opened in rest_session_close().
     */
    rc = close(s->resp_pipe[0]);
    assert(rc == 0 || errno != EBADF);

    rc = close(s->resp_pipe[1]);
    assert(rc == 0 || errno != EBADF);

    free(s);
}

static struct url_desc *
get_url_desc(const char *path)
{
    int              i, cnt;
    struct url_desc *match = NULL;
    size_t           match_len = 0;

    mutex_lock(&rest.url_tab_lock);
    cnt = table_len(rest.url_tab);

    for (i = 0; i < cnt; i++) {
        struct url_desc *p = table_at(rest.url_tab, i);

        if (p->url_flags & URL_FLAG_EXACT) {
            if (strcmp(p->name, path) == 0) {
                match = p;
                break;
            }
        } else {
            size_t len = strlen(p->name);

            if (strncmp(p->name, path, len) == 0) {
                if (len > match_len) {
                    /* we want the most precise match */
                    match_len = len;
                    match = p;
                }
            }
        }
    }

    if (match)
        atomic_inc(&match->refcnt);

    mutex_unlock(&rest.url_tab_lock);

    return match;
}

static void
url_handler(struct work_struct *w)
{
    struct thread_arg *ta = container_of(w, struct thread_arg, work);
    struct url_desc *  ud = ta->udesc;
    merr_t             err;

    if (ta->op == URL_GET)
        err = ud->get_handler(ta->path, ta->ci, ud->name, &ta->iter, ud->context);
    else
        err = ud->put_handler(ta->path, ta->ci, ud->name, &ta->iter, ud->context);

    shutdown(ta->ci->resp_fd, SHUT_RDWR);
    atomic_dec(&ud->refcnt);

    if (ev(err))
        hse_elog(HSE_WARNING "rest: handler failed: @@e", err);

    atomic_set(&ta->busy, 0);

    rest_session_release(container_of(ta, struct session, targ));
}

static int
valid_method(const char *method_name)
{
    return (
        method_name &&
        (!strcmp(method_name, MHD_HTTP_METHOD_GET) || !strcmp(method_name, MHD_HTTP_METHOD_PUT) ||
         !strcmp(method_name, MHD_HTTP_METHOD_POST)));
}

static int
gen_help_msg(size_t *bytes, char *buf, size_t bufsz)
{
    int i, len;

    struct yaml_context yc = {
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_buf = buf,
        .yaml_buf_sz = bufsz,
        .yaml_emit = NULL,
    };

    if (!bytes)
        return merr(ev(EINVAL));

    memset(buf, 0, bufsz);

    yaml_start_element_type(&yc, "Usage");

    yaml_start_element_type(&yc, "GET");
    yaml_element_field(
        &yc,
        "Syntax (w/o kv)",
        "curl --noproxy localhost --unix-socket /path/to/socket "
        "http://localhost/path/to/command");

    yaml_element_field(
        &yc,
        "Syntax (w/  kv)",
        "curl --noproxy localhost --unix-socket /path/to/socket "
        "http://localhost/path/to/command?arg1=val1&arg2=val2");

    yaml_end_element(&yc);
    yaml_end_element_type(&yc); /* GET */

    yaml_start_element_type(&yc, "PUT");
    yaml_element_field(
        &yc,
        "Syntax (w/o kv)",
        "curl --noproxy localhost --unix-socket /path/to/socket "
        "-X PUT http://localhost/path/to/command");

    yaml_element_field(
        &yc,
        "Syntax (w/  kv)",
        "curl --noproxy localhost --unix-socket /path/to/socket "
        "-X PUT http://localhost/path/to/command?arg1=val1&arg2=val2");

    yaml_end_element(&yc);
    yaml_end_element_type(&yc); /* PUT */

    yaml_end_element_type(&yc); /* Usage */

    yaml_start_element_type(&yc, "Registered URLs");

    mutex_lock(&rest.url_tab_lock);
    len = table_len(rest.url_tab);

    for (i = 0; i < len; i++) {
        struct url_desc *p = table_at(rest.url_tab, i);
        char *           ops;

        if (!p->get_handler && !p->put_handler)
            continue; /* skip this URL. It was deregistered */

        ops = p->get_handler && p->put_handler
                  ? "put,get"
                  : p->put_handler ? "put" : p->get_handler ? "get" : "(none)";

        yaml_start_element(&yc, "name", p->name);
        yaml_element_field(&yc, "ops", ops);
        yaml_end_element(&yc);
    }
    mutex_unlock(&rest.url_tab_lock);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc); /* Registered URLs */

    *bytes = yc.yaml_offset;

    return 0;
}

static void
rest_response_free(void *cls)
{
    rest_session_release(cls);
}

static ssize_t
rest_response_cb(void *cls, uint64_t pos, char *buf, size_t max)
{
    struct timespec tv = {.tv_sec = 10 };
    struct session *s = cls;
    struct pollfd   pfdv[1];
    sigset_t        mask;
    ssize_t         cc;
    int             fd, n;

    assert(s->magic == s);

    fd = s->resp_pipe[0];

    cc = read(fd, buf, max);
    if (cc > 0)
        return cc;
    if (cc == 0)
        return MHD_CONTENT_READER_END_OF_STREAM;

    pfdv[0].fd = fd;
    pfdv[0].events = POLLIN;

    sigfillset(&mask);

    n = ppoll(pfdv, 1, &tv, &mask);
    if (ev(n == -1))
        return MHD_CONTENT_READER_END_WITH_ERROR;

    cc = read(fd, buf, max);
    if (cc > 0)
        return cc;

    return MHD_CONTENT_READER_END_OF_STREAM;
}

static struct session *
rest_session_create(void)
{
    int             i, ret;
    int             flags;
    struct session *tmp;

    tmp = calloc(1, sizeof(*tmp));
    if (ev(!tmp))
        return NULL;

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, tmp->resp_pipe);
    if (ev(ret == -1)) {
        free(tmp);
        return NULL;
    }

    /* A session is born with a reference which will be released
     * by rest_session_complete().
     */
    atomic_set(&tmp->refcnt, 1);
    tmp->enqueued = false;
    tmp->magic = tmp;

    /* the two ends of the pipe must be non-blocking */
    flags = fcntl(tmp->resp_pipe[0], F_GETFL);
    if (ev(flags < 0))
        goto err;

    ret = fcntl(tmp->resp_pipe[0], F_SETFL, flags | O_NONBLOCK);
    if (ev(ret < 0))
        goto err;

    flags = fcntl(tmp->resp_pipe[1], F_GETFL);
    if (ev(flags < 0))
        goto err;

    ret = fcntl(tmp->resp_pipe[1], F_SETFL, flags | O_NONBLOCK);
    if (ev(ret < 0))
        goto err;

    spin_lock(&rest.sessions_lock);
    for (i = 0; i < MAX_SESSIONS; ++i) {
        if (!rest.sessions[i]) {
            tmp->slot = rest.sessions + i;
            rest.sessions[i] = tmp;
            break;
        }
    }
    spin_unlock(&rest.sessions_lock);

err:
    if (!tmp->slot) {
        rest_session_release(tmp);
        tmp = NULL;
    }

    return tmp;
}

#if (MHD_VERSION >= 0x00097002)
static enum MHD_Result
#else
static int
#endif
webserver_response(
    void *                 cls,
    struct MHD_Connection *connection,
    const char *           url,
    const char *           method,
    const char *           version,
    const char *           upload_data,
    unsigned long *        upload_data_size,
    void **                ptr)
{
    const char *     request_pfx = "http+unix://";
    size_t           request_pfx_len = strlen(request_pfx);
    int              http_status = MHD_HTTP_NOT_FOUND;
    int              ret;
    struct session * session;
    char *           path;
    struct url_desc *udesc = 0;
    int              write_fd;
    merr_t           err = 0;

    if (!(*ptr)) {
        /* The first call is only to establish a connection.
         * Create a new session to hold session-specific info
         */
        session = rest_session_create();
        if (ev(!session))
            return MHD_NO;

        /* Acquire a reference for the response callback, will
         * be released by rest_response_free().
         */
        atomic_inc(&session->refcnt);

        session->response = MHD_create_response_from_callback(
            MHD_SIZE_UNKNOWN, PIPE_BUF * 8, rest_response_cb, session, rest_response_free);

        if (!session->response) {
            rest_session_release(session);
            rest_session_release(session);
            return MHD_NO;
        }

        *ptr = session;

        return MHD_YES;
    }

    session = *ptr;
    write_fd = session->resp_pipe[1];

    if (strncmp(request_pfx, url, request_pfx_len) == 0) {
        const char *suffix = ".sock";
        char *      p = strstr(url + request_pfx_len, suffix);

        if (p)
            path = p + strlen(suffix) + 1;
        else
            path = (char *)url;
    } else {
        path = (char *)(url + 1);
    }

    if (!path || path[0] == 0) {
        err = merr(ev(ENOENT));
        http_status = MHD_HTTP_BAD_REQUEST;
        goto respond;
    }

    err = string_validate(path, REST_URL_LEN_MAX);
    if (ev(err)) {
        http_status = MHD_HTTP_UNPROCESSABLE_ENTITY;
        goto respond;
    }

    if (ev(!valid_method(method))) {
        http_status = MHD_HTTP_NOT_ACCEPTABLE;
        goto respond;
    }

    udesc = get_url_desc(path);
    if (!udesc) {
        size_t bytes;

        http_status = MHD_HTTP_NOT_FOUND;

        /* REST API version */
        if (strcmp(method, MHD_HTTP_METHOD_GET) == 0 && strcasecmp(path, "version") == 0) {
            bytes = snprintf(
                session->buf,
                sizeof(session->buf),
                "HSE REST API Version %d.%d %s\n",
                REST_VERSION_MAJOR,
                REST_VERSION_MINOR,
                HSE_VERSION_STRING);

            http_status = MHD_HTTP_OK;
            if (write(write_fd, session->buf, bytes) != bytes)
                http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
            shutdown(write_fd, SHUT_RDWR);
            goto respond;
        }

        /* REST API help */
        if (strcmp(method, MHD_HTTP_METHOD_GET) == 0 && strcasecmp(path, "help") == 0) {
            http_status = MHD_HTTP_OK;
            gen_help_msg(&bytes, session->buf, sizeof(session->buf));
            if (write(write_fd, session->buf, bytes) != bytes)
                http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
            shutdown(write_fd, SHUT_RDWR);
        }

        goto respond;
    }

    session->targ.udesc = udesc;
    session->targ.path = path;
    session->targ.ci = &session->ci;

    /* create an iterator for all the key=val pairs in the URL */
    err = kv_iter_init(&session->targ.iter);
    if (ev(err)) {
        http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        goto respond;
    }

    MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &extract_kv_pairs, session);

    if (ev(session->targ.iter.err)) {
        http_status = MHD_HTTP_UNPROCESSABLE_ENTITY;
        err = session->targ.iter.err;
        goto respond;
    }

    session->ci.data = upload_data;
    session->ci.data_sz = upload_data_size;
    session->ci.resp_fd = session->resp_pipe[1];
    session->ci.buf = session->buf;
    session->ci.buf_sz = sizeof(session->buf);

    /* Call the requested operation's handler, if registered */
    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0 && udesc->get_handler) {
        http_status = MHD_HTTP_OK;
        session->targ.op = URL_GET;
    } else if (
        (strcmp(method, MHD_HTTP_METHOD_PUT) == 0 || strcmp(method, MHD_HTTP_METHOD_POST) == 0) &&
        udesc->put_handler) {
        http_status = MHD_HTTP_OK;
        session->targ.op = URL_PUT;
    } else {
        http_status = MHD_HTTP_NOT_IMPLEMENTED;
        goto respond;
    }

    /* Acquire a reference for url_handler(), will be released
     * by url_handler().
     */
    atomic_inc(&session->refcnt);
    atomic_set(&session->targ.busy, 1);

    INIT_WORK(&session->targ.work, url_handler);
    session->enqueued = queue_work(rest.url_hdlr_wq, &session->targ.work);
    if (session->enqueued)
        http_status = MHD_HTTP_OK;
    else
        http_status = MHD_HTTP_TOO_MANY_REQUESTS;

respond:
    if (udesc && (http_status != MHD_HTTP_OK))
        atomic_dec(&udesc->refcnt);

    if (http_status != MHD_HTTP_OK) {
        size_t bytes;

        gen_help_msg(&bytes, session->buf, sizeof(session->buf));
        if (write(write_fd, session->buf, bytes) != bytes)
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        shutdown(write_fd, SHUT_RDWR);
        if (udesc)
            atomic_dec(&udesc->refcnt);
    }

    if (ev(err))
        hse_elog(HSE_ERR "rest api internal error: @@e", err);

    ret = MHD_queue_response(connection, http_status, session->response);
    MHD_destroy_response(session->response);

    return ret;
}

static void *
rest_session_complete(
    void *                          cls,
    struct MHD_Connection *         connection,
    void **                         con_cls,
    enum MHD_RequestTerminationCode toe)
{
    struct session *s = *con_cls;

    if (!s)
        return 0;

    assert(s->magic == s);

    if (s->enqueued) {
        if (ev(toe != MHD_REQUEST_TERMINATED_COMPLETED_OK))
            shutdown(s->resp_pipe[0], SHUT_RDWR);
    }

    rest_session_release(s);

    return 0;
}

static merr_t
get_socket(const char *sock_name, int *sock_out)
{
    struct sockaddr_un name = { 0 };
    int                ret;
    int                sock;
    size_t             n;

    /* In case the program exited inadvertently on the last run,
     * remove the socket.
     */
    unlink(sock_name);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
        return merr(ev(errno));

    name.sun_family = AF_UNIX;
    n = strlcpy(name.sun_path, sock_name, sizeof(name.sun_path));
    if (n >= sizeof(name.sun_path))
        return merr(ev(EINVAL));

    ret = bind(sock, (const struct sockaddr *)&name, sizeof(name));
    if (ret == -1) {
        close(sock);
        return merr(ev(errno));
    }

    ret = listen(sock, MAX_SESSIONS);
    if (ret == -1) {
        close(sock);
        return merr(ev(errno));
    }

    *sock_out = sock;

    return 0;
}

merr_t
rest_server_start(const char *sock_path)
{
    merr_t err;
    size_t n HSE_MAYBE_UNUSED;

    if (rest.monitor_daemon)
        return 0; /* only one rest port per process */

    /* Keep a copy of the socket path so we can unlink it when closing the
     * rest server. Use realpath(3) because unlink doesn't work with symlinks.
     */
    n = strlcpy(rest.sock_name, sock_path, sizeof(rest.sock_name));
    assert(n < sizeof(rest.sock_name));

    err = get_socket(rest.sock_name, &rest.sockfd);
    if (ev(err)) {
        hse_elog(HSE_ERR "Could not create socket %s: @@e", err, rest.sock_name);
        return err;
    }

    spin_lock_init(&rest.sessions_lock);

    rest.url_hdlr_wq = alloc_workqueue("url_handler_wq", 0, WQ_THREADS);
    if (!rest.url_hdlr_wq) {
        unlink(rest.sock_name);
        return merr(ev(ENOMEM));
    }

    rest.monitor_daemon = MHD_start_daemon(
        MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY,
        0,
        NULL,
        NULL,
        &webserver_response,
        NULL,
        MHD_OPTION_THREAD_POOL_SIZE,
        NUM_THREADS,
        MHD_OPTION_LISTEN_SOCKET,
        rest.sockfd,
        MHD_OPTION_CONNECTION_LIMIT,
        (unsigned int)MAX_SESSIONS,
        MHD_OPTION_CONNECTION_TIMEOUT,
        (unsigned int)120,
        MHD_OPTION_NOTIFY_COMPLETED,
        rest_session_complete,
        NULL,
        MHD_OPTION_END);
    if (!rest.monitor_daemon) {
        unlink(rest.sock_name);
        return merr(ev(ENOANO));
    }

    return 0;
}

void
rest_server_stop(void)
{
    int nbusy, tries, i;

    if (ev(!rest.monitor_daemon))
        return;

    unlink(rest.sock_name);
    MHD_stop_daemon(rest.monitor_daemon);

    for (tries = 0; tries < 3; ++tries) {
        spin_lock(&rest.sessions_lock);
        for (nbusy = i = 0; i < MAX_SESSIONS; ++i) {
            struct session *s = rest.sessions[i];

            if (s) {
                shutdown(s->resp_pipe[1], SHUT_RDWR);
                ++nbusy;
            }
        }
        spin_unlock(&rest.sessions_lock);

        if (nbusy == 0)
            break;

        hse_log(HSE_WARNING "%s: %d sessions still active", __func__, nbusy);
        msleep(3000);
    }

    /* Don't hang in desstroy_workqueue() if there are active sessions.
     */
    if (nbusy == 0)
        destroy_workqueue(rest.url_hdlr_wq);

    rest.monitor_daemon = NULL;
    rest.url_hdlr_wq = NULL;
}

ssize_t
rest_write_safe(int fd, const char *buf, size_t sz)
{
    struct timespec tv = {.tv_sec = 10 };
    struct pollfd   pfdv[1];
    sigset_t        mask;
    ssize_t         cc, nwr;
    int             n;

    pfdv[0].fd = fd;
    pfdv[0].events = POLLOUT;

    sigfillset(&mask);
    nwr = 0;

    while (nwr < sz) {
        cc = write(fd, buf + nwr, sz - nwr);
        if (cc > 0) {
            nwr += cc;
            continue;
        }

        if (cc == -1 && errno != EAGAIN)
            return -1;

        n = ppoll(pfdv, 1, &tv, &mask);
        if (n < 1) {
            if (ev(n == -1 && errno != EAGAIN))
                return -1;
            continue;
        }

        if (ev(pfdv[0].revents & (POLLERR | POLLHUP | POLLNVAL)))
            return -1;
    }

    return nwr;
}

ssize_t
rest_write_string(int fd, const char *string)
{
    if (!string && *string)
        return 0;

    return rest_write_safe(fd, string, strlen(string));
}

ssize_t
rest_write_ulong(int fd, const char *prefix, ulong value, const char *suffix)
{
    ssize_t n = 0;
    char    buf[128];

    snprintf(buf, sizeof(buf), "%lu", value);

    n += rest_write_string(fd, prefix);
    n += rest_write_string(fd, buf);
    n += rest_write_string(fd, suffix);

    return n;
}
