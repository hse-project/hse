/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/mutex.h>
#include <hse_util/minmax.h>
#include <hse_util/parse_num.h>
#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>
#include <hse_ikvdb/hse_gparams.h>

#include <hse/version.h>

#include "logging_impl.h"
#include "logging_util.h"

/*
 * This file implements the platform logging functionality. The design
 * objectives for this functionality are as follows:
 *
 *   (1) It must be functional both in user space and inside the Linux kernel
 *
 *   (2) It must support both structured and unstructured logging in a
 *       fashion that can enter a syslog fabric for further processing
 *
 *   (3) It must present minimal syntactic overhead at the call site
 *
 * Item (3) is important to ensure that the facility is widely and uniformly
 * used through the storage engine's source code, and does not impair the
 * readability of the source code.
 */

#define PARAM_GET_INVALID(_type, _dst, _dstsz) \
    ({ ((_dstsz) < sizeof(_type) || !(_dst) || (uintptr_t)(_dst) & (__alignof__(_type) - 1)); })

/**
 * struct hse_log_async_entry - an asynchronous log message in the circular
 * buffer.
 * @ae_source_line:
 * @ae_priority:
 * @ae_buf: The format is: <source filename>0<string>
 *      with "string" 0 terminated. While is should not happen, string may be
 *      empty or not be there at all if <source filename> it too big.
 *      "string" is logged by the async log consumer thread with a format %s.
 */
struct hse_log_async_entry {
    s32          ae_source_line;
    hse_logpri_t ae_priority;
    char         ae_buf[HSE_LOG_STRUCTURED_DATALEN_MAX];
};

/**
 * struct hse_log_async - allow to log from interrupt context.
 *      The log messages are only stored in a circular buffer attached to
 *      structure. The hse_log workqueue calls hse_log_async() to process them later.
 * @al_wstruct:
 * @al_lock: Protect the fields below.
 * @al_th_working: true if the async log consumer thread is working.
 * @al_cons: always increasing and rolling integer.
 *      al_cons%MAX_LOGGING_ASYNC_ENTRIES is the index in al_entries[]
 *      where the next entry to consume is located.
 *      Only changed by the thread _hse_log_async_cons_th().
 * @al_nb: 0 <= al_nb <= MAX_LOGGING_ASYNC_ENTRIES. Number on entries
 *      in al_entries[] ready to be consumed.
 * @al_entries: circular buffer of log messages.
 */
struct hse_log_async {
    struct workqueue_struct *   al_wq;
    struct work_struct          al_wstruct;
    struct mutex                al_lock;
    bool                        al_running;
    u32                         al_cons;
    u32                         al_nb;
    struct hse_log_async_entry *al_entries;
};

struct hse_log_infrastructure {
    char  mli_nm_buf[HSE_LOG_STRUCTURED_DATALEN_MAX] HSE_ACP_ALIGNED;
    char  mli_fmt_buf[HSE_LOG_STRUCTURED_DATALEN_MAX];
    char  mli_sd_buf[HSE_LOG_STRUCTURED_DATALEN_MAX];
    char  mli_json_buf[HSE_LOG_STRUCTURED_DATALEN_MAX];
    char *mli_name_buf[HSE_LOG_NV_PAIRS_MAX];
    char *mli_value_buf[HSE_LOG_NV_PAIRS_MAX];
    bool  mli_active;
    struct hse_log_async mli_async;
};

struct hse_log_code {
    hse_log_fmt_func_t *fmt; /* generic string printf-like fmt  */
    hse_log_add_func_t *add; /* structured field */
};

static DEFINE_MUTEX(hse_log_lock);
static struct hse_log_infrastructure hse_log_inf;

FILE *hse_log_file = NULL;

/**
 * hse_log_async_consume() - log one entry of the circular buffer.
 * @entry: entry in the circular buffer that needs to be logged.
 *
 * Locking: no lock held because this entry in the circular buffer can only
 *      be changed by this thread at the moment.
 */
static void
hse_log_async_consume(struct hse_log_async_entry *entry)
{
    u32 source_file_len;
    const char *slog_prefix = hse_gparams.gp_logging.structured ? "@cee:" : "";

    source_file_len = strlen(entry->ae_buf);
    if (source_file_len >= (sizeof(entry->ae_buf) - 2))
        /* No room to place anything behind the source file name. */
        return;

    entry->ae_buf[sizeof(entry->ae_buf) - 1] = 0;

    hse_slog_emit(entry->ae_priority, "%s%s\n", slog_prefix, entry->ae_buf + source_file_len + 1);
}

/**
 * hse_log_async() - consumer of the async logs.
 * @wstruct:
 *
 * Process the log messages that were posted in the circular buffer
 * until the circular buffer is empty.
 * It offloads the processing and actual logging of the log messages.
 */
static void
hse_log_async(struct work_struct *wstruct)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    u32                         loop = 0;

    async = container_of(wstruct, struct hse_log_async, al_wstruct);

    /* Process all the log messages in the circular buffer.
     */
    mutex_lock(&async->al_lock);

    while (async->al_nb > 0) {
        entry = async->al_entries + async->al_cons % HSE_LOG_ASYNC_ENTRIES_MAX;
        mutex_unlock(&async->al_lock);

        hse_log_async_consume(entry);

        /* Don't hog the cpu. */
        if ((++loop % 128) == 0)
            usleep(100 * 1000);

        mutex_lock(&async->al_lock);
        async->al_cons++;
        async->al_nb--;
    }

    async->al_running = false;
    mutex_unlock(&async->al_lock);
}

/* Note that this function only enables async logging and maybe
 * redirects the logging destination.  Calls to hse_log() should
 * work before, during, and after calls to this function,
 * regardless of whether or not it succeeds.
 */
merr_t
hse_log_init(void)
{
    struct hse_log_async *async = &hse_log_inf.mli_async;
    struct hse_log_async_entry *entryv = NULL;
    struct workqueue_struct *wq = NULL;
    FILE *fp = NULL;
    merr_t err;

    if (!hse_gparams.gp_logging.enabled)
        return 0;

    if (hse_gparams.gp_logging.destination == LD_STDOUT) {
        fp = stdout;
    } else if (hse_gparams.gp_logging.destination == LD_STDERR) {
        fp = stderr;
    } else if (hse_gparams.gp_logging.destination == LD_FILE) {
        fp = fopen(hse_gparams.gp_logging.path, "a");
        if (!fp) {
            err = merr(errno);
            log_errx("failed to open log file %s: @@e",
                     err, hse_gparams.gp_logging.path);
            return err;
        }

        setlinebuf(fp);
    }

    entryv = calloc(HSE_LOG_ASYNC_ENTRIES_MAX, sizeof(*entryv));
    if (!entryv) {
        log_err("failed to alloc async entries");
        err = merr(ENOMEM);
        goto errout;
    }

    wq = alloc_workqueue("hse_log", 0, 1, 1);
    if (!wq) {
        log_err("failed to create hse_log workqueue");
        err = merr(ENOMEM);
        goto errout;
    }

    mutex_lock(&hse_log_lock);
    err = hse_log_inf.mli_active ? merr(EBUSY) : 0;
    if (!err) {
        mutex_init(&async->al_lock);
        async->al_entries = entryv;
        async->al_wq = wq;
        hse_log_file = fp;
        hse_log_inf.mli_active = true;
    }
    mutex_unlock(&hse_log_lock);

errout:
    if (err) {
        if (fp && fp != stdout && fp != stderr)
            fclose(fp);
        destroy_workqueue(wq);
        free(entryv);
    }

    return err;
}

/* Note that this function only disables async logging and maybe
 * redirects the logging destination.  Calls to hse_log() should
 * work before, during, and after calls to this function.
 */
void
hse_log_fini(void)
{
    struct hse_log_async *async = &hse_log_inf.mli_async;
    struct workqueue_struct *wq = NULL;
    void *entryv;
    FILE *fp;

    mutex_lock(&hse_log_lock);
    if (hse_log_inf.mli_active) {
        mutex_lock(&async->al_lock);
        wq = async->al_wq;
        async->al_wq = NULL;
        mutex_unlock(&async->al_lock);
    }
    mutex_unlock(&hse_log_lock);

    if (!wq)
        return;

    /* Wait for the async logging consumer thread to exit. */
    destroy_workqueue(wq);

    /* Other than the async logger (which has an implicit reference
     * on hse_log_file) all other usage of hse_log_file should be
     * guarded by hse_log_lock such that it should now be safe to
     * reset it now that the async logger is no longer running.
     */
    mutex_lock(&hse_log_lock);
    fp = hse_log_file;
    hse_log_file = NULL;

    mutex_destroy(&async->al_lock);
    entryv = async->al_entries;
    async->al_entries = NULL;
    async->al_cons = 0;
    async->al_nb = 0;

    hse_log_inf.mli_active = false;
    mutex_unlock(&hse_log_lock);

    if (fp && fp != stdout && fp != stderr)
        fclose(fp);

    free(entryv);
}

/*
 * hse_log_post_vasync() - post the log message in a circular buffer.
 * @source_file: source file of the logging site
 * @source_line: line number of the logging site
 * @priority: priority of the log message
 * @fmt_string: the platform-specific format string
 * @args: variable-length argument list
 *
 * Locking: can be called from interrupt handler => can't block.
 */
static void
hse_log_post_vasync(
    const char   *source_file,
    s32           source_line,
    hse_logpri_t  priority,
    const char   *fmt_string,
    va_list       args)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    bool                        start;
    char *                      buf;

    async = &(hse_log_inf.mli_async);

    mutex_lock(&async->al_lock);
    if (async->al_nb == HSE_LOG_ASYNC_ENTRIES_MAX || !async->al_wq) {
        /* Circular buffer full. */
        mutex_unlock(&async->al_lock);
        ev(ENOENT);
        return;
    }

    /* Next free entry */
    entry = async->al_entries + (async->al_cons + async->al_nb) % HSE_LOG_ASYNC_ENTRIES_MAX;

    buf = entry->ae_buf;
    buf[0] = 0;
    entry->ae_source_line = source_line;
    entry->ae_priority = priority;

    /*
     * Place the source file name at the beginning of the entry buffer
     * and place a 0 behind.
     */
    strncat(buf, (source_file == NULL) ? "" : source_file, sizeof(entry->ae_buf) - 1);

    /* Move behind the 0 */
    buf += strlen(buf) + 1;

    /*
     * If source_file fills up entry->ae_buf completely, vsnprintf()
     * does nothing.
     */
    vsnprintf(buf, sizeof(entry->ae_buf) - (buf - entry->ae_buf), fmt_string, args);

    async->al_nb++;

    /* Start the consumer thread if it is not already working. */
    start = !async->al_running;
    if (start)
        async->al_running = true;
    mutex_unlock(&async->al_lock);

    if (start) {
        INIT_WORK(&async->al_wstruct, hse_log_async);
        queue_work(async->al_wq, &async->al_wstruct);
    }
}

/*
 * hse_log_post_async() - post the log message as json payload
 * in a circular buffer.
 * @source_file: source file of the logging site
 * @source_line: line number of the logging site
 * @priority: priority of the log message
 * @payload: fixed length payload
 *
 * Locking: can be called from interrupt handler => can't block.
 */
static void
hse_log_post_async(const char *source_file, s32 source_line, hse_logpri_t priority, char *payload)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    bool                        start;
    char *                      buf;

    async = &(hse_log_inf.mli_async);

    mutex_lock(&async->al_lock);
    if (async->al_nb == HSE_LOG_ASYNC_ENTRIES_MAX || !async->al_wq) {
        /* Circular buffer full. */
        mutex_unlock(&async->al_lock);
        ev(ENOENT);
        return;
    }

    /* Next free entry */
    entry = async->al_entries + (async->al_cons + async->al_nb) % HSE_LOG_ASYNC_ENTRIES_MAX;

    buf = entry->ae_buf;
    buf[0] = 0;
    entry->ae_source_line = source_line;
    entry->ae_priority = priority;

    /*
     * Place the source file name at the beginning of the entry buffer
     * and place a 0 behind.
     */
    strncat(buf, (source_file == NULL) ? "" : source_file, sizeof(entry->ae_buf) - 1);

    /* Move behind the 0 */
    buf += strlen(buf) + 1;

    /*
     * If source_file fills up entry->ae_buf completely, vsnprintf()
     * does nothing.
     */
    snprintf(buf, sizeof(entry->ae_buf) - (buf - entry->ae_buf), "%s", payload);

    async->al_nb++;

    /* Start the consumer thread if it is not already working. */
    start = !async->al_running;
    if (start)
        async->al_running = true;
    mutex_unlock(&async->al_lock);

    if (start) {
        INIT_WORK(&async->al_wstruct, hse_log_async);
        queue_work(async->al_wq, &async->al_wstruct);
    }
}

/*
 * The function hse_log() accomplishes the actual logging function and is
 * invoked by client code through the use of macros. The code does two things:
 * (1) abstracts away the difference between logging in user space via
 * syslog() and in kernel space via printk(), and (2) offers structured
 * logging extensions that are relevant to the functional domain.
 *
 * Item (1) is accomplished through macros and conditional compilation. When
 * compiling for user space, the code will use the extended lumberjack API to
 * capture both structured data and a human-readable message. When compiling
 * for operation in kernel space, the code will use the printk_emit kernel
 * function.
 *
 * Item (2) is accomplished by extending the syntax of the format string and
 * by providing an additional variable argument structure that contains
 * pointers to the elements which will be logged. The extended format string
 * uses a '@@' prefix and a handful of domain-specific conversion specifiers.
 *
 * For each of these, the log message targeted at humans is augmented with
 * machine-parseable information. In addition, data is added to the structured
 * log data container specific for user or kernel space. Pointers to data
 * representing the extended types are passed in as an array of pointers.
 */
void
hse_log(
    struct event_counter *ev, /* contains call site info and pri     */
    const char *fmt_string,   /* the platform-specific format string */
    bool        async,        /* true=>only queue in circular buffer */
    void **     hse_args,     /* array of pointers (or NULL)         */
    ...)                      /* variable-length argument list       */
{
    struct hse_log_fmt_state state;
    va_list                  args;
    int                      num_hse_args;
    char *                   int_fmt = hse_log_inf.mli_fmt_buf;
    bool                     res = false;
    u64 now;

    if (ev->ev_pri > hse_gparams.gp_logging.level || !hse_gparams.gp_logging.enabled)
        return;

    event_counter(ev);

    now = get_time_ns();
    if (now < ev->ev_priv)
        return;

    ev->ev_priv = now + hse_gparams.gp_logging.squelch_ns;

    mutex_lock(&hse_log_lock);

    state.dict = hse_log_inf.mli_sd_buf;
    state.dict_rem = HSE_LOG_STRUCTURED_DATALEN_MAX;
    state.dict_pos = state.dict;
    state.names = hse_log_inf.mli_name_buf;
    state.values = hse_log_inf.mli_value_buf;

    /*
     * This code is at the mercy of the caller actually putting a NULL
     * as the last element of the hse_args array. The following code
     * scans until either a NULL is found or HSE_LOG_SPECS_MAX have
     * been found. In the latter case, the call is aborted.
     */
    num_hse_args = 0;
    if (hse_args) {
        while (hse_args[num_hse_args] && num_hse_args <= HSE_LOG_SPECS_MAX)
            num_hse_args++;
        if (hse_args[num_hse_args]) {
            hse_log_backstop("%s: hse_args list too long\n", __func__);
            goto out;
        }
    } else {
        static void *hse_args_none[] = { NULL };

        hse_args = hse_args_none;
    }
    state.num_hse_specs = num_hse_args;
    assert(state.num_hse_specs <= HSE_LOG_SPECS_MAX);

    state.hse_spec_cnt = 0;
    state.nv_index = 0;
    state.source_info_set = false;

    pack_source_info(&state);

    va_start(args, hse_args);
    res = vpreprocess_fmt_string(
        &state, ev->ev_dte.dte_func, fmt_string, int_fmt,
        HSE_LOG_STRUCTURED_DATALEN_MAX, hse_args, args);
    va_end(args);

    if (res) {
        async = async && hse_log_inf.mli_async.al_wq;

        va_start(args, hse_args);
        finalize_log_structure(ev->ev_pri, async, ev->ev_file, ev->ev_line, &state, int_fmt, args);
        va_end(args);
    }

out:
    mutex_unlock(&hse_log_lock);
}

static struct hse_log_code codetab[52];

static struct hse_log_code *
get_code_slot(int code)
{
    if ((code | 32) < 'a' || (code | 32) > 'z')
        return NULL;

    code = (code < 'a') ? code - 'A' : 26 + code - 'a';
    return &codetab[code];
}

bool
pack_source_info(struct hse_log_fmt_state *state)
{
    bool        res;

    if (!state->source_info_set) {
        res =
            (push_nv(state, false, "hse_logver", HSE_LOGGING_VER) &&
             push_nv(state, false, "hse_version", HSE_VERSION_STRING));
        if (!res)
            return res;

        state->nv_hse_index = 2;
        state->source_info_set = true;
    }

    return true;
}

bool
vpreprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char               *func,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    va_list                   args)
{
    /*
     * The loop below scans the format string character by character and
     * constructs a new format string as it does so. If an extended
     * conversion specifier is detected, then the new format string will
     * be populated with a formatted representation of its positionally
     * corresponding object. If a standard conversion specifier is
     * detected then the literal conversion specification will be copied
     * to the new format string.
     *
     * Structured data is captured for the extended conversion specifiers.
     * The structured data is packed into the dictionary format and the
     * data accumulated in dictonary is converted to json paylod. The  json
     * payload is passed as an argument to syslog in user space and
     * printk_emit in kernel space
     *
     * The scanning of the format string is done by consuming one
     * character at a time and executing a simple state machine. The state
     * machine's base state is 'LITERAL', transitioning to IN_STD_FORMAT
     * when a non-extended conversion specifier is detected and to
     * IN_HSE_FORMAT when an extended conversion is detected.
     */

    const char *msg1 = "%s: extra hse conversion specifiers found\n";

    bool  res = true;
    char *src_pos = (char *)fmt;
    char *tgt_pos = new_fmt;
    char *tgt_end = new_fmt + (new_len - 1);
    char  c = *src_pos++;

    void *obj;
    s32   hse_cnt = 0;

    enum hse_log_fmt_parse_state parse_state = LITERAL;

    tgt_pos += snprintf(tgt_pos, tgt_end - tgt_pos, "%s %s: ", HSE_MARK, func);

    /* optimization: copy until special char, if any */
    while (c && c != '%' && c != '@' && tgt_pos < tgt_end) {
        *tgt_pos++ = c;
        c = *src_pos++;
    }

    while (c && (tgt_pos < tgt_end)) {
        switch (parse_state) {
            case LITERAL:
                res = LITERAL_handler(&parse_state, state, c, src_pos, &tgt_pos, tgt_end);
                c = *src_pos++;
                break;

            case IN_STD_FORMAT:
                res =
                    IN_STD_FORMAT_handler(&parse_state, state, args, c, src_pos, &tgt_pos, tgt_end);
                c = *src_pos++;
                break;

            case IN_HSE_FORMAT:
                if (hse_cnt == state->num_hse_specs) {
                    hse_log_backstop(msg1, __func__);
                    return false;
                }

                obj = hse_args[hse_cnt];
                res =
                    IN_HSE_FORMAT_handler(&parse_state, state, obj, c, &src_pos, &tgt_pos, tgt_end);
                if (!res)
                    return false;

                hse_cnt++;
                c = *src_pos++;
                break;

            default:
                assert(0);
                res = false;
        }

        if (!res)
            break;
    }
    *tgt_pos = 0;

    return res;
}

bool
LITERAL_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    char                          c,
    char *                        spec_pos,
    char **                       tgt_pos,
    char *                        tgt_end)
{
    char *tgt = *tgt_pos;

    if (HSE_UNLIKELY(c == '%')) {
        *parse_state = IN_STD_FORMAT;
        *tgt++ = c;
    } else {
        if (HSE_UNLIKELY(c == '@' && *spec_pos == '@')) {
            *parse_state = IN_HSE_FORMAT;
        } else {
            /* likely */
            *tgt++ = c;
        }
    }
    *tgt_pos = tgt;

    return true;
}

bool
IN_STD_FORMAT_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    va_list                       args,
    char                          c,
    char *                        spec_pos,
    char **                       tgt_pos,
    char *                        tgt_end)
{
    char *tgt = *tgt_pos;

    if (is_std_specifier(c))
        *parse_state = LITERAL;

    *tgt++ = c;
    *tgt_pos = tgt;

    return true;
}

bool
IN_HSE_FORMAT_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    void *                        obj,
    char                          c,
    char **                       src_pos,
    char **                       tgt_pos,
    char *                        tgt_end)
{
    /*
     * Execution is here because the LITERAL_handler saw c == '@' and
     * looked ahead one character also seeing a second '@'. The value of
     * c now is that second '@' and spec_pos points at the start of the
     * potential conversion specifier.
     */

    struct hse_log_code *slot = get_code_slot(**src_pos);

    c = **src_pos;

    if (!slot || !slot->fmt) {
        hse_log_backstop("%s: invalid hse conversion specifier %c\n", __func__, c);
        return false;
    }

    ++*src_pos; /* [HSE_REVISIT]: multi-char: pos += slot->len? */

    if (!append_hse_arg(slot, tgt_pos, tgt_end, state, obj)) {
        hse_log_backstop("%s: cannot append hse conversion specifier %c\n", __func__, c);
        return false;
    }

    *parse_state = LITERAL;

    return true;
}

bool
hse_log_register(int code, hse_log_fmt_func_t *fmt, hse_log_add_func_t *add)
{
    struct hse_log_code *slot;
    bool b = false;

    mutex_lock(&hse_log_lock);
    slot = get_code_slot(code);
    if (slot && !slot->fmt && fmt && add) {
        slot->fmt = fmt;
        slot->add = add;
        b = true;
    }
    mutex_unlock(&hse_log_lock);

    return b;
}

bool
hse_log_deregister(int code)
{
    struct hse_log_code *slot;

    mutex_lock(&hse_log_lock);
    slot = get_code_slot(code);
    if (slot) {
        slot->fmt = NULL;
        slot->add = NULL;
    }
    mutex_unlock(&hse_log_lock);

    return !!slot;
}

/* -------------------------------------------------- */

bool
append_hse_arg(
    struct hse_log_code *     slot,
    char **                   tgt_pos,
    char *                    tgt_end,
    struct hse_log_fmt_state *state,
    void *                    obj)
{
    bool        res;

    if (!state->source_info_set) {
        res =
            (push_nv(state, false, "hse_logver", HSE_LOGGING_VER) &&
             push_nv(state, false, "hse_version", HSE_VERSION_STRING));
        if (!res)
            return res;
        state->source_info_set = true;
    }

    res = slot->add(state, obj) && slot->fmt(tgt_pos, tgt_end, obj);
    if (res)
        state->hse_spec_cnt++;

    return res;
}

/******************************************************************************
 * Is the given character a valid printf() conversion specifier?
 ******************************************************************************/
bool
is_std_specifier(int c)
{
    static const bool specv[] = {
        ['%'] = true, ['A'] = true, ['E'] = true, ['F'] = true,
        ['G'] = true, ['X'] = true, ['a'] = true, ['c'] = true,
        ['d'] = true, ['e'] = true, ['f'] = true, ['g'] = true,
        ['i'] = true, ['n'] = true, ['o'] = true, ['p'] = true,
        ['s'] = true, ['u'] = true, ['x'] = true
    };

    return (c > 0) && (c < NELEM(specv)) && specv[c];
}

/******************************************************************************
 * Determine the conversion specifier's length modifier (if any)
 ******************************************************************************/
enum std_length_modifier
get_std_length_modifier(char *spec_pos)
{
    --spec_pos; /* src_pos is pointing one char past the specifier */

    switch (*spec_pos) {
        case 'h':
            return (*(spec_pos - 1) == 'h') ? LEN_MOD_hh : LEN_MOD_h;
        case 'l':
            return (*(spec_pos - 1) == 'l') ? LEN_MOD_ll : LEN_MOD_l;
        case 'j':
            return LEN_MOD_j;
        case 'z':
            return LEN_MOD_z;
        case 't':
            return LEN_MOD_t;
        case 'L':
            return LEN_MOD_L;
        default:
            return LEN_MOD_none;
    }
}

/* public api for private implementation */
bool
hse_log_push(struct hse_log_fmt_state *state, bool index, const char *name, const char *val)
{
    return push_nv(state, index, name, val);
}

bool
push_nv(struct hse_log_fmt_state *state, bool index, const char *name, const char *val)
{
    char * buf = hse_log_inf.mli_nm_buf;
    size_t sz;
    char * tmp = (char *)name;
    char * name_offset;
    char * val_offset;

    if (state->nv_index >= HSE_LOG_NV_PAIRS_MAX)
        return false;

    if (index) {
        sz = snprintf(buf, HSE_LOG_STRUCTURED_NAMELEN_MAX, name, state->hse_spec_cnt);
        if (sz > HSE_LOG_STRUCTURED_NAMELEN_MAX)
            return false;
        tmp = buf;
    }
    if (!pack_nv(state, tmp, &name_offset, val, &val_offset))
        return false;

    state->names[state->nv_index] = name_offset;
    state->values[state->nv_index] = val_offset;
    state->nv_index++;

    return true;
}

/******************************************************************************
 * Take a log format state and name/value pair, and pack the pair into the
 * state's buffer memory.
 *
 * In kernel-space, this is the printk_emit dict format. That format consists
 * of a sequence of bytes with a known total length in which are embedded
 * NULL-terminated blobs of data. Each of these blobs is of the pattern
 * \c+=\c* - one or more printable characters other than '=', followed by
 * zero or more printable characters. These are key/value pairs.
 *
 * In user-space, this is a triple of null-terminated strings. The first
 * string is the name, the second is the conversion specifier giving the
 * type (e.g., "%s" for a string), and the third is the value.
 *
 * In both cases the memory addresses for the start of the name and the start
 * of the value are copied into the two passed-in offset pointers.
 *
 * Restrictions: Caller must ensure that neither 'name' or 'value' contains
 *                the characters '=' or NULL.
 *
 * Returns: false if the data won't fit, true otherwise
 ******************************************************************************/
bool
pack_nv(
    struct hse_log_fmt_state *state,
    const char *              name,
    char **                   name_offset,
    const char *              value,
    char **                   value_offset)
{
    int  space = state->dict_rem;
    int  name_sz = strlen(name);
    int  value_sz = strlen(value);
    char field_sep = '\0';

    if ((name_sz + 1 + value_sz + 1) > space)
        return false;

    memcpy(state->dict_pos, name, name_sz);
    if (name_offset)
        *name_offset = state->dict_pos;
    state->dict_pos += name_sz;

    *state->dict_pos++ = field_sep;
    memcpy(state->dict_pos, value, value_sz);
    if (value_offset)
        *value_offset = state->dict_pos;
    state->dict_pos += value_sz;

    *state->dict_pos++ = field_sep;
    state->dict_rem -= name_sz + value_sz + 2;
    return true;
}

void
finalize_log_structure(
    hse_logpri_t              priority,
    bool                      async,
    const char *              source_file,
    s32                       source_line,
    struct hse_log_fmt_state *st,
    const char *              fmt,
    va_list                   args)
{
    int                 i, j;
    struct json_context jc = { 0 };
    char *              msg_buf;
    const char *        slog_prefix = "@cee:";

    msg_buf = hse_log_inf.mli_nm_buf;

    i = vsnprintf(msg_buf, HSE_LOG_STRUCTURED_DATALEN_MAX, fmt, args);

    if (!hse_gparams.gp_logging.structured) {
        jc.json_buf = msg_buf;
        slog_prefix = "";
        goto emit_logs;
    }

    jc.json_buf = hse_log_inf.mli_json_buf;
    jc.json_buf_sz = HSE_LOG_STRUCTURED_DATALEN_MAX;

    json_element_start(&jc, NULL);

    json_element_field(&jc, "type", "%s", "log");

    for (i = 0; i < st->nv_hse_index; ++i)
        json_element_field(&jc, st->names[i], "%s", st->values[i]);

    json_element_start(&jc, "content");
    json_element_field(&jc, "msg", "%s", msg_buf);

    for (j = i; j < st->nv_index; ++j)
        json_element_field(&jc, st->names[j], "%s", st->values[j]);

    json_element_end(&jc);
    json_element_end(&jc);

  emit_logs:
    if (async)
        hse_log_post_async(source_file, source_line, priority, jc.json_buf);
    else
        hse_slog_emit(priority, "%s%s\n", slog_prefix, jc.json_buf);
}

const char *
hse_logpri_val_to_name(hse_logpri_t val)
{
    static const char *namev[] = {
        "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"
    };

    val = clamp_t(hse_logpri_t, val, 0, NELEM(namev) - 1);

    return namev[val];
}

hse_logpri_t
hse_logpri_name_to_val(const char *name)
{
    const char *list = "EMERG   ALERT   CRIT    ERR     WARNING NOTICE  INFO    DEBUG   ";

    name = strcasestr(list, name);
    if (name)
        return (name - list) / 8;

    return HSE_LOGPRI_DEBUG;
}

static void
package_source_info(struct json_context *jc)
{
    json_element_field(jc, "hse_logver", "%s", HSE_LOGGING_VER);
    json_element_field(jc, "hse_version", "%s", HSE_VERSION_STRING);
}

static void
hse_format_payload(struct json_context *jc, va_list payload)
{
    int   token, cnt;
    char *key, *fmt;
    void *val;

    token = va_arg(payload, int);

    while (token) {
        switch (token) {
            case _SLOG_START_TOKEN:
                json_element_start(jc, NULL);
                json_element_fieldv(jc, payload);
                package_source_info(jc);
                json_element_start(jc, "content");
                break;
            case _SLOG_CHILD_START_TOKEN:
                key = va_arg(payload, char *);
                json_element_start(jc, key);
                break;
            case _SLOG_FIELD_TOKEN:
                json_element_fieldv(jc, payload);
                break;
            case _SLOG_LIST_TOKEN:
                key = va_arg(payload, char *);
                fmt = va_arg(payload, char *);
                cnt = va_arg(payload, int);
                val = va_arg(payload, void *);
                json_element_list(jc, key, fmt, cnt, val);
                break;
            case _SLOG_CHILD_END_TOKEN:
                json_element_end(jc);
                break;
            case _SLOG_END_TOKEN:
                json_element_end(jc);
                json_element_end(jc);
                break;
            default:
                break;
        }

        token = va_arg(payload, int);
    }
}

/* The hse_slog() interface provides a simple way to build structured log
 * messages. The provided macros validate the format string and return tokens
 * understood by the internal parser. Refer to the example below.
 *
 * hse_slog(
 *     HSE_NOTICE
 *     HSE_SLOG_START("example")
 *     HSE_SLOG_FIELD("hello", "%s", "world")
 *     HSE_SLOG_CHILD_START("data")
 *     HSE_SLOG_FIELD("foobar", "%d", 2000)
 *     HSE_SLOG_LIST("count", "%d", argc, argv)
 *     HSE_SLOG_CHILD_END
 *     HSE_SLOG_END
 * )
 *
 * @cee:{
 *     "type": "example",
 *     "hse_logver": "1",
 *     "hse_version": "nfpib-r0.20191212.59d333394"
 *     "hse_branch": "nfpib",
 *     "content": {
 *         "hello": "world",
 *         "data": {
 *             "foobar": 2000,
 *             "count": [1,2,3]
 *         }
 *     }
 * }
 *
 * Note that certain fields are always packed into the final payload. Since
 * the C standard specifies up to 127 arguments in a function call, hse_slog()
 * can support at least 30 fields. However, no such limit is enforced by GCC.
 *
 * When the structure is not known in advance, the message may be built
 * programmatically. Use hse_slog_create(), hse_slog_append(), and
 * hse_slog_commit() to parse tokens dynamically. The start and end tokens
 * are implictly set, so hse_slog_append() can handle fields directly. The
 * example below creates five keys-value pairs at runtime.
 *
 * char          key[32];
 * struct slog  *logger;
 *
 * hse_slog_create(&logger, "example");
 *
 * for (i = 0; i < 5; i++) {
 *     snprintf(key, sizeof(key), "key_%d", i);
 *     for (j = 0; j < 5; j++)
 *         hse_slog_append(logger, HSE_SLOG_FIELD(key, "%d", j));
 * }
 *
 * hse_slog_commit(HSE_NOTICE, logger);
 *
 * 1) The hse_log and hse_alog macros resolve to the same hse_log() call.
 * Since all hse_log calls are asynchronous by default, hse_alog should be
 * removed.
 *
 * 2) The hse_log() call does duplicate work since it handles both async
 * and sync calls. The logic should be divided similar to hse_slog() and
 * hse_slog_emit().
 *
 * 3) The filename and source line are placed on the circular buffer, but
 * are not logged anywhere. If they are not part of the CEE payload, they
 * should be removed from the function definition.
 *
 * 4) Standard messages are still structured but only populate the "msg"
 * field. The existing logic for hse_slog() can be used to refactor
 * hse_log().
 *
 * 5) The locks for the global logging buffer and the async circular
 * buffer should be mutually exclusive. Adding additional global buffers
 * would also allow for multiple threads to preprocess their messages
 * without waiting on any locks.
 *
 * 6) The syslog-ng config ensures that all messages are
 * in CEE format. This is done with a JSON parser in the template. If the
 * MESSAGE field in journalctl is always in CEE format, then we can remove
 * this extra post processing .
 */
void
hse_slog_internal(hse_logpri_t priority, const char *fmt, ...)
{
    va_list       payload;
    const char *  buf;

    if (!hse_gparams.gp_logging.structured)
        return;

    if (priority >= hse_gparams.gp_logging.level || !hse_gparams.gp_logging.enabled)
        return;

    va_start(payload, fmt);
    mutex_lock(&hse_log_lock);

    if (fmt) {
        buf = fmt;
    } else {
        struct json_context jc = { 0 };

        jc.json_buf = hse_log_inf.mli_fmt_buf;
        jc.json_buf_sz = HSE_LOG_STRUCTURED_DATALEN_MAX;

        hse_format_payload(&jc, payload);

        buf = hse_log_inf.mli_fmt_buf;
    }

    hse_log_post_vasync("_hse_slog", 1, priority, buf, payload);

    mutex_unlock(&hse_log_lock);
    va_end(payload);
}

/* hse_slog_emit() is overridden by all the logging unit tests.
 */
void HSE_WEAK
hse_slog_emit(hse_logpri_t priority, const char *fmt, ...)
{
    va_list payload;

    va_start(payload, fmt);
    if (hse_log_file) {
        vfprintf(hse_log_file, fmt, payload);
    } else {
        vsyslog(priority, fmt, payload);
    }
    va_end(payload);
}

int
hse_slog_create(hse_logpri_t priority, struct slog **sl, const char *type)
{
    struct json_context *jc;

    if (!sl || !type)
        return EINVAL;

    if (priority > hse_gparams.gp_logging.level || !hse_gparams.gp_logging.enabled) {
        *sl = NULL;
        return 0;
    }

    *sl = calloc(1, sizeof(struct slog));
    if (ev(!*sl))
        return ENOMEM;

    jc = &((*sl)->sl_json);
    jc->json_buf_sz = 2048;

    jc->json_buf = malloc(jc->json_buf_sz);
    if (ev(!jc->json_buf)) {
        free(*sl);
        *sl = NULL;
        return ENOMEM;
    }

    json_element_start(jc, NULL);
    json_element_field(jc, "type", "%s", type);
    package_source_info(jc);
    json_element_start(jc, "content");

    (*sl)->sl_priority = priority;
    (*sl)->sl_entries = 0;

    return 0;
}

int
hse_slog_append_internal(struct slog *sl, ...)
{
    va_list              payload;
    struct json_context *jc;

    if (!sl)
        return 0;

    jc = &sl->sl_json;

    if (jc->json_offset > (jc->json_buf_sz - jc->json_offset) / 2) {
        char *new_buf;

        new_buf = realloc(jc->json_buf, jc->json_buf_sz * 2);
        if (ev(!new_buf))
            goto err;

        jc->json_buf = new_buf;
        jc->json_buf_sz *= 2;
    }

    va_start(payload, sl);
    hse_format_payload(jc, payload);
    va_end(payload);

    sl->sl_entries++;

    return 0;
err:
    free(jc->json_buf);
    free(sl);
    return ENOMEM;
}

int
hse_slog_commit(struct slog *sl)
{
    struct json_context *jc;

    if (!sl)
        return 0;

    jc = &sl->sl_json;

    json_element_end(jc);
    json_element_end(jc);

    mutex_lock(&hse_log_lock);
    if (sl->sl_entries)
        hse_slog_emit(sl->sl_priority, "@cee:%s\n", jc->json_buf);
    mutex_unlock(&hse_log_lock);

    free(jc->json_buf);
    free(sl);

    return 0;
}
