/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/config.h>
#include <hse_util/string.h>
#include <hse_util/delay.h>
#include <hse_util/parse_num.h>
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
    ({ ((_dstsz) < sizeof(_type) || !(_dst) || (uintptr_t)(_dst) & (__alignof(_type) - 1)); })

/**
 * struct priority_name - A table mapping priorities to their enum values
 * @priority_name:
 * @priority_val:
 */
struct priority_name {
    const char *   priority_name;
    log_priority_t priority_val;
};

DEFINE_SPINLOCK(hse_logging_lock);

FILE *logging_file = NULL;

struct hse_logging_infrastructure hse_logging_inf = {
    .mli_nm_buf = 0,    /* temp buffer for structured data field name */
    .mli_fmt_buf = 0,   /* intermediate format buffer                 */
    .mli_sd_buf = 0,    /* buffer to accumulate structured data       */
    .mli_name_buf = 0,  /* buffer to accumulate key offsets data      */
    .mli_value_buf = 0, /* buffer to accumulate value offsets         */
    .mli_json_buf = 0,  /* buffer to accumulate json elements         */
    .mli_active = 0,    /* has the logging been initialized           */
    .mli_opened = 0,    /* has the logging been "opened"              */
    .mli_async =
        {.al_wq = NULL, .al_cons = 0, .al_nb = 0, .al_entries = NULL, .al_th_working = false }
};

struct hse_log_code {
    hse_log_fmt_func_t *fmt; /* generic string printf-like fmt  */
    hse_log_add_func_t *add; /* structured field */
};

bool hse_logging_disable_init = false;

void
_hse_fmt(char *buf, size_t buflen, const char *fmt, ...)
{
    va_list ap;
    size_t  hlen;
    size_t  copylen;
    char *  beg;

    if ((buf == NULL) || (buflen < 2))
        return;

    va_start(ap, fmt);
    vsnprintf(buf, buflen, fmt, ap);
    va_end(ap);

    /* Remove the "....[HSE] " from the beginning of the string. */
    beg = strstr(buf, "[HSE]");
    if (beg == NULL)
        return;
    hlen = (beg - buf) + strlen("[HSE] ");
    if (strlen(buf) <= hlen)
        return;
    copylen = strlen(buf + hlen); /* copylen >= 1 */
    memmove(buf, buf + hlen, copylen);

    /* Remove potential trailing \n and add a 0 at the end */
    if (buf[copylen - 1] == '\n')
        buf[copylen - 1] = 0;
    else
        buf[copylen] = 0;
}

/**
 * _hse_consume_one_async() - log one entry of the circular buffer.
 * @entry: entry in the circular buffer that needs to be logged.
 *
 * Locking: no lock held because this entry in the circular buffer can only
 *      be changed by this thread at the moment.
 */
static void
_hse_consume_one_async(struct hse_log_async_entry *entry)
{
    u32 source_file_len;

    source_file_len = strlen(entry->ae_buf);
    if (source_file_len >= (sizeof(entry->ae_buf) - 2))
        /* No room to place anything behind the source file name. */
        return;

    entry->ae_buf[sizeof(entry->ae_buf) - 1] = 0;

    hse_slog_emit(entry->ae_priority, "@cee:%s\n", entry->ae_buf + source_file_len + 1);
}

/**
 * _hse_log_async_cons_th() - consumer of the async logs.
 * @wstruct:
 *
 * Process the log messages that were posted in the circular buffer
 * until the circular buffer is empty.
 * It offloads the processing and actual logging of the log messages.
 * The posting of log messages in the circular buffer is done via
 * hse_alog() which can safely be called from interrupt context.
 */
static void
_hse_log_async_cons_th(struct work_struct *wstruct)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    unsigned long               flags = 0;
    u32                         loop = 0;

    async = container_of(wstruct, struct hse_log_async, al_wstruct);

    /* Process all the log messages in the circular buffer.
     */
    spin_lock_irqsave(&async->al_lock, flags);

    while (async->al_nb > 0) {
        entry = async->al_entries + async->al_cons % MAX_LOGGING_ASYNC_ENTRIES;
        spin_unlock_irqrestore(&async->al_lock, flags);

        _hse_consume_one_async(entry);

        /* Don't hog the cpu. */
        if ((++loop % 128) == 0)
            msleep(100);

        spin_lock_irqsave(&async->al_lock, flags);
        async->al_cons++;
        async->al_nb--;
    }

    async->al_th_working = false;
    spin_unlock_irqrestore(&async->al_lock, flags);
}

static merr_t
get_log_level(const char *str, void *dst, size_t dstsz)
{
    merr_t err;
    u64    num;

    if (PARAM_GET_INVALID(log_priority_t, dst, dstsz))
        return merr(EINVAL);

    err = parse_u64(str, &num);
    if (err)
        *(log_priority_t *)dst = hse_logprio_name_to_val(str);
    else
        *(log_priority_t *)dst = num;

    return 0;
}

merr_t
hse_logging_init(void)
{
    void * nm_buf = 0, *fmt_buf = 0, *sd_buf = 0;
    void * json_buf = 0;
    char **name_buf = 0, **value_buf = 0;
    void * async_entries = NULL;
    merr_t err;

    struct workqueue_struct *wq = NULL;
    struct hse_log_async *   async;

    if (hse_logging_disable_init)
        return 0;

    if (!hse_gparams.gp_logging.enabled)
        return 0;

    if (hse_gparams.gp_logging.destination == LD_STDOUT) {
        logging_file = stdout;
    } else if (hse_gparams.gp_logging.destination == LD_STDERR) {
        logging_file = stderr;
    } else if (hse_gparams.gp_logging.destination == LD_FILE) {
        logging_file = fopen(hse_gparams.gp_logging.path, "a");
        if (!logging_file)
            return merr(errno);
    }

    spin_lock(&hse_logging_lock);
    err = hse_logging_inf.mli_active ? EBUSY : 0;
    spin_unlock(&hse_logging_lock);

    if (err)
        return merr(err);

    nm_buf = malloc(MAX_STRUCTURED_DATA_LENGTH);
    if (!nm_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "name buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    fmt_buf = malloc(MAX_STRUCTURED_DATA_LENGTH);
    if (!fmt_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "format buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    sd_buf = malloc(MAX_STRUCTURED_DATA_LENGTH);
    if (!sd_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "structured data buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    json_buf = malloc(MAX_STRUCTURED_DATA_LENGTH);
    if (!json_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "json structured data buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    name_buf = malloc(sizeof(void *) * MAX_HSE_NV_PAIRS);
    if (!name_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "name offset structured data buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    value_buf = malloc(sizeof(void *) * MAX_HSE_NV_PAIRS);
    if (!value_buf) {
        backstop_log("init_hse_logging() failed to allocate "
                     "value offset structured data buffer");
        err = merr(ENOMEM);
        goto out_err;
    }

    async_entries = malloc(sizeof(struct hse_log_async_entry) * MAX_LOGGING_ASYNC_ENTRIES);
    if (!async_entries) {
        backstop_log("init_hse_logging() failed to allocate "
                     "async entries");
        err = merr(ENOMEM);
        goto out_err;
    }

    wq = alloc_workqueue("hse_logd", 0, 1);
    if (!wq) {
        backstop_log("init_hse_logging() failed to allocate "
                     "the work queue");
        err = merr(ENOMEM);
        goto out_err;
    }

    spin_lock(&hse_logging_lock);
    if (hse_logging_inf.mli_active) {
        /* Lost race to initialize logging, free memory and return */
        spin_unlock(&hse_logging_lock);
        err = merr(EBUSY);
        goto out_err;
    }

    hse_logging_inf.mli_nm_buf = nm_buf;
    hse_logging_inf.mli_fmt_buf = fmt_buf;
    hse_logging_inf.mli_sd_buf = sd_buf;
    hse_logging_inf.mli_json_buf = json_buf;
    hse_logging_inf.mli_name_buf = name_buf;
    hse_logging_inf.mli_value_buf = value_buf;
    async = &(hse_logging_inf.mli_async);
    async->al_entries = async_entries;
    async->al_wq = wq;
    spin_lock_init(&async->al_lock);
    hse_logging_inf.mli_active = 1;

    spin_unlock(&hse_logging_lock);

    return 0;

out_err:
    free(nm_buf);
    free(fmt_buf);
    free(sd_buf);
    free(json_buf);
    free(name_buf);
    free(value_buf);
    free(async_entries);
    destroy_workqueue(wq);

    return err;
}

merr_t
log_level_validator(
    const char *              instance,
    const char *              path,
    struct dt_set_parameters *dsp,
    void *                    dfault,
    void *                    rock,
    char *                    errbuf,
    size_t                    errbuf_sz)
{
    int    level;
    merr_t err;

    err = get_log_level(dsp->value, &level, sizeof(level));
    if (err)
        return merr(EINVAL);

    if ((level < HSE_EMERG_VAL) || (level > HSE_DEBUG_VAL))
        return merr(EINVAL);

    return 0;
}

merr_t
hse_logging_post_init(void)
{
    return 0;
}

void
hse_logging_fini(void)
{
    struct workqueue_struct *wq;
    struct hse_log_async *   async;
    unsigned long            flags;

    if (!hse_gparams.gp_logging.enabled)
        return;

    spin_lock(&hse_logging_lock);
    hse_gparams.gp_logging.level = -1;
    spin_unlock(&hse_logging_lock);

    async = &hse_logging_inf.mli_async;

    flags = 0;
    spin_lock_irqsave(&async->al_lock, flags);
    wq = async->al_wq;
    async->al_wq = NULL;
    spin_unlock_irqrestore(&async->al_lock, flags);

    /* Wait for the async logging consumer thread to exit. */
    destroy_workqueue(wq);

    spin_lock(&hse_logging_lock);

    if (hse_gparams.gp_logging.destination == LD_FILE &&
        logging_file != stdout &&
        logging_file != stderr)
        fclose(logging_file);

    free(hse_logging_inf.mli_name_buf);
    hse_logging_inf.mli_name_buf = 0;

    free(hse_logging_inf.mli_value_buf);
    hse_logging_inf.mli_value_buf = 0;

    free(hse_logging_inf.mli_nm_buf);
    hse_logging_inf.mli_nm_buf = 0;

    free(hse_logging_inf.mli_fmt_buf);
    hse_logging_inf.mli_fmt_buf = 0;

    free(hse_logging_inf.mli_sd_buf);
    hse_logging_inf.mli_sd_buf = 0;

    free(hse_logging_inf.mli_json_buf);
    hse_logging_inf.mli_json_buf = 0;

    /*
     * Thread _hse_log_async_cons_th() exited, the async logging resources
     * can be freed.
     */
    free(async->al_entries);
    async->al_entries = NULL;
    async->al_cons = 0;
    async->al_nb = 0;

    hse_logging_inf.mli_active = 0;
    hse_logging_inf.mli_opened = 0;

    spin_unlock(&hse_logging_lock);
}

/*
 * _hse_log_post_vasync() - post the log message in a circular buffer.
 * @source_file: source file of the logging site
 * @source_line: line number of the logging site
 * @priority: priority of the log message
 * @fmt_string: the platform-specific format string
 * @args: variable-length argument list
 *
 * Locking: can be called from interrupt handler => can't block.
 */
static void
_hse_log_post_vasync(
    const char *source_file,
    s32         source_line,
    s32         priority,
    const char *fmt_string,
    va_list     args)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    unsigned long               flags = 0;
    bool                        start;
    char *                      buf;

    async = &(hse_logging_inf.mli_async);

    spin_lock_irqsave(&async->al_lock, flags);
    if (async->al_nb == MAX_LOGGING_ASYNC_ENTRIES || !async->al_wq) {
        /* Circular buffer full. */
        spin_unlock_irqrestore(&async->al_lock, flags);
        ev(ENOENT);
        return;
    }

    /* Next free entry */
    entry = async->al_entries + (async->al_cons + async->al_nb) % MAX_LOGGING_ASYNC_ENTRIES;

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
    start = !async->al_th_working;
    if (start)
        async->al_th_working = true;
    spin_unlock_irqrestore(&async->al_lock, flags);

    if (start) {
        INIT_WORK(&async->al_wstruct, _hse_log_async_cons_th);
        queue_work(async->al_wq, &async->al_wstruct);
    }
}

/*
 * _hse_log_post_async() - post the log message as json payload
 * in a circular buffer.
 * @source_file: source file of the logging site
 * @source_line: line number of the logging site
 * @priority: priority of the log message
 * @payload: fixed length payload
 *
 * Locking: can be called from interrupt handler => can't block.
 */
static void
_hse_log_post_async(const char *source_file, s32 source_line, s32 priority, char *payload)
{
    struct hse_log_async *      async;
    struct hse_log_async_entry *entry;
    unsigned long               flags = 0;
    bool                        start;
    char *                      buf;

    async = &(hse_logging_inf.mli_async);

    spin_lock_irqsave(&async->al_lock, flags);
    if (async->al_nb == MAX_LOGGING_ASYNC_ENTRIES || !async->al_wq) {
        /* Circular buffer full. */
        spin_unlock_irqrestore(&async->al_lock, flags);
        ev(ENOENT);
        return;
    }

    /* Next free entry */
    entry = async->al_entries + (async->al_cons + async->al_nb) % MAX_LOGGING_ASYNC_ENTRIES;

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
    start = !async->al_th_working;
    if (start)
        async->al_th_working = true;
    spin_unlock_irqrestore(&async->al_lock, flags);

    if (start) {
        INIT_WORK(&async->al_wstruct, _hse_log_async_cons_th);
        queue_work(async->al_wq, &async->al_wstruct);
    }
}

/*
 * The function _hse_log() accomplishes the actual logging function and is
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
_hse_log(
    const char *source_file, /* source file of the logging site     */
    s32         source_line, /* line number of the logging site     */
    s32         priority,    /* priority of the log message         */
    const char *fmt_string,  /* the platform-specific format string */
    bool        async,       /* true=>only queue in circular buffer */
    void **     hse_args,    /* array of pointers (or NULL)         */
    ...)                     /* variable-length argument list       */
{
    struct hse_log_fmt_state state;
    va_list                  args;
    int                      num_hse_args;
    char *                   int_fmt = hse_logging_inf.mli_fmt_buf;
    bool                     res = false;
    unsigned long            flags = 0;

    assert(hse_gparams.gp_logging.enabled);

    if (priority > hse_gparams.gp_logging.level)
        return;

    spin_lock_irqsave(&hse_logging_lock, flags);

    if (priority > hse_gparams.gp_logging.level)
        goto out;

    assert(hse_logging_inf.mli_nm_buf != 0);
    assert(hse_logging_inf.mli_fmt_buf != 0);
    assert(hse_logging_inf.mli_sd_buf != 0);
    assert(hse_logging_inf.mli_name_buf != 0);
    assert(hse_logging_inf.mli_value_buf != 0);
    assert(hse_logging_inf.mli_json_buf != 0);

    state.dict = hse_logging_inf.mli_sd_buf;
    state.dict_rem = MAX_STRUCTURED_DATA_LENGTH;
    state.dict_pos = state.dict;
    state.names = hse_logging_inf.mli_name_buf;
    state.values = hse_logging_inf.mli_value_buf;

    /*
     * This code is at the mercy of the caller actually putting a NULL
     * as the last element of the hse_args array. The following code
     * scans until either a NULL is found or MAX_HSE_SPECS have been
     * found. In the latter case, the call is aborted.
     */
    num_hse_args = 0;
    if (hse_args) {
        while (hse_args[num_hse_args] && num_hse_args <= MAX_HSE_SPECS)
            num_hse_args++;
        if (hse_args[num_hse_args]) {
            backstop_log("Too many HSE arguments given to _hse_log(), "
                         "aborting log attempt");
            goto out;
        }
    } else {
        static void *hse_args_none[] = { NULL };

        hse_args = hse_args_none;
    }
    state.num_hse_specs = num_hse_args;
    assert(state.num_hse_specs <= MAX_HSE_SPECS);

    state.hse_spec_cnt = 0;
    state.nv_index = 0;
    state.source_info_set = false;

    pack_source_info(&state);

    va_start(args, hse_args);
    res = vpreprocess_fmt_string(
        &state, fmt_string, int_fmt, MAX_STRUCTURED_DATA_LENGTH, hse_args, args);
    va_end(args);

    if (!res)
        goto out;

    va_start(args, hse_args);
    finalize_log_structure(priority, async, source_file, source_line, &state, int_fmt, args);
    va_end(args);

out:
    spin_unlock_irqrestore(&hse_logging_lock, flags);
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
             push_nv(state, false, "hse_version", HSE_VERSION_STRING) &&
             push_nv(state, false, "hse_tag", HSE_VERSION_TAG));
        if (!res)
            return res;

        state->nv_hse_index = 3;
        state->source_info_set = true;
    }

    return true;
}

bool
vpreprocess_fmt_string(
    struct hse_log_fmt_state *state,
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

    const char *msg1 = "Extra hse conversion specifiers found\n";

    bool  res = true;
    char *src_pos = (char *)fmt;
    char *tgt_pos = new_fmt;
    char *tgt_end = new_fmt + (new_len - 1);
    char  c = *src_pos++;

    void *obj;
    s32   hse_cnt = 0;

    enum hse_log_fmt_parse_state parse_state = LITERAL;

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
                    backstop_log(msg1);
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
    char                 errmsg[50];

    c = **src_pos;

    if (!slot || !slot->fmt) {
        snprintf(errmsg, sizeof(errmsg), "invalid hse conversion specifier %c", c);
        backstop_log(errmsg);
        return false;
    }

    ++*src_pos; /* [HSE_REVISIT]: multi-char: pos += slot->len? */

    if (!append_hse_arg(slot, tgt_pos, tgt_end, state, obj)) {
        snprintf(errmsg, sizeof(errmsg), "cannot append hse conversion specifier %c", c);
        backstop_log(errmsg);
        return false;
    }

    *parse_state = LITERAL;

    return true;
}

bool
hse_log_register(int code, hse_log_fmt_func_t *fmt, hse_log_add_func_t *add)
{
    struct hse_log_code *slot;

    if (!fmt || !add)
        return false;

    slot = get_code_slot(code);

    if (!slot || slot->fmt)
        return false;

    slot->fmt = fmt;
    slot->add = add;
    return true;
}

bool
hse_log_deregister(int code)
{
    struct hse_log_code *slot = get_code_slot(code);

    if (!slot)
        return false;

    slot->fmt = 0;
    slot->add = 0;
    return true;
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
             push_nv(state, false, "hse_version", HSE_VERSION_STRING) &&
             push_nv(state, false, "hse_tag", HSE_VERSION_TAG));
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
is_std_specifier(char c)
{
    static char std_specifiers[] = { 'd', 'i', 'u', 'o', 'x', 'X', 'f', 'F', 'e', 'E',
                                     'g', 'G', 'a', 'A', 'c', 's', 'p', 'n', '%' };
    int i;

    for (i = 0; i < sizeof(std_specifiers); ++i) {
        if (c == std_specifiers[i])
            return true;
    }
    return false;
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
    char * buf = hse_logging_inf.mli_nm_buf;
    size_t sz;
    char * tmp = (char *)name;
    char * name_offset;
    char * val_offset;

    if (state->nv_index >= MAX_HSE_NV_PAIRS)
        return false;

    if (index) {
        sz = snprintf(buf, MAX_STRUCTURED_NAME_LENGTH, name, state->hse_spec_cnt);
        if (sz > MAX_STRUCTURED_NAME_LENGTH)
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
    int                       priority,
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

    msg_buf = hse_logging_inf.mli_nm_buf;

    i = vsnprintf(msg_buf, MAX_STRUCTURED_DATA_LENGTH, fmt, args);

    jc.json_buf = hse_logging_inf.mli_json_buf;
    jc.json_buf_sz = MAX_STRUCTURED_DATA_LENGTH;

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

    if (async)
        _hse_log_post_async(source_file, source_line, priority, jc.json_buf);
    else
        hse_slog_emit(priority, "@cee:%s\n", jc.json_buf);
}

static const char *pri_name[] = {
    "HSE_EMERG",   "HSE_ALERT",  "HSE_CRIT", "HSE_ERR",
    "HSE_WARNING", "HSE_NOTICE", "HSE_INFO", "HSE_DEBUG",
};

const char *
hse_logprio_val_to_name(int priority)
{
    if (priority > HSE_DEBUG_VAL || priority < 0)
        priority = HSE_DEBUG_VAL;

    return pri_name[priority];
}

struct priority_name priority_names[] = {
    { "HSE_EMERG", HSE_EMERG_VAL },     { "HSE_ALERT", HSE_ALERT_VAL },
    { "HSE_CRIT", HSE_CRIT_VAL },       { "HSE_ERR", HSE_ERR_VAL },
    { "HSE_WARNING", HSE_WARNING_VAL }, { "HSE_NOTICE", HSE_NOTICE_VAL },
    { "HSE_INFO", HSE_INFO_VAL },       { "HSE_DEBUG", HSE_DEBUG_VAL },
};

log_priority_t
hse_logprio_name_to_val(const char *priority)
{
    int  i = 0, best_fit = -1;
    char pri[20];

    if (strncasecmp("hse_", priority, strlen("hse_")))
        snprintf(pri, sizeof(pri), "hse_%s", priority);
    else
        snprintf(pri, sizeof(pri), "%s", priority);

    while (priority_names[i].priority_name != NULL) {
        if (!strcasecmp(priority_names[i].priority_name, pri))
            break;
        if (!strncasecmp(priority_names[i].priority_name, pri, strlen(pri))) {
            assert(best_fit != -1);
            best_fit = i;
        }
        i++;
    }
    if ((priority_names[i].priority_name == NULL) && (best_fit != -1))
        i = best_fit;

    return priority_names[i].priority_val;
}

static void
package_source_info(struct json_context *jc)
{
    json_element_field(jc, "hse_logver", "%s", HSE_LOGGING_VER);
    json_element_field(jc, "hse_version", "%s", HSE_VERSION_STRING);
    json_element_field(jc, "hse_tag", "%s", HSE_VERSION_TAG);
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
 * 1) The hse_log and hse_alog macros resolve to the same _hse_log() call.
 * Since all hse_log calls are asynchronous by default, hse_alog should be
 * removed.
 *
 * 2) The _hse_log() call does duplicate work since it handles both async
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
hse_slog_internal(int priority, const char *fmt, ...)
{
    va_list       payload;
    const char *  buf;
    unsigned long flags = 0;

    if (priority > hse_gparams.gp_logging.level || !hse_gparams.gp_logging.enabled)
        return;

    va_start(payload, fmt);
    spin_lock_irqsave(&hse_logging_lock, flags);

    if (fmt) {
        buf = fmt;
    } else {
        struct json_context jc = { 0 };

        jc.json_buf = hse_logging_inf.mli_fmt_buf;
        jc.json_buf_sz = MAX_STRUCTURED_DATA_LENGTH;

        hse_format_payload(&jc, payload);

        buf = hse_logging_inf.mli_fmt_buf;
    }

    _hse_log_post_vasync("_hse_slog", 1, priority, buf, payload);

    spin_unlock_irqrestore(&hse_logging_lock, flags);
    va_end(payload);
}

void
hse_slog_emit(int priority, const char *fmt, ...)
{
    va_list payload;

    va_start(payload, fmt);
    if (hse_gparams.gp_logging.destination == LD_SYSLOG) {
        vsyslog(priority, fmt, payload);
    } else {
        vfprintf(logging_file, fmt, payload);
    }
    va_end(payload);
}

int
hse_slog_create(int priority, const char *unused, struct slog **sl, const char *type)
{
    struct json_context *jc;

    if (!sl || !type)
        return -EINVAL;

    if (priority > hse_gparams.gp_logging.level || !hse_gparams.gp_logging.enabled) {
        *sl = NULL;
        return 0;
    }

    *sl = calloc(1, sizeof(struct slog));
    if (ev(!*sl))
        goto err2;

    jc = &((*sl)->sl_json);
    jc->json_buf_sz = 2048;

    jc->json_buf = malloc(jc->json_buf_sz);
    if (ev(!jc->json_buf))
        goto err1;

    json_element_start(jc, NULL);
    json_element_field(jc, "type", "%s", type);
    package_source_info(jc);
    json_element_start(jc, "content");

    (*sl)->sl_priority = priority;
    (*sl)->sl_entries = 0;

    return 0;
err1:
    free(*sl);
err2:
    *sl = NULL;
    return -ENOMEM;
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
    return -ENOMEM;
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

    if (sl->sl_entries)
	    hse_slog_emit(sl->sl_priority, "@cee:%s\n", jc->json_buf);

    free(jc->json_buf);
    free(sl);

    return 0;
}
