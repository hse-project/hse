/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOGGING_IMPL_HEADER
#define HSE_LOGGING_IMPL_HEADER

#include <hse_util/logging.h>
#include <hse_util/inttypes.h>
#include <hse_util/workqueue.h>
#include <hse_util/mutex.h>
#include <hse_util/json.h>
#include <hse_util/hse_err.h>

#define HSE_LOGGING_VER "1"

/**
 * MAX_LOGGING_ASYNC_ENTRIES - maximum number of asynchronous log messages
 *      in the circular buffer al_entries[].
 *      If the async log messages are posted faster then the consumer thread
 *      hse_log_async_cons_th() can consume them, the max capacity of the
 *      circular buffer is reached (MAX_LOGGING_ASYNC_ENTRIES). Beyond that,
 *      new async log messages are dropped.
 */
#define MAX_LOGGING_ASYNC_ENTRIES 256

/******************************************************************************
 * Enumeration of values the state machine parsing an HSE log format string
 * can be in.
 ******************************************************************************/
enum hse_log_fmt_parse_state { LITERAL = 1, IN_STD_FORMAT = 2, IN_HSE_FORMAT = 3 };

/******************************************************************************
 * Enumeration capturing the various length modifiers for printf() specifiers
 ******************************************************************************/
enum std_length_modifier {
    LEN_MOD_none = 0,
    LEN_MOD_hh = 1,
    LEN_MOD_h = 2,
    LEN_MOD_l = 3,
    LEN_MOD_ll = 4,
    LEN_MOD_j = 5,
    LEN_MOD_z = 6,
    LEN_MOD_t = 7,
    LEN_MOD_L = 8
};

/******************************************************************************
 * The processing of constructing the message to be logged requires the use
 * of scratch memory. The logging is currently protected by a lock so
 * this is handled by having dynamically allocated scratch space that is
 * set up when the logging subsystem is initialized and freed upon subsystem
 * release.
 ******************************************************************************/

#define MAX_STRUCTURED_DATA_LENGTH 4000
#define MAX_STRUCTURED_NAME_LENGTH 100

/******************************************************************************
 * HSE Conversion Specifiers
 *
 * The HSE logging subsystem defines a convention for conversion specifiers
 * beyond those available in the printf() family of functions. These are
 * prefixed by the literal "@@" (instead of "%"). The set of conversion
 * specifiers is extensible for new structures via a registration mechanism.
 *
 * At present, only a single character is allowed, from the alphabet A-Za-z.
 * Two methods must be provided when registering:
 *      add - push each field as structured data
 *      fmt - printf-like generic string
 * These methods completely own the formatting of the specified object.
 *
 * While registration may be added at any time, as a convenience,
 * there is an init function which can be modified to call the
 * various registration functions.
 *
 * WARNING: The add and fmt methods are in the performance path!  Use with care!
 ******************************************************************************/

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
    s32  ae_source_line;
    s32  ae_priority;
    char ae_buf[MAX_STRUCTURED_DATA_LENGTH];
};

/**
 * struct hse_log_async - allow to log from interrupt context.
 *      The log messages are only stored in a circular buffer attached to
 *      structure. The thread _hse_log_async_cons_th() process them later.
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
    bool                        al_th_working;
    u32                         al_cons;
    u32                         al_nb;
    struct hse_log_async_entry *al_entries;
};

struct hse_logging_infrastructure {
    char *               mli_nm_buf;
    char *               mli_fmt_buf;
    char *               mli_sd_buf;
    char *               mli_json_buf;
    char **              mli_name_buf;
    char **              mli_value_buf;
    int                  mli_active;
    int                  mli_opened;
    struct hse_log_async mli_async;
};

struct slog {
    int                 sl_priority;
    int                 sl_entries;
    struct json_context sl_json;
};

extern struct hse_logging_infrastructure hse_logging_inf;

merr_t
hse_logging_init(void) HSE_COLD;

void
hse_logging_fini(void) HSE_COLD;

struct hse_log_fmt_state {
    char * dict;
    char * dict_pos;
    s32    dict_rem;
    s32    num_hse_specs;
    s32    hse_spec_cnt;
    s32    nv_index;
    s32    nv_hse_index;
    bool   source_info_set;
    char **names;
    char **values;
};

bool
is_std_specifier(int c);

enum std_length_modifier
get_std_length_modifier(char *specifier_pos);

bool
push_nv(struct hse_log_fmt_state *state, bool index, const char *name, const char *value);

bool
pack_nv(
    struct hse_log_fmt_state *state,
    const char *              name,
    char **                   name_offset,
    const char *              value,
    char **                   value_offset);

bool
pack_source_info(struct hse_log_fmt_state *state);

void
finalize_log_structure(
    int                       priority,
    bool                      async,
    const char *              source_file,
    s32                       source_line,
    struct hse_log_fmt_state *st,
    const char *              fmt,
    va_list                   args);

bool
vpreprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char *              func,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    va_list                   args);

bool
LITERAL_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    char                          c,
    char *                        spec_pos,
    char **                       tgt_pos,
    char *                        tgt_end);

bool
IN_STD_FORMAT_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    va_list                       args,
    char                          c,
    char *                        spec_pos,
    char **                       tgt_pos,
    char *                        tgt_end);

bool
IN_HSE_FORMAT_handler(
    enum hse_log_fmt_parse_state *parse_state,
    struct hse_log_fmt_state *    state,
    void *                        obj,
    char                          c,
    char **                       src_pos,
    char **                       tgt_pos,
    char *                        tgt_end);

struct hse_log_code;

bool
append_hse_arg(
    struct hse_log_code *     slot,
    char **                   tgt_pos,
    char *                    tgt_end,
    struct hse_log_fmt_state *state,
    void *                    obj);

bool
fmt_hse_err(char **tgt_pos, char *tgt_end, void *object);

bool
add_hse_err(struct hse_log_fmt_state *state, void *object);

void
hse_slog_emit(int priority, const char *fmt, ...);

#endif /* HSE_LOGGING_IMPL_HEADER */
