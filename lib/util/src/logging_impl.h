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
 * HSE_LOG_ASYNC_ENTRIES_MAX - maximum number of asynchronous log messages
 *      in the circular buffer al_entries[].
 *      If the async log messages are posted faster then the consumer thread
 *      hse_log_async_cons_th() can consume them, the max capacity of the
 *      circular buffer is reached (MAX_LOGGING_ASYNC_ENTRIES). Beyond that,
 *      new async log messages are dropped.
 */
#define HSE_LOG_ASYNC_ENTRIES_MAX 256

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

#define HSE_LOG_STRUCTURED_DATALEN_MAX (4000 / HSE_ACP_LINESIZE * HSE_ACP_LINESIZE)
#define HSE_LOG_STRUCTURED_NAMELEN_MAX (100)

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

struct slog {
    hse_logpri_t        sl_priority;
    int                 sl_entries;
    struct json_context sl_json;
};

merr_t
hse_log_init(void) HSE_COLD;

void
hse_log_fini(void) HSE_COLD;

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
    hse_logpri_t              priority,
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
hse_slog_emit(hse_logpri_t priority, const char *fmt, ...);

#endif /* HSE_LOGGING_IMPL_HEADER */
