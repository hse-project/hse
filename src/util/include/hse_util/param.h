/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UI_CLI_PARAM_H
#define HSE_UI_CLI_PARAM_H

#include <hse_util/hse_err.h>
#include <hse_util/parser.h>

/* MTF_MOCK_DECL(param) */

#define PARAM_GET_INVALID(_type, _dst, _dstsz) \
    ({ ((_dstsz) < sizeof(_type) || !(_dst) || (uintptr_t)(_dst) & (__alignof(_type) - 1)); })

#define PARAM_SHOW_INVALID(_type, _val) ({ (!(_val) || (uintptr_t)val & (__alignof(_type) - 1)); })

typedef merr_t
param_get_t(const char *src, void *dst, size_t dstsz);

typedef merr_t
param_show_t(char *dst, size_t dstsz, const void *val, size_t val_nb);

typedef merr_t
param_check_t(uintptr_t min, uintptr_t max, void *val);

/**
 * struct param_type -
 * @param_token:
 * @param_size:
 * @param_min:
 * @param_max:
 * @param_str_to_val:
 * @param_val_to_str:
 * @param_range_check: validate value is within [param_min, param_max);
 */
struct param_type {
    char *         param_token;
    size_t         param_size;
    uintptr_t      param_min;
    uintptr_t      param_max;
    param_get_t *  param_str_to_val;
    param_show_t * param_val_to_str;
    param_check_t *param_range_check;
};

/**
 * struct param_inst -
 * @pi_type:  parameter props and getter/setter ops
 * @pi_value: ptr to the parameter
 * @pi_msg:   Short description of the parameter
 * @pi_entered: set to false before the command line parameters are parsed.
 *      The parser set it to true if the parameter is present/entered on the
 *      command line.
 */
struct param_inst {
    struct param_type pi_type;
    void *            pi_value;
    char *            pi_msg;
    u32               pi_flags;
    bool              pi_entered;
};

param_get_t   get_u8;
param_get_t   get_u8_list;
param_show_t  show_u8;
param_show_t  show_u8_dec;
param_show_t  show_u8_list;
param_check_t check_u8;

param_get_t   get_u16;
param_show_t  show_u16;
param_check_t check_u16;
param_show_t  show_u16_dec;

param_get_t   get_u32;
param_show_t  show_u32;
param_show_t  show_u32_dec;
param_check_t check_u32;

param_get_t  get_u32_size;
param_show_t show_u32_size;

param_get_t  get_s32;
param_show_t show_s32;

param_get_t  get_u64;
param_show_t show_u64;
param_show_t show_u64_dec;
param_show_t show_u64_list;

param_get_t  get_u64_size;
param_show_t show_u64_size;

param_get_t  get_s64;
param_show_t show_s64;

param_get_t  get_string;
param_get_t  get_stringptr;
param_show_t show_string;

param_get_t  get_bool;
param_show_t show_bool;

param_get_t  get_uid;
param_show_t show_uid;
#define PARAM_TYPE_UID                                         \
    {                                                          \
        "uid=%s", sizeof(uid_t), 0, 0, get_uid, show_uid, NULL \
    }

param_get_t  get_gid;
param_show_t show_gid;
#define PARAM_TYPE_GID                                         \
    {                                                          \
        "gid=%s", sizeof(gid_t), 0, 0, get_gid, show_gid, NULL \
    }

param_get_t  get_mode;
param_show_t show_mode;
#define PARAM_TYPE_MODE                                            \
    {                                                              \
        "mode=%s", sizeof(mode_t), 0, 0, get_mode, show_mode, NULL \
    }

param_get_t  get_log_level;
param_show_t show_log_level;
#define PARAM_TYPE_LOG_LEVEL                                                                   \
    {                                                                                          \
        "log_level=%s", sizeof(log_priority_t), HSE_EMERG_VAL, HSE_INVALID_VAL, get_log_level, \
            show_log_level, NULL                                                               \
    }

param_get_t  get_space;
param_show_t show_space;

/**
 * shuffle() - rearrange argument list
 * @argc:
 * @argv:
 * @insert:
 * @check:
 */
void
shuffle(int argc, char **argv, int insert, int check);

/**
 * process_params() - process a set of command-line params
 * @argc: int, number of arguments available on the command-line
 * @argv: char **, an array of command-line arguments to parse
 * @pi: struct param *, an array defining how the params should
 *         be parsed.
 * @next_arg: int *, will be set to first arg in list that is not a param
 * @flag:
 *
 * The 'hse' UI expects params to have the form x=y where x is the
 * param name, and y is the value. The 'sp' array defines how
 * a given param should be processed in the form of a string to
 * handler array.
 */
/* MTF_MOCK */
merr_t
process_params(int argc, char **argv, struct param_inst *pi, int *next_arg, u32 flag);

/**
 * show_default_params() - show available params
 * @params: struct param *, list of available params
 * @flag:
 * Part of CLI help functionality.
 */
void
show_default_params(struct param_inst *params, u32 flag, FILE *fp);

merr_t
param_gen_match_table(struct param_inst *pi, struct match_token **table, int *entry_cnt);

void
param_free_match_table(struct match_token *table);

/**
 * param_help() - Fills up buf with a help msg extracted from the table arg
 * @buf: buffer that will be filled with the help message (Can be NULL)
 * @buf_len: size of buf
 * @p: ptr to a params struct instance with the param values that the caller
 *     would like displayed
 * @table: param_inst table
 * @table_sz: number of elements in table
 * @base: base of the struct into whose members the table points
 *
 * Return: If buf was not NULL, a pointer to buf.
 *         If buf was NULL, returns a pointer to a global help buffer. This
 *         option is not thread safe
 */
char *
params_help(char *buf, size_t buf_len, void *p, struct param_inst *table, int table_sz, void *base);

/**
 * params_print() - Prints the values of parameters from the table to the log
 * @table: param_inst table
 * @table_sz: number of elements in table
 * @params: ptr to a structure with values to be printed
 * @base: base of the struct into whose members the table points. If this is
 *        NULL, base is set to params
 */
void
params_print(
    const struct param_inst *table,
    size_t                   table_sz,
    const char *             type,
    void *                   params,
    void *                   base);

/**
 * param_entered() - return true is the param was entered on the command line
 * @pi:
 * @name: name of the param.
 */
bool
param_entered(struct param_inst *pi, char *name);

enum param_flag {
    PARAM_FLAG_EXPERIMENTAL = 0x1,
    PARAM_FLAG_TUNABLE = 0x2,
    PARAM_FLAG_ID = 0x4,
    PARAM_FLAG_BOUND_CK = 0x8,
};

#define PARAM_TYPE_END            \
    {                             \
        NULL, 0, 0, 0, 0, 0, NULL \
    }

#define PARAM_INST(ptype, val, msg) \
    {                               \
        ptype, (void *)&val, msg, 0 \
    }

#define PARAM_INST_EXP(ptype, val, msg)                   \
    {                                                     \
        ptype, (void *)&val, msg, PARAM_FLAG_EXPERIMENTAL \
    }

#define PARAM_INST_END             \
    {                              \
        PARAM_TYPE_END, 0, NULL, 0 \
    }

/* Special purpose PARAM_INST macros for certain data types */
#define PARAM_INST_type(type, val, name, msg)                                                   \
    {                                                                                           \
        { name "=%s", sizeof(type), 0, 0, get_##type, show_##type, NULL }, (void *)&val, msg, 0 \
    }

#define PARAM_INST_EXP_type(type, val, name, msg)                                             \
    {                                                                                         \
        { name "=%s", sizeof(type), 0, 0, get_##type, show_##type, NULL }, (void *)&val, msg, \
            PARAM_FLAG_EXPERIMENTAL                                                           \
    }

#define PARAM_INST_STRING(val, valsz, name, msg)                                         \
    {                                                                                    \
        { name "=%s", valsz, 0, 0, get_string, show_string, NULL }, (void *)&val, msg, 0 \
    }

#define PARAM_INST_STRINGPTR(val, name, msg)                                                       \
    {                                                                                              \
        { name "=%s", sizeof(char *), 0, 0, get_stringptr, show_string, NULL }, (void *)&val, msg, \
            0                                                                                      \
    }

#define PARAM_INST_U8(val, name, msg) PARAM_INST_type(u8, val, name, msg)

#define PARAM_INST_U8_EXP(val, name, msg) PARAM_INST_EXP_type(u8, val, name, msg)

#define PARAM_INST_U16(val, name, msg) PARAM_INST_type(u16, val, name, msg)

#define PARAM_INST_U32(val, name, msg) PARAM_INST_type(u32, val, name, msg)

#define PARAM_INST_U32_EXP(val, name, msg) PARAM_INST_EXP_type(u32, val, name, msg)

typedef u32 u32_size;
#define PARAM_INST_U32_SIZE(val, name, msg) PARAM_INST_type(u32_size, val, name, msg)

#define PARAM_INST_U64(val, name, msg) PARAM_INST_type(u64, val, name, msg)

#define PARAM_INST_U64_EXP(val, name, msg) PARAM_INST_EXP_type(u64, val, name, msg)

typedef u64 u64_size;
#define PARAM_INST_U64_SIZE(val, name, msg) PARAM_INST_type(u64_size, val, name, msg)

#define PARAM_INST_S64(val, name, msg) PARAM_INST_type(s64, val, name, msg)

#define PARAM_INST_S32(val, name, msg) PARAM_INST_type(s32, val, name, msg)

#define PARAM_INST_BOOL(val, name, msg) PARAM_INST_type(bool, val, name, msg)

#define PARAM_INST_PCT(val, name, msg)                                                    \
    {                                                                                     \
        { name "=%s", sizeof(u8), 0, 101, get_u8, show_u8, check_u8 }, (void *)&val, msg, \
            PARAM_FLAG_TUNABLE                                                            \
    }

#define PARAM_INST_U8_LIST(val, valsz, name, msg)                                              \
    {                                                                                          \
        { name "=%s", valsz, 0, 101, get_u8_list, show_u8_list, check_u8 }, (void *)&val, msg, \
            PARAM_FLAG_TUNABLE                                                                 \
    }

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "param_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_UI_CLI_PARAM_H */
