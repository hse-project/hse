/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_param

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/param.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>

#include <getopt.h>
#include <pwd.h>
#include <grp.h>

merr_t
get_u8(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u8, dst, dstsz))
        return merr(EINVAL);

    return parse_u8(src, dst);
}

merr_t
get_u8_list(const char *src, void *dst, size_t dstsz)
{
    merr_t      err = 0;
    const char *start = src;
    const char *next;
    u8 *        dstu8 = (u8 *)dst;
    char        tmp[4]; /* 3 char for 255 then one 0 */
    size_t      len;

    if (PARAM_GET_INVALID(u8, dst, dstsz))
        return merr(EINVAL);

    while (true) {
        next = strchr(start, ',');
        if (next == NULL)
            len = strlen(start);
        else
            len = next - start;

        if (len > 3) {
            err = merr(EINVAL);
            break;
        }
        memcpy(tmp, start, len);
        tmp[len] = 0;

        err = get_u8(tmp, dstu8, 1);
        if (err)
            break;
        dstu8++;
        dstsz--;
        if ((next == NULL) || (dstsz == 0))
            break;
        start = next + 1;
        if (*start == 0)
            break;
    }
    return err;
}

merr_t
show_u8(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u8, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "0x%hhx", *(const u8 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_u8_list(char *str, size_t strsz, const void *val, size_t val_nb)
{
    size_t    n;
    int       i;
    bool      ending_comma = false;
    const u8 *valu8 = (u8 *)val;

    for (i = 0; i < val_nb; i++, valu8++) {
        n = snprintf(str, strsz, "%u", *valu8);
        if (n >= strsz)
            /* string provided is too short. */
            return merr(EINVAL);
        str += n;
        strsz -= n;
        if (strsz == 1) {
            i++;
            ending_comma = false;
            break;
        }

        ending_comma = true;
        *str = ',';
        str++;
        strsz--;
    }
    if (i < val_nb)
        /* string provided is too short. */
        return merr(EINVAL);

    /* Overwrite the last ',' with a zero. */
    if (ending_comma)
        *(str - 1) = 0;

    return 0;
}

merr_t
get_u16(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u16, dst, dstsz))
        return merr(EINVAL);

    return parse_u16(src, dst);
}

merr_t
show_u16(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u16, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "0x%hx", *(const u16 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_u16_dec(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u16, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "%hu", *(const u16 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_u32(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u32, dst, dstsz))
        return merr(EINVAL);

    return parse_u32(src, dst);
}

merr_t
show_u32(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u32, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "0x%x", *(const u32 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
check_u32(uintptr_t min, uintptr_t max, void *val)
{
    if (((u32)min > *(u32 *)val) || (*(u32 *)val >= (u32)max))
        return merr(ev(EINVAL));

    return 0;
}

merr_t
check_u16(uintptr_t min, uintptr_t max, void *val)
{
    if (((u16)min > *(u16 *)val) || (*(u16 *)val >= (u16)max))
        return merr(ev(EINVAL));

    return 0;
}

merr_t
check_u8(uintptr_t min, uintptr_t max, void *val)
{
    if (((u8)min > *(u8 *)val) || (*(u8 *)val >= (u8)max))
        return merr(ev(EINVAL));

    return 0;
}

merr_t
show_u32_dec(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u32, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "%u", *(const u32 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_u8_dec(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u8, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "%u", *(const u8 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_u32_size(const char *src, void *dst, size_t dstsz)
{
    u64    v;
    merr_t err;

    if (PARAM_GET_INVALID(u32, dst, dstsz))
        return merr(EINVAL);

    err = parse_size(src, &v);
    *(u32 *)dst = (u32)v;
    return err;
}

static size_t
space_to_string(u64 spc, char *string, size_t strsz)
{
    const char  suffixtab[] = "\0KMGTPEZY";
    double      space = spc;
    const char *stp;

    stp = suffixtab;
    while (space >= 1024) {
        space /= 1024;
        ++stp;
    }

    return snprintf(string, strsz, "%4.2lf%c", space, *stp);
}

merr_t
show_space(char *str, size_t strsz, const void *val, size_t unused)
{
    space_to_string(*(const u64 *)val, str, strsz);
    return 0;
}

merr_t
get_space_from_arg(const char *str, u64 *dst, size_t dstsz)
{
    const char  kmgtp[] = "KkMmGgTtPp";
    const char *pos;
    char *      endptr;
    double      d;

    if (PARAM_GET_INVALID(u64, dst, dstsz))
        return merr(EINVAL);

    errno = 0;
    d = strtod(str, &endptr);
    if (errno || endptr == str || d < 0)
        return errno ? merr(errno) : merr(EINVAL);

    while (isspace(*endptr))
        ++endptr; /* allow white space to precede suffix */

    if (*endptr) {
        ulong mult = 1;

        pos = strchr(kmgtp, *endptr++);
        if (!pos)
            return merr(EINVAL);

        while (isspace(*endptr))
            ++endptr; /* allow trailing white space */
        if (*endptr)
            return merr(EINVAL);

        mult <<= ((pos - kmgtp) / 2 + 1) * 10;
        d *= mult;
    }

    if (d > U64_MAX) {
        *dst = U64_MAX;
        return merr(ERANGE);
    }

    *dst = d;
    return 0;
}

merr_t
get_space(const char *str, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u64, dst, dstsz))
        return merr(EINVAL);

    return get_space_from_arg(str, dst, dstsz);
}

merr_t
show_u32_size(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u32, val))
        return merr(EINVAL);

    n = space_to_string(*(const u32 *)val, str, strsz);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_u64(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u64, dst, dstsz))
        return merr(EINVAL);

    return parse_u64(src, dst);
}

merr_t
show_u64(char *str, size_t strsz, const void *val, size_t unused)
{
    u64         hex_threshold = 64 * 1024;
    const char *fmt;
    size_t      n;

    if (PARAM_SHOW_INVALID(u64, val))
        return merr(EINVAL);

    fmt = (*(const u64 *)val < hex_threshold) ? "%lu" : "0x%lx";
    n = snprintf(str, strsz, fmt, *(const u64 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_u64_dec(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u64, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "%lu", (ulong) * (const u64 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_u64_list(char *str, size_t strsz, const void *val, size_t val_nb)
{
    size_t     n;
    int        i;
    bool       ending_comma = false;
    const u64 *valu64 = (u64 *)val;

    for (i = 0; i < val_nb; i++, valu64++) {
        n = snprintf(str, strsz, "%lu", (ulong)*valu64);
        if (n >= strsz)
            /* string provided is too short. */
            return merr(EINVAL);
        str += n;
        strsz -= n;
        if (strsz == 1) {
            i++;
            ending_comma = false;
            break;
        }

        ending_comma = true;
        *str = ',';
        str++;
        strsz--;
    }
    if (i < val_nb)
        /* string provided is too short. */
        return merr(EINVAL);

    /* Overwrite the last ',' with a zero. */
    if (ending_comma)
        *(str - 1) = 0;

    return 0;
}

merr_t
get_u64_size(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(u64, dst, dstsz))
        return merr(EINVAL);

    return parse_size(src, dst);
}

merr_t
show_u64_size(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(u64, val))
        return merr(EINVAL);

    n = space_to_string(*(const u64 *)val, str, strsz);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_s64(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(s64, dst, dstsz))
        return merr(EINVAL);

    return parse_s64(src, dst);
}

merr_t
get_s32(const char *src, void *dst, size_t dstsz)
{
    if (PARAM_GET_INVALID(s32, dst, dstsz))
        return merr(EINVAL);

    return parse_s32(src, dst);
}

merr_t
show_s32(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(s32, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "0x%x", *(const s32 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
show_s64(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(s64, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "0x%lx", (ulong) * (const s64 *)val);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_string(const char *src, void *dst, size_t dstsz)
{
    size_t n;

    assert(src >= (char *)dst + dstsz || (char *)dst >= src + strlen(src));

    n = strlcpy(dst, src, dstsz);

    return (n < dstsz) ? 0 : merr(EINVAL);
}

merr_t
get_stringptr(const char *src, void *dst, size_t dstsz)
{
    *(void **)dst = strdup(src);

    return *(void **)dst ? 0 : merr(ENOMEM);
}

merr_t
show_string(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    assert((const char *)val >= str + strsz || str >= (const char *)val + strsz);

    n = strlcpy(str, val, strsz);

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
get_bool(const char *str, void *dst, size_t dstsz)
{
    bool   v;
    size_t len;
    merr_t err;

    if (!str || !dst || dstsz < sizeof(bool))
        return merr(EINVAL);

    /* Allow leading and trailing white space. */
    while (isspace(*str))
        ++str;

    len = strcspn(str, " \t\n\v\f\r");

    err = 0;
    v = false;

    if (len == 1 && str[0] == '1')
        v = true;
    else if (len == 1 && str[0] == '0')
        v = false;
    else if (len == 4 && !strncasecmp("true", str, len))
        v = true;
    else if (len == 5 && !strncasecmp("false", str, len))
        v = false;
    else
        err = merr(EINVAL);

    *(bool *)dst = v;
    return err;
}

merr_t
show_bool(char *str, size_t strsz, const void *val, size_t unused)
{
    size_t n;

    if (PARAM_SHOW_INVALID(bool, val))
        return merr(EINVAL);

    n = snprintf(str, strsz, "%s", *(const bool *)val ? "true" : "false");

    return (n < strsz) ? 0 : merr(EINVAL);
}

merr_t
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
show_log_level(char *str, size_t strsz, const void *val, size_t unused)
{
    log_priority_t pri;
    size_t         n;

    if (PARAM_SHOW_INVALID(log_priority_t, val))
        return merr(EINVAL);

    pri = *(const log_priority_t *)val;
    if (pri >= HSE_INVALID_VAL)
        return merr(EINVAL);

    n = strlcpy(str, hse_logprio_val_to_name(pri), strsz);

    return (n < strsz) ? 0 : merr(EINVAL);
}

void
shuffle(int argc, char **argv, int insert, int check)
{
    char *saved = argv[check];
    int   i;

    for (i = check; i > insert; i--)
        argv[i] = argv[i - 1];
    argv[insert] = saved;
}

merr_t
param_gen_match_table(struct param_inst *pi, struct match_token **table, int *entry_cnt)
{
    int                 cnt;
    struct param_inst * pil;
    struct match_token *t;

    pil = pi;
    cnt = 0;
    while (pil && pil->pi_type.param_token != NULL) {
        cnt++;
        pil++;
    }

    t = calloc(cnt + 1, sizeof(*pi));
    if (!t)
        return merr(ev(ENOMEM));

    *table = t;

    *entry_cnt = cnt;
    pil = pi;
    cnt = 0;
    while (pil && pil->pi_type.param_token != NULL) {
        t->token = cnt++;
        t->pattern = pil->pi_type.param_token;
        t++;
        pil++;
    }
    t->token = -1;
    t->pattern = NULL;

    return 0;
}

void
param_free_match_table(struct match_token *table)
{
    free(table);
}

bool show_advanced_params = false;

merr_t
process_params(int argc, char **argv, struct param_inst *pi, int *next_arg, u32 flag)
{
    struct match_token *table = NULL;
    substring_t         val;
    merr_t              err;
    int                 arg;
    int                 index;
    int                 entry_cnt = 0;

    /* Clear 'pi_set' to know what parameters are passed on the cmd line */
    for (index = 0; pi[index].pi_type.param_token != NULL; index++)
        pi[index].pi_entered = false;

    /* Need to create a match_table for this param_inst set */
    err = param_gen_match_table(pi, &table, &entry_cnt);
    if (ev(err))
        return err;

    for (arg = 0; arg < argc; arg++) {
        index = match_token(argv[arg], table, &val);
        if (index < 0)
            continue;

        if (flag && !(flag & pi[index].pi_flags))
            /* skip if type not requensted. */
            continue;

        if ((index >= 0) && (index < entry_cnt)) {
            err = pi[index].pi_type.param_str_to_val(
                val.from, pi[index].pi_value, pi[index].pi_type.param_size);
            if (ev(err))
                goto out;

            /* Validate if pi_value is within allowed range */
            if (pi[index].pi_type.param_range_check) {
                err = pi[index].pi_type.param_range_check(
                    pi[index].pi_type.param_min, pi[index].pi_type.param_max, pi[index].pi_value);
                if (ev(err)) {
                    char   name[128];
                    char * token = pi[index].pi_type.param_token;
                    size_t len = strcspn(token, "=");

                    len = min_t(size_t, sizeof(name) - 1, len);
                    strncpy(name, token, len);
                    name[len] = '\0';
                    goto out;
                }
            }
            pi[index].pi_entered = true;
            shuffle(argc, argv, 0, arg);
            if (next_arg)
                (*next_arg)++;
        }
    }

out:
    param_free_match_table(table);
    return err;
}

static void
param_get_name(int index, char *buf, size_t buf_sz, const struct param_inst *table)
{
    char * key;
    size_t len;

    assert(buf);
    assert(buf_sz);

    key = table[index].pi_type.param_token;
    len = strcspn(key, "=");

    strlcpy(buf, key, MIN(len + 1, buf_sz));
}

/* Set the values in table params to defaults before calling this function
 */
void
show_default_params(struct param_inst *params, u32 flag, FILE *fp)
{
    int  i = 0;
    char value[120];
    char param_name[DT_PATH_ELEMENT_LEN];

    fprintf(fp, "\nParams:\n");
    while (params[i].pi_type.param_token) {

        if (!show_advanced_params && (params[i].pi_flags & PARAM_FLAG_EXPERIMENTAL)) {
            /* If we do not want the advanced params, skip them */
            i++;
            continue;
        }

        if (flag && !(flag & params[i].pi_flags)) {
            /* skip if type not requested. */
            i++;
            continue;
        }

        param_get_name(i, param_name, sizeof(param_name), params);

        params[i].pi_type.param_val_to_str(value, sizeof(value), params[i].pi_value, 1);
        fprintf(fp, "\t%s: %s (default = %s)\n", param_name, params[i].pi_msg, value);
        i++;
    }
}

char *
params_help(
    char *             buf,
    size_t             buf_sz,
    void *             params,
    struct param_inst *table,
    int                table_sz,
    void *             base)
{
    int    i = 0;
    size_t buf_offset = 0;
    char * bufp = buf;
    char   line[80];

    if (!bufp || buf_sz < 1)
        return NULL;

    memset(line, '-', sizeof(line));
    line[sizeof(line) - 2] = '\n';
    line[sizeof(line) - 1] = '\0';

    bufp[0] = '\0';

    snprintf_append(bufp, buf_sz, &buf_offset, line);
    snprintf_append(
        bufp,
        buf_sz,
        &buf_offset,
        "%-13s| %-*s | %-36s\n",
        "Default",
        DT_PATH_ELEMENT_LEN,
        "Parameter name",
        "Parameter description");
    snprintf_append(bufp, buf_sz, &buf_offset, line);

    for (i = 0; i < table_sz; i++) {
        void * default_value;
        char   valstr[PATH_MAX];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t offset = table[i].pi_value - base;

        if (!show_advanced_params && (table[i].pi_flags & PARAM_FLAG_EXPERIMENTAL))
            /* If we do not want the advanced params, skip them */
            continue;

        param_get_name(i, param_name, sizeof(param_name), table);

        valstr[0] = '\0';
        default_value = params + offset;
        (void)table[i].pi_type.param_val_to_str(valstr, sizeof(valstr), default_value, 1);

        snprintf_append(
            bufp,
            buf_sz,
            &buf_offset,
            "%-13s| %-*s | %-36s\n",
            valstr,
            DT_PATH_ELEMENT_LEN,
            param_name,
            table[i].pi_msg);
    }

    return bufp;
}

void
params_print(
    const struct param_inst *table,
    size_t                   table_sz,
    const char *             type,
    void *                   params,
    void *                   base)
{
    int          i;
    struct slog *logger;

    if (!table || !params) {
        ev(1);
        return;
    }

    if (!base)
        base = params;

    hse_slog_create(HSE_NOTICE, &logger, type);

    for (i = 0; i < table_sz; i++) {
        void * value;
        char   valstr[PATH_MAX];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t offset = table[i].pi_value - (void *)base;

        if (!show_advanced_params && (table[i].pi_flags & PARAM_FLAG_EXPERIMENTAL))
            /* If we do not want the advanced params, skip them */
            continue;

        param_get_name(i, param_name, sizeof(param_name), table);

        valstr[0] = '\0';
        value = params + offset;
        (void)table[i].pi_type.param_val_to_str(valstr, sizeof(valstr), value, 1);

        hse_slog_append(logger, HSE_SLOG_FIELD(param_name, "%s", valstr));
    }

    hse_slog_commit(logger);
}

bool
param_entered(struct param_inst *pi, char *name)
{
    while (pi && pi->pi_type.param_token != NULL) {
        if (!strncmp(pi->pi_type.param_token, name, strlen(name))) {
            if (pi->pi_entered)
                return true;
            else
                return false;
        }
        pi++;
    }
    return false;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "param_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
