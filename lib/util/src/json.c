/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/json.h>

#include <stdarg.h>

#define _json_snprintf(jc, ...) \
    (snprintf_append(jc->json_buf, jc->json_buf_sz, &jc->json_offset, __VA_ARGS__))

#define _json_vsnprintf(jc, ...) \
    (vsnprintf_append(jc->json_buf, jc->json_buf_sz, &jc->json_offset, __VA_ARGS__))

static bool
json_process_fmt(const char *fmt, char *new_fmt, size_t size)
{
    char *s = strchr(fmt, '%');

    if (!s)
        return false;

    switch (*(++s)) {
        case 's':
        case 'p':
        case 'x':
        case 'X':
            snprintf(new_fmt, size, "\"%s\",", fmt);
            return true;
    }

    snprintf(new_fmt, size, "%s,", fmt);
    return true;
}

void
json_element_start(struct json_context *jc, const char *key)
{
    if (!jc || (!jc->json_depth && key) || (jc->json_depth && !key))
        return;

    jc->json_depth++;

    if (!key) {
        _json_snprintf(jc, "{");
        return;
    }

    _json_snprintf(jc, "\"%s\":{", key);
}

void
json_element_fieldv(struct json_context *jc, va_list fields)
{
    char *key, *fmt;
    char  new_fmt[32];

    if (!jc || !jc->json_depth)
        return;

    key = va_arg(fields, char *);
    fmt = va_arg(fields, char *);

    if (!json_process_fmt(fmt, new_fmt, sizeof(new_fmt)))
        return;

    _json_snprintf(jc, "\"%s\":", key);
    _json_vsnprintf(jc, new_fmt, fields);
}

void
json_element_field(struct json_context *jc, ...)
{
    va_list fields;

    if (!jc || !jc->json_depth)
        return;

    va_start(fields, jc);
    json_element_fieldv(jc, fields);
    va_end(fields);
}

void
json_element_list(struct json_context *jc, const char *key, const char *fmt, int argc, void *argv)
{
    int i;

    if (!jc || !jc->json_depth || !key || !strchr(fmt, '%') || !argc)
        return;

    _json_snprintf(jc, "\"%s\":[", key);

    for (i = 0; i < argc; i++) {
        switch (fmt[1]) {
            case 's':
                _json_snprintf(jc, "\"%s\",", *((char **)argv + i));
                break;
            case 'd':
                _json_snprintf(jc, "%d,", *((int *)argv + i));
                break;
            case 'l':
                _json_snprintf(jc, "%lu,", *((unsigned long *)argv + i));
                break;
            default:
                goto out;
        }
    }

    jc->json_offset--;
out:
    _json_snprintf(jc, "],");
}

void
json_element_list_custom(
    struct json_context *jc,
    const char *         key,
    void (*cb)(const void *, int, char *, size_t),
    int   argc,
    void *argv)
{
    int  i;
    char value[32];

    if (!jc || !jc->json_depth || !argc)
        return;

    _json_snprintf(jc, "\"%s\":[", key);

    for (i = 0; i < argc; i++) {
        cb(argv, i, value, sizeof(value));
        _json_snprintf(jc, "%s,", value);
    }

    jc->json_offset--;
    _json_snprintf(jc, "],");
}

void
json_element_end(struct json_context *jc)
{
    if (!jc || !jc->json_depth)
        return;

    jc->json_depth--;

    if (*(jc->json_buf + jc->json_offset - 1) != '{')
	    jc->json_offset--;

    if (jc->json_depth)
        _json_snprintf(jc, "},");
    else
        _json_snprintf(jc, "}");
}
