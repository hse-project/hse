/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_YAML_H
#define HSE_PLATFORM_YAML_H

#include <hse_util/printbuf.h>

enum yaml_context_type {
    Yaml_Context_Type_Invalid,
    Yaml_Context_Type_Element_Type,
    Yaml_Context_Type_Element,
    Yaml_Context_Type_Element_Field,
};

struct yaml_context;
typedef void
yaml_emit_t(struct yaml_context *yc);

struct yaml_context {
    char *                 yaml_buf;
    size_t                 yaml_buf_sz;
    size_t                 yaml_offset;
    int                    yaml_indent;
    enum yaml_context_type yaml_prev;
    yaml_emit_t *          yaml_emit;
    void *                 yaml_free;
};

void
yaml_start_element_type(struct yaml_context *yc, const char *name);

void
yaml_end_element_type(struct yaml_context *yc);

void
yaml_start_element(struct yaml_context *yc, const char *key, const char *value);

void
yaml_end_element(struct yaml_context *yc);

void
yaml_element_field(struct yaml_context *yc, const char *key, const char *value);

void
yaml_element_bool(struct yaml_context *yc, const char *key, bool val);

void
yaml_element_list(struct yaml_context *yc, const char *key);

void
yaml_field_fmt(struct yaml_context *yc, const char *key, const char *valfmt, ...);

void
yaml_list_fmt(struct yaml_context *yc, const char *keyfmt, ...);

/**
 * yaml_print_and_rewind() - print yaml_buf and rewind yaml_offset
 * @yc:
 */
void
yaml_print_and_rewind(struct yaml_context *yc);

/**
 * yaml_realloc_buf() - realloc yaml_buf, double the buffer size
 * @yc:
 */
void
yaml_realloc_buf(struct yaml_context *yc);

#endif /* HSE_PLATFORM_YAML_H */
