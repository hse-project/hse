/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/printbuf.h>
#include <hse_util/yaml.h>

void
yaml_print_and_rewind(struct yaml_context *yc)
{
    printf("%s", yc->yaml_buf);
    yc->yaml_offset = 0;
    yc->yaml_buf[0] = 0;
}

/* Note: In the kernel this function is called under a spin lock
 * with interrupts disabled (ugh) and therefore must not block.
 * Additionally, if the allocation fails it must not free the old
 * buffer, and it must never call ev() (otherwise dt_add() will
 * likely deadlock on dt_lock).
 *
 * We now allocate a sufficiently large buffer in mpioc_dt_get()
 * such that this function should not normally be called.
 */
void
yaml_realloc_buf(struct yaml_context *yc)
{
    void *buf;

    buf = realloc(yc->yaml_buf, yc->yaml_buf_sz * 2);

    if (!buf)
        return; /* DO NOT call ev() */

    yc->yaml_buf = buf;
    yc->yaml_buf_sz *= 2;
}

static void
yaml_indent(struct yaml_context *yc)
{
    char * dst, *end;
    size_t indent;

    indent = yc->yaml_indent * 2;

    if (yc->yaml_offset + indent > yc->yaml_buf_sz)
        indent = yc->yaml_buf_sz - yc->yaml_offset;

    dst = yc->yaml_buf + yc->yaml_offset;
    end = dst + indent;
    yc->yaml_offset += indent;

    while (dst < end)
        *dst++ = ' ';
}

/**
 * yaml_emit() -
 * @yc:
 * Once yaml_offset exceeds 3/4 watermark of the yaml_buf_sz,
 * flush yaml_buf and rewind yaml_offset to 0.
 * This routine can be called, after a line of characters
 * is saved into yaml_buf. We don't need to call it before each
 * snprintf, since it guaranteed that at least 1/4 of yaml_buf
 * is available before a new line starts.
 * The assumption is that the buffer yaml users allocate is big
 * enough, such that the longest line can fit in 1/4 of yaml_buf.
 */
static inline void
yaml_emit(struct yaml_context *yc)
{
    if ((yc->yaml_offset + yc->yaml_buf_sz / 4) > yc->yaml_buf_sz)
        yc->yaml_emit(yc);
}

void
yaml_start_element_type(struct yaml_context *yc, const char *name)
{
    if (!yc)
        return;

    /* Need to decide what to do about the indent level. */
    switch (yc->yaml_prev) {

        case Yaml_Context_Type_Invalid:
            /* We must be the original root. */
            yc->yaml_indent = 0;
            break;

        case Yaml_Context_Type_Element_Type:
            /*
         * Recursive element_type. Ideally, we need to increase
         * indent for Type_Element as well, however, we don't,
         * as there's currently no way to end the element_type
         * started by the root emitter.
         */
            yc->yaml_indent++;
            break;

        case Yaml_Context_Type_Element:
        case Yaml_Context_Type_Element_Field:
            break;
    }

    yaml_indent(yc);

    strlcpy_append(yc->yaml_buf, name, yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, ":\n", yc->yaml_buf_sz, &yc->yaml_offset);

    yc->yaml_prev = Yaml_Context_Type_Element_Type;

    if (yc->yaml_emit)
        yaml_emit(yc);
}

void
yaml_end_element_type(struct yaml_context *yc)
{
    if (!yc)
        return;

    switch (yc->yaml_prev) {

        case Yaml_Context_Type_Invalid:
        case Yaml_Context_Type_Element_Field:
            /* The previous element context hasn't ended. */
            return;

        case Yaml_Context_Type_Element_Type:
        case Yaml_Context_Type_Element:
            /* This is expected context. Nothing to do. */
            break;
    }

    if (yc->yaml_indent) {
        /* Decrease indent. */
        yc->yaml_indent--;
        yc->yaml_prev = Yaml_Context_Type_Element_Type;
    } else {
        /* root element */
        yc->yaml_prev = Yaml_Context_Type_Invalid;
    }
}

void
yaml_start_element(struct yaml_context *yc, const char *key, const char *value)
{
    if (!yc)
        return;

    /*
     * Should never start a yaml context with an element
     * (vs an element_type).
     */
    if (yc->yaml_prev == Yaml_Context_Type_Invalid)
        return;

    yaml_indent(yc);

    strlcpy_append(yc->yaml_buf, "- ", yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, key, yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, ": ", yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, value, yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, "\n", yc->yaml_buf_sz, &yc->yaml_offset);

    yc->yaml_indent++;
    yc->yaml_prev = Yaml_Context_Type_Element;

    if (yc->yaml_emit)
        yaml_emit(yc);
}

void
yaml_end_element(struct yaml_context *yc)
{
    if (!yc)
        return;

    switch (yc->yaml_prev) {

        case Yaml_Context_Type_Invalid:
        case Yaml_Context_Type_Element_Type:
            /* There's no element context to end. */
            return;

        case Yaml_Context_Type_Element:
        case Yaml_Context_Type_Element_Field:
            /* This is expected context. Nothing to do. */
            break;
    }

    yc->yaml_indent--;
    yc->yaml_prev = Yaml_Context_Type_Element;
}

void
yaml_element_list(struct yaml_context *yc, const char *key)
{
    if (!yc)
        return;

    /* Need to decide what to do about the indent level. */
    switch (yc->yaml_prev) {

        case Yaml_Context_Type_Invalid:
            /*
         * Shouldn't be here. Should never start a
         * yaml context with an element field.
         */
            return;

        case Yaml_Context_Type_Element_Type:
            /* element_type context within an element context */
            yc->yaml_indent++;
            break;

        case Yaml_Context_Type_Element:
        case Yaml_Context_Type_Element_Field:
            /* This is the expected context. Nothing to do.  */
            break;
    }

    yaml_indent(yc);

    strlcpy_append(yc->yaml_buf, "- ", yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, key, yc->yaml_buf_sz, &yc->yaml_offset);
    strlcpy_append(yc->yaml_buf, "\n", yc->yaml_buf_sz, &yc->yaml_offset);

    yc->yaml_prev = Yaml_Context_Type_Element_Field;

    if (yc->yaml_emit)
        yaml_emit(yc);
}

void
yaml_element_field(struct yaml_context *yc, const char *key, const char *value)
{
    size_t dstsz;
    char * dst;

    if (!yc)
        return;

    /* Need to decide what to do about the indent level. */
    switch (yc->yaml_prev) {

        case Yaml_Context_Type_Invalid:
            /*
         * Shouldn't be here. Should never start a
         * yaml context with an element field.
         */
            return;

        case Yaml_Context_Type_Element_Type:
            /* element_type context within an element context */
            yc->yaml_indent++;
            break;

        case Yaml_Context_Type_Element:
        case Yaml_Context_Type_Element_Field:
            /* This is the expected context. Nothing to do.  */
            break;
    }

    yaml_indent(yc);

    dst = yc->yaml_buf;
    dstsz = yc->yaml_buf_sz;

    strlcpy_append(dst, key, dstsz, &yc->yaml_offset);

    if (value) {
        strlcpy_append(dst, ": ", dstsz, &yc->yaml_offset);
        strlcpy_append(dst, value, dstsz, &yc->yaml_offset);
        strlcpy_append(dst, "\n", dstsz, &yc->yaml_offset);
    } else {
        strlcpy_append(dst, ":\n", dstsz, &yc->yaml_offset);
    }

    yc->yaml_prev = Yaml_Context_Type_Element_Field;

    if (yc->yaml_emit)
        yaml_emit(yc);
}

void
yaml_element_bool(struct yaml_context *yc, const char *key, bool val)
{
    yaml_element_field(yc, key, val ? "true" : "false");
}

void
yaml_field_fmt(struct yaml_context *yc, const char *key, const char *valfmt, ...)
{
    char    val[64];
    va_list ap;

    va_start(ap, valfmt);
    vsnprintf(val, sizeof(val), valfmt, ap);
    va_end(ap);

    yaml_element_field(yc, key, val);
}

void
yaml_list_fmt(struct yaml_context *yc, const char *keyfmt, ...)
{
    char    key[64];
    va_list ap;

    va_start(ap, keyfmt);
    vsnprintf(key, sizeof(key), keyfmt, ap);
    va_end(ap);

    yaml_element_list(yc, key);
}
