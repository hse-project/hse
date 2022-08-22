/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ELEMENT_SOURCE_H
#define HSE_PLATFORM_ELEMENT_SOURCE_H

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>

struct element_source;

/**
 * element_source_get_next() -
 * @source:     struct element_source handle
 * @data:       reference to pointer to result
 *
 * RESTRICTION: The user of this interface cannot rely on the returned value
 *              being valid after a subsequent call to this interface. If the
 *              caller needs the data across multiple calls then it must make
 *              a copy of it.
 *
 * Return: true if a new element was retrieved, false if the
 *         element source is empty
 */
typedef bool
element_source_get_next(struct element_source *source, void **data);

typedef bool
element_source_unget(struct element_source *source);

struct element_source {
    element_source_get_next *es_get_next;
    element_source_unget *   es_unget;
    struct element_source *  es_next_src;
    bool                     es_eof;
    s64                      es_sort;
};

static inline struct element_source
es_make(element_source_get_next *get, element_source_unget *unget, struct element_source *next)
{
    struct element_source es = { get, unget, next, 0, 0 };

    return es;
}

#endif
