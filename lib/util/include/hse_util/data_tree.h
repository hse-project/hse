/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_DATA_TREE_H
#define HSE_PLATFORM_DATA_TREE_H

#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/yaml.h>

#include <rbtree.h>

typedef enum {
    DT_TYPE_INVALID,
    DT_TYPE_DONT_CARE,
    DT_TYPE_ROOT,
    DT_TYPE_ERROR_COUNTER,
    DT_TYPE_PERFC,
    DT_TYPE_WP_KVDB,
    DT_TYPE_WP_KVS,
    DT_TYPE_PMD,
    DT_TYPE_TEST_ELEMENT,
} dt_type_t;

typedef enum {
    DT_FIELD_INVALID,
    DT_FIELD_ODOMETER_TIMESTAMP,
    DT_FIELD_ODOMETER,
    DT_FIELD_TRIP_ODOMETER_TIMESTAMP,
    DT_FIELD_TRIP_ODOMETER,
    DT_FIELD_PRIORITY,
    DT_FIELD_FLAGS,
    DT_FIELD_ENABLED,
    DT_FIELD_CLEAR,
    DT_FIELD_DATA,
    DT_FIELD_INVALIDATE_HANDLE,
} dt_field_t;

/* Operations */
enum { DT_OP_INVALID, DT_OP_EMIT, DT_OP_SET, DT_OP_COUNT, DT_OP_LOG };

/* clang-format on */

/* DT_PATH_SZ restricts the path size of a statically allocated dt_element,
 * while DT_PATH_LEN restricts the size of a dynamically allocated dt_element.
 *
 * DT_PATH_SZ is sized such that when statically allocated along with an
 * event counter the total size of both is 256 bytes (to maximize page
 * density and reduce waste).
 *
 * [MU_REVISIT] We can eliminate dte_pathbuf and support for dynamic dte
 * allocation once we have replaced the kvdb name in the path with it's
 * inode number.
 */
#define DT_PATH_SZ                ((64 * 3) - 80)
#define DT_PATH_LEN               (256)
#define DT_PATH_ELEMENT_LEN       (32)

#define DT_PATH_ROOT              "/data"
#define DT_PATH_EVENT             "/data/event_counter"
#define DT_PATH_PERFC             "/data/perfc"
#define DT_PATH_TEST              "/data/test"

#define _dt_section               __attribute__((section("hse_dt")))

struct dt_element {
    union {
        struct rb_node      dte_node;
        struct list_head    dte_list;
    };
    void                   *dte_data;
    struct dt_element_ops  *dte_ops;
    dt_type_t               dte_type;
    uint32_t                dte_flags;
    int                     dte_line;
    const char             *dte_file;
    const char             *dte_func;
    char                    dte_path[DT_PATH_SZ]; /* whole path */
    char                    dte_pathbuf[];
} HSE_ALIGNED(64);

/* clang-format on */

/**
 * dt_selector_t - callback function used by the iterators to
 *                 determine if a given element should be operated on.
 *
 * Return: non-zero for selection approved, zero for selection denied.
 */
typedef int dt_selector_t(struct dt_element *);

struct dt_set_parameters {
    char *     path;
    char *     value;
    size_t     value_len;
    dt_field_t field;
};

union dt_iterate_parameters {
    struct yaml_context *     yc;
    struct dt_set_parameters *dsp;
    int                       log_level;
};

/* The real definition of struct dt_tree is in data_tree.c */
struct dt_tree;

typedef size_t dt_remove_handler_t(struct dt_element *);
typedef size_t dt_emit_handler_t(struct dt_element *, struct yaml_context *);
typedef size_t dt_set_handler_t(struct dt_element *, struct dt_set_parameters *);
typedef bool dt_match_handler_t(struct dt_element *, char *, char *);

struct dt_element_ops {
    dt_remove_handler_t *dto_remove;
    dt_emit_handler_t   *dto_emit;
    dt_set_handler_t    *dto_set;
    dt_match_handler_t  *dto_match_selector;
};

extern struct dt_tree *dt_data_tree;

/* Data Tree's Interface */

/**
 * dt_init - Initialize the data_tree tree.
 *
 * dt_init (no arguments) will create the
 * dt_tree and root node of the tree shared by Error Counters,
 * Performance Counters, Traces, Tunables, and Component Info.
 *
 * Return: void
 */
void
dt_init(void) HSE_COLD;

/**
 * dt_fini - Free resources allocated by dt_init().
 *
 * dt_init (no arguments) frees the workqueue allocated by dt_init()
 * and removes the dt_data_tree, which will free all of the elements
 * currently in the tree.
 *
 * Return: void
 */
void
dt_fini(void) HSE_COLD;

/**
 * dt_add() - Add a pre-allocated and pre-initialized element to tree
 * @dte:    struct dt_element to add
 *
 * dt_add is going to grab the write-side of this tree's
 * Read/Write semaphore.
 *
 * It will use the dte->path field
 * (max length PATH_LEN) to determine the proper place to insert
 * the dte.
 *
 * If an entry is already in the tree with that path, dt_add will
 * not add or replace.
 *
 * Return: 0 on success, -errno on error
 *   EINVAL: either the tree or dte are NULL
 *   EEXIST: a node with the same path already exists
 */
int
dt_add(struct dt_element *dte);

/**
 * dt_remove - Disconnect a dt_element from a dt_tree
 * @dt_element:    Pointer to a struct dt_element to disconnect
 *
 * dt_remove is going to grab the write-side of this tree's
 * Read/Write semaphore.
 *
 * dt_remove removes a dt_element that had been connected to a
 * dt_tree via dt_add.
 *
 * Note, the memory used for the dt_element and the underlying
 * data object was not allocated by the DataTree, and so will not
 * be freed by it. The registered remove handler (in the
 * dt_element_ops structure) will be called to perform any
 * necessary frees.
 *
 * Return: 0 on success, -errno on error
 *   EACCES: element is not removable
 */
int
dt_remove(struct dt_element *dte);

/**
 * dt_remove_by_name() - Remove a specific dt_element identified by path
 * @path, char *, a data_tree path indicating the element to remove
 *
 * Return: 0 on success, errno on error
 */
int
dt_remove_by_name(char *path);

/**
 * dt_remove_recursive() - Recursively remove all of the dt_elements in a path
 * @path, char *, a data_tree path indicating the start of the subtree to remove
 *
 * dt_remove_recursive is used to remove a whole subtree of a data_tree.
 * A specific use case is for the mpool kernel module to be able to remove
 * its event counters when it is rmmod'd
 *
 * Return: 0 on success, errno on error
 */
int
dt_remove_recursive(char *path);

/**
 * dt_find - Find a dte within the data tree
 * @path:               string used to match dte
 * @exact:              if 1, match must be exact
 * if 0, match with closest element that
 * includes @path.
 *
 * dt_find can be used in two ways:
 * 1. exact match, given a path (string), find and return a pointer
 * to the dte with that exact path.
 * 2. fuzzy match, return the dte if the exact match is found, but if
 * no exact match found, return the next closest entry that includes
 * all of @path.
 *
 * For example, your tree includes /data/foo/able, and nothing else
 * in the /data/foo branch. A fuzzy (exact==0) search for '/data/foo'
 * will find and return the path with /data/foo/able, while an exact
 * search will return NULL.
 *
 * fuzzy match is used when the user wants to operate on a whole branch
 * without knowing any specific entry within the branch.
 * E.g. To support GET /data/event_counter/kvdb we need to find the
 * first entry in the /data/event_counter/kvdb branch, and then
 * iterate from there.
 *
 * Return: Matching dte if search was successful, NULL otherwise
 */
struct dt_element *
dt_find(const char *path, int exact);

/**
 * dt_iterate_cmd - Iteratively execute a command on elements of the data tree.
 * @op:                 Command to execute, DT_OP_EMIT, e.g.
 * @path:       Starting path
 * @yc:             YAML context, Includes buffer, buffer size, and offset.
 * @selector:   An optional callback function that will determine
 *              whether a given element should be operated on.
 *
 * dt_iterate_cmd will execute the given command on every element
 * in the tree that includes @path and the selector function
 * (if one exists) returns non-zero.
 *
 * For example, to emit (print) all Error Counters, you can do this:
 * bytes = dt_iterate_cmd( DT_OP_EMIT, "/data/event_counter", buf, &selector);
 *
 * Return: number of elements operated on
 */
size_t
dt_iterate_cmd(
    int                          op,
    const char *                 path,
    union dt_iterate_parameters *dip,
    dt_selector_t *              selector,
    char *                       selector_field,
    char *                       selector_value);

/**
 * dt_iterate_next - Iteratively find elements of the data tree.
 * @path:   path to operate on (first element to be returned will
 *          be the result of a fuzzy search on this path.
 * @prev:   NULL on first invocation, previous element on subsequent
 *          calls to dt_iterate_next.
 *
 * dt_iterate_next, when called with @prev==NULL will do a fuzzy find
 * to get the first element that matches @path and return that
 * dt_element *. On subsequent calls, with the previously found
 * element passed in, dt_iterate_next will return the next element
 * in the path. It will return NULL when no further elements exist
 * in the specified path.
 *
 * For example, if you had the following elements in your tree:
 * 1. /test/one
 * 2. /test/one/two
 * 3. /test/one/two/three/four
 *
 * And you started the iterator like this:
 *
 * found = dt_iterate_next(tree, "/test", NULL);
 *
 * You would get the element at the path "/test/one".
 *
 * On the next call:
 *
 * found = dt_iterate_next(tree, "/test", found);
 *
 * You will get the element at "/test/one/two". A subsequent calls
 * will get the element at "/test/one/two/three/four", and then NULL.
 *
 * Return: Pointer to next struct dt_element *, or NULL if none.
 */
struct dt_element *
dt_iterate_next(const char *path, struct dt_element *previous);

/**
 * dt_tree_emit() - A debug function that outputs the entire data tree.
 *
 * Meant to be called from user-space platform code on exit,
 * this function will dump all Error and Performance Counters.
 */
void
dt_tree_emit(void);

/**
 * dt_tree_log() - A debug function that outputs Error Counters to system log.
 *
 * Meant to be called from user-space platform on exit,
 * this function will dump all Error and Performance Counters.
 */
void
dt_tree_log(void);

/**
 * dt_tree_emit_path() - A debug function that outputs the entire data tree.
 * @path:   char *, the data tree path to traverse
 *
 * Meant to be called from user-space platform code on exit,
 * this function will dump all elements starting from @path.
 */
void
dt_tree_emit_path(char *path);

/**
 * dt_tree_emit_pathbuf() - A debug function that outputs the entire data
 *                          tree in the specified buffer.
 * @path:   char *, the data tree path to traverse
 * @buf :   output buffer
 * @buflen: buffer length
 *
 * Meant to be called from user-space platform code on exit,
 * this function will dump all elements starting from @path in the
 * specified output buffer.
 */
void
dt_tree_emit_pathbuf(char *path, char *buf, u32 buflen);

dt_field_t
dt_get_field(const char *field);

#endif /* HSE_PLATFORM_DATA_H */
