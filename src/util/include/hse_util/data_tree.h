/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_DATA_TREE_H
#define HSE_PLATFORM_DATA_TREE_H

#include <hse_util/list.h>
#include <hse_util/yaml.h>
#include <hse_util/inttypes.h>
#include <hse_util/bug.h>

#include <3rdparty/rbtree.h>

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

/* The limit on the number of elements in the path length is 7 and each of
 * the path elements must be bound by the length of the name of an mpool
 * with one exception.
 *
 * Because of hierachical naming pattern of mpool-name then dataset-name and
 * then dataset constituents, provision is made for one of the path elements
 * to be compound and contain 3 name fields plus two separator characters.
 */
#define DT_PATH_ELEMENT_CNT 7
#define DT_PATH_ELEMENT_LEN 32
#define DT_PATH_SEPARATOR_CNT (DT_PATH_ELEMENT_CNT - 1)
#define DT_PATH_COMP_ELEMENT_LEN ((DT_PATH_ELEMENT_LEN * 3) + 2)

#define DT_PATH_LEN                                                                        \
    (((DT_PATH_ELEMENT_CNT - 1) * DT_PATH_ELEMENT_LEN) + ((DT_PATH_ELEMENT_LEN * 3) + 2) + \
     DT_PATH_SEPARATOR_CNT)

/* Operations */
enum { DT_OP_INVALID, DT_OP_EMIT, DT_OP_SET, DT_OP_COUNT, DT_OP_LOG };

/* Flags */
#define DT_FLAGS_IN_TREE 0x1
#define DT_FLAGS_NON_REMOVEABLE 0x2

struct dt_element {
    union {
        struct rb_node      dte_node;
        struct list_head    dte_list;
    };
    void                   *dte_data;
    struct dt_element_ops  *dte_ops;
    dt_type_t               dte_type;
    int                     dte_severity;
    uint32_t                dte_flags;
    int                     dte_line;
    const char             *dte_file;
    const char             *dte_func;
    const char             *dte_comp;
    char                    dte_path[DT_PATH_LEN]; /* whole path */
};

/**
     * dt_selector_t - callback function used by the iterators to
     *                 determine if a given element should be operated on.
     *
     * Return: non-zero for selection approved, zero for selection denied.
     */
typedef int(dt_selector_t)(struct dt_element *);

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

typedef size_t(dt_remove_handler_t)(struct dt_element *);

typedef size_t(dt_emit_handler_t)(struct dt_element *, struct yaml_context *);

typedef size_t(dt_log_handler_t)(struct dt_element *, int log_level);

typedef size_t(dt_set_handler_t)(struct dt_element *, struct dt_set_parameters *);

typedef size_t(dt_count_handler_t)(struct dt_element *);

typedef bool(dt_match_select_handler_t)(struct dt_element *, char *, char *);

struct dt_element_ops {
    dt_remove_handler_t *      remove;
    dt_emit_handler_t *        emit;
    dt_log_handler_t *         log;
    dt_set_handler_t *         set;
    dt_count_handler_t *       count;
    dt_match_select_handler_t *match_selector;
};

extern struct dt_tree *dt_data_tree;

/* Data Tree's Interface */

/**
 * dt_init - Initialize the data_tree tree.
 *
 * dt_init (no arguments) will create (using dt_create) the
 * dt_tree and root node of the tree shared by Error Counters,
 * Performance Counters, Traces, Tunables, and Component Info.
 *
 * To make sure that this has been called before anything
 * tries to insert a new node, this function will be called by
 * the hse_platform kernel modules initialization code or,
 * the load function in user_init.c (for user mode applications).
 *
 * Return: void
 */
void
dt_init(void);

/**
 * dt_fini - Free resources allocated by dt_init().
 *
 * dt_init (no arguments) frees the workqueue allocated by dt_init()
 * and removes the dt_data_tree, which will free all of the elements
 * currently in the tree.
 *
 * May only be called by hse_platform kernel module cleanup code.
 *
 * Return: void
 */
void
dt_fini(void);

/**
 * dt_create - Create a dt_tree.
 * @name:  String that identifies the tree.
 *
 * dt_create will create a struct dt_tree that will act as
 * a top-level directory and tree for all elements connected
 * to that directory.
 *
 * E.g. dt_create("data") will create the path '/data' that
 * will be reflected in all of the Data Tree (dt) user access
 * methods (sysctl, sysfs, REST, ioctl, etc.)
 *
 * The struct dt_tree pointer returned by dt_create will be
 * passed to all of the other dt API functions to indicate
 * which tree they should act on.
 *
 * Return: struct dt_tree * on success, NULL on error
 */
struct dt_tree *
dt_create(const char *name);

/**
 * dt_destroy - Destroy a dt_tree created by dt_create
 * @tree:    Pointer to struct dt_tree to destroy
 *
 * dt_destroy will remove every element that is attached
 * to the tree, invoking the registered remove handler for
 * each. Note, the memory for the dt_element and data object
 * structures was not allocated by the DataTree subsystem
 * and, therefore, won't be freed by it. Instead, users of
 * a dt_tree that might get destroyed need to register a
 * remove handler as part of the dt_element_ops structure.
 *
 * Return: void
 */
void
dt_destroy(struct dt_tree *tree);

/**
 * dt_add() - Add a pre-allocated and pre-initialized element to tree
 * @tree:   pointer to dt_tree to add this element to
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
 *   -EINVAL: either the tree or dte are NULL
 *   -EEXIST: a node with the same path already exists
 */
int
dt_add(struct dt_tree *tree, struct dt_element *dte);

/**
 * dt_remove - Disconnect a dt_element from a dt_tree
 * @tree:   pointer to dt_tree to remove this element from
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
 *   -EACCES: element is flagged DT_FLAGS_NON_REMOVEABLE
 */
int
dt_remove(struct dt_tree *tree, struct dt_element *dte);

/**
 * dt_remove_by_name() - Remove a specific dt_element identified by path
 * @tree, struct dt_tree *, the tree from which elements should be removed
 * @path, char *, a data_tree path indicating the element to remove
 *
 * Return: 0 on success, -einval on error
 */
int
dt_remove_by_name(struct dt_tree *tree, char *path);

/**
 * dt_remove_recursive() - Recursively remove all of the dt_elements in a path
 * @tree, struct dt_tree *, the tree from which elements should be removed
 * @path, char *, a data_tree path indicating the start of the subtree to remove
 *
 * dt_remove_recursive is used to remove a whole subtree of a data_tree.
 * A specific use case is for the mpool kernel module to be able to remove
 * its event counters when it is rmmod'd
 *
 * Return: 0 on success, -einval on error
 */
int
dt_remove_recursive(struct dt_tree *tree, char *path);

/**
 * dt_find - Find a dte within the data tree
 * @tree:   pointer to dt_tree to search
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
dt_find(struct dt_tree *tree, const char *path, int exact);

/**
 * dt_find_locked() - find a dt_element without locking the tree. The caller
 *                    must gain a lock before calling this function.
 * @tree:  pointer to dt_tree to search.
 * @path:  string used to match dte.
 * @exact: if 1, match must be exact.
 *         if 0, match with closest element that includes @path.
 *
 * Return: Matching dte if search was successful, NULL otherwise
 */
struct dt_element *
dt_find_locked(struct dt_tree *tree, const char *path, int exact);

/**
 * dt_iterate_cmd - Iteratively execute a command on elements
 * of the data tree.
 * @tree:   pointer to dt_tree to operate on
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
 * bytes = dt_iterate_cmd( DT_OP_GET, "/data/event_counter", buf,
 *      &selector);
 *
 * Return: number of elements operated on
 */
size_t
dt_iterate_cmd(
    struct dt_tree *             tree,
    int                          op,
    const char *                 path,
    union dt_iterate_parameters *dip,
    dt_selector_t *              selector,
    char *                       selector_field,
    char *                       selector_value);

/**
 * dt_iterate_next - Iteratively find elements of the data tree.
 * @tree:   pointer to dt_tree to operate on
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
dt_iterate_next(struct dt_tree *tree, const char *path, struct dt_element *previous);

/**
 * dt_get_tree() - Find a dt_tree root based on pathname
 * @path: char *, the data tree path from which to derive the tree
 *
 * dt_get_tree uses the first element of a path, e.g. '/data',
 * to find the dt_tree that begins with that path.
 *
 * Returns: struct dt_tree *, or NULL if there is no matching tree.
 */
struct dt_tree *
dt_get_tree(char *path);

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
