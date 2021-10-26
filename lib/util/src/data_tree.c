/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/mutex.h>
#include <hse_util/list.h>
#include <hse_util/string.h>
#include <hse_util/invariant.h>
#include <hse_util/event_counter.h>
#include <hse_util/data_tree.h>

#include <rbtree.h>

/* clang-format off */

struct dt_tree {
    struct mutex        dt_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct rb_root      dt_root;

    struct mutex        dt_pending_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head    dt_pending_list;

    struct dt_element   dt_element HSE_ALIGNED(SMP_CACHE_BYTES);
};

/**
 * struct field_name - A table mapping field names to their enum values
 * @field_name:
 * @field_val:
 */
struct field_name {
    const char *field_name;
    dt_field_t  field_val;
};

/* clang-format on */

static size_t dt_root_emit_handler(struct dt_element *, struct yaml_context *);

static struct dt_element_ops dt_root_ops = {
    .dto_emit = dt_root_emit_handler,
};

static struct dt_tree hse_dt_tree _dt_section = {
    .dt_lock = { PTHREAD_MUTEX_INITIALIZER },
    .dt_pending_lock = { PTHREAD_MUTEX_INITIALIZER },
    .dt_pending_list = {
        .prev = &hse_dt_tree.dt_pending_list,
        .next = &hse_dt_tree.dt_pending_list,
    },
    .dt_element = {
        .dte_ops = &dt_root_ops,
        .dte_type = DT_TYPE_ROOT,
        .dte_file = __FILE__,
        .dte_line = __LINE__,
        .dte_path = DT_PATH_ROOT,
    },
};

static HSE_ALWAYS_INLINE void
dt_lock(struct dt_tree *tree)
{
    mutex_lock(&tree->dt_lock);
}

static HSE_ALWAYS_INLINE void
dt_unlock(struct dt_tree *tree)
{
    mutex_unlock(&tree->dt_lock);
}

static size_t
dt_root_emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    /* For some reason we require the user to supply the data tree root
     * path when making queries, yet we never emit it...
     */
#if 0
    yaml_start_element_type(yc, DT_PATH_ROOT + 1);
    return 1;
#else
    return 0;
#endif
}

/**
 * dt_build_pathname() - Build up pathname one step at a time
 * @string:    The original, full path
 * @saveptr:   A char ** used to keep track of where we are in path
 *
 * dt_build_pathname takes a path and iteratively returns subsets
 * of that path. It is used to find all of the tree elements
 * from / to the full pathname.
 *
 * E.g. starting with this path: /abc/def/ghi/jkl/mno
 *
 * dt_build_pathname will return successively:
 * /abc
 * /abc/def
 * /abc/def/ghi
 * /abc/def/ghi/jkl
 * /abc/def/ghi/jkl/mno
 *
 * Note, dt_build_pathname modifies both arguments.
 *
 * Return: Pointer to the composed string.
 */

static char *
dt_build_pathname(char *string, char **saveptr)
{
    char *ret;

    if (*saveptr == NULL) {
        /* This is the first pass of this path */
        *saveptr = string;
    } else {
        /* This is a follow-on pass of this path */
        **saveptr = '/';
    }

    ret = *saveptr + 1;
    while (ret && *ret && (*ret != '/')) {
        /* loop until we hit the next '/' */
        ret++;
    }
    if (ret && *ret == '/') {
        *ret = 0;
        *saveptr = ret;
    } else {
        /* we're done */
        *saveptr = NULL;
    }
    return string;
}

/* Caller must hold dt_lock.
 */
static int
dt_add_pending_dte(struct dt_tree *tree, struct dt_element *dte)
{
    struct rb_node **new, *parent = NULL;
    struct rb_root *root;

    assert(dte->dte_type != DT_TYPE_INVALID);

    root = &tree->dt_root;
    new = &root->rb_node;

    while (*new) {
        struct dt_element *this = container_of(*new, typeof(*this), dte_node);
        int result;

        result = (dte == this) ? 0 : strcmp(dte->dte_path, this->dte_path);
        parent = *new;

        if (result < 0)
            new = &(*new)->rb_left;
        else if (result > 0)
            new = &(*new)->rb_right;
        else
            return EEXIST;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&dte->dte_node, parent, new);
    rb_insert_color(&dte->dte_node, root);

    /* This ev() serves to prove that we can add a new event
     * counter whilst holding the dt lock.
     */
    ev_info(1);

    return 0;
}

/* Caller must hold dt_lock.
 */
static void
dt_add_pending(struct dt_tree *tree)
{
    struct dt_element *dte;
    struct list_head list;
    int rc;

    INIT_LIST_HEAD(&list);

    mutex_lock(&tree->dt_pending_lock);
    list_splice(&tree->dt_pending_list, &list);
    INIT_LIST_HEAD(&tree->dt_pending_list);
    mutex_unlock(&tree->dt_pending_lock);

    while (!list_empty(&list)) {
        dte = list_first_entry(&list, typeof(*dte), dte_list);
        list_del(&dte->dte_list);

        rc = dt_add_pending_dte(tree, dte);

        /* Failure to add likely means that the caller tried to
         * install mulitple counters with identical paths.  This
         * shouldn't happen outside development of new counters.
         */
        assert(rc == 0);
        ev_warn(rc);
    }
}

int
dt_add(struct dt_element *dte)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *item;
    int rc = 0;

    if (!dte || !dte->dte_ops)
        return EINVAL;

    assert(dte->dte_type != DT_TYPE_INVALID);

    /* Check the pending list to protect against broken or malicious
     * callers trying to add the same dte more than once.  There is
     * still a case where the new dte is in the active rb tree so
     * async attempts by dt_add_pending() to insert it will fail.
     * In this case we assert if assert is enabled, otherwise we
     * we simply record the event with an event counter.
     */
    mutex_lock(&tree->dt_pending_lock);
    list_for_each_entry(item, &tree->dt_pending_list, dte_list) {
        if (item == dte || 0 == strcmp(item->dte_path, dte->dte_path)) {
            rc = EEXIST;
            break;
        }
    }

    if (!rc)
        list_add(&dte->dte_list, &tree->dt_pending_list);
    mutex_unlock(&tree->dt_pending_lock);

    return rc;
}

static int
dt_remove_locked(struct dt_tree *tree, struct dt_element *dte, int force)
{
    if (dte->dte_ops->dto_remove || force)
        rb_erase(&dte->dte_node, &tree->dt_root);

    if (!dte->dte_ops->dto_remove)
        return EACCES;

    /* Invoke the remove handler for cleanup of the
     * data tree and data object structures.
     */
    dte->dte_ops->dto_remove(dte);

    return 0;
}

int
dt_remove(struct dt_element *dte)
{
    struct dt_tree *tree = &hse_dt_tree;
    int ret;

    dt_lock(tree);
    dt_add_pending(tree);

    ret = dt_remove_locked(tree, dte, 0);
    dt_unlock(tree);

    return ret;
}

/* Assumes that dt_lock is held */
static struct dt_element *
dt_find_locked(struct dt_tree *tree, const char *path, int exact)
{
    struct rb_root *   root;
    struct rb_node *   node;
    struct dt_element *dte = NULL;
    struct dt_element *last_valid = NULL;
    int                result;
    int                prev = 0;
    int                pathlen;

    dt_add_pending(tree);

    root = &tree->dt_root;
    node = root->rb_node;

    pathlen = strnlen(path, DT_PATH_MAX);
    if (pathlen >= DT_PATH_MAX)
        return NULL;

    while (node) {
        dte = container_of(node, struct dt_element, dte_node);

        result = strcmp(path, dte->dte_path);

        if (!strncmp(path, dte->dte_path, pathlen)) {
            /* Keep this one in case the next is off our path */
            last_valid = dte;
        }

        if (result < 0) {
            if ((prev > 0) && (exact == 0) && (!node->rb_left)) {
                dte = NULL;
                goto out;
            }
            node = node->rb_left;
        } else if (result > 0) {
            if ((prev < 0) && (exact == 0) && (!node->rb_right)) {
                dte = NULL;
                goto out;
            }
            node = node->rb_right;
        } else {
            /* found it exactly */
            goto out;
        }
        prev = result;
        dte = NULL;
    }

  out:
    if ((exact == 0) && (dte == NULL)) {
        /* We've passed what we were looking for */
        dte = last_valid;
    }
    return dte;
}

struct dt_element *
dt_find(const char *path, int exact)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *ret;

    dt_lock(tree);
    ret = dt_find_locked(tree, path, exact);
    dt_unlock(tree);

    return ret;
}

int
dt_remove_by_name(char *path)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *dte;
    int                ret = 0;

    dt_lock(tree);
    dte = dt_find_locked(tree, path, 1);
    if (dte)
        ret = dt_remove_locked(tree, dte, 1);
    dt_unlock(tree);

    return ret;
}

int
dt_remove_recursive(char *path)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *dte;
    struct rb_node *   node;
    int                ret = 0;
    int                pathlen;

    pathlen = strnlen(path, DT_PATH_MAX);
    if (pathlen >= DT_PATH_MAX)
        return ENAMETOOLONG;

    dt_lock(tree);
    dte = dt_find_locked(tree, path, 0);
    while (dte) {
        node = rb_next(&dte->dte_node);
        ret = dt_remove_locked(tree, dte, 1);

        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, pathlen)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
        }
    }
    dt_unlock(tree);

    return ret;
}

void
dt_init(void)
{
    struct dt_tree *tree = &hse_dt_tree;

    dt_add(&tree->dt_element);
}

void
dt_fini(void)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *dte;
    struct rb_root *root;

    dt_lock(tree);
    dt_add_pending(tree);

    root = &tree->dt_root;

    while (root->rb_node) {
        dte = container_of(root->rb_node, typeof(*dte), dte_node);
        dt_remove_locked(tree, dte, 1);
    }

    dt_unlock(tree);
}

/* Assumes dt_lock is held */
static size_t
emit_roots_upto(struct dt_tree *tree, const char *path, struct yaml_context *yc)
{
    size_t count = 0;
    char my_path[DT_PATH_MAX];
    char *saveptr = NULL;
    int pathlen;

    pathlen = strlcpy(my_path, path, DT_PATH_MAX);
    if (pathlen >= sizeof(my_path))
        return 0;

    while (1) {
        struct dt_element *dte;
        char *ptr;

        ptr = dt_build_pathname(my_path, &saveptr);
        if (strlen(ptr) >= pathlen) {
            /* stop _before_ eating the whole path,
             * the normal iterator will take it from here */
            break;
        }

        dte = dt_find_locked(tree, ptr, 1);
        if (dte && (dte->dte_type == DT_TYPE_ROOT) && dte->dte_ops->dto_emit) {
            count += dte->dte_ops->dto_emit(dte, yc);
        }
    }

    return count;
}

size_t
dt_iterate_cmd(
    int                          op,
    const char *                 path,
    union dt_iterate_parameters *dip,
    dt_selector_t *              selector,
    char *                       selector_field,
    char *                       selector_value)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *dte;
    size_t count = 0;
    int pathlen;

    pathlen = strnlen(path, DT_PATH_MAX);
    if (pathlen >= DT_PATH_MAX)
        return 0;

    if (DT_OP_EMIT == op && (!dip || !dip->yc))
        return 0;

    if (DT_OP_SET == op && (!dip || !dip->dsp))
        return 0;

    dt_lock(tree);
    dt_add_pending(tree);

    if (DT_OP_EMIT == op) {
        /* Emit root nodes up to this path */
        count = emit_roots_upto(tree, path, dip->yc);
    }

    dte = dt_find_locked(tree, path, 0);
    while (dte) {
        struct dt_element_ops *ops = dte->dte_ops;
        struct rb_node *node;

        switch (op) {
        case DT_OP_EMIT:
            if (!ops->dto_emit)
                break;

            if ((selector && selector(dte)) ||
                (selector_field && selector_value && ops->dto_match_selector &&
                 ops->dto_match_selector(dte, selector_field, selector_value)) ||
                (!selector_field && !selector)) {

                count += ops->dto_emit(dte, dip->yc);
            }
            break;

        case DT_OP_SET:
            if (!ops->dto_set)
                break;

            if ((selector && selector(dte)) || !selector) {
                count += ops->dto_set(dte, dip->dsp);
            }
            break;

        case DT_OP_COUNT:
            if ((selector && selector(dte)) ||
                (selector_field && selector_value && ops->dto_match_selector &&
                 ops->dto_match_selector(dte, selector_field, selector_value)) ||
                (!selector_field && !selector)) {

                ++count;
            }
            break;

        default:
            break;
        }

        node = rb_next(&dte->dte_node);
        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, pathlen)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
        }
    }
    dt_unlock(tree);

    return count;
}

struct dt_element *
dt_iterate_next(const char *path, struct dt_element *previous)
{
    struct dt_tree *tree = &hse_dt_tree;
    struct dt_element *dte;
    struct rb_node *   node;
    int                pathlen;

    pathlen = strnlen(path, DT_PATH_MAX);
    if (pathlen >= DT_PATH_MAX)
        return NULL;

    dt_lock(tree);
    if (previous == NULL) {
        dte = dt_find_locked(tree, path, 0);
        dt_unlock(tree);
        return dte;
    }

    dt_add_pending(tree);

    dte = previous;
    if (dte) {
        node = rb_next(&dte->dte_node);
        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, pathlen)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            dte = NULL;
        }
    }
    dt_unlock(tree);

    return dte;
}

static struct field_name dt_field_names[] = {
    { "od_timestamp", DT_FIELD_ODOMETER_TIMESTAMP },
    { "odometer_timestamp", DT_FIELD_ODOMETER_TIMESTAMP },
    { "odt", DT_FIELD_ODOMETER_TIMESTAMP },
    { "od", DT_FIELD_ODOMETER },
    { "odometer", DT_FIELD_ODOMETER },
    { "trip_od_timestamp", DT_FIELD_TRIP_ODOMETER_TIMESTAMP },
    { "trip_odometer_timestamp", DT_FIELD_TRIP_ODOMETER_TIMESTAMP },
    { "todt", DT_FIELD_TRIP_ODOMETER_TIMESTAMP },
    { "trip_od", DT_FIELD_TRIP_ODOMETER },
    { "trip_odometer", DT_FIELD_TRIP_ODOMETER },
    { "tod", DT_FIELD_TRIP_ODOMETER },
    { "priority", DT_FIELD_PRIORITY },
    { "pri", DT_FIELD_PRIORITY },
    { "flags", DT_FIELD_FLAGS },
    { "enabled", DT_FIELD_ENABLED },
    { "clear", DT_FIELD_CLEAR },
    { "data", DT_FIELD_DATA },
    { "invalidate", DT_FIELD_INVALIDATE_HANDLE },
    { NULL, DT_FIELD_INVALID }
};

dt_field_t
dt_get_field(const char *field)
{
    struct field_name *fn;

    for (fn = dt_field_names; fn->field_name; ++fn) {
        if (!strcmp(fn->field_name, field))
            break;
    }

    return fn->field_val;
}

#if HSE_MOCKING
#define DT_TREE_EMIT_BUFSZ (16 * 1024)
static char dt_tree_emit_buf[DT_TREE_EMIT_BUFSZ];

void
dt_tree_emit_path(char *path)
{
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };

    yc.yaml_buf = dt_tree_emit_buf;
    yc.yaml_buf_sz = sizeof(dt_tree_emit_buf);
    yc.yaml_emit = NULL;

    (void)dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
    fprintf(stderr, "%s", dt_tree_emit_buf);
}

void
dt_tree_emit_pathbuf(char *path, char *buf, u32 buflen)
{
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };

    yc.yaml_buf = buf;
    yc.yaml_buf_sz = buflen;
    yc.yaml_emit = NULL;

    (void)dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
}

void
dt_tree_emit(void)
{
    dt_tree_emit_path(DT_PATH_ROOT);
}

void
dt_tree_log_path(char *path, int log_level)
{
    union dt_iterate_parameters dip = {.log_level = log_level };

    (void)dt_iterate_cmd(DT_OP_LOG, path, &dip, NULL, NULL, NULL);
}

void
dt_tree_log(void)
{
    dt_tree_log_path(DT_PATH_ROOT, HSE_INFO_VAL);
}
#endif
