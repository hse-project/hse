/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/spinlock.h>
#include <hse_util/list.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/config.h>
#include <hse_util/data_tree.h>

#include <rbtree/rbtree.h>

struct dt_tree {
    spinlock_t          dt_lock;
    struct rb_root      dt_root;
    spinlock_t          dt_pending_lock;
    struct list_head    dt_pending_list;

    HSE_ALIGNED(SMP_CACHE_BYTES)
    struct dt_element   dt_element;
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

struct dt_tree *dt_data_tree HSE_READ_MOSTLY;


static HSE_ALWAYS_INLINE void
dt_lock(struct dt_tree *tree)
{
    spin_lock(&tree->dt_lock);
}

static HSE_ALWAYS_INLINE void
dt_unlock(struct dt_tree *tree)
{
    spin_unlock(&tree->dt_lock);
}

static size_t
root_emit_handler(struct dt_element *me, struct yaml_context *yc)
{
    return 1;
}

static size_t
root_count_handler(struct dt_element *element)
{
    return 1;
}

static struct dt_element_ops dt_root_ops = {
    .emit = root_emit_handler,
    .count = root_count_handler,
};

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
            return -EEXIST;
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&dte->dte_node, parent, new);
    rb_insert_color(&dte->dte_node, root);
    dte->dte_flags |= DT_FLAGS_IN_TREE;

    /* This ev() serves to prove that we can add a new event
     * counter whilst holding the dt spinlock.
     */
    ev(1);

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

    spin_lock(&tree->dt_pending_lock);
    list_splice(&tree->dt_pending_list, &list);
    INIT_LIST_HEAD(&tree->dt_pending_list);
    spin_unlock(&tree->dt_pending_lock);

    while (!list_empty(&list)) {
        dte = list_first_entry(&list, typeof(*dte), dte_list);
        list_del(&dte->dte_list);

        rc = dt_add_pending_dte(tree, dte);

        if (ev(rc) && dte->dte_ops && dte->dte_ops->remove)
            dte->dte_ops->remove(dte);
    }
}

int
dt_add(struct dt_tree *tree, struct dt_element *dte)
{
    struct dt_element *item;
    int rc = 0;

    if (!tree || !dte)
        return -EINVAL;

    assert(dte->dte_type != DT_TYPE_INVALID);

    /* Check the pending list to protect against broken or malicious
     * callers trying to add the same dte more than once.  There is
     * still a case where the new dte is already in the rb tree, and
     * attempts to insert it will fail, but caller will be notified
     * only asynchronously via the remove() callback.
     */
    spin_lock(&tree->dt_pending_lock);
    list_for_each_entry(item, &tree->dt_pending_list, dte_list) {
        if (item == dte || 0 == strcmp(item->dte_path, dte->dte_path)) {
            rc = -EEXIST;
            break;
        }
    }

    if (!rc)
        list_add_tail(&dte->dte_list, &tree->dt_pending_list);
    spin_unlock(&tree->dt_pending_lock);

    return rc;
}

static int
dt_remove_locked(struct dt_tree *tree, struct dt_element *dte, int force)
{
    if ((force == 0) && (dte->dte_flags & DT_FLAGS_NON_REMOVEABLE)) {
        /* NON_REMOVEABLE flag is used to prevent deletion
         * of debug elements such as Error Counters.
         */
        return -EACCES;
    }

    rb_erase(&dte->dte_node, &tree->dt_root);

    if (dte->dte_ops && dte->dte_ops->remove) {
        /* Invoke the remove handler for cleanup of the
         * data tree and data object structures.
         */
        dte->dte_ops->remove(dte);
    }
    return 0;
}

int
dt_remove(struct dt_tree *tree, struct dt_element *dte)
{
    int ret;

    dt_lock(tree);
    dt_add_pending(tree);

    ret = dt_remove_locked(tree, dte, 0);
    dt_unlock(tree);

    return ret;
}

/* Assumes that dt_lock is held */
struct dt_element *
dt_find_locked(struct dt_tree *tree, const char *path, int exact)
{
    struct rb_root *   root;
    struct rb_node *   node;
    struct dt_element *dte = NULL;
    struct dt_element *last_valid = NULL;
    int                result;
    int                prev = 0;
    int                pathlen;

    if (tree == NULL)
        return NULL;

    dt_add_pending(tree);

    root = &tree->dt_root;
    node = root->rb_node;

    pathlen = strnlen(path, DT_PATH_LEN);
    if (pathlen >= DT_PATH_LEN)
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
dt_find(struct dt_tree *tree, const char *path, int exact)
{
    struct dt_element *ret;

    dt_lock(tree);
    ret = dt_find_locked(tree, path, exact);
    dt_unlock(tree);

    return ret;
}

int
dt_remove_by_name(struct dt_tree *tree, char *path)
{
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
dt_remove_recursive(struct dt_tree *tree, char *path)
{
    struct dt_element *dte;
    struct rb_node *   node;
    int                ret = 0;
    int                pathlen = strnlen(path, DT_PATH_LEN);

    if (pathlen >= DT_PATH_LEN)
        return -ENAMETOOLONG;

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

struct dt_tree_list_entry {
    struct list_head dt_tree_list;
    struct dt_tree * tree;
    char             name[DT_PATH_LEN];
};

struct list_head  dt_tree_list;
static spinlock_t dt_tree_list_lock; /* It is assumed that this spinlock */
                                     /* is NOT taken in interrupt context*/

static void
dttl_lock(void)
{
    spin_lock(&dt_tree_list_lock);
}

static void
dttl_unlock(void)
{
    spin_unlock(&dt_tree_list_lock);
}

static void
get_first_path_element(const char *original_path, char *new_path)
{
    const char *op = original_path;
    char *      np = new_path;

    if (op && np && *op && (*op == '/'))
        *np++ = *op++;

    while (op && np && *op && (*op != '/'))
        *np++ = *op++;

    *np = '\0';
}

static int
dt_register_tree(char *path, struct dt_tree *tree)
{
    struct dt_tree_list_entry *entry, *next, *entry_alloc;
    char                       name[DT_PATH_LEN];

    /* We only need the first part of the path */
    get_first_path_element(path, name);

    /* Didn't find it, so add it */
    entry_alloc = calloc(1, sizeof(*entry));
    if (entry_alloc == NULL)
        return -ENOMEM;

    dttl_lock();

    list_for_each_entry_safe (entry, next, &dt_tree_list, dt_tree_list) {
        if (!strcmp(name, entry->name)) {
            free(entry_alloc);
            dttl_unlock();
            return 0;
        }
    }

    entry = entry_alloc;
    strlcpy(entry->name, name, sizeof(entry->name));
    entry->tree = tree;
    list_add(&entry->dt_tree_list, &dt_tree_list);

    dttl_unlock();

    return 0;
}

static void
dt_unregister_tree(struct dt_tree *tree)
{
    struct dt_tree_list_entry *entry, *next;

    dttl_lock();
    list_for_each_entry_safe (entry, next, &dt_tree_list, dt_tree_list) {
        if (entry->tree == tree) {
            list_del_init(&entry->dt_tree_list);
            free(entry);
            break;
        }
    }
    dttl_unlock();
}

struct dt_tree *
dt_get_tree(char *path)
{
    struct dt_tree_list_entry *entry;
    char                       name[DT_PATH_LEN];
    struct dt_tree *           tree;

    /* We only need the first part of the path */
    get_first_path_element(path, name);
    tree = NULL;

    dttl_lock();
    list_for_each_entry (entry, &dt_tree_list, dt_tree_list) {
        if (!strcmp(name, entry->name)) {
            tree = entry->tree;
            break;
        }
    }
    dttl_unlock();

    return tree;
}

struct dt_tree *
dt_create(const char *name)
{
    struct dt_element  *element;
    struct dt_tree     *tree;

    if (strnlen(name, DT_PATH_ELEMENT_LEN) >= DT_PATH_ELEMENT_LEN)
        return NULL;

    tree = alloc_aligned(sizeof(*tree), _Alignof(*tree));
    if (ev(!tree))
        return NULL;

    memset(tree, 0, sizeof(*tree));
    spin_lock_init(&tree->dt_lock);
    spin_lock_init(&tree->dt_pending_lock);
    INIT_LIST_HEAD(&tree->dt_pending_list);

    element = &tree->dt_element;
    snprintf(element->dte_path, sizeof(element->dte_path), "/%s", name);
    element->dte_ops = &dt_root_ops;
    element->dte_type = DT_TYPE_ROOT;
    dt_register_tree(element->dte_path, tree);
    dt_add(tree, element);

    return tree;
}

void
dt_destroy(struct dt_tree *tree)
{
    struct rb_root     *root;
    struct dt_element  *dte;

    dt_lock(tree);
    dt_add_pending(tree);

    root = &tree->dt_root;

    while (root->rb_node) {
        dte = container_of(root->rb_node, typeof(*dte), dte_node);
        dt_remove_locked(tree, dte, 1);
    }

    dt_unregister_tree(tree);
    dt_unlock(tree);

    free_aligned(tree);
}

void
dt_init(void)
{
    if (dt_data_tree) {
        assert(!dt_data_tree);
        return;
    }

    /* This tree is shared by Error Counters, Traces,
     * Performance Counters, and Component Info.
     */
    spin_lock_init(&dt_tree_list_lock);
    INIT_LIST_HEAD(&dt_tree_list);
    dt_data_tree = dt_create("data");
    event_counter_init();
    config_init();
}

void
dt_fini(void)
{
    if (!dt_data_tree) {
        assert(dt_data_tree);
        return;
    }

    dt_destroy(dt_data_tree);
    dt_data_tree = NULL;
}

/* Assumes dt_lock is held */
static size_t
emit_roots_upto(struct dt_tree *tree, const char *path, struct yaml_context *yc)
{
    size_t             count = 0;
    char               my_path[DT_PATH_LEN];
    char *             ptr, *saveptr = NULL;
    struct dt_element *dte;
    int                pathlen = strnlen(path, DT_PATH_LEN);

    if (pathlen >= DT_PATH_LEN)
        return 0;

    strlcpy(my_path, path, DT_PATH_LEN);

    do {
        ptr = dt_build_pathname(my_path, &saveptr);
        if (strlen(ptr) == pathlen) {
            /* stop _before_ eating the whole path,
             * the normal iterator will take it from here */
            break;
        }
        dte = dt_find_locked(tree, ptr, 1);
        if (dte && (dte->dte_type == DT_TYPE_ROOT) && dte->dte_ops && dte->dte_ops->emit) {
            count += dte->dte_ops->emit(dte, yc);
        }
    } while (strlen(ptr) < pathlen);
    return count;
}

size_t
dt_iterate_cmd(
    struct dt_tree *             tree,
    int                          op,
    const char *                 path,
    union dt_iterate_parameters *dip,
    dt_selector_t *              selector,
    char *                       selector_field,
    char *                       selector_value)
{
    size_t                    count = 0;
    int                       pathlen;
    struct dt_element *       dte;
    struct rb_node *          node;
    struct yaml_context *     yc;
    struct dt_set_parameters *dsp;

    pathlen = strnlen(path, DT_PATH_LEN);
    if (pathlen >= DT_PATH_LEN)
        return 0;

    dt_lock(tree);
    dt_add_pending(tree);

    if (DT_OP_EMIT == op) {
        if ((dip == NULL) || (dip->yc == NULL)) {
            dt_unlock(tree);
            return 0;
        }
        yc = dip->yc;
        /* Emit root nodes up to this path */
        count = emit_roots_upto(tree, path, yc);
    }

    dte = dt_find_locked(tree, path, 0);
    while (dte) {
        switch (op) {
            case DT_OP_EMIT:
                if (dte->dte_ops->emit &&
                    (((selector != NULL) && selector(dte)) ||
                     (selector_field != NULL && (selector_value != NULL) &&
                      (dte->dte_ops->match_selector != NULL) &&
                      dte->dte_ops->match_selector(dte, selector_field, selector_value)) ||
                     (selector_field == NULL && selector == NULL))) {

                    yc = dip->yc;
                    count += dte->dte_ops->emit(dte, yc);
                }
                break;

            case DT_OP_LOG:
                if (dte->dte_ops->log &&
                    ((selector != NULL && selector(dte)) || selector == NULL)) {

                    count += dte->dte_ops->log(dte, dip->log_level);
                }
                break;

            case DT_OP_SET:
                if (dte->dte_ops->set &&
                    ((selector != NULL && selector(dte)) || selector == NULL)) {

                    if (dip == NULL || dip->dsp == NULL)
                        return 0;

                    dsp = dip->dsp;
                    count += dte->dte_ops->set(dte, dsp);
                }
                break;

            case DT_OP_COUNT:
                if (dte->dte_ops->count &&
                    ((selector != NULL && selector(dte)) ||
                     (selector_field != NULL && selector_value != NULL &&
                      dte->dte_ops->match_selector != NULL &&
                      dte->dte_ops->match_selector(dte, selector_field, selector_value)) ||
                     (selector_field == NULL && selector == NULL))) {

                    count += dte->dte_ops->count(dte);
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
dt_iterate_next(struct dt_tree *tree, const char *path, struct dt_element *previous)
{
    struct dt_element *dte;
    struct rb_node *   node;
    int                pathlen;

    pathlen = strnlen(path, DT_PATH_LEN);
    if (pathlen >= DT_PATH_LEN)
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

    (void)dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
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

    (void)dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
}

void
dt_tree_emit(void)
{
    dt_tree_emit_path("/data");
}

void
dt_tree_log_path(char *path, int log_level)
{
    union dt_iterate_parameters dip = {.log_level = log_level };

    (void)dt_iterate_cmd(dt_data_tree, DT_OP_LOG, path, &dip, NULL, NULL, NULL);
}

void
dt_tree_log(void)
{
    dt_tree_log_path("/data", HSE_INFO_VAL);
}

struct field_name field_names[] = { { "od_timestamp", DT_FIELD_ODOMETER_TIMESTAMP },
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
                                    { NULL, DT_FIELD_INVALID } };

dt_field_t
dt_get_field(const char *field)
{
    int i = 0;

    while (field_names[i].field_name != NULL) {
        if (!strcmp(field_names[i].field_name, field))
            break;
        i++;
    }
    return field_names[i].field_val;
}
