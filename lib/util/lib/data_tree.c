/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <errno.h>
#include <rbtree.h>
#include <stdarg.h>
#include <stdio.h>

#include <bsd/string.h>

#include <hse/util/alloc.h>
#include <hse/util/assert.h>
#include <hse/util/data_tree.h>
#include <hse/util/event_counter.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/util/platform.h>
#include <hse/util/slab.h>

/* clang-format off */

struct dt_tree {
    struct mutex dt_lock HSE_ACP_ALIGNED;
    struct rb_root dt_root;

    struct mutex dt_pending_lock HSE_L1X_ALIGNED;
    struct list_head dt_pending_list;

    struct dt_element dt_element HSE_L1D_ALIGNED;
};

/* clang-format on */

static size_t
dt_root_emit_handler(struct dt_element *, cJSON *);

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
        .dte_file = REL_FILE(__FILE__),
        .dte_line = __LINE__,
        .dte_path = DT_PATH_ROOT,
    },
};

static HSE_ALWAYS_INLINE void
dt_lock(void)
{
    mutex_lock(&hse_dt_tree.dt_lock);
}

static HSE_ALWAYS_INLINE void
dt_unlock(void)
{
    mutex_unlock(&hse_dt_tree.dt_lock);
}

static size_t
dt_root_emit_handler(struct dt_element *dte, cJSON *root)
{
    /* TODO: For some reason we require the user to supply the data tree root
     * path when making queries, yet we never emit it...
     */
#if 0
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
dt_add_pending(void)
{
    int rc;
    struct dt_element *dte;
    struct list_head list;

    INIT_LIST_HEAD(&list);

    mutex_lock(&hse_dt_tree.dt_pending_lock);
    list_splice(&hse_dt_tree.dt_pending_list, &list);
    INIT_LIST_HEAD(&hse_dt_tree.dt_pending_list);
    mutex_unlock(&hse_dt_tree.dt_pending_lock);

    while (!list_empty(&list)) {
        dte = list_first_entry(&list, typeof(*dte), dte_list);
        list_del(&dte->dte_list);

        rc = dt_add_pending_dte(&hse_dt_tree, dte);

        /* Failure to add likely means that the caller tried to install mulitple
         * elements with identical paths. This shouldn't happen outside
         * development of new elements.
         */
        assert(rc == 0);
        ev_warn(rc);
    }
}

merr_t
dt_add(struct dt_element * const dte)
{
    merr_t err = 0;
    struct dt_element *item;

    if (!dte || !dte->dte_ops)
        return merr(EINVAL);

    if (strlen(dte->dte_path) >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    mutex_lock(&hse_dt_tree.dt_pending_lock);

    /* Check the pending list to protect against broken or malicious callers
     * trying to add the same dte more than once.
     */
    list_for_each_entry(item, &hse_dt_tree.dt_pending_list, dte_list) {
        if (item == dte || 0 == strcmp(item->dte_path, dte->dte_path)) {
            err = merr(EEXIST);
            break;
        }
    }

    if (!err)
        list_add(&dte->dte_list, &hse_dt_tree.dt_pending_list);

    mutex_unlock(&hse_dt_tree.dt_pending_lock);

    return err;
}

/* Caller must hold tree lock. */
static merr_t
dt_remove_impl(struct dt_element * const dte, const bool force)
{
    if (dte->dte_ops->dto_remove || force)
        rb_erase(&dte->dte_node, &hse_dt_tree.dt_root);

    if (!dte->dte_ops->dto_remove)
        return merr(EACCES);

    /* Invoke the remove handler for cleanup of the
     * data tree and data object structures.
     */
    dte->dte_ops->dto_remove(dte);

    return 0;
}

/* Assumes that dt_lock is held */
static struct dt_element *
dt_find(const char * const path, const size_t path_len, const bool exact)
{
    struct rb_root *root;
    struct rb_node *node;
    struct dt_element *dte = NULL;
    struct dt_element *last_valid = NULL;
    int result;
    int prev = 0;

    dt_add_pending();

    root = &hse_dt_tree.dt_root;
    node = root->rb_node;

    while (node) {
        dte = container_of(node, struct dt_element, dte_node);

        result = strcmp(path, dte->dte_path);

        if (!strncmp(path, dte->dte_path, path_len)) {
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

void
dt_init(void)
{
    dt_add(&hse_dt_tree.dt_element);
}

void
dt_fini(void)
{
    struct dt_element *dte;
    struct rb_root *root;

    dt_lock();
    dt_add_pending();

    root = &hse_dt_tree.dt_root;

    while (root->rb_node) {
        dte = container_of(root->rb_node, typeof(*dte), dte_node);
        dt_remove_impl(dte, true);
    }

    dt_unlock();
}

merr_t
dt_access(const char * const path, dt_access_t access, void * const ctx)
{
    merr_t err = 0;
    size_t path_len;
    struct dt_element *dte;

    if (!path)
        return merr(EINVAL);

    path_len = strlen(path);
    if (path_len >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    dt_lock();

    dte = dt_find(path, path_len, 1);
    if (!dte) {
        err = merr(ENOENT);
        goto out;
    }

    if (access)
        err = access(dte->dte_data, ctx);

out:
    dt_unlock();

    return err;
}

unsigned int
dt_count(const char * const path)
{
    size_t path_len;
    unsigned int count = 0;
    struct dt_element *dte;

    if (!path)
        return merr(EINVAL);

    path_len = strlen(path);
    if (path_len >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    dt_lock();

    dte = dt_find(path, path_len, false);
    while (dte) {
        struct rb_node *node;

        count++;

        node = rb_next(&dte->dte_node);
        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, path_len)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
        }
    }

    dt_unlock();

    return count;
}

/* Assumes data tree lock is held */
static merr_t
emit_roots_upto(const char * const path, cJSON * const root)
{
    merr_t err = 0;
    size_t path_len;
    char *saveptr = NULL;
    char my_path[DT_PATH_MAX];

    path_len = strlcpy(my_path, path, sizeof(my_path));
    if (path_len >= sizeof(my_path))
        return 0;

    while (1) {
        char *ptr;
        size_t ptr_len;
        struct dt_element *dte;

        ptr = dt_build_pathname(my_path, &saveptr);
        ptr_len = strlen(ptr);
        if (ptr_len >= path_len) {
            /* stop _before_ eating the whole path,
             * the normal iterator will take it from here */
            break;
        }

        dte = dt_find(ptr, ptr_len, true);
        if (dte && dte->dte_ops->dto_emit) {
            err = dte->dte_ops->dto_emit(dte, root);
            if (err)
                break;
        }
    }

    return err;
}

merr_t
dt_emit(const char * const path, cJSON ** const root)
{
    merr_t err;
    cJSON *tmp;
    size_t path_len;
    struct dt_element *dte;

    if (!path || !root)
        return merr(EINVAL);

    *root = NULL;

    if (!path)
        return merr(EINVAL);

    path_len = strlen(path);
    if (path_len >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    tmp = cJSON_CreateArray();
    if (ev(!tmp))
        return merr(ENOMEM);

    dt_lock();

    err = emit_roots_upto(path, tmp);
    if (ev(err))
        goto out;

    dte = dt_find(path, path_len, false);
    while (dte) {
        struct rb_node *node;

        if (dte->dte_ops->dto_emit) {
            err = dte->dte_ops->dto_emit(dte, tmp);
            if (err)
                goto out;
        }

        node = rb_next(&dte->dte_node);
        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, path_len)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
        }
    }

out:
    dt_unlock();

    if (err) {
        cJSON_Delete(tmp);
    } else {
        *root = tmp;
    }

    return err;
}

merr_t
dt_remove(const char * const path)
{
    merr_t err = 0;
    size_t path_len;
    struct dt_element *dte;

    if (!path)
        return merr(EINVAL);

    path_len = strlen(path);
    if (path_len >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    dt_lock();

    dte = dt_find(path, path_len, true);
    if (!dte) {
        err = merr(ENOENT);
    } else {
        err = dt_remove_impl(dte, false);
    }

    dt_unlock();

    return err;
}

merr_t
dt_remove_recursive(const char * const path)
{
    merr_t err = 0;
    size_t path_len;
    struct dt_element *dte;

    if (!path)
        return merr(EINVAL);

    path_len = strlen(path);
    if (path_len >= DT_PATH_MAX)
        return merr(ENAMETOOLONG);

    dt_lock();

    dte = dt_find(path, path_len, false);
    while (dte) {
        struct rb_node *node;

        node = rb_next(&dte->dte_node);
        err = dt_remove_impl(dte, true);

        dte = container_of(node, struct dt_element, dte_node);
        if (dte && strncmp(path, dte->dte_path, path_len)) {
            /* We've hit the first thing that doesn't include
             * the search path. That means we're done. */
            break;
        }
    }

    dt_unlock();

    return err;
}
