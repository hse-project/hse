/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_UTIL_DATA_TREE_H
#define HSE_UTIL_DATA_TREE_H

#include <stdbool.h>

#include <cjson/cJSON.h>
#include <rbtree.h>

#include <hse/error/merr.h>

#include <hse/util/compiler.h>
#include <hse/util/list.h>

/* clang-format on */

/* DT_PATH_MAX restricts the path size of a statically allocated dt_element to
 * avoid wasting too much space.
 */
#define DT_PATH_ELEMENT_MAX       (32)
#define DTE_PATH_OFFSET           (72)
#define DT_PATH_MAX               (192 - DTE_PATH_OFFSET)
#define DT_PATH_ROOT              "/data"

#define _dt_section               __attribute__((section("hse_dt")))

struct dt_element {
    union {
        struct rb_node      dte_node;
        struct list_head    dte_list;
    };
    struct dt_element_ops  *dte_ops;
    void                   *dte_data;
    const char             *dte_file;
    int                     dte_line;
    const char             *dte_func;
    char                    dte_path[DT_PATH_MAX]; /* whole path */
} HSE_ALIGNED(64);

static_assert(offsetof(struct dt_element, dte_path) == DTE_PATH_OFFSET,
              "invalid pre-computed dte_path offset");

/* clang-format on */

typedef void dt_remove_handler_t(struct dt_element *);
typedef merr_t dt_emit_handler_t(struct dt_element *, cJSON *);
typedef merr_t dt_access_t(void *, void *);

struct dt_element_ops {
    dt_remove_handler_t *dto_remove;
    dt_emit_handler_t   *dto_emit;
};

/* Data Tree's Interface */

/** @brief Initialize the data tree.
 */
void
dt_init(void) HSE_COLD;

/** @brief Finalize data tree resources including removing all elements.
 */
void
dt_fini(void) HSE_COLD;

/** @brief Add a pre-allocated and pre-initialized element to the data tree.
 *
 * @param dte Data tree element.
 *
 * @returns Error status.
 * @return 0 - Success.
 * @return EINVAL - Bad arguments.
 * @return ENAMETOOLONG - Path is too long.
 * @return EEXIST - Data tree path already in use.
 */
merr_t
dt_add(struct dt_element *dte);

/** @brief Access a data tree element.
 *
 * @param path Element path.
 * @param access Access function to call (optional). Passing @p NULL will probe
 *      for existence.
 * @param ctx Function call context.
 *
 * @returns Error status.
 * @return 0 - Success.
 * @return ENOENT - Path does not exist in tree.
 * @return EINVAL - Bad arguments.
 * @return ENAMETOOLONG - Path is too long.
 */
merr_t
dt_access(const char *path, dt_access_t access, void *ctx);

/** @brief Count children of the specified data tree element.
 *
 * @param path Element path.
 *
 * @returns Number of children.
 */
unsigned int
dt_count(const char *path);

/** @brief Emit the content of the data tree from the given path.
 *
 * @param path Element path.
 * @param[out] root Pointer to set to allocated JSON object.
 *
 * @returns Error status.
 * @return 0 - Success.
 * @return ENOENT - Path does not exist in tree.
 * @return EINVAL - Bad arguments.
 * @return ENAMETOOLONG - Path is too long.
 */
merr_t
dt_emit(const char *path, cJSON **root);

/** @brief Remove a data tree element.
 *
 * @param path Element path.
 *
 * @returns Error status.
 * @return 0 - Success.
 * @return EINVAL - Bad arguments.
 * @return ENOENT - Path does not exist in tree.
 * @return ENAMETOOLONG - Path is too long.
 */
merr_t
dt_remove(const char *path);

/** @brief Recursively remove data tree elements.
 *
 * @param path Element path.
 *
 * @returns Error status.
 * @return 0 - Success.
 * @return EINVAL - Bad arguments.
 * @return ENAMETOOLONG - Path is too long.
 */
merr_t
dt_remove_recursive(const char *path);

#endif /* HSE_UTIL_DATA_TREE_H */
