/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_DARRAY_H
#define HSE_PLATFORM_DARRAY_H

/*
 * Darray provides a useful abstraction of a small dynamic array
 * that holds pointers to things.  It is optimized for the
 * use case of an unknown, typically small and unique set of pointers
 * that must be tracked as they are added.
 *
 * It is valid in kernel or user space, or code that is dual-homed.
 *
 * Its advantage over static arrays is:
 * - Don't need to know (or care) about number of elements
 * - It provides an append only unique values (idempotentcy)
 * - It has an apply method over its active elements
 * - It does not need to be initialized, but it can be.
 *
 * It should not:
 * - replace static arrays in the normal case
 * - be used for random access -- it is meant for append only
 * - although it can, in limited scenarios -- see unit tests
 *
 * All functions return 0 on success, or ENOMEM on failure.
 */

struct darray {
    void **arr; /* array of ptr elements */
    int    cur; /* current index */
    int    cap; /* capacity */
};

/**
 * darray_init - allows for pre-allocation of a known quantity
 * @da:  ptr to the darray
 * @cap: pre-allocate this many ptrs
 */
int
darray_init(struct darray *da, int cap);

/**
 * darray_reset - resets current index to 0 and zeroes out ptr elements.
 * @da:  ptr to the darray
 */
void
darray_reset(struct darray *da);

/**
 * darray_fini - deallocates the darray
 * @da:  ptr to the darray
 */
void
darray_fini(struct darray *da);

/**
 * darray_append - append a new ptr to the array
 * @da:  ptr to the darray
 * @p:   ptr to add
 *
 * This function will automatically initialize and allocate
 * sufficient space, or extend the allocation to allow appending.
 */
int
darray_append(struct darray *da, void *p);

/**
 * darray_append_uniq - only append p if not already in array
 * @da:  ptr to the darray
 * @p:   ptr to append, only if it is not present
 *
 * Returns non-zero only if needed to allocate and could not.
 * It does not indicate if the value was already present.
 * NB: presently uses a linear scan -- do not use in hi perf path
 */
int
darray_append_uniq(struct darray *da, void *p);

/**
 * darray_append_loc - return ptr to next avail location in array
 * @da:  ptr to the darray
 *
 * Returns ptr to void * location, or NULL if cannot expand array.
 */
void **
darray_append_loc(struct darray *da);

/**
 * darray_len - returns number of elements in array
 * @da:  ptr to the darray
 */
int
darray_len(struct darray *da);

/**
 * darray_arr - returns the array
 * @da:  ptr to the darray
 */
void *
darray_arr(struct darray *da);

typedef void (*darray_func)(void *);

/**
 * darray_apply - applys func to each element of array
 * @da:   ptr to the darray
 * @func: function to call for each array element
 */
void
darray_apply(struct darray *da, darray_func func);

/**
 * darray_apply_rev - applys func to each element of array in reverse order
 * @da:   ptr to the darray
 * @func: function to call for each array element
 */
void
darray_apply_rev(struct darray *da, darray_func func);

#endif
