/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MOCKS_MOCK_MPOOL_H
#define MOCKS_MOCK_MPOOL_H

#include <mock/api.h>

#include <hse/mpool/mpool.h>

#include <hse/util/platform.h>

#define MPM_MAX_MAPS 1024
#define MPM_MAX_MBLOCKS 1024
#define MPM_MBLOCK_ID_BASE 10000

/*
 * Back doors for allocating, reading and writing mblocks.
 */

/* Allocate an mblock */
merr_t
mpm_mblock_alloc(size_t capacity, u64 *id_out);

/* Write data to an mblock */
merr_t
mpm_mblock_write(u64 blkid, const void *data, u64 offset, u32 len);

/* Read data from an mblock */
merr_t
mpm_mblock_read(u64 blkid, void *data, u64 offset, u32 len);

/* Read a file into an already allocated mblock */
merr_t
mpm_mblock_load_file(u64 blkid, const char *filename);

/* Allocate an mblock big enough to hold file, then
 * load mblock with contents of file */
merr_t
mpm_mblock_alloc_file(u64 *blkid, const char *filename);

/* Read an MDC into an already allocated mblock */
/* If data is not zero, return the address and len of the data */
merr_t
mpm_mdc_load_file(const char *filename, char **data, int *len);

merr_t
mpm_mblock_get_base(u64 id, void **data, size_t *wlen);

/* provide a function which can interpret a buffer and return
 * the length of the next record for a particular MDC
 */
merr_t
mpm_mdc_set_getlen(struct mpool_mdc *mdc, size_t (*getlen)(void *, size_t));

/* Retrieve pointers to the mocked_mdc "written" memmory. */
merr_t
mpm_mdc_get_written(struct mpool_mdc *mdc, char **data, int *len);

void
mock_mpool_set(void);

void
mock_mpool_unset(void);
#endif
