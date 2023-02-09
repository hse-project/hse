/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MOCKS_MOCK_MPOOL_H
#define MOCKS_MOCK_MPOOL_H

#include <stdint.h>

#include <hse/mpool/mpool.h>
#include <hse/util/platform.h>

#include <hse/test/mock/api.h>

#define MPM_MAX_MAPS       1024
#define MPM_MAX_MBLOCKS    1024
#define MPM_MBLOCK_ID_BASE 10000

/*
 * Back doors for allocating, reading and writing mblocks.
 */

/* Allocate an mblock */
merr_t
mpm_mblock_alloc(size_t capacity, uint64_t *id_out);

/* Write data to an mblock */
merr_t
mpm_mblock_write(uint64_t blkid, const void *data, uint64_t offset, uint32_t len);

/* Read data from an mblock */
merr_t
mpm_mblock_read(uint64_t blkid, void *data, uint64_t offset, uint32_t len);

/* Read a file into an already allocated mblock */
merr_t
mpm_mblock_load_file(uint64_t blkid, const char *filename);

/* Allocate an mblock big enough to hold file, then
 * load mblock with contents of file */
merr_t
mpm_mblock_alloc_file(uint64_t *blkid, const char *filename);

/* Read an MDC into an already allocated mblock */
/* If data is not zero, return the address and len of the data */
merr_t
mpm_mdc_load_file(const char *filename, char **data, int *len);

merr_t
mpm_mblock_get_base(uint64_t id, void **data, size_t *wlen);

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
