/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef MPOOL_MCACHE_H
#define MPOOL_MCACHE_H

#include <stdint.h>

#include <sys/types.h>

#include <hse/error/merr.h>


struct mpool_mcache_map; /* opaque mcache map handle */
struct mpool;

/******************************** MCACHE APIs ************************************/

/**
 * mpool_mcache_madvise() - Give advice about use of memory
 *
 * @map:    mcache map handle
 * @mbidx:  logical mblock number in mcache map
 * @offset: offset into the mblock specified by mbidx
 * @length: see madvise(2)
 * @advice: see madvise(2)
 *
 * Like madvise(2), but for mcache maps.
 *
 * Note that one can address the entire map (including holes) by
 * specifying zero for %mbidx, zero for %offset, and %SIZE_MAX for
 * %length.  In general, %SIZE_MAX may always be specified for %length,
 * in which case it addresses the map from the given mbidx based offset
 * to the end of the map.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_madvise(
    struct mpool_mcache_map *map,
    uint32_t                 mbidx,
    off_t                    offset,
    size_t                   length,
    int                      advice);

/**
 * mpool_mcache_getbase() - Get the base address of a memory-mapped mblock in an mcache map
 *
 * @map:   mcache map handle
 * @mbidx: mcache map mblock index
 *
 * If the pages of an mcache map are contiguous in memory (as is the case in
 * user-space), return the the base address of the mapped mblock.  If the
 * pages are not contiguous, return NULL.
 */
/* MTF_MOCK */
void *
mpool_mcache_getbase(struct mpool_mcache_map *map, const uint32_t mbidx);

/**
 * mpool_mcache_getpages() - Get a vector of pages from a single mblock
 *
 * @map:     mcache map handle
 * @pagec:   page count (len of @pagev array)
 * @mbidx:   mcache map mblock index
 * @offsetv: vector of page offsets into objects/mblocks
 * @pagev:   vector of pointers to pages (output)
 *
 * mbidx is an index into the mbidv[] vector that was given to mpool_mcache_create().
 *
 * Return: %0 on success, merr_t on failure
 */
/* MTF_MOCK */
merr_t
mpool_mcache_getpages(
    struct mpool_mcache_map *map,
    const uint32_t           pagec,
    const uint32_t           mbidx,
    const off_t              offsetv[],
    void *                   pagev[]);

/**
 * mpool_mcache_mmap() - Create an mcache map
 *
 * @mp:    handle for the mpool
 * @mbidc: mblock ID count
 * @mbidv: vector of mblock IDs
 * @mapp:  pointer to (opaque) mpool_mcache_map ptr
 *
 * Create an mcache map for the list of given mblock IDs and returns a handle to it via *mapp.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_mmap(struct mpool *mp, size_t mbidc, uint64_t *mbidv, struct mpool_mcache_map **mapp);

/**
 * mpool_mcache_munmap() - munmap an mcache mmap
 *
 * @map:
 */
/* MTF_MOCK */
void
mpool_mcache_munmap(struct mpool_mcache_map *map);

/**
 * mpool_mcache_purge() - Purge map (NOT SUPPORTED)
 *
 * @map: mcache map handle
 * @mp:  mp mpool
 */
/* MTF_MOCK */
merr_t
mpool_mcache_purge(struct mpool_mcache_map *map, const struct mpool *mp);

/**
 * mpool_mcache_mincore() - Get VSS and RSS for the mcache map (NOT SUPPORTED)
 *
 * @map:  mcache map handle
 * @mp:   mpool handle
 * @rssp: ptr to count of resident pages in the map
 * @vssp: ptr to count of virtual pages in the map
 *
 * Get the virtual and resident set sizes (in pages count)
 * for the given mcache map.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_mincore(
    struct mpool_mcache_map *map,
    const struct mpool *     mp,
    size_t *                 rssp,
    size_t *                 vssp);

#endif /* MPOOL_MCACHE_H */
