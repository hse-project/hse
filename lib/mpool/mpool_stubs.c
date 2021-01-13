/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_mpool

#include <mpool/mpool.h>

merr_t
mpool_create(
	const char             *mpname,
	const char             *devname,
	struct mpool_params    *params,
	uint32_t                flags)
{
    return 0;
}

merr_t mpool_destroy(const char *mpname, uint32_t flags)
{
    return 0;
}

merr_t
mpool_mclass_add(
	const char             *mpname,
	const char             *devname,
	enum mp_media_classp    mclass,
	struct mpool_params    *params,
	uint32_t                flags)
{
    return 0;
}

merr_t mpool_scan(int *propcp, struct mpool_params **propvp)
{
    return 0;
}

merr_t mpool_list(int *propcp, struct mpool_params **propvp)
{
    return 0;
}

merr_t
mpool_open(const char *mpname, uint32_t flags, struct mpool **mp)
{
    return 0;
}

merr_t mpool_close(struct mpool *mp)
{
    return 0;
}

merr_t
mpool_mclass_get(struct mpool *mp, enum mp_media_classp mclass, struct mpool_mclass_props *props)
{
    if (mclass != MP_MED_CAPACITY)
        return merr(ENOENT);

    if (props)
        props->mc_mblocksz = MPOOL_MBSIZE_MB_DEFAULT;

    return 0;
}

merr_t mpool_usage_get(struct mpool *mp, struct mpool_usage *usage)
{
    return 0;
}

void mpool_params_init(struct mpool_params *params)
{
}

merr_t
mpool_params_get(struct mpool *mp, struct mpool_params *params)
{
    memset(params, 0, sizeof(*params));

    return 0;
}

merr_t
mpool_params_set(struct mpool *mp, struct mpool_params *params)
{
    return 0;
}

merr_t
mpool_mdc_alloc(
	struct mpool               *mp,
	uint64_t                   *logid1,
	uint64_t                   *logid2,
	enum mp_media_classp        mclassp,
	const struct mdc_capacity  *capreq,
	struct mdc_props           *props)
{
    return 0;
}

merr_t mpool_mdc_commit(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    return 0;
}

merr_t mpool_mdc_abort(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    return 0;
}

merr_t mpool_mdc_delete(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    return 0;
}

merr_t mpool_mdc_get_root(struct mpool *mp, uint64_t *logid1, uint64_t *logid2)
{
    *logid1 = 0;
    *logid2 = 0;

    return 0;
}

merr_t
mpool_mdc_open(
	struct mpool        *mp,
	uint64_t             logid1,
	uint64_t             logid2,
	uint8_t              flags,
	struct mpool_mdc   **mdc_out)
{
    return 0;
}

merr_t mpool_mdc_close(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t mpool_mdc_rewind(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t mpool_mdc_read(struct mpool_mdc *mdc, void *data, size_t len, size_t *rdlen)
{
    return 0;
}

merr_t mpool_mdc_append(struct mpool_mdc *mdc, void *data, ssize_t len, bool sync)
{
    return 0;
}

merr_t mpool_mdc_cstart(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t mpool_mdc_cend(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t mpool_mdc_usage(struct mpool_mdc *mdc, size_t *usage)
{
    return 0;
}


merr_t
mpool_mblock_alloc(
	struct mpool           *mp,
	enum mp_media_classp	mclassp,
	bool                    spare,
	uint64_t               *mbid,
	struct mblock_props    *props)
{
    return 0;
}

merr_t mpool_mblock_find(struct mpool *mp, uint64_t objid, struct mblock_props *props)
{
    return 0;
}

merr_t mpool_mblock_commit(struct mpool *mp, uint64_t mbid)
{
    return 0;
}

merr_t mpool_mblock_abort(struct mpool *mp, uint64_t mbid)
{
    return 0;
}

merr_t mpool_mblock_delete(struct mpool *mp, uint64_t mbid)
{
    return 0;
}

merr_t mpool_mblock_props_get(struct mpool *mp, uint64_t mbid, struct mblock_props *props)
{
    return 0;
}

merr_t mpool_mblock_write(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc)
{
    return 0;
}

merr_t
mpool_mblock_read(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc, off_t offset)
{
    return 0;
}

merr_t
mpool_mcache_madvise(
	struct mpool_mcache_map    *map,
	uint32_t                    mbidx,
	off_t                       offset,
	size_t                      length,
	int                         advice)
{
    return 0;
}

merr_t mpool_mcache_purge(struct mpool_mcache_map *map, const struct mpool *mp)
{
    return 0;
}

merr_t
mpool_mcache_mincore(
	struct mpool_mcache_map    *map,
	const struct mpool         *mp,
	size_t                     *rssp,
	size_t                     *vssp)
{
    return 0;
}

void *mpool_mcache_getbase(struct mpool_mcache_map *map, const uint32_t mbidx)
{
    return NULL;
}


merr_t
mpool_mcache_getpages(
	struct mpool_mcache_map    *map,
	const uint32_t              pagec,
	const uint32_t              mbidx,
	const off_t                 offsetv[],
	void                       *pagev[])
{
    return 0;
}

merr_t
mpool_mcache_mmap(
	struct mpool               *mp,
	size_t                      mbidc,
	uint64_t                   *mbidv,
	enum mpc_vma_advice         advice,
	struct mpool_mcache_map    **mapp)
{
    return 0;
}

merr_t mpool_mcache_munmap(struct mpool_mcache_map *map)
{
    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "mpool_ut_impl.i"
#endif
