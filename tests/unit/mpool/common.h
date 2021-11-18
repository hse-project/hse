/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>

#include <hse_util/logging.h>
#include <mpool/mpool_structs.h>

extern char capacity_path[PATH_MAX];
extern char staging_path[PATH_MAX];
extern char pmem_path[PATH_MAX];

extern struct mpool_cparams tcparams;
extern struct mpool_rparams trparams;
extern struct mpool_dparams tdparams;

struct mtf_test_info;

int
mpool_test_pre(struct mtf_test_info *info);

int
mpool_test_post(struct mtf_test_info *info);

int
mpool_collection_pre(struct mtf_test_info *info);

int
make_capacity_path(void);

int
make_staging_path(void);

int
make_pmem_path(void);

int
remove_capacity_path(void);

int
remove_staging_path(void);

int
remove_pmem_path(void);

void
unset_mclass(const enum mpool_mclass mclass);

void
setup_mclass(const enum mpool_mclass mclass);
