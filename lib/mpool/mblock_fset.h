/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FSET_H
#define MPOOL_MBLOCK_FSET_H

#include <hse_util/hse_err.h>

#define MBLOCK_FS_FCNT_MAX      (1 << 8)    /* 8-bit for file-id */
#define MBLOCK_FS_FCNT_DFLT      32

struct mblock_file;

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 * @filev:     vector of mblock file handles
 * @filec:     mblock file count
 * @meta_fd:   fd of the fileset meta file
 * @meta_name: fileset meta file name
 */
struct mblock_fset {
	struct media_class  *mc;

	struct mblock_file **filev;
	int                  filec;

	int                  meta_fd;
	char                 meta_name[32];
};

/**
 * mblock_fset_open() - open an mblock fileset
 *
 * @mc:             media class handle
 * @flags:          open flags
 * @mbfsp (output): mblock fileset handle
 */
merr_t
mblock_fset_open(struct media_class *mc, int flags, struct mblock_fset **mbfsp);

/**
 * mblock_fset_close() - close an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 */
void
mblock_fset_close(struct mblock_fset *mbfsp);

/**
 * mblock_fset_remove() - remove an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 */
void
mblock_fset_remove(struct mblock_fset *mbfsp);

#endif /* MPOOL_MBLOCK_FSET_H */

