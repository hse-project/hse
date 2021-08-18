/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2016 Micron Technology, Inc.  All rights reserved.
 */
#ifndef RSGEN_H
#define RSGEN_H

#include <hse_util/inttypes.h>

/*
 * The approach used here to generate large random strings doesn't work too
 * well with extremely large values, so we limit the max value length to avoid
 * disappointing unsuspecting users.
 */
#define RS_MAX_VALUE_LEN  (1024*1024)

struct rsgen {
	u8     *rs_buf;
	u64     rs_max_iter;
	u64     rs_max_id;
	u32     rs_min_len;
	u32     rs_max_len;
	u32     rs_seed;
	u32     rs_hidden_iter_bytes;
	u32     rs_hidden_id_bytes;
	u32     rs_prefix_tid_bytes;
	bool    rs_tags;
	char    rs_errmsg[256];
};

int
rsgen_init(
	struct rsgen   *rs,
	u64             max_id,
	u64             max_iter,
	bool            tags,
	u32             min_len,
	u32             max_len,
	u32             nthreads,
	u32             seed);

void
rsgen_str(
	struct rsgen   *rs,
	u16             tid,
	u64             id,
	u64             iter,
	u8              tag,
	void           *val,
	u32            *len);

void
rsgen_set_tid(
	struct rsgen  *rs,
	void          *buf,
	u16            tid);

u16
rsgen_decode(
	void         *str,
	int           len,
	u64          *id,
	u64          *iter,
	u8           *tag);

void
rsgen_fini(
	struct rsgen   *rs);


#endif
