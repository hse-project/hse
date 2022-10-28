/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/xrand.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "rsgen.h"

#define RS_BUF_SIZE       (16*1024*1024)


int
rsgen_init(
	struct rsgen   *rs,
	u64             max_id,
	u64             max_iter,
	bool            tags,
	u32             min_len,
	u32             max_len,
	u32             nthreads,
	u32             seed)
{
	struct xrand xr;
	size_t          i;
	u64             tmp;
	void           *mem = 0;
	unsigned        hidden_iter_bytes = 0;
	unsigned        hidden_id_bytes = 0;
	unsigned        hidden_bytes = 0;
	unsigned        prefix_tid_bytes = 0;
	unsigned        hidden_len = 1;
        int             rc;

	if (!rs)
		return -1;

	memset(rs, 0, sizeof(*rs));

	if (min_len == 0 || max_len > RS_MAX_VALUE_LEN) {
		snprintf(rs->rs_errmsg, sizeof(rs->rs_errmsg),
			 "must be between 1 and %u inclusive.",
			 RS_MAX_VALUE_LEN);
		return -1;
	}

	if (max_len < min_len) {
		snprintf(rs->rs_errmsg, sizeof(rs->rs_errmsg),
			 "max length must be greater than min length.");
		return -1;
	}

	/* compute bytes needed for hidden "uniqifier" data, which includes
	 * the id, the iteration count, and the tag. */
	if (max_id) {
		tmp = max_id - 1;
		while (tmp) {
			tmp = tmp >> 8;
			++hidden_id_bytes;
		}
	}

	if (max_iter) {
		tmp = max_iter - 1;
		while (tmp) {
			tmp = tmp >> 8;
			++hidden_iter_bytes;
		}
		if (!hidden_iter_bytes && nthreads > 1)
			++hidden_iter_bytes;
	}

	/*
	 * If multiple threads are running, they form a prefix
	 * to allow scans to select them independent of other threads.
	 * These overlay the first N bytes (one thread has no prefix).
	 */
	if (nthreads) {
		tmp = nthreads - 1;
		while (tmp) {
			tmp = tmp >> 8;
			++prefix_tid_bytes;
		}
	}

	hidden_bytes = hidden_iter_bytes
		+ hidden_id_bytes
		+ hidden_len
		+ prefix_tid_bytes
		+ (tags ? 1 : 0);

	/* ensure min_len can accommodate hidden bytes */
	if (hidden_bytes > min_len) {
		snprintf(rs->rs_errmsg, sizeof(rs->rs_errmsg),
			 "minimum length of %u is too small for "
			 "given parameters.\n"
			 "Increase min len to %u, or decrease "
			 "number of keys and/or iterations.",
			 min_len, hidden_bytes);
		return -1;
	}

	rc = posix_memalign(&mem, 4096, RS_BUF_SIZE + RS_MAX_VALUE_LEN);
	if (rc || !mem) {
		snprintf(rs->rs_errmsg, sizeof(rs->rs_errmsg),
			 "memory allocation failure.");
		return -1;
	}

	memset(mem, 0, RS_BUF_SIZE + RS_MAX_VALUE_LEN);

	rs->rs_buf = mem;
	rs->rs_min_len = min_len;
	rs->rs_max_len = max_len;
	rs->rs_max_iter = max_iter;
	rs->rs_max_id = max_id;
	rs->rs_seed = seed;
	rs->rs_tags = tags;
	rs->rs_hidden_id_bytes = hidden_id_bytes;
	rs->rs_hidden_iter_bytes = hidden_iter_bytes;
	rs->rs_prefix_tid_bytes = prefix_tid_bytes;

	xrand_init(&xr, seed);
	for (i = 0; i < RS_BUF_SIZE/sizeof(u32); i++)
		((u32 *)(rs->rs_buf))[i] = xrand64(&xr);

	return 0;
}


/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static
u32
rol32(
	u32             word,
	unsigned int    shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static
u32
rsgen_jhash_final(
	u32     a,
	u32     b,
	u32     c)
{
	c ^= b; c -= rol32(b, 14);
	a ^= c; a -= rol32(c, 11);
	b ^= a; b -= rol32(a, 25);
	c ^= b; c -= rol32(b, 16);
	a ^= c; a -= rol32(c, 4);
	b ^= a; b -= rol32(a, 14);
	c ^= b; c -= rol32(b, 24);
	return c;
}

extern char *
hexstr(
	char   *data,
	size_t  data_len,
	char   *out,
	size_t  out_len);

static
u8 *
rsgen_hidden_set(
	u8 *here,
	u32 nbytes,
	u64 x)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
	switch (nbytes) {
	case 8: *here++ = (u8)(x >> 56);
	case 7: *here++ = (u8)(x >> 48);
	case 6: *here++ = (u8)(x >> 40);
	case 5: *here++ = (u8)(x >> 32);
	case 4: *here++ = (u8)(x >> 24);
	case 3: *here++ = (u8)(x >> 16);
	case 2: *here++ = (u8)(x >> 8);
	case 1: *here++ = (u8)(x);
	}
#pragma GCC diagnostic pop
	return here;
}

static
u64
rsgen_hidden_get(
	u8  *here,
	u32  nbytes)
{
	u64 x = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
	switch (nbytes) {
	case 8: x |= ((u64)here[-7]) << 56;
	case 7: x |= ((u64)here[-6]) << 48;
	case 6: x |= ((u64)here[-5]) << 40;
	case 5: x |= ((u64)here[-4]) << 32;
	case 4: x |= ((u64)here[-3]) << 24;
	case 3: x |= ((u64)here[-2]) << 16;
	case 2: x |= ((u64)here[-1]) << 8;
	case 1: x |= here[0];
	}
#pragma GCC diagnostic pop
	return x;
}

void
rsgen_str(
	struct rsgen   *rs,
	u16             tid,
	u64             id,
	u64             iter,
	u8              tag,
	void           *val,
	u32            *len)
{
	u32     hidden_len = 1;
	u32     rv, offset, htotal;
	u8     *hide;

	rv = rsgen_jhash_final((u32)id, (u32)iter, rs->rs_seed+tag);

	*len = rs->rs_min_len;
	if (rs->rs_min_len < rs->rs_max_len)
		*len += rv % (rs->rs_max_len - rs->rs_min_len + 1);

	/* Ensure all keys and values are aligned.  This keeps valgrind
	 * from complaining about memcmp reading uninitialized data.
	 */
	offset = (rv % RS_BUF_SIZE) & 7;

	assert(offset + *len <= RS_BUF_SIZE + RS_MAX_VALUE_LEN);

	memcpy(val, rs->rs_buf + offset, *len);

	if (tag)
		*(u8 *)val = tag;
	else if (rs->rs_prefix_tid_bytes)
		rsgen_set_tid(rs, val, tid);

	htotal = (rs->rs_hidden_id_bytes +
		  rs->rs_hidden_iter_bytes +
		  hidden_len +
		  (rs->rs_tags ? 1 : 0));

	hide = val + *len - htotal;
	hide = rsgen_hidden_set(hide, rs->rs_hidden_iter_bytes, iter);
	hide = rsgen_hidden_set(hide, rs->rs_hidden_id_bytes, id);

	if (rs->rs_tags)
		*hide++ = tag;

	/*
	 * to allow reverse recovery of the tid, key id and iter,
	 * we encode in a trailing byte the number of bytes for each
	 */
	*hide++ = (!!rs->rs_tags << 7) |
		  (!!rs->rs_prefix_tid_bytes << 6) |
		  ((rs->rs_hidden_id_bytes - 1) << 3) |
		  rs->rs_hidden_iter_bytes;
}

/*
 * Encode the tid as one or two bytes of int value:
 * if the msb is 0, then it is a single byte
 * else the first two bytes are the tid.
 * The init() code arranges the counts, so the second 0xff mask
 * will never have the high bit set on a single byte tid.
 */

void
rsgen_set_tid(
	struct rsgen   *rs,
	void           *buf,
	u16            tid)
{
	unsigned char *ucp = buf;

	if (rs->rs_prefix_tid_bytes > 1)
		*ucp++ = 0x80 | (tid >> 8 & 0x7f);
	*ucp = tid & 0xff;
}

u16
rsgen_decode(
	void         *str,
	int           len,
	u64          *keynum,
	u64          *iter,
	u8           *tag)
{
	/*
	 * memory layout is: [tid] key id iter [tag] len
	 * recover in reverse order: len [tag] iter id ... tid
	 *
	 * byte encoding:
	 *	tTkkkiii: istag, istid, keynum, iter
	 * iter may be zero for non-exist, 1 for 1 byte, up to 8 for 8 bytes
	 * keynum will be zero for 1 byte, up to 7 for 8 bytes
	 * tid is two bytes if it exists
	 */

	unsigned char *ucp = str + len - 1;
	u32            iterlen = *ucp & 7;
	u32            keylen = 1 + ((*ucp >> 3) & 7);
	bool           istid = (*ucp >> 6) & 1;
	bool           istag = *ucp >> 7;
	u16            tid = 0;

	--ucp;
	if (istag && tag)
		*tag = *ucp--;

	*keynum = rsgen_hidden_get(ucp, keylen);
	*iter = rsgen_hidden_get(ucp - keylen, iterlen);

	if (istid) {
		ucp = str;
		tid = ucp[0];
		if (tid & 0x80)
			tid |= ((tid & 0x7f) << 8) | ucp[1];
	}
	return tid;
}

void
rsgen_fini(
	struct rsgen   *rs)
{
	if (rs) {
		free(rs->rs_buf);
		memset(rs, 0, sizeof(*rs));
	}
}
