/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_VBLOCK_BUILDER_INT_H
#define HSE_KVS_CN_VBLOCK_BUILDER_INT_H

#define WBUF_LEN_MAX (1024 * 1024)
#define VBLOCK_HDR_LEN 4096

struct vbb_ext;
struct cn_merge_stats;

/**
 * struct vblock_builder - create vblocks from a stream of values
 * @ds:        mpool dataset
 * @pc:        performance counters
 * @vblk_list: list of vblocks
 * @asyncio_head:   list holding async io buffers
 * @asyncio_lstcnt: No. of elments in asyncio_head
 * @asyncio_ctx:    Context object for kernel.
 * @asyncio_max:    Max pending IO for a vblock
 * @asyncio_ctxswi: Max IO the context can hold before allocating new one.
 * @asyncio_ingestpool: Pool from which memory allocation is done.
 * @wbuf:      write buffer
 * @wbuf_off:  offset of next unused byte in write buffer
 * @wbuf_len:  length of next write to media
 * @vblk_off:  offset of next unused byte in vblock
 * @vsize:     vblock size for compaction stats.  for vblocks, vsize
 *             is the number of bytes written to the vblock before committing it
 *             minus the size of the vblock byte header.
 * @destruct:  if true, vlbock builder is ready to be destroyed
 * @stripe_len: mblock stripe length
 *
 * WBUF_LEN_MAX is the allocated size of the write buffer.  Each mblock write
 * will be at most WBUF_LEN_MAX bytes.  Member @wbuf_len is the actual write
 * size, and is set to the largest value that meets the following criteria:
 *   1) @wbuf_len <= WBUF_LEN_MAX, and
 *   2) @wbuf_len is a multiple of the mblock stripe length.
 *
 * The vblock builder creates as many vblocks as needed to store the values.
 * The write buffer is allocated once when the builder is created, and is
 * reused between vblocks.  The following logic explains how the vlbock
 * builder state is managed as new values are added.
 *
 * When a new value is given to the vblock builder
 * -----------------------------------------------
 *
 *   Let @vlen be the lenght of the new value
 *
 *   If current vblock has not been allocated, start a new vblock as follows:
 *     - allocate vblock
 *     - set @wbuf_len according to new vblock's stripe length
 *     - format vblock header at start of @wbuf
 *     - set @wbuf_off to header len
 *     - set @vblk_off to header len
 *
 *   If current vblock does not have room for new value:
 *     - write residual contents of @wbuf to mblock
 *     - start a new vblock as described above
 *
 *   While @vlen > 0:
 *     - copy whatever fits into @wbuf (cannot exceed @wbuf_len)
 *     - let @copied be number of bytes copied
 *     - set @vlen -= @copied
 *     - set @wbuf_off += @copied
 *     - if @wbuf_off == @wbuf_len:
 *       -- write @wbuf_len bytes to mblock
 *       -- set @wbuf_off to 0
 *       -- set @vblk_off += @wbuff_off
 */
struct vblock_builder {
    struct mpool *         ds;
    struct cn *            cn;
    struct perfc_set *     pc;
    struct cn_merge_stats *mstats;
    struct blk_list        vblk_list;
    struct list_head       asyncio_head;
    int                    asyncio_lstcnt;
    struct mp_asyncctx_ioc asyncio_ctx;
    enum mp_media_classp   mclass;
    int                    asyncio_max;
    int                    asyncio_ctxswi;
    bool                   asyncio_ingestpool;
    u64                    vsize;
    u64                    blkid;
    uint                   max_size;
    uint                   vblk_off;
    void *                 wbuf;
    uint                   wbuf_off;
    uint                   wbuf_len;
    uint                   flags;
    u64                    vgroup;
    bool                   destruct;
    u32                    stripe_len;
    struct vbb_ext *       vbb_ext;
};

/* struct asyncio_list_entry
 * @mp_link:
 * @mp_buf:
 * @mp_ctx: Pointer to context.
 *
 * Struct holding the list of async IO buffers.
 */
struct asyncio_list_entry {
    struct list_head mp_link;
    void *           mp_buf;
    void *           mp_ctx;
};

static inline bool
_vblock_has_room(struct vblock_builder *bld, size_t vlen)
{
    return bld->vblk_off + vlen <= bld->max_size;
}

static inline uint
_vblock_unused_media_space(struct vblock_builder *bld)
{
    return bld->max_size - bld->vblk_off;
}

merr_t
_vblock_finish_ext(struct vblock_builder *bld, u8 slot, bool final);

#endif
