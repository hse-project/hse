/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <ftw.h>

#include <hse_util/mutex.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/minmax.h>
#include <hse_util/log2.h>
#include <hse_util/page.h>

#include "mblock_file.h"
#include "io.h"
#include "omf.h"
#include "mclass.h"

/* clang-format off */

#define MBLOCK_FILE_META_HDRLEN    (4096)
#define MBLOCK_FILE_UNIQ_DELTA     (1024)
#define MBLOCK_MMAP_CHUNK_MAX      (1024)

/**
 * struct mblock_rgnmap -
 *
 * @rm_lock: lock protecting the region map
 * @rm_root: root of the region map rbtree
 */
struct mblock_rgnmap {
    struct mutex   rm_lock;
    struct rb_root rm_root;

    struct kmem_cache *rm_cache HSE_ALIGNED(SMP_CACHE_BYTES);
};

/**
 * struct mblock_mmap -
 *
 * @addr: base address of the mmap chunk
 * @ref:  ref. count on the mapped chunk
 */
struct mblock_mmap {
    char   *addr;
    int64_t ref HSE_ALIGNED(SMP_CACHE_BYTES);
};

/**
 * struct mblock_file - mblock file handle (one per file)
 *
 * @rgnmap: region map for block management
 *
 * @mbfsp: mblock fileset handle
 * @io:    io handle for sync/async rw ops
 *
 * @fszmax:   max. file size
 * @mblocksz: mblock size
 * @mcid:     media class id of this mblock file
 * @fileid:   mblock file identifier
 * @fd:       file descriptor
 *
 * @wlenv:    vector of write lengths, one slot for each mblock
 *
 * @uniq_lock: lock to protect uniquifier
 * @uniq:      uniquifier used in mblock id
 *
 * @meta_lock: lock to protect metadata updates
 * @meta_addr: start of the metadata region for this data file
 *
 * @mmap_lock: lock protecting mmapv
 * @mmapc:     number of mapped chunks
 * @mmapv:     vector of mapped chunks
 *
 * @wlen:      total write length for this file
 * @mbcnt:     count of allocated mblocks
 */
struct mblock_file {
    struct mblock_rgnmap rgnmap;

    struct mblock_fset *mbfsp;
    struct io_ops       io;

    size_t         fszmax;
    size_t         mblocksz;
    enum mclass_id mcid;
    int            fileid;
    int            fd;

    atomic_t *wlenv;

    struct mutex uniq_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    uint32_t     uniq;

    struct mutex meta_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    char        *meta_addr;

    struct mutex        mmap_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    int                 mmapc;
    struct mblock_mmap *mmapv;

    atomic64_t wlen HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic_t   mbcnt;
};

/* clang-format on */

/* Forward declarations */
static void
mblock_file_unmapall(struct mblock_file *mbfp);

static int
mblock_mmap_cshift(size_t mblocksz);

static merr_t
mblock_file_insert(struct mblock_file *mbfp, uint64_t mbid);

/**
 * Region map interfaces.
 */

static merr_t
mblock_rgnmap_init(struct mblock_file *mbfp, struct kmem_cache *rmcache)
{
    struct mblock_rgnmap *rgnmap;
    struct mblock_rgn    *rgn;
    uint32_t rmax;

    rgnmap = &mbfp->rgnmap;
    mutex_init(&rgnmap->rm_lock);
    rgnmap->rm_root = RB_ROOT;

    rgn = kmem_cache_alloc(rmcache);
    if (!rgn)
        return merr(ENOMEM);

    rgn->rgn_start = 1;
    rmax = mbfp->fszmax >> ilog2(mbfp->mblocksz);
    rgn->rgn_end = rmax + 1;

    mutex_lock(&rgnmap->rm_lock);
    rb_link_node(&rgn->rgn_node, NULL, &rgnmap->rm_root.rb_node);
    rb_insert_color(&rgn->rgn_node, &rgnmap->rm_root);
    mutex_unlock(&rgnmap->rm_lock);

    rgnmap->rm_cache = rmcache;

    return 0;
}

static uint32_t
mblock_rgn_alloc(struct mblock_rgnmap *rgnmap)
{
    struct mblock_rgn *rgn;
    struct rb_root    *root;
    struct rb_node    *node;
    uint32_t           key;

    rgn = NULL;
    key = 0;

    mutex_lock(&rgnmap->rm_lock);
    root = &rgnmap->rm_root;
    node = rb_first(root);

    if (node) {
        rgn = rb_entry(node, struct mblock_rgn, rgn_node);

        key = rgn->rgn_start++;

        if (rgn->rgn_start < rgn->rgn_end)
            rgn = NULL;
        else
            rb_erase(&rgn->rgn_node, root);
    }
    mutex_unlock(&rgnmap->rm_lock);

    if (rgn)
        kmem_cache_free(rgnmap->rm_cache, rgn);

    return key;
}

static merr_t
mblock_rgn_insert(struct mblock_rgnmap *rgnmap, uint32_t key)
{
    struct mblock_rgn *this, *to_free = NULL;
    struct rb_root *root;
    struct rb_node *node, **new, *parent;
    uint32_t start, end;
    merr_t   err = 0;

    mutex_lock(&rgnmap->rm_lock);
    root = &rgnmap->rm_root;
    node = root->rb_node;

    while (node) {
        this = rb_entry(node, struct mblock_rgn, rgn_node);

        if (key < this->rgn_start)
            node = node->rb_left;
        else if (key >= this->rgn_end)
            node = node->rb_right;
        else
            break; /* Found overlapping node */
    };

    if (ev(!node)) {
        err = merr(ENOENT);
        goto exit;
    }

    if (key == this->rgn_start) {
        this->rgn_start++;
        if (this->rgn_start == this->rgn_end) {
            rb_erase(&this->rgn_node, root);
            to_free = this;
        }
        node = NULL;
    } else if (key == this->rgn_end - 1) {
        this->rgn_end--;
        node = NULL;
    }

    if (!node)
        goto exit;

    /* Split the current node and find a position for the new node */
    start = this->rgn_start;
    end = key;
    this->rgn_start = key + 1;

    new = &node->rb_left;
    parent = node;

    while (*new) {
        this = rb_entry(*new, struct mblock_rgn, rgn_node);
        parent = *new;

        if (this->rgn_end == start) {
            this->rgn_end = end;
            new = NULL;
            break;
        }

        new = &(*new)->rb_right;
    }

    if (new) {
        struct mblock_rgn *rgn;

        /* Allocate new node and link it at parent */
        rgn = kmem_cache_alloc(rgnmap->rm_cache);
        if (!rgn) {
            err = merr(ENOMEM);
            goto exit;
        }

        rgn->rgn_start = start;
        rgn->rgn_end = end;

        rb_link_node(&rgn->rgn_node, parent, new);
        rb_insert_color(&rgn->rgn_node, root);
    }

exit:
    mutex_unlock(&rgnmap->rm_lock);

    if (to_free)
        kmem_cache_free(rgnmap->rm_cache, to_free);

    return err;
}

static merr_t
mblock_rgn_free(struct mblock_rgnmap *rgnmap, uint32_t key)
{
    struct mblock_rgn *this, *that;
    struct rb_node **new, *parent;
    struct rb_node *nxtprv;
    struct rb_root *root;
    merr_t err = 0;

    assert(rgnmap && key > 0);

    this = that = NULL;
    parent = NULL;
    nxtprv = NULL;

    mutex_lock(&rgnmap->rm_lock);
    root = &rgnmap->rm_root;
    new = &root->rb_node;

    while (*new) {
        this = rb_entry(*new, struct mblock_rgn, rgn_node);
        parent = *new;

        if (key < this->rgn_start) {
            if (key == this->rgn_start - 1) {
                --this->rgn_start;
                nxtprv = rb_prev(*new);
                new = NULL;
                break;
            }
            new = &(*new)->rb_left;
        } else if (key >= this->rgn_end) {
            if (key == this->rgn_end) {
                ++this->rgn_end;
                nxtprv = rb_next(*new);
                new = NULL;
                break;
            }
            new = &(*new)->rb_right;
        } else {
            new = NULL;
            err = merr(ENOENT);
            break;
        }
    }

    if (nxtprv) {
        that = rb_entry(nxtprv, struct mblock_rgn, rgn_node);

        if (this->rgn_start == that->rgn_end) {
            this->rgn_start = that->rgn_start;
            rb_erase(&that->rgn_node, root);
        } else if (this->rgn_end == that->rgn_start) {
            this->rgn_end = that->rgn_end;
            rb_erase(&that->rgn_node, root);
        } else {
            that = NULL;
        }
    } else if (new) {
        struct mblock_rgn *rgn;

        rgn = kmem_cache_alloc(rgnmap->rm_cache);
        if (rgn) {
            rgn->rgn_start = key;
            rgn->rgn_end = key + 1;

            rb_link_node(&rgn->rgn_node, parent, new);
            rb_insert_color(&rgn->rgn_node, root);
        }
    }
    mutex_unlock(&rgnmap->rm_lock);

    if (that)
        kmem_cache_free(rgnmap->rm_cache, that);

    return err;
}

static merr_t
mblock_rgn_find(struct mblock_rgnmap *rgnmap, uint32_t key)
{
    struct mblock_rgn *this;
    struct rb_node *cur;

    assert(rgnmap && key > 0);

    mutex_lock(&rgnmap->rm_lock);
    cur = rgnmap->rm_root.rb_node;

    while (cur) {
        this = rb_entry(cur, struct mblock_rgn, rgn_node);

        if (key < this->rgn_start)
            cur = cur->rb_left;
        else if (key >= this->rgn_end)
            cur = cur->rb_right;
        else
            break;
    }

    mutex_unlock(&rgnmap->rm_lock);

    return cur ? merr(ENOENT) : 0;
}

/**
 * Mblock file meta interfaces.
 */

static HSE_ALWAYS_INLINE uint32_t
block_id(uint64_t mbid)
{
    return mbid & MBID_BLOCK_MASK;
}

static HSE_ALWAYS_INLINE uint64_t
block_off(uint64_t mbid, size_t mblocksz)
{
    return ((uint64_t)block_id(mbid)) << ilog2(mblocksz);
}

static HSE_ALWAYS_INLINE uint32_t
uniquifier(uint64_t mbid)
{
    return (mbid & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT;
}

size_t
mblock_file_meta_len(size_t fszmax, size_t mblocksz)
{
    size_t mblkc;

    mblkc = fszmax >> ilog2(mblocksz);

    return MBLOCK_FILE_META_HDRLEN + mblkc * MBLOCK_FILE_META_OIDLEN;
}

static merr_t
mblock_file_meta_format(struct mblock_file *mbfp, struct mblock_filehdr *fh)
{
    char *addr;
    int   rc;

    addr = mbfp->meta_addr;

    omf_mblock_filehdr_pack_htole(fh, addr);

    rc = msync((void *)((unsigned long)addr & PAGE_MASK), PAGE_SIZE, MS_SYNC);
    if (rc == -1)
        return merr(errno);

    return 0;
}

static merr_t
mblock_file_meta_load(struct mblock_file *mbfp)
{
    struct mblock_filehdr fh = {};
    char                 *addr, *bound;
    size_t                mblkc = 0;

    addr = mbfp->meta_addr;
    mbfp->uniq = 0;

    /* Validate per-file header */
    omf_mblock_filehdr_unpack_letoh(addr, &fh);
    if (fh.fileid != mbfp->fileid)
        return merr(EBADMSG);

    if (fh.uniq != 0)
        mbfp->uniq = fh.uniq + MBLOCK_FILE_UNIQ_DELTA;

    bound = addr + mblock_file_meta_len(mbfp->fszmax, mbfp->mblocksz);
    addr += MBLOCK_FILE_META_HDRLEN;

    while (addr < bound) {
        struct mblock_oid_omf *mbomf;
        uint64_t               mbid;
        uint64_t               wlen;
        merr_t                 err;

        mbomf = (struct mblock_oid_omf *)addr;

        mbid = omf_mblk_id(mbomf);
        if (mbid != 0) {
            mblkc++; /* Debug */

            err = mblock_file_insert(mbfp, mbid);
            if (err)
                return merr(EBADMSG);

            wlen = omf_mblk_wlen(mbomf);

            atomic_set(mbfp->wlenv + block_id(mbid), wlen);
            atomic_inc(&mbfp->mbcnt);
            atomic_add(&mbfp->wlen, wlen);

            if (HSE_UNLIKELY(fh.uniq == 0))
                mbfp->uniq = max_t(uint32_t, mbfp->uniq, uniquifier(mbid) + 1);
        }

        addr += MBLOCK_FILE_META_OIDLEN;
    }

    log_debug("mclass %d, file-id %d found %lu valid mblocks, uniq %u.",
              mbfp->mcid, mbfp->fileid, mblkc, mbfp->uniq);

    return 0;
}

static inline bool
omf_isvalid(uint64_t mbid, uint64_t omfid, uint32_t wlen, uint32_t omfwlen, bool exists)
{
    return (exists && mbid == omfid && wlen == omfwlen) || (!exists && 0 == omfid && 0 == omfwlen);
}

static merr_t
mblock_file_meta_log(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, bool delete)
{
    struct mblock_oid_omf *mbomf;
    uint32_t block, wlen, omfwlen;
    char    *addr;
    int      rc;
    merr_t   err = 0;
    uint64_t omfid;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    addr = mbfp->meta_addr;
    block = block_id(*mbidv);

    wlen = atomic_read(mbfp->wlenv + block);

    addr += MBLOCK_FILE_META_HDRLEN;
    addr += (block * MBLOCK_FILE_META_OIDLEN);
    mbomf = (struct mblock_oid_omf *)addr;

    mutex_lock(&mbfp->meta_lock);
    omfid = omf_mblk_id(mbomf);
    omfwlen = omf_mblk_wlen(mbomf);

    if (!omf_isvalid(*mbidv, omfid, wlen, omfwlen, delete)) {
        mutex_unlock(&mbfp->meta_lock);
        return merr(EINVAL);
    }

    omf_set_mblk_id(mbomf, delete ? 0 : *mbidv);
    omf_set_mblk_wlen(mbomf, delete ? 0 : wlen);
    omf_set_mblk_rsvd1(mbomf, 0);
    omf_set_mblk_rsvd2(mbomf, 0);

    rc = msync((void *)((unsigned long)addr & PAGE_MASK), PAGE_SIZE, MS_SYNC);
    if (rc == -1)
        err = merr(errno);
    mutex_unlock(&mbfp->meta_lock);

    return err;
}

/**
 * Mblock file interfaces.
 */

merr_t
mblock_file_open(
    struct mblock_fset        *mbfsp,
    struct media_class        *mc,
    struct mblock_file_params *params,
    int                        flags,
    char                      *meta_addr,
    struct kmem_cache         *rmcache,
    struct mblock_file       **handle)
{
    struct mblock_file *mbfp;
    enum mclass_id      mcid;
    int    fd, rc, dirfd, mmapc, wlenc, fileid;
    merr_t err = 0;
    char   name[32];
    bool   create = false;
    size_t sz, mblocksz, fszmax;

    if (!mbfsp || !mc || !meta_addr || !handle || !params || !rmcache)
        return merr(EINVAL);

    if (flags & O_CREAT)
        create = true;

    mblocksz = params->mblocksz;
    fszmax = params->fszmax;
    fileid = params->fileid;

    mcid = mclass_id(mc);
    dirfd = mclass_dirfd(mc);
    snprintf(name, sizeof(name), "%s-%s-%d-%d", MBLOCK_FILE_PFX, "data", mcid, fileid);

    rc = faccessat(dirfd, name, F_OK, 0);
    if (rc == -1 && errno == ENOENT && !create)
        return merr(ENOENT);
    if (rc == 0 && create)
        return merr(EEXIST);

    mmapc = fszmax >> mblock_mmap_cshift(mblocksz);
    wlenc = fszmax >> ilog2(mblocksz);

    sz = sizeof(*mbfp);
    sz += roundup(wlenc * sizeof(*mbfp->wlenv), alignof(mbfp->mmapv));
    sz += mmapc * sizeof(*mbfp->mmapv);
    sz = roundup(sz, alignof(*mbfp));

    assert(alignof(*mbfp) >= alignof(mbfp->mmapv));

    mbfp = aligned_alloc(alignof(*mbfp), sz);
    if (!mbfp)
        return merr(ENOMEM);

    memset(mbfp, 0, sz);
    mbfp->fd = -1;
    mbfp->mbfsp = mbfsp;
    mbfp->meta_addr = meta_addr;
    mbfp->fileid = fileid;
    mbfp->mcid = mcid;
    mbfp->mblocksz = mblocksz;

    mbfp->fszmax = fszmax;
    err = mblock_rgnmap_init(mbfp, rmcache);
    if (err) {
        free(mbfp);
        return err;
    }

    mbfp->wlenv = (void *)(mbfp + 1);

    if (create) {
        struct mblock_filehdr fh = {};

        fh.fileid = fileid;
        err = mblock_file_meta_format(mbfp, &fh);
    } else {
        err = mblock_file_meta_load(mbfp);
    }
    if (err)
        goto err_exit;

    fd = openat(dirfd, name, flags | O_DIRECT | O_SYNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        goto err_exit;
    }
    mbfp->fd = fd;

    /* ftruncate to the maximum size to make it a sparse file */
    if ((flags & O_ACCMODE) != O_RDONLY) {
        rc = ftruncate(fd, mbfp->fszmax);
        if (rc == -1) {
            err = merr(errno);
            goto err_exit;
        }
    }

    mbfp->io = io_sync_ops;

    mutex_init(&mbfp->uniq_lock);
    mutex_init(&mbfp->meta_lock);

    mutex_init(&mbfp->mmap_lock);
    mbfp->mmapc = mmapc;
    mbfp->mmapv = (void *)roundup((uintptr_t)(mbfp->wlenv + wlenc), alignof(*mbfp->mmapv));

    *handle = mbfp;

    return 0;

err_exit:
    mblock_file_close(mbfp);

    if (create)
        unlinkat(dirfd, name, 0);

    return err;
}

void
mblock_file_close(struct mblock_file *mbfp)
{
    struct mblock_rgnmap *rgnmap;
    struct mblock_rgn    *rgn, *next;

    if (!mbfp)
        return;

    rgnmap = &mbfp->rgnmap;

    rbtree_postorder_for_each_entry_safe(rgn, next, &rgnmap->rm_root, rgn_node)
        kmem_cache_free(rgnmap->rm_cache, rgn);

    rgnmap->rm_cache = NULL;

    mblock_file_unmapall(mbfp);

    if (mbfp->fd != -1) {
        fsync(mbfp->fd);
        close(mbfp->fd);
    }

    free(mbfp);
}

merr_t
mblock_file_insert(struct mblock_file *mbfp, uint64_t mbid)
{
    return mblock_rgn_insert(&mbfp->rgnmap, block_id(mbid) + 1);
}

static merr_t
mblock_uniq_gen(struct mblock_file *mbfp, uint32_t *uniqout)
{
    uint32_t uniq;
    merr_t   err = 0;

    mutex_lock(&mbfp->uniq_lock);

    uniq = ++mbfp->uniq;
    if (uniq % MBLOCK_FILE_UNIQ_DELTA == 0) {
        struct mblock_filehdr fh = {};

        fh.fileid = mbfp->fileid;
        fh.uniq = uniq;

        err = mblock_file_meta_format(mbfp, &fh);
    }

    mutex_unlock(&mbfp->uniq_lock);

    if (!err && uniqout)
        *uniqout = uniq;

    return err;
}

merr_t
mblock_file_alloc(struct mblock_file *mbfp, int mbidc, uint64_t *mbidv)
{
    uint64_t mbid;
    uint32_t block, uniq;
    merr_t   err;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = mblock_rgn_alloc(&mbfp->rgnmap);
    if (block == 0)
        return merr(ENOSPC);

    err = mblock_uniq_gen(mbfp, &uniq);
    if (err) {
        mblock_rgn_free(&mbfp->rgnmap, block);
        return err;
    }

    if ((mbfp->fileid & (MBID_FILEID_MASK >> MBID_FILEID_SHIFT)) != mbfp->fileid ||
        (mbfp->mcid & (MBID_MCID_MASK >> MBID_MCID_SHIFT)) != mbfp->mcid ||
        ((block - 1) & MBID_BLOCK_MASK) != block - 1) {
        mblock_rgn_free(&mbfp->rgnmap, block);
        return merr(EBUG);
    }

    mbid = 0;
    mbid |= ((uint64_t)uniq << MBID_UNIQ_SHIFT);
    mbid |= ((uint64_t)mbfp->fileid << MBID_FILEID_SHIFT);
    mbid |= ((uint64_t)mbfp->mcid << MBID_MCID_SHIFT);
    mbid |= (block - 1);

    atomic_set(mbfp->wlenv + block - 1, 0);
    atomic_inc(&mbfp->mbcnt);

    *mbidv = mbid;

    return 0;
}

static merr_t
mblock_file_meta_validate(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, bool exists)
{
    struct mblock_oid_omf *mbomf;
    uint32_t               block, wlen, omfwlen;
    char                  *addr;
    uint64_t               omfid;
    merr_t                 err = 0;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    addr = mbfp->meta_addr;
    block = block_id(*mbidv);

    wlen = atomic_read(mbfp->wlenv + block);

    addr += MBLOCK_FILE_META_HDRLEN;
    addr += (block * MBLOCK_FILE_META_OIDLEN);

    mbomf = (struct mblock_oid_omf *)addr;
    omfid = omf_mblk_id(mbomf);
    omfwlen = omf_mblk_wlen(mbomf);

    if (!omf_isvalid(*mbidv, omfid, wlen, omfwlen, exists)) {
        if (exists && *mbidv != omfid)
            err = (omfid != 0) ? merr(ENOENT) : 0;
        else
            err = merr(EINVAL);
    }

    return err;
}

merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, uint32_t *wlen)
{
    uint32_t block;
    merr_t   err, err2;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = block_id(*mbidv);

    mutex_lock(&mbfp->meta_lock);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err && merr_errno(err) != ENOENT) {
        mutex_unlock(&mbfp->meta_lock);
        return err;
    }

    err2 = mblock_file_meta_validate(mbfp, mbidv, mbidc, !err);
    if (!err2 && wlen)
        *wlen = atomic_read(mbfp->wlenv + block);
    mutex_unlock(&mbfp->meta_lock);

    return err2 ?: err;
}

merr_t
mblock_file_commit(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    merr_t err;
    bool delete = false;
    uint32_t block;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = block_id(*mbidv);

    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    err = mblock_file_meta_log(mbfp, mbidv, mbidc, delete);
    if (err)
        return err;

    atomic_add(&mbfp->wlen, atomic_read(mbfp->wlenv + block));

    return 0;
}

merr_t
mblock_file_abort(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint32_t block;
    merr_t   err;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = block_id(*mbidv);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    err = mblock_file_meta_validate(mbfp, mbidv, mbidc, false);
    if (err)
        return err;

    err = mblock_rgn_free(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    atomic_set(mbfp->wlenv + block, 0);
    atomic_dec(&mbfp->mbcnt);

    return 0;
}

merr_t
mblock_file_delete(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint64_t block;
    size_t   mblocksz;
    merr_t   err;
    int      rc;
    bool delete = true;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = block_id(*mbidv);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    /* First log the delete */
    err = mblock_file_meta_log(mbfp, mbidv, mbidc, delete);
    if (err)
        return err;

    mblocksz = mbfp->mblocksz;
    /* Discard mblock */
    rc = fallocate(
        mbfp->fd,
        FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
        block_off(*mbidv, mblocksz),
        mblocksz);
    ev(rc);

    err = mblock_rgn_free(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    atomic_sub(&mbfp->wlen, atomic_read(mbfp->wlenv + block));
    atomic_set(mbfp->wlenv + block, 0);
    atomic_dec(&mbfp->mbcnt);

    return 0;
}

static merr_t
iov_len_get(const struct iovec *iov, int iovc, size_t *tlen)
{
    uintptr_t align = 0;
    size_t len = 0;
    int    i;

    for (i = 0; i < iovc; i++) {
        align |= (uintptr_t)iov[i].iov_base;
        len += iov[i].iov_len;
    }

    if (!PAGE_ALIGNED(align))
        return merr(EINVAL);

    *tlen = len;

    return 0;
}

merr_t
mblock_file_read(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    uint32_t  block;
    off_t     roff, eoff;
    size_t    len = 0, mblocksz, wlen;
    merr_t    err;
    atomic_t *wlenp;

    if (!mbfp || !iov)
        return merr(EINVAL);

    if (iovc == 0)
        return 0;

    if (!PAGE_ALIGNED(off))
        return merr(EINVAL);

    block = block_id(mbid);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    wlenp = mbfp->wlenv + block;
    wlen = atomic_read(wlenp);

    mblocksz = mbfp->mblocksz;
    roff = block_off(mbid, mblocksz);
    eoff = roff + wlen - 1;
    roff += off;

    err = iov_len_get(iov, iovc, &len);
    if (err)
        return err;

    if (!PAGE_ALIGNED(len) || (roff + len - 1 > eoff))
        return merr(EINVAL);

    return mbfp->io.read(mbfp->fd, roff, iov, iovc, 0, NULL);
}

merr_t
mblock_file_write(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc)
{
    uint32_t  block;
    size_t    len = 0, mblocksz;
    off_t     woff, eoff, off;
    merr_t    err;
    atomic_t *wlenp;

    if (!mbfp || !iov)
        return merr(EINVAL);

    if (iovc == 0)
        return 0;

    block = block_id(mbid);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    wlenp = mbfp->wlenv + block;
    off = atomic_read(wlenp);
    assert(PAGE_ALIGNED(off));

    mblocksz = mbfp->mblocksz;
    woff = block_off(mbid, mblocksz);
    eoff = woff + mblocksz - 1;
    woff += off;

    err = iov_len_get(iov, iovc, &len);
    if (err)
        return err;

    if (!PAGE_ALIGNED(len) || (woff + len - 1 > eoff))
        return merr(EINVAL);

    err = mbfp->io.write(mbfp->fd, woff, iov, iovc, 0, NULL);
    if (!err)
        atomic_add(wlenp, len);

    return err;
}

static HSE_ALWAYS_INLINE size_t
mblock_mmap_csize(size_t mblocksz)
{
    return mblocksz * MBLOCK_MMAP_CHUNK_MAX;
}

static HSE_ALWAYS_INLINE uint64_t
mblock_mmap_cmask(size_t mblocksz)
{
    return ~(mblock_mmap_csize(mblocksz) - 1);
}

static HSE_ALWAYS_INLINE int
mblock_mmap_cshift(size_t mblocksz)
{
    return ilog2(mblock_mmap_csize(mblocksz));
}

static HSE_ALWAYS_INLINE uint32_t
chunk_idx(uint64_t mbid, size_t mblocksz)
{
    return block_off(mbid, mblocksz) >> mblock_mmap_cshift(mblocksz);
}

static HSE_ALWAYS_INLINE uint64_t
chunk_start_off(uint64_t mbid, size_t mblocksz)
{
    return block_off(mbid, mblocksz) & mblock_mmap_cmask(mblocksz);
}

static HSE_ALWAYS_INLINE uint64_t
chunk_off(uint64_t mbid, size_t mblocksz)
{
    return block_off(mbid, mblocksz) ^ chunk_start_off(mbid, mblocksz);
}

merr_t
mblock_file_map_getbase(struct mblock_file *mbfp, uint64_t mbid, char **addr_out, uint32_t *wlen)
{
    struct mblock_mmap *map;
    char               *addr;
    int                 cidx, rc;
    off_t               soff, off;
    size_t              mblocksz;
    merr_t              err = 0;

    if (!mbfp || !addr_out)
        return merr(EINVAL);

    mblocksz = mbfp->mblocksz;
    cidx = chunk_idx(mbid, mblocksz);
    map = &mbfp->mmapv[cidx];

    soff = chunk_start_off(mbid, mblocksz);
    off = chunk_off(mbid, mblocksz);

    mutex_lock(&mbfp->mmap_lock);
    addr = map->addr;
    if (!addr) {
        /* Setup map */
        addr = mmap(NULL, mblock_mmap_csize(mblocksz), PROT_READ, MAP_SHARED, mbfp->fd, soff);
        if (addr == MAP_FAILED) {
            err = merr(errno);
            goto exit;
        }

        rc = madvise(addr, mblock_mmap_csize(mblocksz), MADV_RANDOM);
        if (rc) {
            err = merr(errno);
            goto exit;
        }

        map->addr = addr;
        assert(map->ref == 0);
        map->ref = 1;
    } else {
        assert(map->ref >= 1);
        ++map->ref;

        rc = mprotect(addr + off, mbfp->mblocksz, PROT_READ);
        if (rc)
            err = merr(errno);
    }
exit:
    mutex_unlock(&mbfp->mmap_lock);

    if (!err) {
        *addr_out = addr + off;
        *wlen = atomic_read(mbfp->wlenv + block_id(mbid));
    }

    return err;
}

merr_t
mblock_file_unmap(struct mblock_file *mbfp, uint64_t mbid)
{
    struct mblock_mmap *map;
    char               *addr;
    int                 cidx;
    size_t              mblocksz;
    merr_t              err = 0;

    if (!mbfp)
        return merr(EINVAL);

    mblocksz = mbfp->mblocksz;
    cidx = chunk_idx(mbid, mblocksz);
    map = &mbfp->mmapv[cidx];

    mutex_lock(&mbfp->mmap_lock);
    addr = map->addr;
    assert(addr);
    if (--map->ref == 0) {
        int rc;

        rc = madvise(addr, mblock_mmap_csize(mblocksz), MADV_DONTNEED);
        ev(rc);

        rc = munmap(addr, mblock_mmap_csize(mblocksz));
        if (rc)
            err = merr(errno);
        else
            map->addr = NULL;
    }
    mutex_unlock(&mbfp->mmap_lock);

    return err;
}

static void
mblock_file_unmapall(struct mblock_file *mbfp)
{
    struct mblock_mmap *map;
    int                 i;

    if (!mbfp)
        return;

    mutex_lock(&mbfp->mmap_lock);
    for (i = 0; i < mbfp->mmapc; i++) {
        char *addr;

        map = &mbfp->mmapv[i];

        addr = map->addr;
        if (addr) {
            int rc;

            log_warn("Leaked map mcid %d fileid %d chunk-id %d ref %lu",
                     mbfp->mcid, mbfp->fileid, i, map->ref);

            rc = munmap(addr, mblock_mmap_csize(mbfp->mblocksz));
            ev(rc);

            map->addr = NULL;
            map->ref = 0;
        }
    }
    mutex_unlock(&mbfp->mmap_lock);
}

merr_t
mblock_file_stats_get(struct mblock_file *mbfp, struct mblock_file_stats *stats)
{
    struct stat sbuf;
    int         rc;

    if (!mbfp || !stats)
        return merr(EINVAL);

    rc = fstat(mbfp->fd, &sbuf);
    if (rc == -1)
        return merr(errno);
    stats->allocated = 512 * sbuf.st_blocks;

    stats->used = atomic_read(&mbfp->wlen);
    stats->mbcnt = atomic_read(&mbfp->mbcnt);

    return 0;
}
