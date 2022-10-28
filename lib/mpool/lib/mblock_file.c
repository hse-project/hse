/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <ftw.h>
#include <sys/mman.h>

#include <hse/logging/logging.h>
#include <hse/util/platform.h>
#include <hse/util/assert.h>
#include <hse/util/mutex.h>
#include <hse/util/slab.h>
#include <hse/util/event_counter.h>
#include <hse/util/minmax.h>
#include <hse/util/log2.h>
#include <hse/util/page.h>

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
    struct mutex   rm_lock HSE_ACP_ALIGNED;
    struct rb_root rm_root;

    struct kmem_cache *rm_cache HSE_L1D_ALIGNED;
};

/**
 * struct mblock_mmap -
 *
 * @addr: base address of the mmap chunk
 * @ref:  ref. count on the mapped chunk
 */
struct mblock_mmap {
    char   *addr HSE_ACP_ALIGNED;
    int64_t ref HSE_L1D_ALIGNED;
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
    struct io_ops       dataio;
    struct io_ops       metaio;

    size_t         fszmax;
    size_t         mblocksz;
    enum mclass_id mcid;
    int            fileid;
    int            fd;

    atomic_uint_least32_t *wlenv;

    struct mutex uniq_lock HSE_L1D_ALIGNED;
    uint32_t     uniq;

    struct mutex meta_lock HSE_L1D_ALIGNED;
    char        *meta_addr;
    char        *meta_ugaddr;

    struct mutex        mmap_lock HSE_L1D_ALIGNED;
    int                 mmapc;
    struct mblock_mmap *mmapv;

    atomic_long wlen HSE_L1D_ALIGNED;
    atomic_int  mbcnt;
};

/* clang-format on */

/* Forward declarations */
static void
mblock_file_unmap(struct mblock_file *mbfp);

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

static HSE_ALWAYS_INLINE off_t
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
mblock_file_meta_len(size_t fszmax, size_t mblocksz, uint32_t version)
{
    size_t mblkc;

    mblkc = fszmax >> ilog2(mblocksz);

    return MBLOCK_FILE_META_HDRLEN + mblkc * omf_mblock_oid_len(version);
}

static merr_t
mblock_file_meta_format(struct mblock_file *mbfp, char *addr, struct mblock_filehdr *fh)
{
    omf_mblock_filehdr_pack(fh, addr);

    return mbfp->metaio.msync(addr, omf_mblock_filehdr_len(MBLOCK_METAHDR_VERSION), MS_SYNC);
}

static void
mblock_file_upgrade_log(char *ugaddr, uint64_t mbid, uint32_t wlen)
{
    struct mblock_oid_info mbinfo;
    uint32_t block;

    block = block_id(mbid);

    ugaddr += MBLOCK_FILE_META_HDRLEN;
    ugaddr += (block * omf_mblock_oid_len(MBLOCK_METAHDR_VERSION));

    mbinfo.mb_oid = mbid;
    mbinfo.mb_wlen = wlen;
    omf_mblock_oid_pack(&mbinfo, ugaddr);
}

static merr_t
mblock_file_meta_load(struct mblock_file *mbfp, uint32_t version, bool gclose, bool rdonly)
{
    struct mblock_filehdr fh = {};
    char                 *addr, *end;
    size_t                mblkc = 0;
    merr_t                err;
    bool                  upgrade = (!!mbfp->meta_ugaddr && !rdonly);

    addr = mbfp->meta_addr;
    mbfp->uniq = 0;

    err = omf_mblock_filehdr_unpack(addr, version, gclose, &fh);
    if ((err && merr_errno(err) != ENOMSG) || (fh.fileid != mbfp->fileid))
        return err ?: merr(EBADMSG);

    /*
     * Likely crash while updating file header during mblock allocation.
     * Adding MBLOCK_FILE_UNIQ_DELTA to fh.uniq below takes care of this scenario.
     */
    if (ev(err)) {
        assert(merr_errno(err) == ENOMSG);
        err = 0;
    }

    if (upgrade)
        mblock_file_meta_format(mbfp, mbfp->meta_ugaddr, &fh);

    if (fh.uniq != 0)
        mbfp->uniq = fh.uniq + MBLOCK_FILE_UNIQ_DELTA;

    end = addr + mblock_file_meta_len(mbfp->fszmax, mbfp->mblocksz, version);
    addr += MBLOCK_FILE_META_HDRLEN;

    while (addr < end) {
        struct mblock_oid_info mbinfo;
        merr_t                 err;

        /* ENOMSG return indicates a likely crash while logging mblock commit/delete op */
        err = omf_mblock_oid_unpack(addr, version, gclose, &mbinfo);
        if (err && merr_errno(err) != ENOMSG)
            return err;

        if (!err && mbinfo.mb_oid != 0) {
            mblkc++; /* Debug */

            err = mblock_file_insert(mbfp, mbinfo.mb_oid);
            if (err)
                return merr(EBADMSG);

            atomic_set(mbfp->wlenv + block_id(mbinfo.mb_oid), mbinfo.mb_wlen);
            atomic_inc(&mbfp->mbcnt);
            atomic_add(&mbfp->wlen, mbinfo.mb_wlen & MBLOCK_WLEN_MASK);

            if (HSE_UNLIKELY(fh.uniq == 0))
                mbfp->uniq = max_t(uint32_t, mbfp->uniq, uniquifier(mbinfo.mb_oid) + 1);

            if (upgrade)
                mblock_file_upgrade_log(mbfp->meta_ugaddr, mbinfo.mb_oid, mbinfo.mb_wlen);
        } else if (err && !rdonly) {
            assert(merr_errno(err) == ENOMSG);
            omf_mblock_oid_pack_zero(addr);
            mbfp->metaio.msync(addr, omf_mblock_oid_len(MBLOCK_METAHDR_VERSION), MS_SYNC);
        }

        addr += omf_mblock_oid_len(version);
    }

    if (upgrade) {
        char *start;

        addr = mbfp->meta_ugaddr;
        start = (void *)((uintptr_t)addr & PAGE_MASK);
        end = addr + mblock_file_meta_len(mbfp->fszmax, mbfp->mblocksz, MBLOCK_METAHDR_VERSION);

        err = mbfp->metaio.msync(start, end - start, MS_SYNC);
        if (err)
            return err;
    }

    log_debug("mclass %d, file-id %d found %lu valid mblocks, uniq %u",
              mbfp->mcid, mbfp->fileid, mblkc, mbfp->uniq);

    return 0;
}

static inline bool
mblock_oid_isvalid(uint64_t mbid, uint64_t omfid, uint32_t wlen, uint32_t omfwlen, bool exists)
{
    return (exists && mbid == omfid && wlen == omfwlen) || (0 == omfid && 0 == omfwlen);
}

static merr_t
mblock_file_meta_log(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, bool delete)
{
    struct mblock_oid_info mbinfo;
    uint32_t block, wlen, oid_len;
    char    *addr;
    merr_t   err = 0;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    addr = mbfp->meta_addr;
    block = block_id(*mbidv);

    wlen = atomic_read(mbfp->wlenv + block);
    oid_len = omf_mblock_oid_len(MBLOCK_METAHDR_VERSION);

    addr += MBLOCK_FILE_META_HDRLEN;
    addr += (block * oid_len);

    mutex_lock(&mbfp->meta_lock);

    err = omf_mblock_oid_unpack(addr, MBLOCK_METAHDR_VERSION, true, &mbinfo);

    if (err || !mblock_oid_isvalid(*mbidv, mbinfo.mb_oid, wlen, mbinfo.mb_wlen, delete)) {
        mutex_unlock(&mbfp->meta_lock);
        return err ?: merr(EINVAL);
    }

    if (delete) {
        omf_mblock_oid_pack_zero(addr);
    } else {
        mbinfo.mb_oid = *mbidv;
        mbinfo.mb_wlen = wlen;
        omf_mblock_oid_pack(&mbinfo, addr);
    }

    err = mbfp->metaio.msync(addr, oid_len, MS_SYNC);
    mutex_unlock(&mbfp->meta_lock);

    return err;
}

/**
 * Mblock file interfaces.
 */

void
mblock_wlen_set(struct mblock_file *mbfp, uint64_t mbid, uint32_t wlen, bool prealloc)
{
    INVARIANT(mbfp);
    INVARIANT(wlen <= mbfp->mblocksz);

    if (prealloc)
        wlen |= (1U << MBLOCK_WLEN_PREALLOC_SHIFT);

    atomic_set(mbfp->wlenv + block_id(mbid), wlen);
}

static HSE_ALWAYS_INLINE uint32_t
mblock_wlen_get(const struct mblock_file *mbfp, uint64_t mbid)
{
    return atomic_read(mbfp->wlenv + block_id(mbid)) & MBLOCK_WLEN_MASK;
}

static HSE_ALWAYS_INLINE bool
mblock_is_prealloc(const struct mblock_file *mbfp, uint64_t mbid)
{
    const uint32_t wlen = atomic_read(mbfp->wlenv + block_id(mbid));

    return (wlen >> MBLOCK_WLEN_PREALLOC_SHIFT) == 1;
}

static HSE_ALWAYS_INLINE void
mblock_wlen_add(struct mblock_file *mbfp, uint64_t mbid, uint32_t len)
{
    bool prealloc = mblock_is_prealloc(mbfp, mbid);
    uint32_t wlen = mblock_wlen_get(mbfp, mbid);

    mblock_wlen_set(mbfp, mbid, wlen + len, prealloc);
}

merr_t
mblock_file_open(
    struct mblock_fset        *mbfsp,
    struct media_class        *mc,
    struct mblock_file_params *params,
    int                        flags,
    uint32_t                   version,
    struct mblock_file       **handle)
{
    struct mblock_file *mbfp;
    enum mclass_id      mcid;
    int    fd, rc, dirfd, mmapc, wlenc, fileid;
    merr_t err = 0;
    char   name[32];
    bool   create = (flags & O_CREAT), rdonly = ((flags & O_ACCMODE) == O_RDONLY);
    size_t sz, mblocksz, fszmax;

    if (!mbfsp || !mc || !handle || !params)
        return merr(EINVAL);

    INVARIANT(params->rmcache && params->meta_addr);

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
    sz += roundup(wlenc * sizeof(*mbfp->wlenv), __alignof__(*mbfp->mmapv));
    sz += mmapc * sizeof(*mbfp->mmapv);
    sz = roundup(sz, __alignof__(*mbfp));

    assert(__alignof__(*mbfp) >= __alignof__(*mbfp->mmapv));

    mbfp = aligned_alloc(__alignof__(*mbfp), sz);
    if (!mbfp)
        return merr(ENOMEM);

    memset(mbfp, 0, sz);
    mbfp->fd = -1;
    mbfp->mbfsp = mbfsp;
    mbfp->meta_addr = params->meta_addr;
    mbfp->fileid = fileid;
    mbfp->mcid = mcid;
    mbfp->mblocksz = mblocksz;
    mbfp->dataio = io_sync_ops;
    mbfp->metaio = *params->metaio;

    mbfp->fszmax = fszmax;
    err = mblock_rgnmap_init(mbfp, params->rmcache);
    if (err) {
        free(mbfp);
        return err;
    }

    mbfp->wlenv = (void *)(mbfp + 1);

    if (create) {
        struct mblock_filehdr fh = {};

        fh.fileid = fileid;
        err = mblock_file_meta_format(mbfp, mbfp->meta_addr, &fh);
    } else {
        mbfp->meta_ugaddr = params->meta_ugaddr;
        err = mblock_file_meta_load(mbfp, version, params->gclose, rdonly);
        if (!err && mbfp->meta_ugaddr)
            mbfp->meta_addr = mbfp->meta_ugaddr;
    }
    if (err)
        goto err_exit;

    fd = openat(dirfd, name, flags | O_SYNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        goto err_exit;
    }
    mbfp->fd = fd;

    /* ftruncate to the maximum size to make it a sparse file */
    if (!rdonly) {
        rc = ftruncate(fd, mbfp->fszmax);
        if (rc == -1) {
            err = merr(errno);
            goto err_exit;
        }
    }

    mutex_init(&mbfp->uniq_lock);
    mutex_init(&mbfp->meta_lock);

    mutex_init(&mbfp->mmap_lock);
    mbfp->mmapc = mmapc;
    mbfp->mmapv = (void *)roundup((uintptr_t)(mbfp->wlenv + wlenc), __alignof__(*mbfp->mmapv));

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

    mblock_file_unmap(mbfp);

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

        err = mblock_file_meta_format(mbfp, mbfp->meta_addr, &fh);
    }

    mutex_unlock(&mbfp->uniq_lock);

    if (!err && uniqout)
        *uniqout = uniq;

    return err;
}

merr_t
mblock_file_alloc(struct mblock_file *mbfp, uint32_t flags, int mbidc, uint64_t *mbidv)
{
    uint64_t mbid;
    uint32_t block, uniq;
    merr_t   err;
    bool     prealloc, punch_hole;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    prealloc = (flags & MPOOL_MBLOCK_PREALLOC);
    punch_hole = (flags & MPOOL_MBLOCK_PUNCH_HOLE);

    if (prealloc && punch_hole)
        return merr(EINVAL);

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

    if (prealloc) {
        int rc;

        rc = posix_fallocate(mbfp->fd, block_off(mbid, mbfp->mblocksz), mbfp->mblocksz);
        if (ev(rc != 0)) /* advisory */
            prealloc = false;
    } else if (punch_hole) {
        int rc;

        rc = fallocate(mbfp->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                       block_off(mbid, mbfp->mblocksz), mbfp->mblocksz);
        if (rc == -1) {
            mblock_rgn_free(&mbfp->rgnmap, block);
            return merr(errno);
        }
    }

    mblock_wlen_set(mbfp, mbid, 0, prealloc);
    atomic_inc(&mbfp->mbcnt);

    *mbidv = mbid;

    return 0;
}

static merr_t
mblock_file_meta_validate(const struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, bool exists)
{
    struct mblock_oid_info mbinfo;
    uint32_t               block, wlen;
    char                  *addr;
    merr_t                 err = 0;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    addr = mbfp->meta_addr;
    block = block_id(*mbidv);

    wlen = atomic_read(mbfp->wlenv + block);

    addr += MBLOCK_FILE_META_HDRLEN;
    addr += (block * omf_mblock_oid_len(MBLOCK_METAHDR_VERSION));

    err = omf_mblock_oid_unpack(addr, MBLOCK_METAHDR_VERSION, true, &mbinfo);

    if (!err && !mblock_oid_isvalid(*mbidv, mbinfo.mb_oid, wlen, mbinfo.mb_wlen, exists)) {
        if (exists && *mbidv != mbinfo.mb_oid)
            err = (mbinfo.mb_oid != 0) ? merr(ENOENT) : 0;
        else
            err = merr(EINVAL);
    }

    return err;
}

merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, struct mblock_props *props)
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
    if (!err && !err2 && props) {
        props->mpr_objid = *mbidv;
        props->mpr_mclass = mcid_to_mclass(mbfp->mcid);
        props->mpr_write_len = mblock_wlen_get(mbfp, *mbidv);
        if (mblock_is_prealloc(mbfp, *mbidv))
            props->mpr_alloc_cap = mbfp->mblocksz;
        else
            props->mpr_alloc_cap = props->mpr_write_len;
    }
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

    hse_wmesg_tls = "mbcommit";
    err = mblock_file_meta_log(mbfp, mbidv, mbidc, delete);
    hse_wmesg_tls = "-";

    return err;
}

merr_t
mblock_file_delete(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc)
{
    uint32_t block;
    off_t    mblocksz;
    merr_t   err;
    int      rc;

    if (!mbfp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    block = block_id(*mbidv);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    err = mblock_file_meta_log(mbfp, mbidv, mbidc, true);
    if (err)
        return err;

    mblocksz = mbfp->mblocksz;
    rc = fallocate(mbfp->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                   block_off(*mbidv, mblocksz), mblocksz);
    ev(rc);

    atomic_sub(&mbfp->wlen, mblock_wlen_get(mbfp, *mbidv));
    mblock_wlen_set(mbfp, *mbidv, 0, false);
    atomic_dec(&mbfp->mbcnt);

    err = mblock_rgn_free(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

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
mblock_read(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc, off_t off)
{
    uint32_t  block;
    off_t     roff, eoff;
    size_t    len = 0, mblocksz, wlen;
    merr_t    err;

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

    wlen = mblock_wlen_get(mbfp, mbid);

    mblocksz = mbfp->mblocksz;
    roff = block_off(mbid, mblocksz);
    eoff = roff + wlen - 1;
    roff += off;

    err = iov_len_get(iov, iovc, &len);
    if (err)
        return err;

    if (!PAGE_ALIGNED(len) || (roff + len - 1 > eoff)) {
        log_err("Failed mblock read check: len %ld roff %ld eoff %ld block %u wlen %ld",
                len, roff, eoff, block, wlen);
        return merr(EINVAL);
    }

    hse_wmesg_tls = "mbread";
    err = mbfp->dataio.read(mbfp->fd, roff, iov, iovc, 0, NULL);
    hse_wmesg_tls = "-";

    return err;
}

merr_t
mblock_write(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc)
{
    uint32_t block;
    size_t len = 0, mblocksz;
    off_t woff, eoff, off;
    merr_t err;

    if (!mbfp || !iov)
        return merr(EINVAL);

    if (iovc == 0)
        return 0;

    block = block_id(mbid);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    off = mblock_wlen_get(mbfp, mbid);
    assert(PAGE_ALIGNED(off));

    mblocksz = mbfp->mblocksz;
    woff = block_off(mbid, mblocksz);
    eoff = woff + mblocksz - 1;
    woff += off;

    err = iov_len_get(iov, iovc, &len);
    if (err)
        return err;

    if (!PAGE_ALIGNED(len) || (woff + len - 1 > eoff)) {
        log_err("Failed mblock write check: len %ld woff %ld eoff %ld block %u",
                len, woff, eoff, block);
        return merr(EINVAL);
    }

    hse_wmesg_tls = "mbwrite";
    err = mbfp->dataio.write(mbfp->fd, woff, iov, iovc, 0, NULL);
    hse_wmesg_tls = "-";

    if (!err) {
        mblock_wlen_add(mbfp, mbid, len);
        atomic_add(&mbfp->wlen, len);
    }

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

static HSE_ALWAYS_INLINE off_t
chunk_start_off(uint64_t mbid, size_t mblocksz)
{
    return block_off(mbid, mblocksz) & mblock_mmap_cmask(mblocksz);
}

static HSE_ALWAYS_INLINE off_t
chunk_off(uint64_t mbid, size_t mblocksz)
{
    return block_off(mbid, mblocksz) ^ chunk_start_off(mbid, mblocksz);
}

merr_t
mblock_map_getbase(struct mblock_file *mbfp, uint64_t mbid, char **addr_out, uint32_t *wlen)
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

    hse_wmesg_tls = "mbmapget";

    mutex_lock(&mbfp->mmap_lock);
    addr = map->addr;
    if (!addr) {
        /* Setup map */
        err = mbfp->dataio.mmap((void **)&addr, mblock_mmap_csize(mblocksz), PROT_READ,
                                MAP_SHARED, mbfp->fd, soff);
        if (err)
            goto exit;

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

    hse_wmesg_tls = "-";

    if (!err) {
        *addr_out = addr + off;
        *wlen = mblock_wlen_get(mbfp, mbid);
    }

    return err;
}

merr_t
mblock_unmap(struct mblock_file *mbfp, uint64_t mbid)
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

    hse_wmesg_tls = "mbunmap";

    mutex_lock(&mbfp->mmap_lock);
    addr = map->addr;
    assert(addr);
    if (--map->ref == 0) {
        int rc;

        rc = madvise(addr, mblock_mmap_csize(mblocksz), MADV_DONTNEED);
        ev(rc);

        err = mbfp->dataio.munmap(addr, mblock_mmap_csize(mblocksz));
        if (!err)
            map->addr = NULL;
    }
    mutex_unlock(&mbfp->mmap_lock);

    hse_wmesg_tls = "-";

    return err;
}

static void
mblock_file_unmap(struct mblock_file *mbfp)
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
mblock_file_info_get(const struct mblock_file *mbfp, struct mblock_file_info *info)
{
    struct stat sbuf;
    int         rc;

    INVARIANT(mbfp);
    INVARIANT(info);

    rc = fstat(mbfp->fd, &sbuf);
    if (rc == -1)
        return merr(errno);

    info->allocated = S_BLKSIZE * sbuf.st_blocks;
    info->used = atomic_read(&mbfp->wlen);

    return 0;
}

merr_t
mblock_info_get(struct mblock_file *mbfp, uint64_t mbid, struct mblock_file_mbinfo *mbinfo)
{
    uint32_t block;
    merr_t err;

    block = block_id(mbid);
    err = mblock_rgn_find(&mbfp->rgnmap, block + 1);
    if (err)
        return err;

    mbinfo->fd = mbfp->fd;
    mbinfo->off = block_off(mbid, mbfp->mblocksz);
    mbinfo->wlen = mblock_wlen_get(mbfp, mbid);

    return 0;
}
