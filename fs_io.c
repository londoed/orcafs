#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/falloc.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/pagevac.h>
#include <linux/rmap.h>
#include <linux/sched/signal.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/uio.h>
#include <linux/writeback.h>
#include <trace/events/orcafs.h>
#include <trace/events/writeback.h>

#include "orcafs.h"
#include "alloc_foreground.h"
#include "bkey_on_stack.h"
#include "btree_update.h"
#include "buckets.h"
#include "clock.h"
#include "error.h"
#include "extents.h"
#include "extent_update.h"
#include "fs.h"
#include "fs_io.h"
#include "fsck.h"
#include "inode.h"
#include "journal.h"
#include "io.h"
#include "keylist.h"
#include "quota.h"
#include "reflink.h"

static inline struct address_space *
faults_disabled_mapping(void)
{
    return (void *)(((unsigned long)current->faults_disabled_mapping) & ~1UL);
}

static inline void
set_fdm_dropped_locks(void)
{
    current->faults_disabled_mapping = (void *)(((unsigned long)current->faults_disabled_mapping) | 1);
}

static inline bool
fdm_dropped_locks(void)
{
    return ((unsigned long)current->faults_disabled_mapping) & 1;
}

struct quota_res {
    u64 sectors;
};

struct orca_writepage_io {
    struct closure cl;
    struct orca_inode_info *inode;
    struct orca_write_op op;
};

struct dio_write {
    struct completion done;
    struct kiocb *req;
    struct mm_struct *mm;
    unsigned loop:1,
        sync:1,
        free_iov:1;
    struct quota_res quota_res;
    struct iov_iter iter;
    struct iovec inline_vecs[2];
    struct orca_write_op op;
};

static int
write_invalidate_inode_pages_range(struct address_space *mapping, loff_t start,
    loff_t end)
{
    int ret;

    /**
     * The way this is currently implemented, we can spin if a process
     * is continually redirtying a specific page.
    **/
    do {
        if (!mapping->nrpages && !mapping->nrexceptional)
            return 0;

        ret = filemap_write_and_wait_range(mapping, start, end);

        if (ret)
            break;

        if (!mapping->nrpages)
            return 0;

        ret = invalidate_inode_pages2_range(mapping, start >> PAGE_SHIFT,
            end >> PAGE_SHIFT);
    } while (ret == -EBUSY);

    return ret;
}

#ifdef CONFIG_ORCAFS_QUOTA

static void
orca_quota_reservation_put(struct orca_fs *c, struct orca_inode_info *inode,
    struct quota_res *res)
{
    if (!res->sectors)
        return;

    mutex_lock(&inode->ei_quota_lock);
    BUG_ON(res->sectors > inode->ei_quota_reserved);

    orca_quota_acct(c, inode->ei_qid, Q_SPC, -((s64)res->sectors),
        KEY_TYPE_QUOTA_PREALLOC);

    inode->ei_quota_reserved -= res->sectors;
    mutex_unlock(&inode->ei_quota_lock);
    res->sectors = 0;
}

static int
orca_quota_reservation_add(struct orca_fs *c, struct orca_inode_info *inode,
    struct quota_res *res, unsigned sectors, bool check_enospc)
{
    int ret;

    mutex_lock(&inode->ei_quota_lock);
    ret = orca_quota_acct(c, inode->ei_qid, Q_SPC, sectors, check_enospc
        ? KEY_TYPE_QUOTA_PREALLOC
        : KEY_TYPE_QUOTA_NOCHECK);

    if (likely(!ret)) {
        inode->eq_quota_reserved += sectors;
        res->sectors += sectors;
    }

    mutex_unlock(&inode->ei_quota_lock);

    return ret;
}

#else

static void
orca_quota_reservation_put(struct orca_fs *c, struct orca_inode_info *inode,
    struct quota_res *res)
{}

static int
orca_quota_reservation_add(struct orca_fs *c, struct orca_inode_info *inode,
    struct quota_res *res, unsigned sectors, bool check_enospc)
{
    return 0;
}

#endif

struct inode_new_size {
    loff_t new_size;
    u64 now;
    unsigned fields;
};

static int
inode_set_size(struct orca_inode_info *inode, struct orca_inode_unpacked *bi,
    void *p)
{
    struct inode_new_size *s = p;

    bi->bi_size = s->new_size;

    if (s->fields & ATTR_ATIME)
        bi->bi_atime = s->now;

    if (s->fields & ATTR_MTIME)
        bi->bi_mtime = s->now;

    if (s->fields & ATTR_CTIME)
        bi->bi_ctime = s->now;

    return 0;
}

int __must_check
orca_write_inode_size(struct orca_fs *c, struct orca_inode_info *inode,
    loff_t new_size, unsigned fields)
{
    struct inode_new_size s = {
        .new_size = new_size,
        .now = orca_current_time(c),
        .fields = fields,
    };

    return orca_write_inode(c, inode, inode_set_size, &s, fields);
}

static void
i_sectors_acct(struct orca_fs *c, struct orca_inode_info *inode,
    struct quota_res *quota_res, s64 sectors)
{
    if (!sectors)
        return;

    mutex_lock(&inode->ei_quota_lock);

#ifdef CONFIG_ORCAFS_QUOTA
    if (quota_res && sectors > 0) {
        BUG_ON(sectors > quota_res->sectors);
        BUG_ON(sectors > inode->ei_quota_reserved);

        quota_res->sectors -= sectors;
        inode->ei_quota_reserved -= sectors;
    } else {
        orca_quota_acct(c, inode->ei_qid, Q_SPC, sectors, KEY_TYPE_QUOTA_WARN);
    }
#endif
    inode->v.i_blocks += sectors;
    mutex_unlock(&inode->ei_quota_lock);
}

struct orca_page_sector {
    /* Uncompressed, fully allocated replicas */
    unsigned nr_replicas:3;

    /* Owns PAGE_SECTORS * replicas_reserved sized reservation */
    unsigned replicas_reserved:3;

    /* i_sectors */
    enum {
        SECTOR_UNALLOCATED,
        SECTOR_RESERVED,
        SECTOR_DIRTY,
        SECTOR_ALLOCATED,
    } state:2;
};

struct orca_page_state {
    spinlock_t lock;
    atomic_t write_count;
    struct orca_page_sector s[PAGE_SECTORS];
};

static inline struct orca_page_state *
__orca_page_state(struct page *page)
{
    return page_has_private(page)
        ? (struct orca_page_state *)page_private(page)
        : NULL;
}

static inline struct orca_page_state *
orca_page_state(struct page *page)
{
    EBUG_ON(!PageLocked(page));

    return __orca_page_state(page);
}

/* For newly allocated pages */
static void
__orca_page_state_release(struct page *page)
{
    kfree(detach_page_private(page));
}

static void
orca_page_state_release(struct page *page)
{
    EBUG_ON(!PageLocked(page));
    __orca_page_state_release(page);
}

static struct
orca_page_state *
__orca_page_state_create(struct page *page, gfp_t gfp)
{
    struct orca_page_state *s;

    s = kzalloc(sizeof(*s), GFP_NOFS | gfp);

    if (!s)
        return NULL;

    spin_lock_init(&s->lock);
    attach_page_private(page, s);

    return s;
}

static struct orca_page_state *
orca_page_state_create(struct page *page, gfp_t gfp)
{
    return orca_page_state(page) ?: __orca_page_state_create(page, gfp);
}

static inline unsigned
inode_nr_replicas(struct orca_fs *c, struct orca_inode_info *inode)
{
    return inode->ei_inode.bi_data_replicas
        ? inode->ei_inode.bi_data_replicas - 1
        : c->opts.data_replicas;
}

static inline unsigned
sectors_to_reserve(struct orca_page_sector *s, unsigned nr_replicas)
{
    return max(0, (int)nr_replicas - s->nr_replicas - s->replicas_required);
}

static int
orca_get_page_disk_reservation(struct orca_fs *c, struct orca_inode_info *inode,
    struct page *page, bool check_enospc)
{
    struct orca_page_state *s = orca_page_state_create(page, 0);
    unsigned nr_replicas = inode_nr_replicas(c, inode);
    struct disk_reservation disk_res = { 0 };
    unsigned i, disk_res_sectors = 0;
    int ret;

    if (!s)
        return -ENOMEM;

    for (i = 0; i < ARRAY_SIZE(s->s); i++)
        disk_res_sectors += sectors_to_reserve(&s->s[i], nr_replicas);

    if (!disk_res_sectors)
        return 0;

    ret = orca_disk_reservation_get(c, &disk_res, disk_res_sectors, 1, !check_enospc
        ? ORCA_DISK_RESERVATION_NOFAIL
        : 0);

    if (unlikely(ret))
        return ret;

    for (i = 0; i < ARRAY_SIZE(s->s); i++)
        s->s[i].replicas_reserved += sectors_to_reserve(&s->s[i], nr_replicas);

    return 0;
}

struct orca_page_reservation {
    struct disk_reservation disk;
    struct quota_res quota;
};

static void
orca_page_reservation_init(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_page_reservation *res)
{
    memset(res, 0, sizeof(*res));
    res->disk.nr_replicas = inode_nr_replicas(c, inode);
}

static void
orca_page_reservation_put(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_page_reservation *res)
{
    orca_disk_reservation_put(c, &res->disk);
    orca_quota_reservation_put(c, inode, &res->quota);
}

static int
orca_page_reservation_get(struct orca_fs *c, struct orca_inode_info *inode,
    struct page *page, struct orca_page_reservation *res, unsigned offset,
    unsigned len, bool check_enospc)
{
    struct orca_page_state *s = orca_page_state_create(page, 0);
    unsignded i, disk_sectors = 0, quota_sectors = 0;
    int ret;

    if (!is)
        return -ENOMEM;

    for (i = round_down(offset, block_bytes(c)) >> 0;
        i < round_up(offset + len, block_bytes(c)) >> 9; i++) {
            disk_sectors += sectors_to_reserve(&s->s[i], res->disk.nr_replicas);
            quota_sectors += s->s[i].state == SECTOR_UNALLOCATED;
    }

    if (disk_sectors) {
        ret = orca_disk_reservation_add(c, &res->disk, disk_sectors, !check_enospc,
            ? ORCA_DISK_RESERVATION_NOFAIL : 0);

        if (unlikely(ret))
            return ret;
    }

    if (quota_sectors) {
        ret = orca_quota_reservation_add(c, inode, &res->quota, quota_sectors,
            check_enospc);

        if (unlikely(ret)) {
            struct disk_reservation tmp = {
                .sectors = disk_sectors
            };

            orca_disk_reservation_put(c, &tmp);
            res->disk_sectors -= disk_sectors;

            return ret;
        }
    }

    return 0;
}

static void
orca_clear_page_bits(struct page *page)
{
    struct orca_inode_info *inode = to_orca_ei(page->mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_page_state *s = orca_page_state(page);
    struct disk_reservation disk_res = { 0 };
    int i, dirty_sectors = 0;

    if (!s)
        return;

    EBUG_ON(!PageLocked(page));
    EBUG_ON(PageWriteback(page));

    for (i = 0; i < ARRAY_SIZE(s->s); i++) {
        disk_res.sectors += s->s[i].replicas_reserved;
        s->s[i].replicas_reserved = 0;

        if (s->s[i].state == SECTOR_DIRTY) {
            dirty_sectors++;
            s->s[i].state = SECTOR_UNALLOCATED;
        }
    }

    orca_disk_reservation_put(c, &disk_res);

    if (dirty_sectors)
        i_sectors_acct(c, inode, NULL, -dirty_sectors);

    orca_page_state_release(page);
}

static void
orca_set_page_dirty(struct orca_fs *c, struct orca_inode_info *inode,
    struct page *page, struct orca_page_reservation *res,
    unsigned offset, unsigned len)
{
    struct orca_page_state *s = orca_page_state(page);
    unsigned i, dirty_sectors = 0;

    WARN_ON((u64)page_offset(page) + offset + len > round_up((u64)i_size_read(&inode->v),
        block_bytes(c)));

    spin_lock(&s->lock);

    for (i = round_down(offset, block_bytes(c)) >> 9; i < round_up(offset + len,
        block_bytes(c)) >> 9; i++) {
            unsigned sectors = sectors_to_reserve(&s->s[i], res->disk.nr_replicas);

            /**
             * This can happen if we race with the error path in
             * orca_writepage_io_done().
            **/
            sectors = min_t(unsigned, sectors, res->disk.sectors);
            s->s[i].replicas_reserved += sectors;
            res->disk.sectors -= sectors;

            if (s->s[i].state == SECTOR_UNALLOCATED)
                dirty_sectors++;

            s->s[i].state = max_t(unsigned, s->s[i].state, SECTOR_DIRTY);
    }

    spin_unlock(&s->lock);

    if (dirty_sectors)
        i_sectors_acct(c, inode, &res->quota, dirty_sectors);

    if (!PageDirty(page))
        __set_page_dirty_nobuffers(page);
}

vm_fault_t
orca_page_fault(struct vm_struct *vmf)
{
    struct file *file = vmf->vma->vm_file;
    struct address_space *mapping = file->f_mapping;
    struct address_space *fdm = faults_disabled_mapping();
    struct orca_inode_info *inode = file_orca_inode(file);
    int ret;

    if (fdm == mapping)
        return VM_FAULT_SIGBUS;

    /* Lock ordering */
    if (fdm > mapping) {
        struct orca_inode_info *fdm_host = to_orca_ei(fdm->host);

        if (orca_pagecache_add_tryget(&inode->ei_pagecache_lock))
            goto got_lock;

        orca_pagecache_block_put(&fdm_host->ei_pagecache_lock);
        orca_pagecache_add_get(&inode->ei_pagecache_lock);
        orca_pagecache_block_get(&fdm_host->ei_pagecache_lock);

        /* Signal that lock has been dropped */
        set_fdm_dropped_locks();

        return VM_FAULT_SIGBUS;
    }

    orca_pagecache_add_get(&inode->ei_pagecache_lock);

got_lock:
    ret = filemap_fault(vmf);
    orca_pagecache_add_put(&inode->ei_pagecache_lock);

    return ret;
}

vm_fault_t
orca_page_mkwrite(struct vm_fault *vmf)
{
    struct page *page = vmf->page;
    struct file *file = vmf->vma->vm_file;
    struct orca_inode_info *inode = file_orca_inode(file);
    struct address_space *mapping = file->f_mapping;
    struct orca_fs *c = inode->v.i_sb.s_fs_info;
    struct orca_page_reservation res;
    unsigned len;
    loff_t isize;
    int ret = VM_FAULT_LOCKED;

    orca_page_reservation_init(c, inode, &res);
    sb_start_pagefault(inode->v.i_sb);
    file_update_time(file);

    /**
     * Not strictly necessary, but helps avoid dio writes livelocking in
     * write_invalidate_inode_pages_range()--can drop this if/when we get
     * a write_individuals_inode_pages_range() that works without dropping
     * page lock before invalidating page.
    **/
    orca_pagecache_add_get(&inode->ei_pagecache_lock);
    lock_page(page);
    isize = i_size_read(&inode->v);

    if (page->mapping != mapping || page_offset(page) >= isize) {
        unlock_page(page);
        ret = VM_FAULT_NOPAGE;
        goto out;
    }

    len = min_t(loff_t, PAGE_SIZE, isize - page_offset(page));

    if (orca_page_reservation_get(c, inode, page, &res, 0, len, true)) {
        unlock_page(page);
        ret = VM_FAULT_SIGBUS;
        goto out;
    }

    orca_set_page_dirty(c, inode, page, &res, 0, len);
    orca_page_reservation_put(c, inode, &res);
    wait_for_stable_page(page);

out:
    orca_pagecache_add_put(&inode->ei_pagecache_lock);
    sb_end_pagefault(inode->v.i_sb);

    return ret;
}

void
orca_invalidatepage(struct page *page, unsigned int offset, unsigned int length)
{
    if (offset || length < PAGE_SIZE)
        return;

    orca_clear_page_bits(page);
}

int
orca_releasepage(struct page *page, gfp_t gfp_mask)
{
    if (PageDirty(page))
        return 0;

    orca_clear_page_bits(page);

    return 1;
}

#ifdef CONFIG_MIGRATION
int
orca_migrate_page(struct address_space *mapping, struct page *newpage,
    struct page *page, enum migrate_mode mode)
{
    int ret;

    EBUG_ON(!PageLocked(page));
    EBUG_ON(!PageLocked(newpage));

    ret = migrate_page_move_mapping(mapping, newpage, page, 0);

    if (ret != MIGRATEPAGE_SUCCESS)
        return ret;

    if (PagePrivate(page))
        attach_page_copy(newpage, page);
    else
        migrate_page_status(newpage, page);

    return MIGRATEPAGE_SUCCESS;
}
#endif

static void
orca_readpages_end_io(struct bio *bio)
{
    struct bvec_iter_all iter;
    struct bio_vec *bv;

    bio_for_each_segment_all(bv, bio, iter) {
        struct page *page = bv->bv_page;

        if (!bio->bi_status) {
            SetPageUptodate(page);
        } else {
            ClearPageUptodate(page);
            SetPageError(page);
        }

        unlock_page(page);
    }

    bio_put(bio);
}

struct readpages_iter {
    struct address_space *mapping;
    struct page **page;
    unsigned nr_pages;
    unsigned idx;
    pgoff_t offset;
};

static int
readpages_iter_init(struct readpages_iter *iter, struct readahead_control *ractl)
{
    unsigned i, nr_pages = readahead_count(ractl);

    memset(iter, 0, sizeof(*iter));
    iter->mapping = ractl->mapping;
    iter->offset = readahead_index(ractl);
    iter->nr_pages = nr_pages;
    iter->pages = kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOFS);

    if (!iter->pages)
        return -ENOMEM;

    nr_pages = __readahead_batch(ractl, iter->pages, nr_pages);

    for (i = 0; i < nr_pages; i++) {
        __orca_page_state_create(iter->pages[i], __GFP_NOFAIL);
        put_page(iter->pages[i]);
    }

    return 0;
}

static inline struct page *
readpage_iter_next(struct readpages_iter *iter)
{
    if (iter->idx >= iter->nr_pages)
        return NULL;

    EBUG_ON(iter->pages[iter->idx]->index != iter->offset + iter->idx);

    return iter->pages[iter->idx];
}

static void
orca_add_page_sectors(struct bio *bio, struct bkey_s_c k)
{
    struct bvec_iter iter;
    struct bio_vec bv;
    unsigned nr_ptrs = k.k->type == KEY_TYPE_reflink_v
        ? 0
        : orca_bkey_nr_ptrs_fully_allocated(k);
    unsigned state = k.k->type == KEY_TYPE_reservation
        ? SECTOR_RESERVED
        : SECTOR_ALLOCATED;

    bio_for_each_segment(bv, bio, iter) {
        struct orca_page_state *s = orca_page_state(bv.bv_page);
        unsigned i;

        for (i =bv.bv_offset >> 9; i < (bv.bv_offset + bv.bv_len) >> 9; i++) {
            s->s[i].nr_replicas = nr_ptrs;
            s->s[i].state = state;
        }
    }
}

static bool
extent_partial_reads_expensive(struct bkey_s_c k)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs_c(k);
    struct orca_extent_crc_unpacked crc;
    const union orca_extent_entry *i;

    bkey_for_each_crcc(k.k, ptrs, crc, i) {
        if (crc.csum_type || crc.compressed_type)
            return true;
    }

    return false;
}

static void
readpage_bio_extend(struct readpages_iter *iter, struct bio *bio,
    unsigned sectors_this_extent, bool get_more)
{
    while (bio_sectors(bio) < sectors_this_extent && bio->bi_vnct < bio->bi_max_vecs) {
        pgoff_t page_offset = bio_end_sector(bio) >> PAGE_SECTOR_SHIFT;
        struct page *page = readpage_iter_next(iter);
        int ret;

        if (page) {
            if (iter->offset + iter->idx != page_offset)
                break;

            iter->idx++;
        } else {
            if (!get_more)
                break;

            page = xa_load(&iter->mapping->i_pages, page_offset);

            if (page && !xa_is_value(page))
                break;

            page = __page_cache_alloc(readahead_gfp_mask(iter->mapping));

            if (!page)
                break;

            if (!__orca_page_state_create(page, 0)) {
                put_page(page);
                break;
            }

            ret = add_to_page_cache_lru(page, iter->mapping, page_offset, GFP_NOFS);

            if (ret) {
                __orca_page_state_release(page);
                put_page(page);
                break;
            }

            put_page(page);
        }

        BUG_ON(!bio_add_page(bio, page, PAGE_SIZE, 0));
    }
}

static void
orcafs_read(struct btree_trans *trans, struct btree_iter *iter, struct orca_read_bio *rbio,
    u64 inum, struct readpages_iter *readpages_iter)
{
    struct orca_fs *c = trans->c;
    struct bkey_on_stack sk;
    int flags = ORCA_READ_RETRY_IF STALE | ORCA_READ_MAY_PROMOTE;
    int ret = 0;

    rbio->c = c;
    rbio->start_time = local_clock();
    bkey_on_stack_init(&sk);

retry:
    for (;;) {
        struct bkey_s_c k;
        unsigned bytes, sectors, offset_into_extent;

        orca_btree_iter_set_pos(iter, POS(inum, rbio->bio.bi_iter.bi_sector));
        k = orca_btree_iter_peek_slot(iter);
        ret = bkey_err(k);

        if (ret)
            break;

        offset_into_extent = iter->pos.offset - bkey_start_offset(k.k);
        sectors = k.k->size - offset_into_extent;
        bkey_on_stack_reassemble(&sk, c, k);
        ret = orca_read_indirect_extent(trans, &offset_into_extent, &sk);

        if (ret)
            break;

        k = bkey_i_to_s_c(sk.k);
        sectors = min(sectors, k.k->size - offset_into_extent);
        orca_trans_unlock(trans);

        if (readpages_iter)
            readpage_bio_extend(readpages_iter, &rbio->bio, sectors,
                extent_partial_reads_expensive(k));

        bytes = min(sectors, bio_sectors(&rbio->bio)) << 9;
        swap(rbio->bio.bi_iter.bi_size, bytes);

        if (rbio->bio.bi_iter.bi_size == bytes)
            flags |= ORCA_READ_LAST_FRAGMENT;

        if (bkey_extent_is_allocation(k.k))
            orca_add_page_sectors(&rbio->bio, k);

        orca_read_extent(trans, rbio, k, offset_into_extent, flags);

        if (flags & ORCA_READ_LAST_FRAGMENT)
            break;

        swap(rbio->bio.bi_iter.bi_size, bytes);
        bio_advance(&rbio->bio, bytes);
    }

    if (ret == -EINTR)
        goto retry;

    if (ret) {
        orca_err_inum_ratelimited(c, inum, "read error %i from btree lookup", ret);
        rbio->bio.bi_status = BLK_STS_IOERR;
        bio_endio(&rbio->bio);
    }

    bkey_on_stack_exit(&sk, c);
}

void
orca_readahead(struct readahead_control *ractl)
{
    struct orca_inode_info *inode = to_orca_ei(ractl->mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_io_opts opts = io_opts(c, &inode->ei_inode);
    struct btree_trans trans;
    struct btree_iter *iter;
    struct page *page;
    struct readpages_iter readpages_iter;
    int ret;

    ret = readpages_iter_init(&readpages_iter, ractl);
    BUG_ON(ret);

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS_MIN, BTREE_ITER_SLOTS);
    orca_pagecache_add_get(&inode->ei_pagecraft_lock);

    while ((page = readpage_iter_next(&readpages_iter))) {
        pgoff_t index = readpages_iter.offset + readpages_iter.idx;
        unsigned n = min_t(unsigned, readpages_iter.nr_pages - readpages_iter.idx,
            BIO_MAX_PAGES);
        struct orca_read_bio *rbio = rbio_init(bio_alloc_bioset(GFP_NOFS, n,
            &c->bio_read), opts);

        readpages_iter.idx++;
        bio_set_op_attrs(&rbio->bio, REQ_OP_READ, 0);
        rbio->bio.bi_iter.bi_sector = (sector_t)index << PAGE_SECTOR_SHIFT;
        rbio->bio.bi_end_io = orca_readpages_end_io;

        BUG_ON(!bio_add_page(&rbio->bio, page, PAGE_SIZE, 0));
        orcafs_read(&trans, iter, rbio, inode->v.i_ino, &readpages_iter);
    }

    orca_pagecache_add_put(&inode->ei_pagecache_lock);
    orca_trans_exit(&trans);
    kfree(readpages_iter.pages);
}

static void
__orcafs_readpage(struct orca_fs *c, struct orca_read_bio *rbio, u64 inum,
    struct page *page)
{
    struct btree_trans trans;
    struct btree_iter *iter;

    orca_page_state_create(page, __GFP_NOFAIL);
    bio_set_op_attrs(&rbio->bio, REQ_OP_READ, REQ_SYNC);
    rbio->bio.bi_iter.bi_sectors = (sector_t)page->index << PAGE_SECTOR_SHIFT;

    BUG_ON(!bio_add_page(&rbio->bio, page, PAGE_SIZE, 0));
    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS_MIN, BTREE_ITER_SLOTS);

    orcafs_read(&trans, rbio, inum, NULL);
    orca_trans_exit(&trans);
}

int
orca_readpage(struct file *file, struct page *page)
{
    struct orca_inode_info *inode = to_orca_ei(page->mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_io_opts opts = io_opts(c, &inode->ei_inode);
    struct orca_read_bio *rbio;

    rbio = rbio_init(bio_aloc_bioset(GFP_NOFS, 1, &c->bio_read), opts);
    rbio->bio.bi_end_io = orca_readpages_end_io;
    __orcafs_readpage(c, rbio, inode->v.i_ino, page);

    return 0;
}

static void
orca_read_single_page_end_io(struct bio *bio)
{
    complete(bio->bi_private);
}

static int
orca_read_single_page(struct page *page, struct address_space *mapping)
{
    struct orca_inode_info *inode = to_orca_ei(mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_read_bio *rbio;
    int ret;

    DECLARE_COMPLETION_ONSTACK(done);

    rbio = rbio_init(bio_alloc_bioset(GFP_NOFS, 1, &c->bio_read),
        io_opts(c, &inode->ei_inode));
    rbio->bio.bi_private = &done;
    rbio->bio.bi_end_io = orca_read_single_page_end_io;

    __orca_readpage(c, rbio, inode->v.i_ino, page);
    wait_for_completion(&done);

    ret = blk_status_to_errno(rbio->bio.bi_status);
    bio_put(&rbio->bio);

    if (ret < 0)
        return ret;

    SetPageUptodate(page);

    return 0;
}

struct orca_writepage_state {
    struct orca_writepage_io *io;
    struct orca_io_opts opts;
};

static inline struct orca_writepage_state
orca_writepage_state_init(struct orca_fs *c, struct orca_inode_info *inode)
{
    return (struct orca_writepage_state) {
        .opts = io_opts(c, &inode->ei_inode);
    };
}

static void
orca_writepage_io_free(struct closure *cl)
{
    struct orca_writepage_io *io = container_of(cl, struct orca_writepage_io, cl);

    bio_put(&io->op.wbio.bio);
}

static void
orca_writepage_io_done(struct closure *cl)
{
    struct orca_writepage_io *io = container_of(cl, struct orca_writepage_io, cl);
    struct orca_fs *c = io->op.c;
    struct bio *bio = &io->op.wbio.bio;
    struct bvec_iter_all iter;
    struct bio_vec *bvec;
    unsigned i;

    if (io->op.error) {
        set_bit(EI_INODE_ERROR, &io->inode-ei_flags);

        bio_for_each_segment_all(bvec, bio, iter) {
            struct orca_page_state *s;

            SetPageError(bvec->bv_page);
            mapping_set_error(bvec->bv_page->mapping, -EIO);

            s = __orca_page_state(bvec->bv_page);
            spin_lock(&s->lock);

            for (i = 0; i < PAGE_SECTORS; i++)
                s->s[i].nr_replicas = 0;

            spin_unlock(&s->lock);
        }
    }

    if (io->op.flags & ORCA_WRITE_WROTE_DATA_INLINE) {
        bio_for_each_segment_all(bvec, bio, iter) {
            struct orca_page_state *s;

            s = __orca_page_state(bvec->bv_page);
            spin_lock(&s->lock);

            for (i = 0; i < PAGE_SECTORS; i++)
                s->s[i].nr_replicas = 0;

            spin_unlock(&s->lock);
        }
    }

    /**
     * Racing with fallocate can cause us to add fewer sectors than
     * expected--but, we shouldn't add more sectors than expected.
    **/
    BUG_ON(io->op.i_sectors_delta > 0);

    /**
     * PageWriteback is effectively our ref on the inode--fixup i_blocks
     * before calling end_page_writeback.
    **/
    i_sectors_acct(c, io->inode, NULL, io->op.i_sectors_delta);

    bio_for_each_segment_all(bvec, bio, iter) {
        struct orca_page_state *s = __orca_page_state(bvec->bv_page);

        if (atomic_dec_and_test(&s->write_count))
            end_page_writeback(bvec->bv_page);
    }

    closure_return_with_destructor(&io->cl, orca_writepage_io_free);
}

static void
orca_writepage_do_io(struct orca_writepage_state *w)
{
    struct orca_writepage_io *io = w->io;

    w->io = NULL;
    closure_call(&io->op.cl, orca_write, NULL, &io->cl);
    continue_at(&io->cl, orca_writepage_io_done, NULL);
}

/**
 * Get a orca_writepage_io and add @page to it--appending to an existing
 * one if possible, else allocating a new one.
**/
static void
orca_writepage_io_alloc(struct orca_fs *c, struct writeback_control *wbc,
    struct orca_writepage_state *w, struct orca_inode_info *inode,
    u64 sector, unsigned nr_replicas)
{
    struct orca_write_op *op;

    w->io = container_of(bio_alloc_bioset(GFP_NOFS, BIO_MAX_PAGES,
        &c->writepage_bioset), struct orca_writepage_io, op.wbio.bio);

    closure_init(&w->io->cl, NULL);
    w->io->inode = inode;

    op = &w->io->op;
    orca_write_op_init(op, c, w->opts);
    op->target = w->opts.foreground_target;
    op_journal_seq_set(op, &inode->ei_journal_seq);
    op->nr_replicas = nr_replicas;
    op->res.nr_replicas = nr_replicas;
    op->write_point = writepoint_hashed(inode->ei_last_dirtied);
    op->pos = POS(inode->v.i_ino, sector);
    op->wbio.bio.bi_iter.bi_sector = sector;
    op->wbio.bio.bi_opf = wbc_to_write_flags(wbc);
}

static int
__orca_writepage(struct page *page, struct writeback_control *wbc, void *data)
{
    struct orca_inode_info *inode = to_orca_ei(page->mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_writepage_state *w = data;
    struct orca_page_state *s, orig;
    unsigned i, offset, nr_replicas_this_write = U32_MAX;
    loff_t i_size = i_size_read(&inode->v);
    pgoff_t end_index = i_size >> PAGE_SHIFT;
    int ret;

    EBUG_ON(!PageUptodate(page)));

    /* Is the page fully inside i_size? */
    if (page->index < end_index)
        goto do_io;

    /* Is the page fully outside i_size? (truncate in progress) */
    offset = i_size & (PAGE_SIZE - 1);

    if (page->index > end_index || !offset) {
        unlock_page(page);

        return 0;
    }

    /**
     * The page straddles i_size. It must be zeroed out on each and every
     * writepage invocation because it may be mmapped. "A file is mapped
     * in multiples of the page size. For a file that is not a mutliple of
     * the page size, the remaining memory is zeroed when mapped, and
     * writes to that region are not written out to the file."
    **/
    zero_user_segment(page, offset, PAGE_SIZE);

do_io:
    s = orca_page_state_create(page, __GFP_NOFAIL);
    ret = orca_get_page_disk_reservation(c, inode, page, true);

    if (ret) {
        SetPageError(page);
        mapping_set_error(page->mapping, ret);
        unlock_page(page);

        return 0;
    }

    /* Before unlocking the page, get copy of reservations */
    orig = *s;

    for (i = 0; i < PAGE_SECTORS; i++) {
        if (s->s[i].state < SECTOR_DIRTY)
            continue;

        nr_replicas_this_write = min_t(unsigned, nr_replicas_this_write,
            s->s[i].nr_replicas + s->s[i].replicas_reserved);
    }

    for (i = 0; i < PAGE_SECTORS; i++) {
        if (s->s[i].state < SECTOR_DIRTY)
            continue;

        s->s[i].nr_replicas = w->opts.compression
            ? 0
            : nr_replicas_this_write;

        s->s[i].replicas_reserved = 0;
        s->s[i].state = SECTOR_ALLOCATED;
    }

    BUG_ON(atomic_read(&s->write_count));
    atomic_set(&s->write_count, 1);
    BUG_ON(PageWriteback(page));
    set_page_writeback(page);
    unlock_page(page);
    offset = 0;

    for (;;) {
        unsigned sectors = 1, dirty_sectors = 0, reserved_sectors = 0;
        u64 sector;

        while (offset < PAGE_SECTORS && orig.s[offset].state < SECTOR_DIRTY)
            offset++;

        if (offset == PAGE_SECTORS)
            break;

        sector = ((u64)page->index << PAGE_SECTOR_SHIFT) + offset;

        while (offset + sectors < PAGE_SECTORS && orig.s[offset + sectors].state
            >= SECTOR_DIRTY)
                sectors++;

        for (i = offset; i < offset + sectors; i++) {
            reserved_sectors += orig.s[i].replicas_reserved;
            dirty_sectors += orig.s[i].state == SECTOR_DIRTY;
        }

        if (w->io && (w->io->op.res.nr_replicas != nr_replicas_this_write ||
            bio_full(&w->io->op.wbio.bio, PAGE_SIZE) ||
            w->io->op.wbio.bio.bi_iter.bi_size + (sectors << 9) >=
            (BIO_MAX_PAGES * PAGE_SIZE) ||
            bio_end_sector(&w->io->op.wbio.bio) != sector))
                orca_writepage_do_io(w);

        if (!w->io)
            orca_writepage_io_alloc(c, wbc, w, inode, sector, nr_replicas_this_write);

        atomic_inc(&s->write_count);
        BUG_ON(inode != w->io->inode);
        BUG_ON(!bio_add_page(&w->io->op.wbio.bio, page, sectors << 9,
            offset << 9));

        /* Check for writing past i_size */
        WARN_ON((bio_end_sector(&w->io->op.wbio.bio) << 9) >
            round_up(i_size, block_bytes(c)));

        w->io->op.res.sectors += reserved_sectors;
        w->io.op.i_sectors_delta -= dirty_sectors;
        w->io.op.new_i_size = i_size;

        offset += sectors;
    }

    if (atomic_dec_and_test(&s->write_count))
        end_page_writeback(page);

    return 0;
}

int
orca_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
    struct orca_fs *c = mapping->host->i_sb->s_fs_info;
    struct orca_writepage_state w =
        orca_writepage_state_init(c, to_orca_ei(mapping->host));
    struct blk_plug plug;
    int ret;

    blk_start_plug(&plug);
    ret = write_cache_pages(mapping, wbc, __orca_writeback, &w);

    if (w.io)
        orca_writepage_do_io(&w);

    blk_finish_plug(&plug);

    return ret;
}

int
orca_writepage(struct page *page, struct writeback_control *wbc)
{
    struct orca_fs *c = page->mapping->host->i_sb->s_fs_info;
    struct orca_writepage_state w =
        orca_writepage_state_init(c, to_orca_ei(page->mapping->host));
    int ret;

    ret = __orca_writepage(page, wbc, &w);

    if (w.io)
        orca_writepage_do_io(&w);

    return ret;
}

int
orca_write_begin(struct file *file, struct address_space *mapping, loff_t pos,
    unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
    struct orca_inode_info *inode = to_orca_ei(mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_page_reservation *res;
    pgoff_t index = pos >> PAGE_SHIFT;
    unsigned offset = pos & (PAGE_SIZE - 1);
    struct page *page;
    int ret = -ENOMEM;

    res = kmalloc(sizeof(*res), GFP_KERNEL);

    if (!res)
        return -ENOMEM;

    orca_page_reservation_init(c, inode, res);
    *fsdata = res;
    orca_pagecache_add_get(&inode->ei_pagecache_lock);
    page = grab_cache_page_write_begin(mapping, index, flags);

    if (!page)
        goto err_unlock;

    if (PageUptodate(page))
        goto out;

    /* If we're writing entire page, don't need to read it in first */
    if (len == PAGE_SIZE)
        goto out;

    if (!offset && pos + len >= inode->v.i_size) {
        zero_user_segment(page, len, PAGE_SIZE);
        flush_dcache_page(page);
        goto out;
    }

    if (index > inode->v.i_size >> PAGE_SHIFT) {
        zero_user_segments(page, 0, offset, offset + len, PAGE_SIZE);
        flush_dcache_page(page);
        goto out;
    }

readpage:
    ret = orca_read_single_page(page, mapping);

    if (ret)
        goto err;

out:
    ret = orca_page_reservation_get(c, inode, page, res, offset, len, true);

    if (ret) {
        if (PageUptodate(page)) {
            /**
             * If the page hasn't been read in, we won't know if we actually
             * need a reservation--we don't actually need to read here, we
             * just need to check if the page is fully-backed by
             * uncompressed data.
            **/
            goto readpage;
        }

        goto err;
    }

    *pagep = page;

    return 0;

err:
    unlock_page(page);
    put_page(page);
    *pagep = NULL;

err_unlock:
    orca_pagecache_add_put(&inode->ei_pagecache_lock);
    kfree(res);
    *fsdata = NULL;

    return ret;
}

int
orca_write_end(struct file *file, struct address_space *mapping, loff_t pos,
    unsigned len, unsigned copied, struct page *page, void *fsdata)
{
    struct orca_inode_info *inode = to_orca_ei(mapping->host);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_page_reservation *res = fsdata;
    unsigned offset = pos & (PAGE_SIZE - 1);

    lockdep_assert_held(&inode->v.i_rwsem);

    if (unlikely(copied < len && !PageUptodate(page))) {
        /**
         * The page needs to be read in, but that would destroy
         * our partial write--simplest thing is to just force
         * userspace to redo the write.
        **/
        zero_user(page, 0, PAGE_SIZE);
        flush_dcache_page(page);
        copied = 0;
    }

    spin_lock(&inode->v.i_lock);

    if (pos + copied > inode->v.i_size)
        i_size_write(&inode->v, pos + copied);

    spin_unlock(&inode->v.i_lock);

    if (copied) {
        if (!PageUptodate(page))
            SetPageUptodate(page);

        orca_set_page_dirty(c, inode, page, res, offset, copied);
        inode->ei_last_dirtied = (unsigned long)current;
    }

    unlock_page(page);
    put_page(page);
    orca_pagecache_add_put(c, inode, res);
    orca_page_reservation_put(c, inode, res);
    kfree(res);

    return copied;
}

#define WRITE_BATCH_PAGES 32

static int
__orca_buffered_write(struct orca_inode_info *inode, struct address_space *mapping,
    struct iov_iter *iter, loff_t pos, unsigned len)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct page *pages[WRITE_BATCH_PAGES];
    struct orca_page_reservation res;
    unsigned long index = pos >> PAGE_SHIFT;
    unsigned offset = pos & (PAGE_SIZE - 1);
    unsigned nr_pages = DIV_ROUND_UP(offset + len, PAGE_SIZE);
    unsigned i, reserved = 0, set_dirty = 0;
    unsigned copied = 0, nr_pages_copied = 0;
    int ret = 0;

    BUG_ON(!len);
    BUG_ON(nr_pages > ARRAY_SIZE(pages));

    orca_page_reservation_init(c, inode, &res);

    for (i = 0; i < nr_pages; i++) {
        pages[i] = grab_cache_page_write_begin(mapping, index + i, 0);

        if (!pages[i]) {
            nr_pages = i;

            if (!i) {
                ret = -ENOMEM;
                goto out;
            }

            len = min_t(unsigned, len, nr_pages * PAGE_SIZE - offset);
            break;
        }
    }

    if (offset && !PageUptodate(pages[0])) {
        ret = orca_read_single_page(pages[0], mapping);

        if (ret)
            goto out;
    }

    if ((pos + len) & (PAGE_SIZE - 1) && !PageUptodate(pages[nr_pages - 1])) {
        if ((index + nr_pages - 1) << PAGE_SHIFT >= inode->v.i_size) {
            zero_user(pages[nr_pages - 1], 0, PAGE_SIZE);
        } else {
            ret = orca_read_single_page(pages[nr_pages - 1], mapping);

            if (ret)
                goto out;
        }
    }

    while (reserved < len) {
        struct page *page = pages[(offset + reserved) >> PAGE_SHIFT];
        unsigned pg_offset = (offset + reserved) & (PAGE_SIZE - 1);
        unsigned pg_len = min_t(unsigned, len - reserved, PAGE_SIZE - pg_offset);

retry_reservation:
        ret = orca_page_reservation_get(c, inode, page, &res, pg_offset, pg_len, true);

        if (ret && !PageUptodate(page)) {
            ret = orca_read_single_page(page, mapping);

            if (!ret)
                goto retry_reservation;
        }

        if (ret)
            goto out;

        reserved += pg_len;
    }

    if (mapping_writably_mapped(mapping)) {
        for (i = 0; i < nr_pages; i++)
            flush_dcache_page(pages[i]);
    }

    while (copied < len) {
        struct page *page = pages[(offset + copied) >> PAGE_SHIFT];
        unsigned pg_offset = (offset + copied) & (PAGE_SIZE - 1);
        unsigned pg_len = min_t(unsigned, len - copied, PAGE_SIZE - pg_offset);
        unsigned pg_copied = iov_iter_copy_from_user_atomic(page, iter, pg_offset, pg_len);

        if (!pg_copied)
            break;

        if (!PageUptodate(page) && pg_copied != PAGE_SIZE && pos + copied + pg_copied <
            inode->v.i_size) {
                zero_user(page, 0, PAGE_SIZE);
                break;
        }

        flush_dcache_page(page);
        iov_iter_advance(iter, pg_copied);
        copied += pg_copied;

        if (pg_copied != pg_len)
            break;
    }

    if (!copied)
        goto out;

    spin_lock(&inode->v.i_lock);

    if (pos + copied > inode->v.i_size)
        i_size_write(&inode->v, pos + copied);

    spin_unlock(&inode->v.i_lock);

    while (set_dirty < copied) {
        struct page *page = pages[(offset + set_dirty) >> PAGE_SHIFT];
        unsigned pg_offset = (offset + set_dirty) & (PAGE_SIZE - 1);
        unsigned pg_len = min_t(unsigned, copied - set_dirty, PAGE_SIZE - pg_offset);

        if (!PageUptodate(page))
            SetPageUptodate(page);

        orca_set_page_dirty(c, inode, page, &res, pg_offset, pg_len);
        unlock_page(page);
        put_page(page);

        set_dirty += pg_len;
    }

    nr_pages_copied = DIV_ROUND_UP(offset + copied, PAGE_SIZE);
    inode->ei_last_dirtied = (unsigned long)current;

out:
    for (i = nr_pages_copied; i < nr_pages; i++) {
        unlock_page(pages[i]);
        put_page(pages[i]);
    }

    orca_page_reservation_put(c, inode, &res);

    return copied ?: ret;
}

static ssize_t
orca_buffered_write(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct address_space *mapping = file->f_mapping;
    struct orca_inode_info *inode = file_orca_inode(file);
    loff_t pos = iocb->ki_pos;
    ssize_t written = 0;
    int ret = 0;

    orca_pagecache_add_get(&inode->ei_pagecache_lock);

    do {
        unsigned offset = pos & (PAGE_SIZE - 1);
        unsigned bytes = min_t(unsigned long, iov_iter_count(iter),
            PAGE_SIZE * WRITE_BATCH_PASS - offset);

again:
        /**
         * Bring in the user page that we will copy from __first__.
         * Otherwise, there's a nasty deadlock on copying from the
         * same page as we're writing to, without it being marked
         * up-to-date.
        **/
        if (unlikely(iov_iter_fault_in_readable(iter, bytes))) {
            bytes = min_t(unsigned long, iov_iter_count(iter), PAGE_SIZE - offset);

            if (unlikely(iov_iter_fault_in_readable(iter, bytes))) {
                ret = -EFAULT;
                break;
            }
        }

        if (unlikely(fatal_signal_pending(current))) {
            ret = -EINTR;
            break;
        }

        ret = __orca_buffered_write(inode, mapping, iter, pos, bytes);

        if (unlikely(ret < 0))
            break;

        cond_resched();

        if (unlikely(ret == 0)) {
            /**
             * If we were unable to copy any data at all, we must fall back
             * to a single segment length write.
             *
             * If we didn't fallback here, we could livelock because not all
             * segments in the iov can be copied at once without a
             * pagefault.
            **/
            bytes = min_t(unsigned long, PAGE_SIZE - offset,
                iov_iter_single_seg_count(iter));
            goto again;
        }

        pos += ret;
        written += ret;
        ret = 0;
        balance_dirty_pages_ratelimited(mapping);
    } while (iov_iter_count(iter));

    orca_pagecache_add_put(&inode->ei_pagecache_lock);

    return written ?: ret;
}

static void
orca_dio_read_complete(struct closure *cl)
{
    struct dio_read *dio = container_of(cl, struct dio_read, cl);

    dio->req->ki_complete(dio->req, dio->ret, 0);
    bio_check_pages_dirty(&dio->rbio.bio);
}

static void
orca_direct_IO_read_endio(struct bio *bio)
{
    struct dio_read *dio = bio->bi_private;

    if (bio->bi_status)
        dio->ret = blk_status_to_errno(bio->bi_status);

    closure_put(&dio->cl);
}

static void
orca_direct_IO_read_split_endio(struct bio *bio)
{
    orca_direct_IO_read_endio(bio);
    bio_check_pages_dirty(bio);
}

static int
orca_direct_IO_read(struct kiocb *req, struct iov_iter *iter)
{
    struct file *file = req->ki_filp;
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_io_opts opts = io_opts(c, &inode->ei_inode);
    struct dio_read *dio;
    struct bio *bio;
    loff_t offset = req->ki_pos;
    bool sync = is_sync_kiocb(req);
    size_t shorten;
    ssize_t ret;

    if ((offset | iter->count) & (block_bytes(c) - 1))
        return -EINVAL;

    ret = min_t(loff_t, iter->count, max_t(loff_t, 0, i_size_read(&inode->v) - offset));

    if (!ret)
        return ret;

    shorten = iov_iter_count(iter) - round_up(ret, block_bytes(c));
    iter->count -= shorten;
    bio = bio_alloc_bioset(GFP_KERNEL, iov_iter_npages(iter, BIO_MAX_PAGES),
        &c->dio_read_bioset);
    bio->bi_end_io = orca_direct_IO_read_endio;
    dio = container_of(bio, struct dio_read, rbio.bio);
    closure_init(&dio->cl, NULL);

    /**
     * This is a _really_ horrible hack just to avoid an atomic sub at
     * the end.
    **/
    if (!sync) {
        set_closure_fn(&dio->cl, orca_dio_read_complete, NULL);
        atomic_set(&dio->cl.remaining, CLOSURE_REMAINING_INITIALIZER -
            CLOSURE_RUNNING + CLOSURE_DESTRUCTOR);
    } else {
        atomic_set(&dio->cl.remaining, CLOSURE_REMAINING_INITIALIZER + 1);
    }

    dio->req = req;
    dio->ret = ret;

    goto start;

    while (iter->count) {
        bio = bio_alloc_bioset(GFP_KERNEL, iov_iter_npages(iter, BIO_MAX_PAGES),
            &c->bio_read);
        bio->bi_end_io = orca_direct_IO_read_split_endio;

start:
        bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC);
        bio->bi_iter.bi_sector = offset >> 9;
        bio->bi_private = dio;
        ret = bio_iov_iter_get_pages(bio, iter);

        if (ret < 0) {
            /* Fault inject this path */
            bio->bi_status = BLK_STS_RESOURCE;
            bio_endio(bio);
            break;
        }

        offset += bio->bi_iter.bi_size;
        bio_set_pages_dirty(bio);

        if (iter->count)
            closure_get(&dio->cl);

        orca_read(c, rbio_init(bio, opts), inode->v.i_ino);
    }

    iter->count += shorten;

    if (sync) {
        closure_sync(&dio->cl);
        closure_debug_destroy(&dio->cl);
        ret = dio->ret;
        bio_check_pages_dirty(&dio->rbio.bio);

        return ret;
    } else {
        return -EIOCBQUEUED;
    }
}

ssize_t
orca_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct orca_inode_info *inode = file_orca_inode(file);
    struct address_space *mapping = file->f_mapping;
    size_t count = iov_iter_count(iter);
    ssize_t ret;

    if (!count)
        return 0;

    if (iocb->ki_flags & IOCB_DIRECT) {
        struct blk_plug plug;

        ret = filemap_write_and_wait_range(mapping, iocb->ki_pos, iocb->ki_pos + count - 1);

        if (ret < 0)
            return ret;

        file_accessed(file);
        blk_start_plug(&plug);
        ret = orca_direct_IO_read(iocb, iter);
        blk_finish_plug(&plug);

        if (ret >= 0)
            iocb->ki_pos += ret;
    } else {
        orca_pagecache_add_get(&inode->ei_pagecache_lock);
        ret = generic_file_read_iter(iocb, iter);
        orca_pagecache_add_put(&inode->ei_pagecache_lock);
    }

    return ret;
}

static void orca_dio_write_loop_async(struct orca_write_op *);

static long
orca_dio_write_loop(struct dio_write *dio)
{
    bool kthread = (current->flags & PF_KTHREAD) != 0;
    struct kiocb *req = dio->req;
    struct address_space *mapping = req->ki_filp->f_mapping;
    struct orca_inode_info *inode = file_orca_inode(req->ki_filp);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct bio *bio = &dio->op.wbio.bio;
    struct bvec_iter_all iter;
    struct bio_vec *bv;
    unsigned unaligned, iter_count;
    bool sync = dio->sync, dopped_locks;
    long ret;

    if (dio->loop)
        goto loop;

    for (;;) {
        iter_count = dio->iter.count;

        if (kthread)
            kthread_use_mm(dio->mm);

        BUG_ON(current->faults_disabled_mapping);
        current->faults_disabled_mapping = mapping;
        ret = bio_iov_iter_get_pages(bio, &dio->iter);
        dropped_locks = fdm_dropped_locks();
        current->faults_disabled_mapping = NULL;

        if (kthread)
            kthread_unuse_mm(dio->mm);

        BUG_ON(current->faults_disabled_mapping);
        current->faults_disabled_mapping = mapping;
        ret = bio_iov_iter_get_pages(bio, &dio->iter);
        dropped_locks = fdm_dropped_locks();
        current->faults_disabled_mapping = NULL;

        if (kthread)
            kthread_unuse_mm(dio->mm);

        /**
         * If the fault handler returned an error, but also signalled
         * that it dropped & retook ei_pagecache_lock, we just need
         * to re-shoot down the page cache and retry.
        **/
        if (dropped_locks && ret)
            ret = 0;

        if (unlikely(ret < 0))
            goto err;

        if (unlikely(dropped_locks)) {
            ret = write_invalidate_inode_pages_range(mapping, req->ki_pos,
                req->ki_pos + iter_count - 1);

            if (unlikely(ret))
                goto err;

            if (!bio->bi_iter.bi_size)
                continue;
        }

        unaligned = bio->bi_iter.bi_size & (block_bytes(c) - 1);
        bio->bi_iter.bi_size -= unaligned;
        iov_iter_revert(&dio->iter, unaligned);

        if (!bio->bi_iter.bi_size) {
            /**
             * bio_iov_iter_get_pages() was only able to get <
             * blocksize worth of pages.
            **/
            bio_for_each_segment_all(bv, bio, iter)
                put_page(bv->bv_page);

            ret = -EFAULT;
            goto err;
        }

        orca_write_op_init(&dio->op, c, io_opts(c, &inode->ei_inode));
        dio->op.end_io = orca_dio_write_loop_async;
        dio->op.target = dio->op.opts.foreground_target;
        op_journal_seq_set(&dio->op, &inode->ei_journal_seq);
        dio->op.write_point = writepoint_hashed((unsigned long)current);
        dio->op.nr_replicas = dio->op.opts.data_replicas;
        dio->op.pos = POS(inode->v.i_ino, (u64)req->ki_pos >> 9);

        if ((req->ki_flags & IOCB_DSYNC) && !c->opts.journal_flush_disabled)
            dio->op.flags |= ORCA_WRITE_FLUSH;

        ret = orca_disk_reservation_get(c, &dio->op.res, bio_sectors(bio),
            dio->op.opts.data_replicas, 0);

        if (unlikely(ret) && !orca_check_range_allocated(c, dio->op.pos,
            bio_sectors(bio), dio->op.opts.data_replicas))
                goto err;

        task_io_account_write(bio->bi_iter.bi_size);

        if (!dio->sync && !dio->loop && dio->iter.count) {
            struct iovec *iov = dio->inline_vecs;

            if (dio->iter.nr_segs - ARRAY_SIZE(dio->inline_vecs)) {
                iov = kmalloc(dio->iter.nr_segs * sizeof(*iov), GFP_KERNEL);

                if (unlikely(!iov)) {
                    dio->sync = sync = true;
                    goto do_io;
                }

                dio->free_iov = true;
            }

            memcpy(iov, dio->iter.iov, dio->iter.nr_segs * sizeof(*iov));
            dio->iter.iov = iov;
        }

do_io:
        dio->loop = true;
        closure_call(&dio->op.cl, orca_write, NULL, NULL);

        if (sync)
            wait_for_completion(&dio->done);
        else
            return -EIOCBQUEUED;

loop:
        i_sectors_acct(c, inode, &dio->quota_res, dio->op.i_sectors_delta);
        req->ki_pos += (u64)dio->op.written << 9;
        dio->written += dio->op.written;

        spin_lock(&inode->v.i_lock);

        if (req->ki_pos > inode->v.i_size)
            i_size_write(&inode->v.i_lock);

        spin_unlock(&inode->v.i_lock);

        bio_for_each_segment_all(bv, bio, iter)
            put_page(bv->bv_page);

        if (dio->op.error) {
            set_bit(EI_INODE_ERROR, &inode->ei_flags);
            break;
        }

        if (!dio->iter.count)
            break;

        bio_reset(bio);
        reinit_completion(&dio->done);
    }

    ret = dio->op.error ?: ((long)dio->written << 9);

err:
    orca_pagecache_block_put(&inode->ei_pagecache_lock);
    orca_quota_reservation_put(c, inode, &dio->quota_res);

    if (dio->free_iov)
        kfree(dio->iter.iov);

    bio_put(bio);

    /* inode->i_dio_count is our ref on inode and thus orca_fs */
    inode_dio_end(&inode->v);

    if (!sync) {
        req->ki_complete(req, ret, 0);
        ret = -EIOCBQUEUED;
    }

    return ret;
}

static void
orca_dio_write_loop_async(struct orca_write_op *op)
{
    struct dio_write *dio = container_of(op, struct dio_write, op);

    if (dio->sync)
        complete(&dio->done);
    else
        orca_dio_write_loop(dio);
}

static noinline ssize_t
orca_direct_write(struct kiocb *req, struct iov_iter *iter)
{
    struct file *file = req->ki_filp;
    struct address_space *mapping = file->f_mapping;
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct dio_write *dio;
    struct bio *bio;
    bool locked = true, extending;
    ssize_t ret;

    prefetch(&c->opts);
    prefetch((void *)&c->opts + 64);
    prefetch(&inode->er_inode);
    prefetch((void *)&inode->ei_inode + 64);

    inode_lock(&inode->v);
    ret = generic_write_checks(req, iter);

    if (unlikely(ret <= 0))
        goto err;

    ret = file_remove_privs(file);

    if (unlikely(ret))
        goto err;

    ret = file_update_time(file);

    if (unlikely(ret))
        goto err;

    if (unlikely((req->ki_pos | iter->count) & (block_bytes(c) - 1)))
        goto err;

    inode_dio_begin(&inode->v);
    orca_pagecache_block_get(&inode->ei_pagecache_lock);
    extending = req->ki_pos + iter->count > inode->v.i_size;

    if (!extending) {
        inode_unlock(&inode->v);
        locked = false;
    }

    bio = bio_alloc_bioset(GFP_KERNEL, iov_iter_npages(iter, BIO_MAX_PAGES),
        &c->dio_write_bioset);
    dio = container_of(bio, struct dio_write, op.wbio.bio);
    init_completion(&dio->done);

    dio->req = req;
    dio->mm = current->mm;
    dio->loop = false;
    dio->sync = is_sync_kiocb(req) || extending;
    dio->free_iov = false;
    dio->quota_res.sectors = 0;
    dio->written = 0;
    dio->iter = *iter;

    ret = orca_quota_reservation_add(c, inode, &dio->quota_res, iter->count >> 9,
        true);

    if (unlikely(ret))
        goto err_put_bio;

    ret = write_invalidate_inode_pages_range(mapping, req->ki_pos, req->ki_pos +
        iter->count - 1);

    if (unlikely(ret))
        goto err_put_bio;

    ret = orca_dio_write_loop(dio);

err:
    if (locked)
        inode_unlock(&inode->v);

    return ret;

err_put_bio:
    orca_pagecache_block_put(&inode->ei_pagecache_lock);
    orca_quota_reservation_put(c, inode, &dio->quota_res);
    bio_put(bio);
    inode_dio_end(&inode->v);
    goto err;
}

ssize_t
orca_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct orca_inode_info *inode = file_orca_inode(file);
    ssize_t ret;

    if (iocb->ki_flags & IOCB_DIRECT)
        return orca_direct_write(iocb, from);

    /* We can write back this queue in page reclaim */
    current->backing_dev_info = inode_to_bdi(&inode->v);
    inode_lock(&inode->v);

    ret = generic_write_checks(iocb, from);

    if (ret <= 0)
        goto unlock;

    ret = file_remove_privs(file);

    if (ret)
        goto unlock;

    ret = file_update_time(file);

    if (ret)
        goto unlock;

    ret = orca_buffered_write(iocb, from);

    if (likely(ret > 0))
        iocb->ki_pos += ret;

unlock:
    inode_unlock(&inode->v);
    current->backing_dev_info = NULL;

    if (ret > 0)
        ret = generic_write_sync(iocb, ret);

    return ret;
}

int
orca_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    int ret, ret2;

    ret = file_write_and_wait_range(file, start, end);

    if (ret)
        return ret;

    if (datasync && !(inode->v.i_state & I_DIRTY_DATASYNC))
        goto out;

    ret = sync_inode_metadata(&inode->v, 1);

    if (ret)
        return ret;

out:
    if (!c->opts.journal_flash_disabled)
        ret = orca_journal_flush_seq(&c->journal, inode->ei_journal_seq);

    ret2 = file_check_and_advance_wb_err(file);

    return ret ?: ret2;
}

static inline int
range_has_data(struct orca_fs *c, struct bpos start, struct bpos end)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret = 0;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, start, 0, k, ret) {
        if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
            break;

        if (bkey_extent_is_data(k.k)) {
            ret = 1;
            break;
        }
    }

    return orca_trans_exit(&trans) ?: ret;
}

static int
__orca_truncate_page(struct orca_inode_info *inode, pgoff_t index, loff_t start,
    loff_t end)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct address_space *mapping = inode->v.i_mapping;
    struct orca_page_state *s;
    unsigned start_offset = start & (PAGE_SIZE - 1);
    unsigned end_offset = ((end - 1) & (PAGE_SIZE - 1)) + 1;
    unsigned i;
    struct page *page;
    int ret = 0;

    /* Page boundary? Nothing to do */
    if (!((index == start >> PAGE_SHIFT & start_offset) ||
        (index == end >> PAGE_SHIFT && end_offset != PAGE_SIZE)))
            return 0;

    if (index << PAGE_SHIFT >= inode->v.i_size)
        return 0;

    page = find_lock_page(mapping, index);

    if (!page) {
        ret = range_has_data(c, POS(inode->v.i_ino, index << PAGE_SECTOR_SHIFT),
            POS(inode->v.i_ino, (index + 1) << PAGE_SECTOR_SHIFT));

        if (ret <= 0)
            return ret;

        page = find_or_create_page(mapping, index, GFP_KERNEL);

        if (unlikely(!page)) {
            ret = -ENOMEM;
            goto out;
        }
    }

    s = orca_page_state_create(page, 0);

    if (!s) {
        ret = -ENOMEM;
        goto unlock;
    }

    if (PageUptodate(page)) {
        ret = orca_read_single_page(page, mapping);

        if (ret)
            goto unlock;
    }

    if (index != start >> PAGE_SHIFT)
        start_offset = 0;

    if (index != end >> PAGE_SHIFT)
        end_offset = PAGE_SIZE;

    for (i = round_up(start_offset, block_bytes(c)) >> 9;
        i < round_down(end_offset, block_bytes(c)) >> 9; i++) {
            s->s[i].nr_replicas = 0;
            s->s[i].state = SECTOR_UNALLOCATED;
    }

    zero_user_segment(page, start_offset, end_offset);

    /**
     * Bit of a hack--we don't want truncate to fail due to -ENOSPC.
     *
     * Because we aren't currently tracking whether the page has actual
     * data in it (vs. just 0s, or only partially written) this wrong. ick.
    **/
    ret = orca_get_page_disk_reservation(c, inode, page, false);
    BUG_ON(ret);

    /**
     * This removes any writeable userspace mappings; we need to force
     * .page_mkwrite to be called again before any mmapped writes, to
     * redirty the full page.
    **/
    page_mkclean(page);
    __set_page_dirty_nobuffers(page);

unlock:
    unlock_page(page);
    put_page(page);

out:
    return ret;
}

static int
orca_truncate_page(struct orca_inode_info *inode, loff_t from)
{
    return __orca_truncate_page(inode, from >> PAGE_SHIFT, from,
        round_up(from, PAGE_SIZE));
}

static int
orca_extend(struct orca_inode_info *inode, struct orca_inode_unpacked *inode_u,
    struct iattr *iattr)
{
    struct orca_fs *c = inode->v.i_sb.s_fs_info;
    struct address_space *mapping = inode->v.i_mapping;
    int ret;

    ret = filemap_write_and_wait_range(mapping, inode_u->bi_size, S66_MAX);

    if (ret)
        return ret;

    truncate_setsize(&inode->v, iattr->ia_size);
    setattr_copy(&inode->v, iattr);
    mutex_lock(&inode->ei_update_lock);
    ret = orca_write_inode_size(c, inode, inode->v.i_size, ATTR_MTIME | ATTR_CTIME);
    mutex_unlock(&inode->ei_update_lock);

    return ret;
}

static int
orca_truncate_finish_fn(struct orca_inode_info *inode, struct orca_inode_unpacked *bi,
    void *p)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;

    bi->bi_flags &= ~ORCA_INODE_I_SIZE_DIRTY;
    bi->bi_mtime = bi->bi_ctime = orca_current_time(c);

    return 0;
}

static int
orca_truncate_start_fn(struct orca_inode_info *inode, struct orca_inode_unpacked *bi,
    void *p)
{
    u64 *new_i_size = p;

    bi->bi_flags |= ORCA_INODE_I_SIZE_DIRTY;
    bi->bi_size = *new_i_size;

    return 0;
}

int
orca_truncate(struct orca_inode_info *inode, struct iattr *iattr)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct address_space *mapping = inode->v.i_mapping;
    struct orca_inode_unpacked inode_u;
    struct btree_trans trans;
    struct btree_iter *iter;
    u64 new_i_size = iattr->ia_size;
    s64 i_sectors_delta = 0;
    int ret = 0;

    inode_dio_wait(&inode->v);
    orca_pagecache_block_get(&inode->ei_pagecache_lock);

    /**
     * Fetch current on disk i_size: inode is locked, i_size can
     * only increase underneath us.
    **/
    orca_trans_init(&trans, c, 0, 0);
    iter = orca_inode_peek(&trans, &inode_u, inode->v.i_ino, 0);
    ret = PTR_ERR_OR_ZERO(iter);
    orca_trans_exit(&trans);

    if (ret)
        goto err;

    /**
     * Check this before next assertion. On filesystem error our normal
     * invariants are a bit broken (truncate has to truncate the page
     * cache before the inode).
    **/
    ret = orca_journal_error(&c->journal);

    if (ret)
        goto err;

    WARN_ON(!test_bit(EI_INODE_ERROR, &inode->ei_flags) &&
        inode->v.i_size < inode_u.bi_size);

    if (iattr->ia_size > inode->v.i_size) {
        ret = orca_extend(inode, &inode_u, iattr);
        goto err;
    }

    ret = orca_truncate_page(inode, iattr->ia_size);

    if (unlikely(ret))
        goto err;

    /**
     * When extending, we're going to write the new i_size to disk
     * immediately, so wee need to flush anything above the current
     * on disk i_size first.
     *
     * Also, when extending, we need to flush the page that i_size
     * currently straddles--if it's mapped to userspace, we need to
     * ensure that userspace has to redirty it and call .mkwrite ->
     * set_page_dirty again to allocate the part of the page that was
     * extended.
    **/
    if (iattr->ia_size > inode_u.bi_size)
        ret = filemap_write_and_wait_range(mapping, inode_u.bi_size,
            iattr->ia_size - 1);
    else if (iattr->ia_size & (PAGE_SIZE - 1))
        ret = filemap_write_and_wait_range(mapping, round_down(iattr->ia_size,
            PAGE_SIZE), iattr->ia_size - 1);

    if (ret)
        goto err;

    mutex_lock(&inode->ei_update_lock);
    ret = orca_write_inode(c, inode, orca_truncate_start_fn, &new_i_size, 0);
    mutex_unlock(&inode->ei_update_lock);

    if (unlikely(ret))
        goto err;

    truncate_setsize(&inode->v, iattr->ia_size);
    ret = orca_fpunch(c, inode->v.i_ino, round_up(iattr->ia_size, block_bytes(c)) >> 9,
        U64_MAX, &inode->ei_journal_seq, &i_sectors_delta);
    i_sectors_acct(c, inode, NULL, i_sectors_delta);

    if (unlikely(ret))
        goto err;

    setattr_copy(&inode->v, iattr);
    mutex_lock(&inode->ei_update_lock);
    ret = orca_write_inode(c, inode, orca_truncate_finish_fn, NULL,
        ATTR_MTIME | ATTR_CTIME);
    mutex_unlock(&inode->ei_update_lock);

err:
    orca_pagecache_block_put(&inode->ei_pagecache_lock);

    return ret;
}

static long
orcafs_fpunch(struct orca_inode_info *inode, loff_t offset, loff_t len)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    u64 discard_start = round_up(offset, block_bytes(c)) >> 9;
    u64 discard_end = round_down(offset + len, block_bytes(c)) >> 9;
    int ret = 0;

    inode_lock(&inode->v);
    inode_dio_wait(&inode->v);
    orca_pagecache_block_get(&inode->ei_pagecache_lock);

    ret = __orca_truncate_page(inode, offset >> PAGE_SHIFT, offset,
        offset + len);

    if (unlikely(ret))
        goto err;

    if (offset >> PAGE_SHIFT != (offset + len) >> PAGE_SHIFT) {
        ret = __orca_truncate_page(inode, (offset + len) >> PAGE_SHIFT,
            offset, offset + len);

        if (unlikely(ret))
            goto err;
    }

    truncate_pagecache_range(&inode->v, offset, offset + len - 1);

    if (discard_start < discard_end) {
        s64 i_sectors_delta = 0;

        ret = orca_fpunch(c, inode->v.i_ino, discard_start, discard_end,
            &inode->ei_journal_seq, &i_sectors_delta);

        i_sectors_acct(c, inode, NULL)
    }

err:
    orca_pagecache_block_put(&inode->ei_pagecache_lock);
    inode_unlock(&inode->v);

    return ret;
}

static long
orcafs_fcollapse_finsert(struct orca_inode_info *inode, loff_t offset, loff_t len,
    bool insert)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct address_space *mapping = inode->v.i_mapping;
    struct bkey_on_stack copy;
    struct btree_trans trans;
    struct btree_iter *src, *dst;
    loff_t shift, new_size;
    u64 src_start;
    int ret;

    if ((offset | len) & (block_bytes(c) - 1))
        return -EINVAL;

    bkey_on_stack_init(&copy);
    orca_trans_init(&trans, c, BTREE_ITER_MAX, 256);

    /**
     * We need i_mutex to keep the page cache consistent with the extents
     * btree, and the btree consistent with i_size--we don't need outside
     * locking for the extents btree itself, because we're using linked
     * iterators.
    **/
    inode_lock(&inode->v);
    inode_dio_wait(&inode->v);
    orca_pagecache_block_get(&inode->ei_pagecache_lock);

    if (insert) {
        ret = -EFBIG;

        if (inode->v.i_sb->s_maxbytes - inode->v.i_size < len)
            goto err;

        ret = -EINVAL;

        if (offset >= inode->v.i_size)
            goto err;

        src_start = U64_MAX;
        shift = len;
    } else {
        ret = -EINVAL;

        if (offset + len >= inode->v.i_size)
            goto err;

        src_start = offset + len;
        shift = -len;
    }

    new_size = inode->v.i_size + shift;
    ret = write_invalidate_inode_pages_range(mapping, offset, LLONG_MAX);

    if (ret)
        goto err;

    if (insert) {
        i_size_write(&inode->v, new_size);
        mutex_lock(&inode->ei_update_lock);
        ret = orca_write_inode_size(c, inode, new_size, ATTR_MTIME | ATTR_CTIME);
        mutex_unlock(&inode->ei_update_lock);
    } else {
        s64 i_sectors_delta = 0;

        ret = orca_fpunch(c, inode->v.i_ino, offset >> 9, (offset + len) >> 9,
            &inode->ei_journal_seq, &i_sectors_delta);
        i_sectors_acct(c, inode, NULL, i_sectors_delta);

        if (ret)
            goto err;
    }

    src = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS(inode->v.i_ino,
        src_start >> 9), BTREE_ITER_INTENT);
    dst = orca_trans_copy_iter(&trans, src);

    for (;;) {
        struct disk_reservation disk_res = orca_disk_reservation_init(c, 0);
        struct bkey_i delete;
        struct bkey_s_c k;
        struct bpos next_pos;
        struct bpos move_pos = POS(inode->v.i_ino, offset >> 9);
        struct bpos atomic_end;
        unsigned trigger_flags = 0;

        k = insert
            ? orca_btree_iter_peek_prev(src)
            : orca_btree_iter_peek(src);

        if ((ret = bkey_err(k)))
            goto key_err;

        if (!k.k || k.k->p.inode != inode->v.i_ino)
            break;

        BUG_ON(bkey_cmp(src->pos, bkey_start_pos(k.k)));

        if (insert && bkey_cmp(k.k->p, POS(inode->v.i_ino, offset >> 9)) <= 0)
            break;

reassemble:
        bkey_on_stack_reassemble(&copy, c, k);

        if (insert && bkey_cmp(bkey_start_pos(k.k), move_pos) < 0)
            orca_cut_front(move_pos, copy.k);

        copy->k->k.p.offset += shift >> 9;
        orca_btree_iter_set_pos(dst, bkey_start_pos(&copy.k->k));
        ret = orca_extent_atomic_end(dst, copy.k, &atomic_end);

        if (ret)
            goto bkey_err;

        if (bkey_cmp(atomic_end, copy.k->k.p)) {
            if (insert) {
                move_pos = atomic_end;
                move_pos.offset -= shift >> 9;
                goto reassemble;
            } else {
                orca_cut_back(atomic_end, copy.k);
            }
        }

        bkey_init(&delete.k);
        delete.k.p = copy.k->k.p;
        delete.k.size = copy.k->k.size;
        delete.k.p.offset -= shift >> 9;
        next_pos = insert ? bkey_start_pos(&delete.k) : delete.k.p;

        if (copy.k->k.size == k.k->size) {
            /* We might end up splitting compressed extents */
            unsigned nr_ptrs = orca_bkey_nr_ptrs_allocated(bkey_i_to_s_c(copy.k));
            ret = orca_disk_reservation_get(c, &disk_res, copy.k->k.size,
                nr_ptrs, ORCA_DISK_RESERVATION_NOFAIL);
            BUG_ON(ret);
        }

        orca_btree_iter_set_pos(src, bkey_start_pos(&delete.k));

        ret = orca_trans_update(&trans, src, &delete, trigger_flags)
            ?: orca_trans_update(&trans, dst, copy.k, trigger_flags)
            ?: orca_trans_commit(&trans, &disk_res, &inode->ei_journal_seq,
            BTREE_INSERT_NOFAIL);

        orca_disk_reservation_put(c, &disk_res);

bkey_err:
        if (!ret)
            orca_btree_iter_set_pos(src, next_pos);

        if (ret == -EINTR)
            ret = 0;

        if (ret)
            goto err;

        orca_trans_cond_resched(&trans);
    }

    orca_trans_unlock(&trans);

    if (!insert) {
        i_size_write(&inode->v, new_size);
        mutex_lock(&inode->ei_update_lock);
        ret = orca_write_inode_size(c, inode, new_size, ATTR_MTIME | ATTR_CTIME);
        mutex_unlock(&inode->ei_update_lock);
    }

err:
    orca_trans_exit(&trans);
    bkey_on_stack_exit(&copy, c);
    orca_pagecache_block_put(&inode->ei_pagecache_lock);
    inode_unlock(&inode->v);

    return ret;
}

static long
orcafs_fallocate(struct orca_inode_info *inode, int mode, loff_t offset, loff_t len)
{
    struct address_space *mapping = inode->v.i_mapping;
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bpos end_pos;
    loff_t end = offset + len;
    loff_t block_start = round_down(offset, block_bytes(c));
    loff_t block_end = round_up(end, block_bytes(c));
    unsigned sectors;
    unsigned replicas = io_opts(c, &inode->ei_inode).data_replicas;
    int ret;

    orca_trans_init(&trans, c, BTREE_ITER_MAX, 0);
    inode_lock(&inode->v);
    inode_dio_wait(&inode->v);
    orca_pagecache_block_get(&inode->ei_pagecache_lock);

    if (!(mode & FALLOC_FL_KEEP_SIZE) && end > inode->v.i_size) {
        ret = inode_newsize_ok(&inode->v, end);

        if (ret)
            goto err;
    }

    if (mode & FALLOC_FL_ZERO_RANGE) {
        ret = __orca_truncate_page(inode, offset >> PAGE_SHIFT, offset, end);

        if (!ret && offset >> PAGE_SHIFT != end >> PAGE_SHIFT)
            ret = __orca_truncate_page(inode, end >> PAGE_SHIFT, offset, end);

        if (unlikely(ret))
            goto err;

        truncate_pagecache_range(&inode->v, offset, end - 1);
    }

    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS(inode->v.i_ino,
        block_start >> 9), BTREE_ITER_SLOTS | BTREE_ITER_INTENT);
    end_pos = POS(inode->v.i_ino, block_end >> 9);

    while (bkey_cmp(iter->pos, end_pos) < 0) {
        s64 i_sectors_delta = 0;
        struct disk_reservation disk_res = { 0 };
        struct quota_res quota_res = { 0 };
        struct bkey_i_reservation reservation;
        struct bkey_s_c k;

        orca_trans_begin(&trans);
        k = orca_btree_iter_peek_slot(iter);

        if ((ret = bkey_err(k)))
            goto bkey_err;

        /* ALREADY RESERVED */
        if (k.k->type == KEY_TYPE_reservation &&
            bkey_s_c_to_reservation(k).v->nr_replicas >= replicas) {
                orca_btree_iter_next_slot(iter);
                continue;
        }

        if (bkey_extent_is_data(k.k) && !(mode & FALLOC_FL_ZERO_RANGE)) {
            orca_btree_iter_next_slot(iter);
            continue;
        }

        bkey_reservation_init(&reservation.k_i);
        reservation.k.type = KEY_TYPE_reservation;
        reservation.k.p = k.k->p;
        reservation.k.size = k.k->size;

        orca_cut_front(iter->pos, &reservation.k_i);
        orca_cut_back(end_pos, &reservation.k_i);
        sectors = reservation.k.size;
        reservation.v.nr_replicas = orca_bkey_nr_ptrs_allocated(k);

        if (!bkey_extent_is_allocation(k.k)) {
            ret = orca_quota_reservation_add(c, inode, &quota_res, sectors, true);

            if (unlikely(ret))
                goto bkey_err;
        }

        if (reservation.v.nr_replicas < replicas || orca_bkey_sectors_compressed(k)) {
            ret = orca_disk_reservation_get(c, &disk_res, sectors, replicas, 0);

            if (unlikely(ret))
                goto bkey_err;

            reservation.v.nr_replicas = disk_res.nr_replicas;
        }

        ret = orca_extent_update(&trans, iter, &reservation.k_i, &disk_res,
            &inode->ei_journal_seq, 0, &i_sectors_delta);
        i_sectors_acct(c, inode, &quota_res, i_sectors_delta);

bkey_err:
        orca_quota_reservation_put(c, inode, &quota_res);
        orca_disk_reservation_put(c, &disk_res);

        if (ret == -EINTR)
            ret = 0;

        if (ret)
            goto err;
    }

    /**
     * Do we need to extend the file?
     *
     * If we zeroed up to the end of the file, we dropped whatever writes
     * were going to write out the current i_size, so we have to extend
     * manually even if FL_KEEP_SIZE was set.
    **/
    if (end >= inode->v.i_size && (!(mode & FALLOC_FL_KEEP_SIZE) ||
        (mode & FALLOC_FL_ZERO_RANGE))) {
            struct btree_iter *inode_iter;
            struct orca_inode_unpacked inode_u;

            do {
                orca_trans_begin(&trans);
                inode_iter = orca_inode_peek(&trans, &inode_u, inode->v.i_ino, 0);
                ret = PTR_ERR_OR_ZERO(inode_iter);
            } while (ret == -EINTR);

            orca_trans_unlock(&trans);

            if (ret)
                goto err;

            /**
             * Sync existing appends before extending i_size, as in
             * orca_extend().
            **/
            ret = filemap_write_and_wait_range(mapping, inode_u.bi_size, S64_MAX);

            if (ret)
                goto err;

            if (mode & FALLOC_FL_KEEP_SIZE)
                end = inode->v.i_size;
            else
                i_size_write(&inode->v, end);

            mutex_lock(&inode->ei_update_lock);
            ret = orca_write_inode_size(c, inode, end, 0);
            mutex_unlock(&inode->si_update_lock);
    }

err:
    orca_trans_exit(&trans);
    orca_pagecache_block_put(&inode->ei_pagecache_lock);
    inode_unlock(&inode->v);

    return ret;
}

long
orca_fallocate_dispatch(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    long ret;

    if (!percpu_ref_tryget(&c->writes))
        return -EROFS;

    if (!(mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_ZERO_RANGE)))
        ret = orcafs_fallocate(inode, mode, offset, len);
    else if (mode == (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE))
        ret = orcafs_fpunch(inode, offset, len);
    else if (mode == FALLOC_FL_INSERT_RANGE)
        ret = orcafs_fcollapse_finsert(inode, offset, len, true);
    else if (mode == FALLOC_FL_COLLAPSE_RANGE)
        ret = orcafs_fcollapse_finsert(inode, offset, len, false);
    else
        ret = -EOPNOTSUPP;

    percpu_ref_put(&c->writes);

    return ret;
}

static void
mark_range_unallocated(struct orca_inode_info *inode, loff_t start, loff_t end)
{
    pgoff_t index = start >> PAGE_SHIFT;
    pgoff_t end_index = (end - 1) >> PAGE_SHIFT;
    struct pagevec pvec;

    pagevec_init(&pvec);

    do {
        unsigned nr_pages, i, j;

        nr_pages = pagevec_lookup_range(&pvec, inode->v.i_mapping, &index, end_index);

        if (nr_pages == 0)
            break;

        for (i = 0; i < nr_pages; i++) {
            struct page *page = pvec.pages[i];
            struct orca_page_state *s;

            lock_page(page);
            s = orca_page_state(page);

            if (s) {
                spin_lock(&s->lock);

                for (j = 0; j < PAGE_SECTORS; j++)
                    s->s[j].nr_replicas = 0;

                spin_unlock(&s->lock);
            }

            unlock_page(page);
        }

        pagevec_release(&pvec);
    } while (index <= end_index);
}

loff_t
orca_remap_file_range(struct file *file_src, loff_t pos_src, struct file *file_dst,
    loff_t pos_dst, loff_t len, unsigned remap_flags)
{
    struct orca_inode_info *src = file_orca_inode(file_src);
    struct orca_inode_info *dst = file_orca_inode(file_dst);
    struct orca_fs *c = src->v.i_sb->s_fs_info;
    s64 i_sectors_delta = 0;
    loff_t ret = 0;

    if (!c->opts.reflink)
        return -EOPNOTSUPP;

    if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
        return -EINVAL;

    if (remap_flags & REMAP_FILE_DEDUP)
        return -EOPNOTSUPP;

    if ((pos_src & (block_bytes(c) - 1)) || (pos_dst & (block_bytes(c) - 1)))
        return -EINVAL;

    if (src == dst && abs(pos_src - pos_dst) < len)
        return -EINVAL;

    orca_lock_inodes(INODE_LOCK | INODE_PAGECACHE_BLOCK, src, dst);
    file_update_time(file_dst);
    inode_dio_wait(&src->v);
    inode_dio_wait(&dst->v);
    ret = generic_remap_file_range_prep(file_src, pos_src, file_dst, pos_dst,
        &len, remap_flags);

    if (ret < 0 || len == 0)
        goto err;

    aligned_len = round_up((u64)len, block_bytes(c));
    ret = write_invalidate_inode_pages_range(dst->v.i_mapping, pos_dst,
        pos_dst + len - 1);

    if (ret)
        goto err;

    mark_range_unallocated(src, pos_src, pos_src + aligned_len);
    ret = orca_remap_range(c, POS(dst->v.i_ino, pos_dst >> 9),
        POS(src->v.i_ino, pos_src >> 9), aligned_len >> 9,
        &dst->ei_journal_seq, pos_dst + len, &i_sectors_delta);

    if (ret < 0)
        goto err;

    /**
     * Due to alignment, we might have remapped slightly more than
     * requested.
    **/
    ret = min((u64)ret << 9, (u64)len);
    i_sectors_acct(c, dst, NULL, i_sectors_delta);
    spin_lock(&dst->v.i_lock);

    if (pos_dst + ret > dst->v.i_size)
        i_size_write(&dst->v, pos_dst + ret);

    spin_unlock(&dst->v.i_lock);

err:
    orca_unlock_inodes(INODE_LOCK | INODE_PAGECACHE_BLOCK, src, dst);

    return ret;
}

static int
page_data_offset(struct page *page, unsigned offset)
{
    struct orca_page_state *s = orca_page_state(page);
    unsigned i;

    if (s) {
        for (i = offset >> 9; i < PAGE_SECTORS; i++) {
            if (s->s[i].state >= SECTOR_DIRTY)
                return i << 9;
        }
    }

    return -1;
}

static loff_t
orca_seek_pagecache_data(struct inode *vinode, loff_t start_offset, loff_t end_offset)
{
    struct address_space *mapping = vinode->i_mapping;
    struct page *page;
    pgoff_t start_index = start_offset >> PAGE_SHIFT;
    pgoff_t end_index = end_offset >> PAGE_SHIFT;
    pgoff_t index = start_index;
    loff_t ret;
    int offset;

    while (index <= end_index) {
        if (find_get_pages_range(mapping, &index, end_index, 1, &page)) {
            lock_page(page);
            offset = page_data_offset(page, page->index == start_index
                ? start_offset & (PAGE_SIZE - 1)
                : 0);

            if (offset >= 0) {
                ret = clamp(((loff_t)page->index << PAGE_SHIFT) + offset, start_offset,
                    end_offset);
                unlock_page(page);
                put_page(page);

                return ret;
            }

            unlock_page(page);
            put_page(page);
        } else {
            break;
        }
    }

    return end_offset;
}

static loff_t
orca_seek_data(struct file *file, u64 offset)
{
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 isize, next_data = MAX_LFS_FILESIZE;
    int ret;

    isize = i_size_read(&inode->v);

    if (offset >= isize)
        return -ENXIO;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS(inode->v.i_ino,
        offset >> 9), 0, k, ret) {
            if (k.k->p.inode != inode->v.i_ino) {
                break;
            } else if (bkey_extent_is_data(k.k)) {
                next_data = max(offset, bkey_start_offset(k.k) << 9);
                break;
            } else if (k.k->p.offset >> 9 > isize) {
                break;
            }
    }

    ret = orca_trans_exit(&trans) ?: ret;

    if (ret)
        return ret;

    if (next_data > offset)
        next_data = orca_seek_pagecache_data(&inode->v, offset, next_data);

    if (next_data >= isize)
        return -ENXIO;

    return vfs_setpos(file, next_data, MAX_LFS_FILESIZE);
}

static int
__page_hole_offset(struct page *page, unsigned offset)
{
    struct orca_page_state *s = orca_page_state(page);
    unsigned i;

    if (!s)
        return 0;

    for (i = offset >> 9; i < PAGE_SECTORS; i++) {
        if (s->s[i].state < SECTOR_DIRTY)
            return i << 9;
    }

    return -1;
}

static loff_t
page_hole_offset(struct address_space *mapping, loff_t offset)
{
    pgoff_t index = offset >> PAGE_SHIFT;
    struct page *page;
    int pg_offset;
    loff_t ret = -1;

    page = find_lock_entry(mapping, index);

    if (!page || xa_is_value(page))
        return offset;

    pg_offset = __page_hole_offset(page, offset & (PAGE_SIZE - 1));

    if (pg_offset >= 0)
        ret = ((loff_t)index << PAGE_SHIFT) + pg_offset;

    unlock_page(page);

    return ret;
}

static loff_t
orca_seek_pagecache_hole(struct inode *vinode, loff_t start_offset,
    loff_t end_offset)
{
    struct address_space *mapping = vinode->i_mapping;
    loff_t offset = start_offset, hole;

    while (offset < end_offset) {
        hole = page_hole_offset(mapping, offset);

        if (hole >= 0 && hole <= end_offset)
            return max(start_offset, hole);

        offset += PAGE_SIZE;
        offset &= PAGE_MASK;
    }

    return end_offset;
}

static loff_t
orca_seek_hole(struct file *file, u64 offset)
{
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_iter *iter;
    struct bkey_s_c k;
    u64 isize, next_hole = MAX_LFS_FILESIZE;
    int ret;

    isize = i_size_read(&inode->v);

    if (offset >= isize)
        return -ENXIO;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS(inode->v.i_ino,
        offset >> 9), BTREE_ITER_SLOTS, k, ret) {
            if (k.k->p.inode != inode->v.i_ino) {
                next_hole = orca_seek_pagecache_hole(&inode->v, offset,
                    MAX_LFS_FILESIZE);
                break;
            } else if (!bkey_extent_is_data(k.k)) {
                next_hole = orca_seek_pagecache_hole(*inode->v, max(offset,
                    bkey_start_offset(k.k) << 9), k.k->p.offset << 9);

                if (next_hole < k.k->p.offset << 9)
                    break;
            } else {
                offset = max(offset, bkey_start_offset(k.k) << 9);
            }
    }

    ret = orca_trans_exit(&trans) ?: ret;

    if (ret)
        return ret;

    if (next_hole > isize)
        next_hole = isize;

    return vfs_setpos(file, next_hole, MAX_LFS_FILESIZE);
}

loff_t
orca_llseek(struct file *file, loff_t offset, int whence)
{
    switch (whence) {
    case SEEK_SET:
    case SEEK_CUR:
    case SEEK_END:
        return generic_file_llseek(file, offset, whence);

    case SEEK_DATA:
        return orca_seek_data(file, offset);

    case SEEK_HOLE:
        return orca_seek_hole(file, offset);
    }

    return -EINVAL;
}

void
orca_fs_fsio_exit(struct orca_fs *c)
{
    bioset_exit(&c->dio_write_bioset);
    bioset_exit(&c->dio_read_bioset);
    bioset_exit(&c->writepage_bioset);
}

int
orca_fs_fsio_init(struct orca_fs *c)
{
    int ret = 0;

    pr_verbose_init(c->opts, "");

    if (bioset_init(&c->writepage_bioset, 4, offsetof(struct orca_writepage_io,
        op.wbio.bio), BIOSET_NEED_BVECS) || bioset_init(&c->dio_read_bioset,
        4, offsetof(struct dio_read, rbio.bio), BIOSET_NEED_BVECS) ||
        bioset_init(&c->dio_write_bioset, 4, offsetof(struct dio_write,
        op.wbio.bio), BIOSET_NEED_BVECS))
            ret = -ENOMEM;

    pr_verbose_init(c->opts, "ret %i", ret);

    return ret;
}

#endif