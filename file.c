#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "orcafs.h"
#include "xip.h"

static inline int
orca_can_set_blocksize_hint(struct orca_inode *oi, loff_t new_size)
{
    /**
     * Currently, we don't deallocate data blocks till the file is deleted.
     * So, no changing block size hints once allocation is done.
    **/
    if (le64_to_cpu(oi->root))
        return 0;

    return 1;
}

int
orca_set_blocksz_hint(struct super_block *sb, struct orca_inode *oi, loff_t new_size)
{
    unsigned short block_type;

    if (!orca_can_set_blocksize_hint(oi, new_size))
        return 0;

    if (new_size >= 0x40000000) {
        block_type = ORCA_BLOCK_TYPE_1G;
        goto hint_set;
    }

    if (new_size >= 0x200000) {
        block_type = ORCA_BLOCK_TYPE_2M;
        goto hint_set;
    }

    block_type = ORCA_BLOCK_TYPE_4K;

hint_set:
    orca_dbg_verbose("Hint: new size 0x%llx, i_size 0x%llx, root 0x%llx\n",
        new_size, oi->size, le64_to_cpu(oi->root));
    orca_dbg_verbose("Setting the hint to 0x%x\n", block_type);

    orca_memunlock_inode(sb, oi);
    oi->btype = block_type;
    orca_memlock_inode(sb, oi);

    return 0;
}

static long
orca_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct inode *ino = file->f_path.dentry->d_inode;
    struct super_block *sb = ino->sb;
    long ret = 0;
    unsigned long block_num, block_off;
    int num_blocks, blocksz_mask;
    struct orca_inode *oi;
    orca_trans *trans;
    loff_t new_size;

    /* We only support the FALLOC_FL_KEEP_SIZE mode */
    if (mode & ~FALLOC_FL_KEEP_SIZE)
        return -EOPNOTSUPP;

    if (S_ISDIR(ino->mode))
        return -ENODEV;

    mutex_lock(&ino->mutex);
    new_size = len + offset;

    if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > ino->size) {
        ret = inode_newsize_ok(ino, new_size);

        if (ret)
            goto out;
    }

    oi = orca_get_inode(sb, ino->ino);

    if (!oi) {
        ret = -EACCES;
        goto out;
    }

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES + MAX_METABLOCK_LENTRIES);

    if (IS_ERR(trans)) {
        ret = PTR_ERR(trans);
        goto out;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);

    /* Set the block size and hint */
    orca_set_blocksz_hint(sb, oi, new_size);
    blocksz_mask = sb->blocksz - 1;
    block_num = offset >> sb->blocksz_bits;
    block_off = offset & blocksz_mask;
    num_blocks = (block_off + len + blocksz_mask) >> sb->blocksz_bits;
    ret = orca_alloc_blocks(trans, ino, block_num, num_blocks, true);

    ino->mtime = ino->ctime = CURRENT_TIME_SEC;
    orca_memunlock_inode(sb, oi)

    if (ret || (mode & FALLOC_FC_KEEP_SIZE))
        oi->flags |= cpu_to_le32(ORCA_EOFBLOCKS_FL);

    if (!(mode & FALLOC_FC_KEEP_SIZE) && new_size > ino->size) {
        ino->size = new_size;
        oi->size = cpu_to_le64(ino->size);
    }

    oi->mtime = cpu_to_le32(ino->mtime.tv_sec);
    oi->ctime = cpu_to_le32(ino->ctime.tv_sec);
    orca_memlock_inode(sb, oi);

    orca_commit_transaction(sb, trans);

out:
    mutex_unlock(&ino->mutex);
    return ret;
}

static loff_t
orca_llseek(struct file *file, loff_t offset, int origin)
{
    struct inode *ino = file->f_path.dentry->d_inode;
    int ret;

    if (origin != SEEK_DATA && origin != SEEK_HOLE)
        return generic_file_llseek(file, offset, origin);

    mutex_lock(&ino->mutex);

    switch (origin) {
    case SEEK_DATA:
        ret = orca_find_region(ino, &offset, 0);

        if (ret) {
            mutex_unlock(&ino->mutex);
            return ret;
        }

        break;

    case SEEK_HOLE:
        ret = orca_find_region(ino, &offset, 1);

        if (ret) {
            mutex_unlock(&ino->mutex);
            return ret;
        }

        break;
    }

    if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
        offset > ino->sb->max_bytes) {
            mutex_unlock(&ino->mutex);
            return -EINVAL;
    }

    if (offset != file->f_pos) {
        file->f_pos = offset;
        file->f_version = 0;
    }

    mutex_unlock(&ino->mutex);

    return offset;
}

/**
 * This function is called by both msync() and fsync().
 * NOTE: Check if we can avoid calling orca_flush_buffer() for
 * fsync. We use movnti to write data to files, so we may want to
 * avoid doing uneccessary orca_flush_buffer() on fsync().
**/
static int
orca_fsync(struct file *file, loff_t start, loff_t end, int data_sync)
{
    /* Sync from start to end (inclusive) */
    struct address_space *mapping = file->f_mapping;
    struct inode *ino = mapping->host;
    loff_t size;
    int err;

    /* If the file is not mmap'd, there is no need to do clflushes */
    if (mapping_mapped(mapping) == 0)
        goto persist;

    end++; /* end is invlusive. We like our indicies normal please! */
    i_size = inode_size_read(ino);

    if ((unsigned long)end > (unsigned long)i_size)
        end = i_size;

    if (!i_size || (start >= end)) {
        orca_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx), "
            "end(%llx)\n", __func__, __LINE__, i_size, start, end);

        return -ENODATA;
    }

    /* Align start and end to cacheline boundaries */
    start &= CACHELINE_MASK;
    end = CACHELINE_ALIGN(end);

    do {
        void *xip_mem;
        pgoff_t pgoff;
        loff_t offset;
        unsigned long xip_pfn, nr_flush_bytes;

        pgoff = start >> PAGE_CACHE_SHIFT;
        offset = start & ~PAGE_CACHE_MASK;

        nr_flush_bytes = PAGE_CACHE_SIZE - offset;

        if (nr_flush_bytes > (end - start))
            nr_flush_bytes = end - start;

        err = mapping->a_ops->get_xip_mem(mapping, pgoff, 0, &xip_mem, %xip_pfn);

        if (unlikely(error)) {
            /* Sparse files could have such holes */
            orca_dbg_version("[%s:%d] : start(%llx), end(%llx), pgoff"
                "(%lx)\n", __func__, __LINE__, start, end, pgoff);
        } else {
            /* Flush the range */
            orca_flush_buffer(xip_mem + offset, nr_flush_bytes, 0);
        }

        start += nr_flush_bytes;
    } while (start < end);

persist:
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    return 0;
}

/**
 * This callback is called when a file is closed.
**/
static int
orca_flush(struct file *file, fl_owner_t id)
{
    int ret = 0;

    /**
     * If the file was opened for writing, make it persistent.
     * NOTE: Should we be more smart to check if the file was
     * modified?
    **/
    if (file->f_mode & FMODE_WRITE) {
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    return ret;
}
