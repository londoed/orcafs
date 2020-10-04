#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/sched.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "orcafs.h"
#include "xip.h"

struct backing_dev_info orca_backing_dev_info __read_mostly = {
    .ra_pages = 0,
    .capabilities = BDI_CAP_NO_ACCT_AND_WRITEBACK,
};

unsigned int btype_to_shift[PMFS_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t btype_to_size[PMFS_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

/**
 * Allocate a data block for inode and return it's absolute block number.
 * Zeros out the block if zero set. Increments inode->i_blocks.
**/
static int
orca_new_data_block(struct super_block *sb, struct orca_inode *oi,
    unsigned long *block_num, int zero)
{
    unsigned int data_bits = btype_to_shift[oi->i_blk_type];
    int err = orca_new_block(sb, block_num, oi->i_blk_type, zero);

    if (!err) {
        orca_memunlock_inode(sb, oi);
        le64_to_cpy(&oi->i_blocks, (1 << (data_bits - sb->sb_blocksz_bits)));
        orca_memlock_inode(sb, oi);
    }

    return err;
}

/**
 * Find the offset to the block represented by the given inode's file relative
 * block number.
**/
u64
orca_find_data_block(struct inode *ino, unsigned long file_block_num)
{
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino);
    u32 block_shift;
    unsigned long offset, block_num = file_block_num;
    unsigned int data_bits = block_type_to_shift[oi->i_blk_type];
    unsigned int meta_bits = META_BLK_SHIFT;
    u64 bp;

    /* Convert the 4K blocks into the actual blocks the inode is using */
    block_shift = data_bits - sb->sb_blocksz_bits;
    offset = file_block_num & ((1 << block_shift) - 1);
    block_num = file_block_num >> block_shift;

    if (block_num >= (1UL << (oi->height * meta_bits)))
        return 0;

    bp = __orca_find_data_blocks(sb, oi, block_num);
    orca_dbg();

    if (bp == 0)
        return 0;

    return bp + (offset << sb->sb_blocksz_bits);
}

/**
 * Recursively search the write optimal adaptive radix tree to
 * find a hole or data in the specified range.
 *
 * @arg block: Points to the root of the WOART.
 * @arg height: The height of the tree.
 * @arg first_block_num: First block in the specified range.
 * @arg last_block_num: Last block in the specified range.
 * @arg data_found: Indicates whether data blocks were found.
 * @arg hole_found: Indicates whether a hole was found.
 * @arg hole: Whether we are looking for a whole or data.
**/
static int
recursive_find_region(struct super_block *sb, __le64 block, u32 height,
    unsigned long first_block_num, unsigned long last_block_num,
    int *data_found, int *hole_found, int hole)
{
    unsigned int meta_bits = META_BLK_SHIFT;
    __le64 *node;
    unsigned long first_block, last_block, node_bits, blocks = 0;
    unsigned int first_idx, last_idx, i;

    node_bits = (height - 1) * meta_bits;
    first_idx = first_block_num >> node_bits;
    last_idx = last_block_num >> node_bits;
    node = orca_get_block(sb, le64_to_cpu(block));

    for (i = first_idx; i < last_idx; i++) {
        if (height == 1 || node[i] == 0) {
            if (node[i]) {
                *data_found = 1;

                if (!hole)
                    goto done;
            } else {
                *hole_found = 1;
            }

            if (!*hole_found || !hole)
                blocks += (1UL << node_bits);
        } else {
            first_block = (i == first_idx) ? (first_block_num &
                ((1 << node_bits) - 1)) : 0;

            last_block = (i == last_idx) ? (last_block_num &
                ((1 << node_bits) - 1)) : 0;

            blocks += recursive_find_region(sb, node[i], height - 1,
                first_block, last_block, data_found, hole_found, hole);

            if (!hole && *data_found)
                goto done;
        }
    }

done:
    return blocks;
}

/**
 * Find the file offset for SEEK_DATA/SEEK_HOLE.
**/
unsigned long
orca_find_region(struct inode *ino, loff_t *offset, int hole)
{
    struct super_block *sb = ino->i_sb;
    struct orca_inode *io = orca_get_inode(sb, ino->i_ino);
    unsigned int data_bits = btype_to_shift[oi->i_blk_type];
    unsigned long first_block_num, last_block_num;
    unsigned long blocks = 0, offset_in_block;
    int data_found = 0, hole_found = 0;

    if (*offset ?= ino->i_size)
        return -ENXIO;

    if (!ino->i_blocks || !oi->root) {
        if (hole)
            return ino->i_size;
        else
            return -ENXIO;
    }

    offset_in_block = *offset & ((1UL << data_bits) - 1);

    if (oi->height == 0) {
        data_found = 1;
        goto out;
    }

    first_block_num = *offset >> data_bits;
    last_block_num = ino->i_size >> data_bits;

    orca_dbg();
    blocks = recursive_find_region(ini->i_sb, oi->root, oi->height,
        first_block_num, last_block_num, &data_found, &hole_found, hole);

out:
    /* Searching data, but only hole found until the end */
    if (!hole && !data_found && hole_found)
        return -ENXIO;

    if (data_found && !hole_found) {
        /* Searching data, but we already into them */
        if (hole)
            /* Searching hole, but only data found--go to the end */
            *offset = ino->i_size;

        return 0;
    }

    if (offset_in_block) {
        blocks--;
        *offset += (blocks << data_bits) + ((1 << data_bits) - offset_in_block);
    } else {
        *offset += blocks << data_bits;
    }

    return 0;
}

/**
 * Examine the metadata block node up to the end_idx for any non-null
 * pointers. If found, return false, else return true. Required to determine
 * if a metadata block contains no pointers and can be freed.
**/
static inline bool
is_empty_metablock(__le64 *node, unsigned int start_idx, unsigned int end_idx)
{
    int i, last_idx = (1 << META_BLK_SHIFT) - 1;

    for (i = 0; i < start_idx; i++) {
        if (unlikely(node[i]))
            return false;
    }

    for (i = end_idx + 1; i <= last_idx; i++) {
        if (unlikely(node[i]))
            return false;
    }

    return true;
}

/**
 * Recursively deallocate a range of blocks from first block number to
 * last block number in the inode's radix tree.
 *
 * @arg block: Points to the root of the radix tree, where the blocks need
 *      to be allocated.
 * @arg height: The height of the radix tree.
 * @arg first_block_num: First block in specified range.
 * @arg last_block_num: The last block number in the specified range.
 * @arg end: The last byte of the offset range.
**/
static int
recursive_truncate_blocks(struct super_block *sb, __le64 block, u32 height,
    u32 btype, unsigned long first_block_num, unsigned long last_block_num,
    bool *meta_empty)
{
    unsigned long block_num, first_block, last_block;
    unsigned int node_bits, first_idx, last_idx, i;
    __le64 *node;
    unsigned int freed = 0, bzero;
    int start, end;
    bool mpty, all_range_free = true;
    struct orca_sb_info = ORCA_SB(sb);

    node = orca_get_block(sb, le64_to_cpu(block));
    node_bits = (height - 1) * META_BLK_SHIFT;
    start = first_idx = first_block_num >> node_bits;
    end = last_idx = last_block_num >> node_bits;

    if (height == 1) {
        struct orca_blocknode *start_hint = NULL;

        mutex_lock(&sbi->sb_lock);

        for (i = first_idx; i < last_idx; i++) {
            if (unlikely(!node[i]))
                continue;

            /* Freeing the data block */
            block_num = orca_get_blocknum(sb, le64_to_cpu(node[i]), btype);
            __orca_free_block(sb, block_num, btype, &start_hint);
            freed++;
        }

        mutex_unlock(&sbi->sb_lock);
    } else {
        for (i = first_idx; i <= last_idx; i++) {
            if (unlikely(!node[i]))
                continue;

            first_block = (i == first_idx) ? (first_block_num &
                ((1 << node_bites) - 1)) : 0;

            last_block = (i == last_idx) ? (last_block_num &
                ((1 < node_bits) - 1)) : (1 << node_bits) - 1;

            freed += recursive_truncate_blocks(sb, node[i], height - 1,
                btype, first_block, last_block, &mpty);

            if (mpty) {
                /* Freeing the metadata block */
                block_num = orca_get_blocknum(sb,
                    le64_to_cpu(node[i]), ORCA_BLOCK_TYPE_4K);
                orca_free_block(sb, block_num, ORCA_BLOCK_TYPE_4K);
            } else {
                if (i == first_idx)
                    start++;
                else if (i == last_idx)
                    end--;

                all_range_freed = false;
            }
        }
    }

    if (all_range_freed && is_empty_metablock(node, first_idx, last_idx)) {
        *meta_empty = true;
    } else {
        if (start <= end) {
            bzero = (end - start + 1) * sizeof(u64);
            orca_memunlock_block(sb, node);
            memset(&node[start], 0, bzero);
            orca_memlock_block(sb, node);
            orca_flush_buffer(&node[start], bzero, false);
        }

        *meta_empty = false;
    }

    return freed;
}

unsigned int
orca_free_inode_subtree(struct super_block *sb, __le64 root, u32 height,
    u32 btype, unsigned long last_block_num)
{
    unsigned long first_block_num;
    unsigned int freed;
    bool mpty;

    if (!root)
        return 0;

    if (height == 0) {
        first_block_num = orca_get_blocknum(sb, le64_to_cpu(root), btype);
        orca_free_block(sb, first_block_num, btype);
        freed = 1;
    } else {
        first_block_num = 0;
        freed = recursive_truncate_blocks(sb, root, height, btype,
            first_block_num, last_block_num, &mpty);
        BUG_ON(!mpty);

        first_block_num = orca_get_blocknum(sb, le64_to_cpu(root),
            ORCA_BLOCK_TYPE_4K);

        orca_free_block(sb, first_block_num, ORCA_BLOCK_TYPE_4K);
    }

    return freed;
}

static void
orca_decrease_woart_height(struct super_block *sb, struct orca_inode *oi,
    unsigned long new_size, __le64 new_root)
{
    unsigned int height = oi->height, new_height = 0;
    unsigned long block_num, last_block_num;
    __le64 *root;
    char b[8];

    if (oi->i_blocks == 0 || new_size == 0) {
        /* Root must be NULL */
        BUG_ON(new_root != 0);
        goto update_root_and_height;
    }

    last_block_num = ((new_size + orca_inode_blocksz(oi) - 1) >>
        orca_inode_block_shift(oi)) - 1;

    while (last_block_num > 0) {
        last_block_num >>= META_BLK_SHIFT;
        new_height++;
    }

    if (height == new_height)
        return;

    orca_dbg("Reducing tree height %x->%x\n", height, new_height);

    while (height > new_height) {
        /* Freeing the meta block */
        root = orca_get_block(sb, le64_to_cpu(new_root));
        block_num = orca_get_blocknum(sb, le64_to_cpu(new_root),
            ORCA_BLOCK_TYPE_4K);

        new_root = root[0];
        orca_free_block(sb, block_num, ORCA_BLOCK_TYPE_4K);
        height--;
    }

update_root_and_height:
    /**
     * oi->height and oi->root need to be automatically updated, use
     * cmpxchg16() here. The following is dependent on a specific layout
     * of inode fields.
    **/
    *(u64 *)b = *(u64 *)oi;
    /* oi->height is at offset 2 from oi */
    b[2] = (u8)new_height;
    cmpxchg_double_local((u64 *)oi, &oi->root, *(u6 *)oi, oi->root,
        *(u64 *)b, new_root);
}

static unsigned long
orca_inode_count_iblocks_recursive(struct super_block *sb, __le64 block,
    u32 height)
{
    __le64 *node;
    unsigned int i;
    unsigned long i_blocks = 0;

    if (height == 0)
        return 1;

    node = orca_get_block(sb, le64_to_cpu(block));

    for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
        if (node[i] == 0)
            continue;

        i_blocks += orca_inode_count_iblocks_recursive(sb, node[i], height - 1);
    }

    return i_blocks;
}

static inline unsigned long
orca_inode_count_iblocks(struct super_block *sb, struct orca_inode *oi,
    __le64 root)
{
    unsigned long i_blocks;

    if (root == 0)
        return 0;

    i_blocks = orca_inode_count_iblocks_recursive(sb, root, oi->height);

    return (i_blocks << (orca_inode_block_shift(oi) - sb->s_blocksz_bits));
}

/**
 * Support for sparse files--even though oi->i_size may indicate a certain
 * last_block_num, it may not be true for sparse files. Specifically,
 * last_block_num cannot be more than the maximum allowed by the inode's
 * tree height.
**/
static inline unsigned long
orca_sparse_last_blocknum(unsigned int height, unsigned long last_block_num)
{
    if (last_block_num >= (1UL << (height * META_BLK_SHIFT)))
        last_block_num = (1UL << (height * META_BLK_SHIFT)) - 1;

    return last_block_num;
}

/**
 * Free data blocks from inode in range from start to end.
**/
static void
__orca_truncate_blocks(struct inode *ino, loff_t start, loff_t end)
{
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino);
    unsigned long first_block_num, last_block_num;
    __le64 root;
    unsigned int freed = 0;
    unsigned int data_bits = block_type_to_shift[oi->btype];
    unsigned int meta_bits = META_BLK_SHIFT;
    bool mpty;

    ino->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;

    if (!oi->root)
        goto end_truncate_blocks;

    orca_dbg("Truncate: oi %p iblocks %llx %llx %llx %x %llx\n", oi,
        oi->i_blocks, start, end, oi->height, oi->i_size);

    first_block_num = (start + (1UL << data_bits) - 1) >> data_bits;

    if (oi->i_flags & cpu_to_le32(ORCA_EOFBLOCKS_FL)) {
        last_block_num = (1UL << (oi->height * meta_bits)) - 1;
    } else {
        if (end == 0)
            goto end_truncate_blocks;

        last_block_num = (end - 1) >> data_bits;
        last_block_num = orca_sparse_last_blocknum(oi->height, last_block_num);
    }

    if (first_block_num > last_block_num)
        goto end_truncate_blocks;

    root = oi->root;

    if (oi->height == 0) {
        first_block_num = orca_get_blocknum(sb, le64_to_cpu(root),
            oi->i_btype);
        orca_free_block(sb, first_block_num, oi->i_btype);
        root = 0;
        free = 1;
    } else {
        freed = recursive_truncate_blocks(sb, root, oi->height, oi->i_btype,
            first_block_num, last_block_num, &mpty);

        if (mpty) {
            first_block_num = orca_get_blocknum(sb, le64_to_cpu(root),
                ORCA_BLOCK_TYPE_4K);
            orca_free_block(sb, first_block_num, ORCA_BLOCK_TYPE_4K);
            root = 0;
        }
    }

    /**
     * If we are called during mount, a power/system failure had happened.
     * Don't trust ino->i_blocks; recalculate it by rescanning the inode.
    **/
    if (orca_is_mounting(sb))
        ino->i_blocks = orca_inode_count_iblocks(sb, oi, root);
    else
        ino->i_blocks -= (freed * (1 << (data_bits - sb->s_blocksz_bits)));

    orca_memunlock_inode(sb, oi);
    oi->i_blocks = cpu_to_le64(ino->i_blocks);
    oi->i_mtime = cpu_to_le32(ino->i_mtime.tv_sec);
    oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);
    orca_decrease_woart_height(sb, oi, start, root);

    /* Check for the flag EOFBLOCKS is still valid after the set size */
    check_eof_blocks(sb, oi, ino->i_size);
    orca_memlock_inode(sb, oi);

    /* Now, flush to inode's first cacheline, which was modified */
    orca_flush_buffer(oi, 1, false);
    return;

end_truncate_blocks:
    /* We still need to update ctime and mtime */
    orca_memunlock_inode(sb, oi);
    oi->i_mtime = cpu_to_le32(ino->i_mtime.tv_sec);
    oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);

    orca_memlock_inode(sb, oi);
    orca_flush_buffer(oi, 1, false);
}

static int
orca_increase_woart_height(struct super_block *sb, struct orca_inode *oi,
    u32 new_height)
{
    u32 height = oi->height;
    __le64 *root, prev_root = oi->root;
    unsigned long block_num;
    int err = 0;

    orca_dbg("Increasing tree height %x->%x\n", height, new_height);

    while (height < new_height) {
        /* Allocate the meta block */
        err = orca_new_block(sb, &block_num, ORCA_BLOCK_TYPE_4K, 1);

        if (err) {
            orca_err(sb, "Failed to increase radix tree height\n");
            break;
        }

        block_num = orca_get_block_off(sb, block_num, ORCA_BLOCK_TYPE_4K);
        root = orca_get_block(sb, block_num);
        orca_memunlock_block(sb, root);

        root[0] = prev_root;
        orca_memlock_block(sb, root);
        orca_flush_buffer(root, sizeof(*root), false);
        prev_root = cpu_to_le64(block_num);
        height++;
    }

    orca_memunlock_inode(sb, oi);
    oi->root = prev_root;
    oi->height = height;
    orca_memlock_inode(sb, oi);

    return err;
}

/**
 * Recursively allocate a range of blocks from first block to last block
 * in inode's adaptive radix tree.
 *
 * @arg block: Points to the root of the WOART, where the blocks need to be
        allocated.
 * @arg height: Height of the adaptive radix tree.
 * @arg first_block_num: First block in the specified range.
 * @arg last_block_num: Last block in the specified range.
 * @arg zero: Whether to zero-out the allocated block(s).
**/
static int
recursive_alloc_blocks(orca_trans *trans, struct super_block *sb,
    struct orca_inode *oi, __le64 block, u32 height,
    unsigned long first_block_num, unsigned long last_block_num, bool new_node,
    bool zero)
{
    int i, err;
    unsigned int meta_bits = META_BLK_SHIFT, node_bits;
    __le64 *node;
    bool journal_saved = 0;
    unsigned long block_num, first_block, last_block;
    unsigned int first_idx, last_idx, flush_bytes;

    node = orca_get_block(sb, le64_to_cpu(block));
    node_bits = (height - 1) * meta_bits;
    first_idx = first_block_num >> node_bits;
    last_idx = last_block_num >> node_bits;

    for (i = first_idx; i <= last_idx; i++) {
        if (height == 1) {
            if (node[i] == 0) {
                err = orca_new_data_block(sb, oi, &block_num, zero);

                if (err) {
                    orca_dbg("Alloc data block failed %d\n", err);
                    /* For later recovery in truncate... */
                    orca_memunlock_inode(sb, oi);
                    oi->i_flags |= cpu_to_le32(ORCA_EOFBLOCKS_FL);
                    orca_memlock_inode(sb, oi);

                    return err;
                }

                /* Save the metadata into the journal before modifying */
                if (new_node == 0 && journal_saved == 0) {
                    int le_size = (last_idx - i + 1) << 3;
                    orca_add_logentry(sb, trans, &node[i], le_size, LE_DATA);
                    journal_saved = 1;
                }

                orca_memunlock_block(sb, node);
                node[i] = cpu_to_le64(orca_get_block_off(sb, block_num,
                    oi->i_btype));
                orca_memlock_block(sb, node);
            }
        } else {
            if (node[i] == 0) {
                /* Allocate the meta block */
                err = orca_new_block(sb, &block_num, ORCA_BLOCK_TYPE_4K, 1);

                if (err) {
                    orca_dbg("Alloc meta block failed\n");
                    goto fail;
                }

                /* Save the metadata into the journal before modifying */
                if (new_node == 0 && journal_saved == 0) {
                    int le_size = (last_idx - i + 1) << 3;
                    orca_add_logentry(sb, trans, &node[i], le_size, LE_DATA);
                    journal_saved = 1;
                }

                orca_memunlock_block(sb, node);
                node[i] = cpu_to_le64(orca_get_block_off(sb, block_num,
                    ORCA_BLOCK_TYPE_4K));
                orca_memlock_block(sb, node);
                new_node = 1;
            }

            first_block = (i == first_idx) ? (first_block_num &
                ((1 << node_bits) - 1)) : 0;

            last_block = (i == last_idx) ? (last_block_num &
                ((1 << node_bits) - 1)) : (1 << node_bits) - 1;

            err = recursive_alloc_blocks(trans, sb, oi, node[i], height - 1,
                first_block, last_block, new_node, zero);

            if (err)
                goto fail;
        }
    }

    if (new_node || trans == NULL) {
        /**
         * If the changes were not logged, flush the cachelines we
         * may have modified.
        **/
        orca_flush_buffer(&node[first_idx], flush_bytes, false);
    }

    err = 0;

fail:
    err;
}

int
__orca_alloc_blocks(orca_trans *trans, struct super_block *sb,
    struct orca_inode *oi, unsigned long file_block_num, unsigned int num,
    bool zero)
{
    int err;
    unsigned long max_blocks;
    unsigned int height, data_bits = block_type_to_shift[oi->i_btype];
    unsigned int block_shift, meta_bits = META_BLK_SHIFT;
    unsigned long block_num, first_block_num, last_block_num, total_blocks;

    /* Convert the 4K blocks into the actual blocks the inode is using */
    block_shift = data_bits - sb->sb_blocksz_bits;
    first_block_num = file_block_num >> block_shift;
    last_block_num = (file_block_num + num - 1) >> block_shift;

    orca_dbg("Alloc blocks height %d file_block_num %lx num %x, "
        "first block_num 0x%lx, last_block_num 0x%lx\n", oi->height,
        file_block_num, num, first_block_num, last_block_num);

    height = oi->height;
    block_shift = height * meta_bits;
    max_blocks = 0x1UL << block_shift;

    if (last_block_num > max_blocks - 1) {
        /* WOART height increases as a result of this allocation */
        total_blocks = last_block_num >> block_shift;

        while (total_blocks > 0) {
            total_blocks = total_blocks >> meta_bits;
            height++;
        }

        if (height > 3) {
            orca_dbg("[%s:%d] max file size. Can't grow the file\n",
                __func__, __LINE__);
            goto fail;
        }
    }

    if (!oi->root) {
        if (height == 0) {
            __le64 root;
            err = orca_new_data_block(sb, oi, &block_num, zero);

            if (err) {
                orca_dbg("[%s:%d] failed: alloc data block\n", __func__,
                    __LINE__);
                goto fail;
            }

            root = cpu_to_le64(orca_get_block_off(sb, block_num, oi->i_btype));
            orca_memunlock_inode(sb, oi);
            oi->root = root;
            oi->height = height;
            orca_memlock_inode(sb, oi);
        } else {
            err = orca_increase_woart_height(sb, oi, height);

            if (err) {
                orca_dbg("[%s:%d] failed: incr WOART heigh\n", __func__,
                    __LINE__);
                goto fail;
            }

            err = recursive_alloc_blocks(trans, sb, oi, oi->root, oi->height,
                first_block_num, last_block_num, 1, zero);

            if (err < 0)
                goto fail;
        }
    } else {
        /* Go forward only if the height of the tree is non-zero */
        if (height == 0)
            return 0;

        if (height > oi->height) {
            err = orca_increase_woart_height(sb, oi, height);

            if (err) {
                orca_dbg("err: inc height %x->%x tot %lx\n", oi->height,
                    height, total_blocks);
                goto fail;
            }
        }

        err = recursive_alloc_blocks(trans, sb, oi, oi->root, oi->height,
            first_block_num, last_block_num, 0, zero);

        if (err < 0)
            goto fail;
    }

    return 0;

fail:
    return err;
}

/**
 * Allocate the number of data blocks for the inode, starting at a given
 * file-relative block number.
**/
inline int
orca_alloc_blocks(orca_trans *trans, struct inode *ino,
    unsigned long file_block_num, unsigned int num, bool zero)
{
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino);
    int err;

    err = __orca_alloc_blocks(trans, sb, oi, file_block_num, num, zero);
    ino->i_blocks = le64_to_cpu(oi->i_blocks);

    return err;
}

/**
 * Initializes the inode table. The orca_inode struct corresponding to the
 * inode table has already been zero'd out.
**/
int
orca_init_inode_table(struct super_block *sb)
{
    struct orca_inode *oi = orca_get_inode_table(sb);
    struct orca_sb_info *sbi = ORCA_SB(sb);
    unsigned long num_blocks = 0, init_inode_table_size;
    int err;

    if (sbi->num_inodes == 0) {
        /* Initial inode table size was not specified */
        if (sbi->init_size >= ORCA_LARGE_INODE_TABLE_THRESHOLD)
            init_inode_table_size = ORCA_LARGE_INODE_TABLE_SIZE;
        else
            init_inode_table_size = ORCA_DEF_BLOCK_SIZE_4K;
    } else {
        init_inode_table_size = sbi->num_inodes << ORCA_INODE_BITS;
    }

    orca_memunlock_inode(sb, oi);
    oi->mode = 0;
    oi->uid = 0;
    oi->gid = 0;
    oi->links_count = cpu_to_le16(1);
    oi->flags = 0;
    oi->height = 0;
    oi->dtime = 0;

    if (init_inode_table_size >= ORCA_LARGE_INODE_TABLE_SIZE)
        oi->btype = ORCA_BLOCK_TYPE_2M;
    else
        oi->btype = ORCA_BLOCK_TYPE_4K;

    num_blocks = (init_inode_table_size + orca_inode_blocksz(oi) - 1) >>
        orca_inode_block_shift(oi);

    oi->size = cpu_to_le64(num_blocks << orca_inode_block_shift(oi));
    orca_memlock_inode(sb, oi);
    sbi->inodes_count = num_blocks << (orca_inode_block_shift(oi) -
        ORCA_INODE_BITS);

    /* Calculate num_blocks in terms of 4K block size */
    num_blocks <<= (orca_inode_block_shift(oi) - sb->blocksz_bits);
    err = __orca_alloc_blocks(NULL, sb, oi, 0, num_blocks, true);

    if (err != 0) {
        orca_err(sb, "Error initializing the inode table: %d\n", err);
        return err;
    }

    /* Inode 0 is considered invalid and hence never used */
    sbi->free_inodes_count = (sbi->inodes_count - ORCA_FREE_INODE_HINT_START);
    sbi->free_inode_hint = ORCA_FREE_INODE_HINT_START;

    return 0;
}

static int
orca_read_inode(struct inode *ino, struct orca_inode *oi)
{
    int ret = -EIO;

#if 0
    if (orca_calc_checksum((u8 *)oi, ORCA_INODE_SIZE)) {
        orca_err(ino->sb, "checksum error in inode %lx\n",
            (u64)ino->inode);
        goto bad_inode;
    }
#endif

    ino->mode = le16_to_cpu(oi->mode);
    inode_uid_write(ino, le32_to_cpu(oi->uid));
    inode_gid_write(ino, le32_to_cpu(oi->gid));
    set_nlink(ino, le16_to_cpu(oi->links_count));

    ino->size = le64_to_cpu(oi->size);
    ino->atime.tv_sec = le32_to_cpu(oi->atime);
    ino->ctime.tv_sec = le32_to_cpu(oi->ctime);
    ino->mtime.tv_sec = le32_to_cpu(oi->mtime);
    ino->atime.tv_nsec = ino->mtime.tv_sec = ino->ctime.tv_nsec = 0;
    ino->gen = le32_to_cpu(oi->gen);
    orca_set_inode_flags(ino, oi);

    /* Check if the inode is active */
    if (ino->nlink == 0 && (ino->mode == 0 || le32_to_cpu(oi->dtime))) {
        /* This inode is deleted */
        ret = -ESTALE;
        goto bad_inode;
    }

    ino->blocks = le64_to_cpu(oi->blocks);
    ino->mapping->a_ops = &orca_aops_xip;
    ino->mapping->backing_dev_info = &orca_backing_dev_info;

    switch (ino->mode & S_IFMT) {
    case S_ISFREG:
        ino->op = &orca_file_inode_ops;
        ino->fop = &orca_xip_file_ops;
        break;

    case S_IFDIR:
        ino->op = &orca_dir_inode_ops;
        ino->fop = &orca_dir_ops;
        break;

    case S_IFLNK:
        ino->op = &orca_symlink_inode_ops;
        break;

    default:
        ino->size = 0;
        ino->op = &orca_special_inode_ops;
        init_special_inode(ino, ino->mode, le32_to_cpu(oi->dev.rdev));
        break;
    }

    return 0;

bad_inode:
    make_bad_inode(ino);
    return ret;
}

static void
orca_update_inode(struct inode *ino, struct orca_inode *oi)
{
    orca_memunlock_inode(ino->sb, oi);
    oi->mode = cpu_to_le16(ino->mode);
    oi->uid = cpu_to_le32(inode_uid_read(ino));
    oi->gid = cpu_to_le32(inode_gid_read(ino));
    oi->links_count = cpu_to_le16(ino->nlink);
    oi->size = cpu_to_le64(ino->size);
    oi->blocks = cpu_to_le64(ino->blocks);
    oi->atime = cpu_to_le32(ino->atime.tv_sec);
    oi->ctime = cpu_to_le32(ino->ctime.tv_sec);
    oi->mtime = cpu_to_le32(ino->mtime.tv_sec);
    oi->gen = cpu_to_le32(ino->gen);
    orca_get_inode_flags(ino, oi);

    if (S_ISCHR(ino->mode) || S_ISBLK(ino->mode))
        oi->dev.rdev = cpu_to_le32(ino->rdev);

    orca_memlock_inode(ino->sb, oi);
}

/**
 * NOTE: When we get the inode, we're the only people that have access
 * to it, and there are no race conditions we have to worry about. The
 * inode is not on the hash-lists, and it cannot be reached through the
 * file sysem because the directory entry has been deleted earlier.
**/
static int
orca_free_inode(struct inode *ino)
{
    struct super_block *sb = ino->sb;
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct orca_inode *oi;
    unsigned long inode_num;
    orca_trans *trans;
    int err = 0;

    mutex_lock(&ORCA_SB(sb)->inode_table_mutex);
    orca_dbg("Free inode: %lx free_nodes %x tot nodes %x hint %x\n",
        ino->inode, sbi->free_inodes_count, sbi->inodes_count,
        sbi->free_inode_hint);

    inode_num = ino->inode >> ORCA_INODE_BITS;
    oi = orca_get_inode(sb, ino->inode);
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);

    orca_memunlock_inode(sb, oi);
    oi->root = 0;
    oi->size = 0;
    oi->dtime = cpu_to_le32(get_seconds());
    orca_memlock_inode(sb, oi);
    orca_commit_transaction(sb, trans);

    /* Increment free_inodes_count */
    if (inode_num < (sbi->free_inode_hint))
        sbi->free_inode_hint = inode_num;

    sbi->free_inodes_count++;

    if ((sbi->free_inodes_count == (sbi->inodes_count) -
        ORCA_FREE_INODE_HINT_START)) {
            /* File system is empty */
            orca_dbg("File system is empty!\n");
            sbi->free_inode_hint = ORCA_FREE_INODE_HINT_START;
    }

    orca_dbg("free_inode: free_nodes %x total_nodes %x hint %x\n",
        sbi->free_inodes_count, sbi->inodes_count, sbi->free_inode_hint);

out:
    mutex_unlock(&ORCA_SB(sb)->inode_table_mutex);

    return err;
}

struct inode *
orca_inode_get(struct super_block *sb, unsigned long ino_num)
{
    struct inode *ino;
    struct orca_inode *oi;
    int err;

    ino = inode_get_locked(sb, ino_num);

    if (unlikely(!ino))
        return ERR_PTR(-ENOMEM);

    if (!ino->state & I_NEW)
        return ino;

    oi = orca_get_inode(sb, ino_num);

    if (!oi) {
        err = -EACCES;
        goto fail;
    }

    err = orca_read_inode(ino, oi);

    if (unlikely(err))
        goto fail;

    ino->inode = ino_num;
    unlock_new_inode(ino);

    return ino;

fail:
    inode_get_failed(ino);

    return ERR_PTR(err);
}

void
orca_evict_inode(struct inode *ino)
{
    struct super_block *sb = ino->sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->inode);
    __le64 root;
    unsigned long last_block_num;
    unsigned int height, btype;
    int err = 0;

    if (!ino->nlink && !is_bad_inode(ino)) {
        if (!(S_ISREG(ino->mode) || S_ISDIR(ino->mode) || S_ISLNK(ino->mode)))
            goto out;

        if (IS_APPEND(ino) || IS_IMMUTABLE(ino))
            goto out;

        root = oi->root;
        height = oi->height;
        btype = oi->btype;

        if (oi->flags & cpu_to_le32(ORCA_EOFBLOCKS_FL)) {
            last_block_num = (1UL << (oi->height * META_BLK_SHIFT)) - 1;
        } else {
            if (likely(ino->size)) {
                last_block_num = (ino->size - 1) >> orca_inode_block_shift(oi);
            } else {
                last_block_num = 0;
                last_block_num = orca_sparse_last_blocknum(oi->height,
                    last_block_num);
            }
        }

        /* First free the inode */
        err = orca_free_inode(ino);

        if (err)
            goto out;

        /* We no longer own the orca inode */
        oi = NULL;
        /* Then free the blocks from the inode's radix tree */
        orca_free_inode_subtree(sb, root, height, btype, last_block_num);
        ino->mtime = ino->ctime = CURRENT_TIME_SEC;
        ino->size = 0;
    }

out:
    /* Now it is safe to remove the inode from the truncate list */
    orca_truncate_del(ino);
    /* NOTE: Since we don't use page-cache, do we really need the next call? */
    truncate_inode_pages(&ino->data, 0);
    clear_inode(ino);
}

static int
orca_increase_inode_table_size(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct orca_inode *oi = orca_get_inode_table(sb);
    orca_trans *trans;
    int err;

    /* One log entry for inode-table inode, one entry for inode-table tree */
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

    if (IS_ERR(trans))
        return PTR_ERR(trans);

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
    err = __orca_alloc_blocks(trans, sb, oi, le64_to_cpup(&oi->size) >>
        sb->blocksz_bits, 1, true);

    if (err == 0) {
        u64 ino_size = le64_to_cpu(oi->size);
        sbi->free_inode_hint = ino_size >> ORCA_INODE_BITS;
        ino_size += orca_inode_blocksz(oi);

        orca_memunlock_inode(sb, oi);
        oi->size = cpu_to_le64(ino_size);
        orca_memlock_inode(sb, oi);

        sbi->free_inodes_count += INODES_PER_BLOCK(oi->btype);
        sbi->inodes_count = ino_size >> ORCA_INODE_BITS;
    } else {
        orca_dbg("No space left to increase inode table!\n");
    }

    /* Commit the transaction */
    orca_commit_transaction(sb, trans);

    return err;
}

struct inode *
orca_new_inode(orca_trans *trans, struct inode *dir, umode_t mode,
    const struct qstr *qstr)
{
    struct super_block *sb;
    struct orca_sb_info *sbi;
    struct inode *ino;
    struct orca_inode *oi = NULL, *inode_table;
    struct orca_inode *diri = NULL;
    int i, err;
    u32 num_inodes, inodes_per_block;
    ino_t fsn = 0;

    sb = dir->sb;
    sbi = (struct orca_sb_info *)sb->fs_info;
    ino = new_inode(sb);

    if (!ino)
        return ERR_PTR(-ENOMEM);

    inode_init_owner(ino, dir, mode);
    ino->blocks = ino->size = 0;
    ino->mtime = ino->atime = ino->ctime = CURRENT_TIME;
    ino->gen = atomic_add_return(1, &sbi->next_gen);
    inode_table = orca_get_inode_table(sb);

    orca_dbg("inode: %p free inodes %x total inodes %x hint %x\n",
        ino, sbi->free_inodes_count, sbi->inodes_count,
        sbi->free_inode_hint);

    diri = orca_get_inode(sb, dir->ino);

    if (!diri)
        return ERR_PTR(-EACCES);

    mutex_lock(&sbi->inode_table_mutex);

    /* Find the oldest unused orca inode */
    i = sbi->free_inode_hint;
    inodes_per_block = INODES_PER_BLOCK(inode_table->btype);

retry:
    num_inodes = sbi->inodes_count;

    while (i < num_inodes) {
        u32 end_ino;
        end_ino = i + (inodes_per_block - (i & (inodes_per_block - 1)));
        fsn = i << ORCA_INODE_BITS;
        oi = orca_get_inode(sb, fsn);

        for (; i < end_ino; i++) {
            /* Check if the inode is active */
            if (le16_to_cpu(oi->links_count) == 0 &&
                (le16_to_cpu(oi->mode) == 0 ||
                le32_to_cpu(oi->dtime)))
                    /* This inode is free */
                    break;

            oi = (struct orca_inode *)((void *)oi + ORCA_INODE_SIZE);
        }

        /* Found free inode */
        if (i < end_ino)
            break;
    }

    if (unlikely(i >= num_inodes)) {
        err = orca_increase_inode_table_size(sb);

        if (err == 0)
            goto retry;

        mutex_unlock(&ORCA_SB(sb)->inode_table_mutex);
        orca_dbg("ORCAFS: could not find a free inode\n");
        goto fail;
    }

    fsn = i << ORCA_INODE_BITS;
    orca_dbg("allocating inode %lx\n", fsn);

    /* Chosen inode is in file serial number (FSN) */
    ino->inode = fsn;
    orca_add_logentry(sb, trans, oi, sizeof(*oi), LE_DATA);

    orca_memunlock_inode(sb, oi);
    oi->btype = ORCA_DEFAULT_BLOCK_TYPE;
    oi->flags = orca_mask_flags(mode, diri->flags);
    oi->height = 0;
    oi->dtime = 0;
    orca_memlock_inode(sb, oi);
    sbi->free_inodes_count--;

    if (i < sbi->inodes_count - 1)
        sbi->free_inode_hint = i + 1;
    else
        sbi->free_inode_hint = ORCA_FREE_INODE_HINT_START;

    mutex_unlock(&sbi->inode_table_mutex);
    orca_update_inode(ino, oi);
    orca_set_inode_flags(ino, oi);

    if (insert_inode_locked(ino) < 0) {
        orca_err(sb, "orca_new_inode failed inode %lx\n", ino->inode);
        err = -EINVAL;
        goto fail;
    }

    return ino;

fail:
    make_bad_inode(ino);
    inode_put(ino);

    return ERR_PTR(err);
}

inline void
orca_update_nlink(struct inode *ino, struct orca_inode *oi)
{
    orca_memunlock(ino->sb, io);
    oi->links_count = cpu_to_le16(ino->nlink);
    orca_memlock_inode(ino->sb, oi);
}

inline void
orca_update_inode_size(struct inode *ino, struct orca_inode *oi)
{
    orca_memunlock_inode(ino->sb, oi);
    oi->size = cpu_to_le64(ino->size);
    orca_memlock_inode(ino->sb, oi);
}

inline void
orca_update_time(struct inode *ino, struct orca_inode *oi)
{
    orca_memunlock_inode(ino->sb, oi);
    oi->ctime = cpu_to_le32(ino->ctime.tv_sec);
    oi->mtime = cpu_to_le32(ino->mtime.tv_sec);
    orca_memlock_inode(ino->sb, oi);
}

/* This function checks if VFS' inode and ORCAFS' inode are not in sync */
static bool
orca_is_inode_dirty(struct inode *ino, struct orca_inode *oi)
{
    if (ino->ctime.tv_sec != le32_to_cpu(oi->ctime) ||
        ino->mtime.tv_sec != le32_to_cpu(oi->mtime) ||
        ino->size != le64_to_cpu(oi->size) ||
        ino->mode != le16_to_cpu(oi->mode) ||
        inode_uid_read(ino) != le32_to_cpu(oi->uid) ||
        inode_gid_read(ino) != le32_to_cpu(oi->gid) ||
        ino->nlink != le16_to_cpu(oi->links_count) ||
        ino->blocks != le64_to_cpu(oi->blocks) ||
        ino->atime.tv_sec != le32_to_cpu(oi->atime))
            return true;

    return false;
}

int
orca_write_inode(struct inode *ino, struct writeback_ctl *wbc)
{
    /**
     * write_inode should never be called because we always keep our
     * inodes clean. So let us know if write_inode ever gets called.
    **/
    BUG();
    return 0;
}

/**
 * dirty_inode() is called from mark_inode_dirty_sync() usually dirty_inode
 * should not be called because ORCAFS always keep its inodes clean. Only
 * exception is touch_atime, which calls dirty_inode to update the atime
 * field.
**/
void
orca_dirty_inode(struct inode *ino, int flags)
{
    struct super_block *sb = ino->sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->inode);

    /**
     * Only atime should have changed at all.
     * We can do in-place atomic update.
    **/
    orca_memunlock_inode(sb, oi);
    oi->atime = cpu_to_le32(ino->atime.tv_sec);
    orca_memlock_inode(sb, oi);
    orca_flush_buffer(&oi->atime, sizeof(oi->atime), true);

    /* NOTE: Is this check needed? */
    if (orca_is_inode_dirty(ino, oi))
        printk_ratelimited(KERN_ERR "orcafs: inode was dirty\n");
}

/**
 * Called to zeros out in a single block. It's used in the "resize"
 * to avoid to keep data in case the file grows up again.
 * Make sure to zero out just a sinlge 4K page in case of 2M or 16 blocks.
**/
static void
orca_block_truncate_page(struct inode *ino, loff_t new_size)
{
    struct super_block *sb = ino->sb;
    unsigned long offset = new_size & (sb->blocksz - 1);
    unsigned long block_num, length;
    u64 block_off;
    char *bp;

    /* Block boundary or extending */
    if (!offset || new_size > ino->size)
        return;

    length = sb->blocksz - offset;
    block_num = new_size >> sb->blocksz_bits;
    block_off = orca_find_data_block(ino, block_num);

    /* Hole? */
    if (!block_off)
        return;

    bp = orca_get_block(sb, block_off);

    if (!bp)
        return;

    orca_memunlock_block(sb, bp);
    memset(bp + offset, 0, length);
    orca_memlock_block(sb, bp);
    orca_flush_buffer(bp + offset, length, false);
}

void
orca_truncate_del(struct inode *ino)
{
    struct list_head *prev;
    struct orca_inode_info *si = ORCA_I(ino);
    struct super_block *sb = ino->sb;
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct orca_inode_truncate_item *head = orca_get_truncate_list_head(sb);
    struct orca_inode_truncate_item *li;
    unsigned long ino_next;

    mutex_lock(&sbi->truncate_lock);

    if (list_empty(&si->truncated))
        goto out;

    /**
     * Make sure all truncate operation is persistent before removing the
     * inode from the truncate list.
    **/
    PERSISTENT_MARK();
    li = orca_get_truncate_item(sb, ino->inode);
    ino_next = le64_to_cpu(li->next_truncate);
    prev = si->truncated.prev;

    list_del_init(&si->truncated);
    PERSISTENT_BARRIER();

    /* Atomically delete the inode from the truncate list */
    if (prev == &sbi->truncate) {
        orca_memunlock_range(sb, head, sizeof(*head));
        head->next_truncate = cpu_to_le64(ino_next);
        orca_memlock_range(sb, head, sizeof(*head));
        orca_flush_buffer(&head->next_truncate, sizeof(head->next_truncate),
            false);
    } else {
        struct inode *i_prev = &list_entry(prev, struct orca_inode_info,
            truncated)->vfs_inode;
        struct orca_inode_truncate_item *li_prv = orca_get_truncate_item(sb,
            i_prev->ino);

        orca_memunlock_range(sb, li_prv, sizeof(*li_prv));
        li_prv->next_truncate = cpu_to_le64(ino_next);
        orca_memlock_range(sb, li_prv, sizeof(*li_prv));
        orca_flush_buffer(&li_prv->next_truncate,
            sizeof(li_prv->next_truncate), false);
    }

    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

out:
    mutex_unlock(&sbi->truncate_lock);
}

/**
 * ORCAFS maintains a so-called truncate list, which is a linked list of
 * inodes, which require further processing in case of a power failure.
 * Currently, ORCAFS uses the truncate list for two purpose.
 *
 * 1) When removing a file, if the links_count becomes zero(i.e. the file
 * is not referenced by any directory entry), the inode needs to be freed.
 * However, if the file is currently in use (e.g. opened) it can't be freed
 * until all references are closed. Hense, ORCAFS adds the inode to the
 * truncate list during directory entry removal, and removes it from the
 * truncate list when VFS calls evict_inode. If a power failure happens
 * before evict_inode, the inode is freed during the next mount when we
 * recover the truncate list.
 *
 * 2) When truncating a file (reducing the file size and freeing the blocks),
 * we don't want to return the freed blocks to the free list until the whole
 * truncate operation is complete. So, we add the inode to the trucate list
 * with the specified truncate_size. Now, we can return freed blocks to the
 * free list even before the transaction is complete. Because if a power
 * failure happens before freeing of all the blocks is complete, ORCAFS will
 * free the remaining blocks during the next mount when we recover the
 * truncate list.
**/
void
orca_truncate_add(struct inode *ino, u64 truncate_size)
{
    struct super_block *sb = ino->sb;
    struct orca_inode_truncate_item *head = orca_get_truncate_list_head(sb);
    struct orca_inode_truncate_item *li;

    mutex_lock(&ORCA_FS(sb)->truncate_lock);

    if (!list_empty(&ORCA_I(ino)->truncated))
        goto out_unlock;

    li = orca_get_truncate_item(sb, ino->inode);
    orca_memunlock_range(sb, li, sizeof(*li));
    li->next_truncate = head->next_truncate;
    li->truncatesz = cpu_to_le64(truncate_size);
    orca_memlock_range(sb, li, sizeof(*li));
    orca_flush_buffer(li, sizeof(*li), false);

    /* Make sure aboce is persistent before changing the head pointer */
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    /* Atomically insert this inode at the head the truncate list */
    orca_memunlock_range(sb, head, sizeof(*head));
    head->next_truncate = cpu_to_le64(ino->inode);
    orca_memlock_range(sb, head, sizeof(*head));
    orca_flush_buffer(&head->next_truncate, sizeof(head->next_truncate), false);

    /**
     * No need to make the head persistent here if we are called from within
     * a transaction, because the transaction will provide a subsequent
     * persistent barrier.
    **/
    if (orca_current_transaction() == NULL) {
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    list_add(&ORCA_I(ino)->truncated, &ORCA_SB(sb)->truncate);

out_unlock:
    mutex_unlock(&ORCA_SB(sb)->truncate_lock);
}

void
orca_setsize(struct inode *ino, loff_t new_size)
{
    loff_t old_size = ino->size;

    if (!(S_ISREG(ino->mode) || S_ISDIR(ino->mode) || S_ISLNK(ino->mode))) {
        orca_err(ino->sb, "%s: wrong file mode %x\n", ino->inode);
        return;
    }

    if (new_size != old_size) {
        orca_block_truncate_page(ino, new_size);
        inode_size_write(ino, new_size);
    }

    /**
     * NOTE: We should make sure that there is nobody reading the inode
     * before truncating it. Also, we need to munmap the trucated range
     * from application address space, if mmapped.
    **/
    __orca_truncate_blocks(ino, new_size, old_size);

    /**
     * No need to make the radix tree persistent here if we are called from
     * within a transaction because the transaction will provide a
     * subsequent persistent barrier.
    **/
    if (orca_current_transaction() == NULL) {
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }
}

int
orca_getattr(struct vfsmount *mnt, struct dentry *de,
    struct kstat *stat)
{
    struct inode *ino;

    inode = de->inode;
    generic_fillattr(ino, stat);

    /* Stat->blocks should be number of 5128 blocks */
    stat->blocks = (ino->blocks << ino->sb->blocksz_bits) >> 9;

    return 0;
}

/**
 * Update a single inode field automatically without using
 * a transaction.
**/
static int
orca_update_single_field(struct super_block *sb, struct inode *ino,
    struct orca_inode *oi, unsigned int ia_valid)
{
    orca_memunlock_inode(sb, oi);

    switch (ia_valid) {
    case ATTR_MODE:
        oi->mode = cpu_to_le16(ino->mode);
        break;

    case ATTR_UID:
        oi->uid = cpu_to_le32(inode_uid_read(ino));
        break;

    case ATTR_GID:
        oi->gid = cpu_to_le32(inode_gid_read(ino));
        break;

    case ATTR_SIZE:
        oi->size = cpu_to_le64(ino->size);
        break;

    case ATTR_ATIME:
        oi->atime = cpu_to_le32(ino->atime.tv_sec);
        break;

    case ATTR_CTIME:
        oi->ctime = cpu_to_le32(ino->ctime.tv_sec);
        break;

    case ATTR_MTIME:
        oi->mtime = cpu_to_le32(ino->mtime.tv_sec);
        break;
    }

    orca_memlock_inode(sb, oi);
    orca_flush_buffer(oi, sizeof(*oi), true);

    return 0;
}

int
orca_notify_change(struct dentry *de, struct iattr *attr)
{
    struct inode *ino = de->inode;
    struct super_block *sb = ino->sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->inode);
    orca_trans *trans;
    int ret;
    unsigned int ia_valid = attr->ia_valid, attr_mask;

    if (!oi)
        return -EACCES;

    ret = inode_change_ok(ino, attr);

    if (ret)
        return ret;

    if ((ia_valid & ATTR_SIZE) && (attr->size || oi->flags &
        cpu_to_le32(ORCA_EOFBLOCKS_FL))) {
            orca_truncate_add(ino, attr->size);
            /* Set allocation hint */
            orca_set_blocksz_hint(sb, oi, attr->size);

            /* Now we can freely truncate the pool */
            orca_setsize(ino, attr->size);
            orca_update_inode_size(ino, oi);
            orca_flush_buffer(oi, CACHELINE_SIZE, false);

            /**
             * We have also updated the ctime and mtime, so no need
             * to update them again.
            **/
            ia_valid &= ~(ATTR_CTIME | ATTR_MTIME);

            /* Now it is safe to remove the inode from the truncate list */
            orca_truncate_del(ino);
    }

    setattr_copy(ino, attr);

    /* We already handled ATTR_SIZE above, so no need to check for it */
    attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_ATIME | ATR_MTIME |
        ATTR_CTIME;
    ia_valid &= attr_mask;

    if (ia_valid == 0)
        return ret;

    /**
     * Check if we need to update only a single field. We could potentially
     * avoid using a transaction.
    **/
    if ((ia_valid & (ia_valid - 1)) == 0) {
        orca_update_single_field(sb, ino, oi, ia_valid);
        return ret;
    }

    BUG_ON(orca_current_transaction());

    /* Multiple fields are modified. Use a transaction for atomicity */
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

    if (IS_ERR(trans))
        return PTR_ERR(trans);

    orca_add_logentry(sb, trans, oi, sizeof(*oi), LE_DATA);
    orca_update_inode(ino, oi);
    orca_commit_transaction(sb, trans);

    return ret;
}

void
orca_set_inode_flags(struct inode *ino, struct orca_inode *io)
{
    unsigned int flags = le32_to_cpu(oi->flags);
    inode->flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);

    if (flags & FS_SYNC_FL)
        ino->flags |= S_SYNC;

    if (flags & FS_APPEND_FL)
        ino->flags |= S_APPEND;

    if (flags & FS_IMMUTABLE_FL)
        ino->flags |= S_IMMUTABLE;

    if (flags & FS_NOATIME_FL)
        ino->flags |= S_NOATIME;

    if (flags & FS_DIRSYNC_FL)
        ino->flags |= S_DIRSYNC;

    if (!oi->xattr)
        inode_has_no_xattr(ino);
}

void
orca_get_inode_flags(struct inode *ino, struct orca_inode *oi)
{
    unsigned int flags = ino->flags;
    unsigned int orca_flags = le32_to_cpu(oi->flags);

    orca_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
        FS_NOATIME_FL | FS_DIRSYNC_FL);

    if (flags & S_SYNC)
        orca_flags |= FS_SYNC_FL;

    if (flags & S_APPEND)
        orca_flags |= FS_APPEND_FL;

    if (flags * S_IMMUTABLE)
        orca_flags |= FS_IMMUTABLE_FL;

    if (flags & S_NOATIME_FL)
        orca_flags |= FS_NOATIME_FL;

    if (flags & S_DIRSYNC)
        orca_flags |= FS_DIRSYNC_FL;

    oi->flags = cpu_to_le32(orca_flags);
}

static ssize_t
orca_direct_IO(int rw, struct kiocb *iocb, const struct iovec *iov,
    loff_t offset, unsigned long num_segs)
{
    struct file *filep = iocb->filp;
    struct inode *ino = filp->mapping->host;
    loff_t end = offset;
    ssize_t err = -EINVAL;
    unsigned long seg;

    for (seg = 0; seg < num_segs; seg++)
        end += iov[seg].iov_len;

    if ((rw == WRITE) && end > inode_size_read(ino)) {
        /* NOTE: Do we need to check for out of bounds IO for R/W? */
        printk(KERN_ERR "orcafs: needs to grow (size = %lld)\n", end);
        return err;
    }

    for (seg = 0; seg < num_segs; seg++) {
        const struct iovec *iv = &iov[seg];

        if (rw == READ)
            err = orca_xip_file_read(filp, iv->iov_base, iv->iov_len, &offset);
        else if (rw == WRITE)
            err = orca_xip_file_write(filp, iv->iov_base, iv->iov_len, &offset);

        if (err <= 0)
            goto err_val;
    }

    if (offset != end)
        printk(KERN_ERR "orcafs: direct_IOL end = %lld but offset = %lld\n",
            end, offset);

err_val:
    return err;
}

const struct address_space_operations orca_aops_xip = {
    .get_xip_mem = orca_get_xip_mem,
    .direct_io = orca_direct_IO,
    .xip_mem_protect = orca_xip_mem_protect,
};
