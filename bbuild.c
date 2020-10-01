#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include "orcafs.h"

struct scan_bitmap {
    unsigned long bitmap_4k_size;
    unsigned long bitmap_2M_size;
    unsigned long bitmap_1G_size;
    unsigned long *bitmap_4k;
    unsigned long *bitmap_2M;
    unsigned long *bitmap_1G;
};

static void
orca_clear_datablock_inode(struct super_block *sb)
{
    struct orca_inode *oi = orca_get_inode(sb, ORCA_BLOCKNODE_IN0);
    orca_trans *trans;

    /* 2 log entry for inode */
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

    if (IS_ERR(trans))
        return;

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);

    orca_memunlock_inode(sb, oi);
    memset(oi, 0, MAX_DATA_PER_LENTRY);
    orca_memlock_inode(sb, oi);

    /* Commit the transaction */
    orca_commit_transaction(sb, trans);
}

static void
orca_init_blockmap_from_inode(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct orca_inode *oi = orca_get_inode(sb, ORCA_BLOCKNODE_IN0);
    struct orca_blocknode_lowhigh *p = NULL;
    struct orca_blocknode *block_node;
    unsigned long index, block_num, i, num_blocknode;
    u64 bp;

    num_blocknode = sbi->num_blocknode_allocated;
    sbi->num_blocknode_allocated = 0;

    for (i = 0; i < num_blocknode; i++) {
        index = i & 0xFF;

        if (index == 0) {
            /* Find and get new data block */
            block_num = i >> 8; /* 256 entries in a block */
            bp = __orca_find_data_block(sb, oi, block_num);
            p = orca_get_block(sb, bp);
        }

        ORCA_ASSERT(p);
        block_node = orca_alloc_blocknode(sb);

        if (block_node == NULL)
            ORCA_ASSERT(0);

        block_node->block_low = le64_to_cpu(p[index].block_low);
        block_node->block_high = le64_to_cpu(p[index].block_high);
        list_add_tail(&block_node->link, &sbi->block_inuse_head);
    }
}

static bool
orca_can_skip_full_scan(struct super_block *sb)
{
    struct orca_inode *oi = orca_get_inode(sb, ORCA_BLOCKNODE_IN0);
    struct orca_super_block *super = orca_get_super(sb);
    struct orca_sb_info *sbi = ORCA_SB(sb);
    __le64 root;
    unsigned int height, btype;
    unsigned long last_block_num;

    if (!oi->root)
        return false;

    sbi->num_blocknode_allocated = le64_to_cpu(super->s_num_blocknode_allocated);
    sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
    sbi->s_inodes_count = le32_to_cpu(super->s_inode_count);
    sbi->s_free_inodes_count = le32_to_cpu(super->s_free_inodes_count);
    sbi->s_inodes_used_count = le32_to_cpu(super->s_inodes_used_count);
    sbi->s_free_inode_hint = le32_to_cpu(super->s_free_inode_hint);

    orca_init_blockmap_from_inode(sb);

    root = oi->root;
    height = oi->height;
    btype = oi->i_blk_type;

    /* oi->i_size can not be zero */
    last_block_num = (le64_to_cpu(oi->i_size) - 1) >> orca_inode_block_shift(oi);

    /* Clearning the datablock inode */
    orca_clear_datablock_inode(sb);
    orca_free_inode_subtree(sb, root, height, btype, last_block_num);

    return true;
}

static int
orca_allocate_datablock_block_inode(orca_trans *trans, struct super_block *sb,
    struct orca_inode *oi, unsigned long num_blocks)
{
    int err;

    orca_memunlock_inode(sb, oi);
    oi->i_mode = 0;
    oi->i_links_count = cpu_to_le16(1);
    oi->i_blk_type = ORCA_BLOCK_TYPE_4K;
    oi->i_flags = 0;
    oi->height = 0;
    oi->i_dtime = 0;
    oi->i_size = cpu_to_le64(num_blocks << sb->s_blocksize_bits);
    orca_memlock_inode(sb, oi);

    err = __orca_alloc_blocks(trans, sb, oi, 0, num_blocks, false);

    return err;
}

void
orca_save_blocknode_mapping(struct super_block *sb)
{
    unsigned long num_blocks, block_num;
    struct orca_inode *oi = orca_get_inode(sb, ORCA_BLOCKNODE_IN0);
    struct orca_blocknode_lowhigh *p;
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct list_head *head = &(sbi->block_inuse_head);
    struct orca_blocknode *i;
    struct orca_super_block *super;
    orca_trans *trans;
    u64 bp;
    int j, k;
    int err;

    num_blocks = ((sbi->num_blocknode_allocated *
        sizeof(struct orca_blocknode_lowhigh) - 1) >> sb->s_blocksize_bits + 1);

    /* Two log entry for inode, two lentry for super block */
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES, MAX_SB_LENTRIES);

    if (IS_ERR(trans))
        return;

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
    err = orca_allocate_datablock_block_inode(trans, sb, oi, num_blocks);

    if (err != 0) {
        orca_dbg("Error saving the blocknode mappings: %d\n", err);
        orca_abort_transaction(sb, trans);
        return;
    }

    j = k = 0;
    p = NULL;

    list_for_each_entry(i, head, link) {
        block_num = k >> 8;

        if (j == 0) {
            /* Find, get, and unlock new data block */
            bp = __orca_find_data_block(sb, oi, block_num);
            p = orca_get_block(sb, bp);
            orca_memunlock_block(sb, p);
        }

        p[j].block_low = cpu_to_le64(i->block_low);
        p[j].block_high = cpu_to_le64(i->block_high);
        j++;

        if (j == 255) {
            j = 0;

            /* Lock the data block */
            orca_memlock_block(sb, p);
            orca_flush_buffer(p, 4096, false);
        }

        k++;
    }

    /* Lock the block */
    if (j) {
        orca_flush_buffer(p, j << 4, false);
        orca_memlock_block(sb, p);
    }

    /**
     * Save the total allocated blocknode mappings in
     * super block.
    **/
    super = orca_get_super(sb);
    orca_add_logentry(sb, trans, &super->s_wtime, ORCA_FAST_MOUNT_FIELD_SIZE,
        LE_DATA);

    orca_memunlock_range(sb, &super->s_wtime, ORCA_FAST_MOUNT_FIELD_SIZE);
    super->s_wtime = cpu_to_le32(get_seconds());
    super->s_num_blocknode_allocated = cpu_to_le64(sbi->num_blocknode_allocated);
    super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
    super->s_inodes_count = cpu_to_le32(sbi->s_inodes_count);
    super->s_free_inodes_count = cpu_to_le32(sbi->s_free_inodes_count);
    super->s_inodes_used_count = cpu_to_le32(sbi->s_inodes_used_count);
    super->s_free_inode_hint = cpu_to_le32(sbi->s_free_inode_hint);
    orca_memlock_range(sb, &super->s_wtime, ORCA_FAST_MOUNT_FIELD_SIZE);

    orca_commit_transaction(sb, trans);
}

static void
orca_inode_crawl_recursive(struct super_block *sb, struct scan_bitmap *bm,
    unsigned long block, u32 height, u8 btype)
{
    __le64 *node;
    unsigned int i;

    if (height == 0) {
        /* This is the data block */
        if (btype == ORCA_BLOCK_TYPE_4K)
            set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
        else if (btype == ORCA_BLOCK_TYPE_2M)
            set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
        else
            set_bit(block >> PAGE_SHIFT_1G, bm->bitmap_1G);

        return;
    }

    node = orca_get_block(sb, block);
    set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

    for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
        if (node[i] == 0)
            continue;

        orca_inode_crawl_recursive(sb, bm, le64_to_cpu(node[i]),
            height - 1, btype);
    }
}

static inline void
orca_inode_crawl(struct super_block *sb, struct scan_bitmap *bm,
    struct orca_inode *oi)
{
    if (oi->root == 0)
        return;

    orca_inode_crawl_recursive(sb, bm, le64_to_cpu(oi->root), oi->height,
        oi->i_blk_type);
}

static void
orca_inode_table_crawl_recursive(struct super_block *sb, struct scan_bitmap *bm,
    unsigned long block, u32 height, u32 btype)
{
    __le64 *node;
    unsigned int i;
    struct orca_inode *oi;
    struct orca_sb_info *sbi = ORCA_SB(sb);

    node = orca_get_block(sb, block);

    if (height == 0) {
        unsigned int inodes_per_block = INODES_PER_BLOCK(btype);

        if (likely(btype == ORCA_BLOCK_TYPE_2M))
            set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M)
        else
            set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

        sbi->s_inodes_count += inodes_per_block;

        for (i = 0; i < inodes_per_block; i++) {
            oi = (struct orca_inode *)((void *)node * ORCA_INODE_SIZE * i);

            if (le16_to_cpu(oi->i_links_count) == 0 &&
                (le16_to_cpu(oi->i_mode) == 0 ||
                le32_to_cpu(oi->i_dtime))) {
                    /* Empty inode */
                    continue;
            }

            sbi->s_inodes_used_count++;
            orca_inode_crawl(sb, bm, oi);
        }

        return;
    }

    set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

    for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
        if (node[i] == 0)
            continue;

        orca_inode_table_crawl_recursive(sb, bm, le64_to_cpu(node[i]), height - 1,
            btype);
    }
}

static int
orca_alloc_insert_blocknode_map(struct super_block *sb, unsigned long low,
    unsigned long high)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct list_head *head = &(sbi->block_inuse_head);
    struct orca_blocknode *i, *next_i;
    struct orca_blocknode *free_blocknode = NULL;
    unsigned long num_blocks = 0;
    struct orca_blocknode *curr_node;
    int err = 0;
    bool found = 0;
    unsigned long = next_block_low;
    unsigned long new_block_low;
    unsigned long new_block_high;

    /* num_blocks = orca_get_numblocks(btype) */
    new_block_low = low;
    new_block_high = high;
    num_blocks = high - low + 1;

    list_for_each_entry(i, head, link) {
        if (i->link.next == head) {
            next_i = NULL;
            next_block_low = sbi->block_end;
        } else {
            next_i = list_entry(i->link.next, typeof(*i), link);
            next_block_low = next_i->block_low;
        }

        if (new_block_high >= next_block_low)
            /* Does not fit - skip to next blocknode */
            continue;

        if ((new_block_low == (i->block_high + 1)) &&
            (new_block_high == (next_block_low - 1))) {
                i->block_high = next_i->block_high;
                list_del(&next_i->link);
                free_blocknode = next_i;
        } else {
            i->block_high = new_block_high;
        }

        found = 1;
        break;
    }

        if ((new_block_low == (i->block_high + 1)) &&
            (new_block_high < (next_block_low - 1))) {
                /* Aligns to left */
                i->block_high = new_block_high;
                found = 1;
                break;
        }

        if ((new_block_low > (i->block_high + 1)) &&
            (new_block_high == (next_block_low - 1))) {
                /* Aligns to right */
                if (next_i) {
                    /* Right node exist */
                    next_i->block_low = new_block_low;
                } else {
                    /* Right node doesn _NOT_ exist */
                    curr_node = orca_alloc_blocknode(sb);
                    ORCA_ASSERT(curr_node);

                    if (curr_node == NULL) {
                        err = -ENOSPC;
                        break;
                    }

                    curr_node->block_low = new_block_low;
                    curr_node->block_high = new_block_high;
                    list_add(&curr_node->link, &i->link);
                }

                found = 1;
                break;
        }

        if ((new_block_low > (i->block_high + 1)) &&
            (new_block_high) < (next_block_low - 1)) {
                curr_node = orca_alloc_blocknode(sb);
                ORCA_ASSERT(curr_node);

                if (curr_node == NULL) {
                    err = -ENOSPC;
                    break;
                }

                curr_node->block_low = new_block_low;
                curr_node->block_high = new_block_high;
                list_add(&curr_node->link, &i->link);

                found = 1;
                break;
        }
    }

    if (found == 1)
        sbi->num_free_blocks -= num_blocks;

    if (free_blocknode)
        orca_free_blocknode(sb, free_blocknode);

    if (found == 0)
        return -ENOSPC;

    return err;
}

static int
__orca_build_blocknode_map(struct super_block *sb, unsigned long *bitmap,
    unsigned long bsize, unsigned long scale)
{
    unsigned long next = 1;
    unsigned long low = 0;

    for (;;) {
        next = find_next_bit(bitmap, bsize, next);

        if (next == bsize)
            break;

        low = next;
        next = find_next_zero_bit(bitmap, bsize, next);

        if (orca_alloc_insert_blocknode_map(sb, low << scale,
            (next << scale) - 1))
                printk("ORCAFS: error could not insert 0x%lz-0x%lx\n".
                    low << scale, ((next << scale) - 1));

        if (next == bsize)
            break;
    }

    return 0;
}

static void
orca_build_blocknode_map(struct super_block *sb, struct scan_bitmap *bm)
{
    __orca_build_blocknode_map(sb, bm->bitmap_4k, bm->bitmap_4k_size * 8,
        PAGE_SHIFT - 12);
    __orca_build_blocknode_map(sb, bm->bitmap_2M, bm->bitmap_2M_size * 8,
        PAGE_SHIFT_2M - 12);
    __orca_build_blocknode_map(sb, bm->bitmap_1G, bm->bitmap_1G_size * 8,
        PAGE_SHIFT_1G - 12);
}

int
orca_setup_blocknode_map(struct super_block *sb)
{
    struct orca_super_block *super = orca_get_super(sb);
    struct orca_inode *oi = orca_get_inode_table(sb);
    orca_journal *journal = orca_get_journal(sb);
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct scan_bitmap bm;
    unsigned long init_size = le64_to_cpu(super->s_size);
    bool value = false;

    mutex_init(&sbi->inode_table_mutex);
    sbi->block_start = (unsigned long)0;
    sbi->block_end = ((unsigned long)(init_size) >> PAGE_SHIFT);

    value = orca_can_skip_full_scan(sb);

    if (value) {
        orca_dbg_verbose("ORCAFS: Skipping full scan of inodes...\n");
        return 0;
    }

    bm.bimap_4k_size = (init_size >> (PAGE_SHIFT + 0x3)) + 1;
    bm.bitmap_2M_size = (init_size >> (PAGE_SHIFT_2M + 0x3)) + 1;
    bm.bitmap_1G_size = (init_size >> (PAGE_SHIFT_1G + 0x3)) + 1;

    /* Alloc memory to hold the block alloc bitmap */
    bm.bitmap_4k = kzalloc(bm.bitmap_4k_size, GFP_KERNEL);
    bm.bitmap_2M = kzalloc(bm.bitmap_2M_size, GFP_KERNEL);
    bm.bitmap_1G = kzalloc(bm.bitmap_1G_size, GFP_KERNEL);

    if (!bm.bitmap_4k || !bm.bitmap_2M || !bm.bitmap_1G)
        goto skip;

    /* Clearing the datablock inode */
    orca_clear_datablock_inode(sb);
    orca_inode_table_crawl_recursive(sb, &bm, le64_to_cpu(oi->root),
        oi->height, oi->i_blk_type);

    /* Reserving two inodes--Inode 0 and Inode for datablock */
    sbi->s_free_inodes_count = sbi->s_inodes_count - (sbi->s_inodes_used_count + 2);

    /* Set the block 0 as this is used */
    sbi->s_free_inode_hint = ORCA_FREE_INODE_HINT_START;

    /* Initialize the num_free_blocks to */
    sbi->num_free_blocks = ((unsigned long)(init_size) >> PAGE_SHIFT);
    orca_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);
    orca_build_blocknode_map(sb, &bm);

skip:
    kfree(bm.bitmap_4k);
    kfree(bm.bitmap_2M);
    kfree(bm.bitmap_1G);

    return 0;
}
