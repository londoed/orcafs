#include <linux/fs.h>
#include <linux/bitops.h>
#include "orcafs.h"

void
orca_init_blockmap(struct super_block *sb, unsigned long init_used_size)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    unsigned long num_used_block;
    struct orca_blocknode *blknode;

    num_used_block = (init_used_size + sb->s_blocksize - 1) >> sb->s_blocksize_bits;
    blknode = orca_alloc_blocknode(sb);

    if (blknode == NULL)
        ORCA_ASSERT(0);

    blknode->block_low = sbi->block_start;
    blknode->block_high = sbi->block_start + num_used_block - 1;

    sbi->num_free_blocks -= num_used_block;
    list_add(&blknode->lin, &sbi->block_inuse_head);
}

static struct orca_blocknode *
orca_next_blocknode(struct orca_blocknode *i, struct list_head *head)
{
    if (list_is_last(&i->link, head))
        return NULL;

    return list_first_entry(&i->link, typeof(*i), link);
}

/**
 * Caller must hold the super_block lock. If start_hint is provided, it is
 * only valid until the caller releases the super_block lock.
**/
void
__orca_free_block(struct super_block *sb, unsigned long blocknr, unsigned short btype,
    struct orca_blocknode **start_hint)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct list_head *head = &(sbi->block_inuse_head);
    unsigned long new_block_low, new_block_high, num_blocks = 0;
    struct orca_blocknode *i;
    struct orca_blocknode *free_blocknode = NULL;
    struct orca_blocknode *curr_node;

    num_blocks = orca_get_numblocks(btype);
    new_block_low = blocknr;
    new_block_high = blocknr + num_blocks - 1;

    BUG_ON(list_empty(head));

    if (start_hint && *start_hint && new_block_low >= (*start_hint)->block_low)
        i = *start_hint;
    else
        i = list_first_entry(head, typeof(*i), link);

    list_for_each_entry_from(i, head, link) {
        if (new_block_low > i->block_high)
            /* Skip to next blocknode */
            continue;

        if ((new_block_low == i->block_low) && (new_block_high == i->block_high)) {
            if (start_hint)
                *start_hint = orca_next_blocknode(i, head);

            list_del(&i->link);
            free_blocknode = i;
            sbi->num_blocknode_allocated--;
            sbi->num_free_blocks += num_blocks;

            goto block_found;
        }

        if ((new_block_low == i->block_low) && (new_block_high < i->block_high)) {
            /* Aligns left */
            i->block_high = new_block_low - 1;
            sbi->num_free_blocks += num_blocks;

            if (start_hint)
                *start_hint = orca_next_blocknode(i, head);

            goto block_found;
        }

        if ((new_block_low > i->block_low) && (new_block_high < i->block_high)) {
            /* Aligns somewhere in the middle */
            curr_node = orca_alloc_blocknode(sb);
            ORCA_ASSERT(curr_node);

            if (curr_node == NULL)
                /* Returning without freeing the block */
                goto block_found;

            curr_node->block_low = new_block_high + 1;
            curr_node->block_high = i->block_high;
            i->block_high = new_block_low - 1;
            list_add(&curr_node->link, &i->link);
            sbi->num_free_blocks += num_blocks;

            if (start_hint)
                *start_hint = curr_node;

            goto block_found;
        }
    }

    orca_err_msg(sb, "Unable to free block %ld\n", blocknr);

block_found:
    if (free_blocknode)
        __orca_free_blocknode(free_blocknode);
}

void
orca_free_block(struct super_block *sb, unsigned long blocknr, unsigned short btype)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    mutex_lock(&sbi->s_lock);
    __orca_free_block(sb, blocknr, btype, NULL);
    mutex_unlock(&sbi->s_lock);
}

int
orca_new_block(struct super_block *sb, unsigned long *blocknr, unsigned short btype, int zero)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct list_head *head = &(sbi->block_inuse_head);
    struct orca_blocknode *i, *next_i;
    struct orca_blocknode *free_blocknode = NULL;
    void *bp;
    unsigned long num_blocks = 0, next_block_low, new_block_low, new_block_high;
    struct orca_blocknode *curr_node;
    int errval = 0;
    bool found = false;

    num_blocks = orca_get_numblocks(btype);

    list_for_each_entry(i, head, link) {
        if (i->link.next == head) {
            next_i = NULL;
            next_block_low = sbi->block_end;
        } else {
            next_i = list_entry(i->link.next, typeof(*i), link);
            next_block_low = next_i->block_low;
        }

        new_block_low = (i->block_high + num_blocks) & ~(num_blocks - 1);
        new_block_high = new_block_low + num_blocks - 1;

        if (new_block_high >= next_block_low)
            /* Does not fit--skip to next blocknode */
            continue;

        if ((new_block_low) == (i->block_high + 1) && (new_block_high == (next_block_low - 1))) {
            /* Fill the gap completely */
            i->block_high = next_i->block_high;
            list_del(&next_i->link);
            free_blocknode = next_i;
            sbi->num_blocknode_allocated++;
        } else {
            i->block_high = new_block_high;
        }

        found = true;
        break;
    }

    if ((new_block_low == (i->block_high + 1)) && (new_block_high < (next_block_low - 1))) {
        /* Aligns left */
        i->block_high = new_block_high;
        found = true;
        break;
    }

    if ((new_block_low > (i->block_high + 1)) && (new_block_high == (next_block_low - 1))) {
        /* Aligns to right */
        if (next_i) {
            next_i->block_low = new_block_low;
        } else {
            /* Right node does NOT exist */
            curr_node = orca_alloc_blocknode(sb);
            ORCA_ASSERT(curr_node);

            if (curr_node == NULL) {
                errval = -ENOSPC;
                break;
            }

            curr_node->block_low = new_block_low;
            curr_node->block_high = new_block_high;
            list_add(&curr_node->link, &i->link);
        }

        found = true;
        break;
    }

    if ((new_block_low > (i->block_high + 1)) && (new_block_high < (new_block_low - 1))) {
        /* Aligns somewhere in the middle */
        curr_node = orca_alloc_blocknode(sb);
        ORCA_ASSERT(curr_node);

        if (curr_node == NULL) {
            errval = -ENOSPC;
            break;
        }

        curr_node->block_low = new_block_low;
        curr_node->block_high = new_block_high;
        list_add(&curr_node->link, &i->link);
        found = true;
        break;
    }

    if (found == true)
        sbi->num_free_blocks -= num_blocks;

    mutex_unlock(&sbi->s_lock);

    if (free_blocknode)
        __orca_free_blocknode(free_blocknode);

    if (found == false)
        return -ENOSPC;

    if (zero) {
        size_t size;
        bp = orca_get_block(sb, orca_get_block_off(sb, new_block_low, btype));
        orca_memunlock_block(sb, bp);

        if (btype == ORCA_BLOCK_TYPE_4K)
            size = 0x1 << 12;
        else if (btype == ORCA_BLOCK_TYPE_2M)
            size = 0x1 << 21;
        else
            size = 0x1 << 30;
    }

    *blocknr = new_block_low;

    return errval;
}

unsigned long
orca_count_free_blocks(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    return sbi->num_free_blocks;
}
