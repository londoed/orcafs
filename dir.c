#include <linux/fs.h>
#include <linux/pagemap.h>
#include "orcafs.h"

/**
 * Parent is locked.
**/
#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

static int
orca_add_dirent_to_buf(orca_trans *trans, struct dentry *de, struct inode *ino,
    struct orca_direntry *dirent, u8 *block_base, struct orca_inode *oi_dir)
{
    struct inode *dir = de->d_parent->d_inode;
    const char *name = de->d_name.name;
    int name_len = de->d_name.len;
    unsigned short rec_len;
    int nlen, rlen;
    char *top;

    rec_len = ORCA_DIR_REC_LEN(name_len);

    if (!dirent) {
        dirent = (struct orca_direntry *)block_base;
        top = block_base + dir->i_sb->s_blocksize - rec_len;

        while ((char *)dirent <= top) {
#if 0
            if (!orca_check_dir_entry("orca_add_dirent_to_buf", dir, dirent,
                block_base, offset))
                    return -EIO;

            if (orca_match(name_len, name, dirent))
                return -EEXIST;

#endif
            rlen = le16_to_cpu(dirent->de_len);

            if (dirent->ino) {
                nlen = ORCA_DIR_REC_LEN(dirent->name_len);

                if ((rlen - nlen) >= rec_len)
                    break;
            } else if (rlen >= rec_len) {
                break;
            }

            dirent = (struct orca_direntry *)((char *)dirent + rlen);
        }

        if ((char *)dirent > top)
            return -ENOSPC;
    }

    rlen = le16_to_cpu(dirent->de_len);

    if (dirent->ino) {
        struct orca_direntry *dirent1;

        orca_add_logentry(dir->i_sb, trans, &dirent->de_len, sizeof(dirent->de_len),
            LE_DATA);
        nlen = ORCA_DIR_REC_LEN(dirent->name_len);
        dirent1 = (struct orca_direntry *)((char *)dirent + nlen);

        orca_memunlock_block(dir->i_sb, block_base);
        dirent1->de_len = cpu_to_le16(rlen - nlen);
        dirent->de_len = cpu_to_le16(rlen - nlen);
        orca_memlock_block(dir-i_sb, block_base);

        dirent = dirent1;
    } else {
        orca_add_logentry(dir->i_sb, trans, &dirent->ino, sizeof(dirent->ino),
            LE_DATA);
    }

    orca_memunlock_block(dir->i_sb, block_base);

    if (ino)
        dirent->ino = cpu_to_le64(ino->i_ino);
    else
        dirent->ino = 0;

    dirent->name_len = name_len;
    memcpy(dirent->name, name, name_len);
    orca_memlock_block(dir-i_sb, block_base);
    orca_flush_buffer(dirent, rec_len, false);

    /**
     * NOTE: Shouldn't update any times until successful completion of
     * syscall, but too many callers depend on this.
    **/
    dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

    orca_memunlock_inode(dir->i_sb, oi_dir);
    oi_dir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    oi_dir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
    orca_memlock_inode(dir->i_sb, oi_dir);

    return 0;
}

/**
 * Adds a directory entry pointing to the inode. Assumes the inode has
 * already been logged for consistency.
**/
int
orca_add_entry(orca_trans *trans, struct dentry *de, struct inode *ino)
{
    struct inode *dir = de->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    int ret = -EINVAL;
    unsigned long block, blocks;
    struct orca_direntry *dirent;
    char *block_base;
    struct orca_inode *oi_dir;

    if (!de->d_name.len)
        return -EINVAL;

    oi_dir = orca_get_inode(sb, dir->i_ino);
    orca_add_logentry(sb, trans, oi_dir, MAX_DATA_PER_LENTRY, LE_DATA);
    blocks = dir->i_size >> sb->s_blocksize_bits;

    for (block = 0; block < blocks; block++) {
        block_base = orca_get_block(sb, orca_find_data_block(dir, block));

        if (!block_base) {
            ret = -EIO;
            goto out;
        }

        ret = orca_add_dirent_to_buf(trans, de, ino, NULL, block_base, oi_dir);

        if (ret != -ENOSPC)
            goto out;
    }

    ret = orca_alloc_blocks(trans, dir, blocks, 1, false);

    if (ret)
        goto out;

    dir->i_size += dir->i_sb->s_blocksize;
    orca_update_isize(dir, oi_dir);
    block_base = orca_get_block(sb, orca_find_data_block(dir, blocks));

    if (!block_base) {
        ret = -ENOSPC;
        goto out;
    }

    /* No need to log the changes to this dirent because it's a new block */
    dirent = (struct orca_direntry *)block_base;
    orca_memunlock_block(sb, block_base);
    dirent->ino = 0;
    dirent->de_len = cpu_to_le16(sb->s_blocksize);
    orca_memlock_block(sb, block_base);

    /* Since this is a new block, no need to log changes to this block */
    ret = orca_add_dirent_to_buf(NULL, de, ino, dirent, block_base, oi_dir);

out:
    return ret;
}

/**
 * Removes a directory entry from pointing to the inode. Assumes the inode has
 * already been logged for consistency.
**/
int
orca_remove_entry(orca_trans *trans, struct dentry *de, struct inode *ino)
{
    struct super_block *sb = ino->i_sb;
    struct inode *dir = de->d_parent->d_inode;
    struct orca_inode *oi_dir;
    struct qstr *entry = &de->d_name;
    struct orca_direntry *res_entry, *prev_entry;
    int ret = -EINVAL;
    unsigned long blocks, block;
    char *block_base;

    if (!de->d_name.len)
        return -EINVAL;

    blocks = dir->i_size >> sb->s_blocksize_bits;

    for (block = 0; block < blocks; block++) {
        block_base = orca_get_block(sb, orca_find_data_block(dir, block));

        if (!block_base)
            goto out;

        if (orca_search_dirblock(block_base, dir, entry,
            block << sb->s_blocksize_bits, &res_entry, &prev_entry) == 1)
                break;
    }

    if (block == blocks)
        goto out;

    if (prev_entry) {
        orca_add_logentry(sb, trans, &prev_entry->de_len,
            sizeof(prev_entry->de_len), LE_DATA);
        orca_memunlock_block(sb, block_base);
        prev_entry->de_len = cpu_to_le16(le16_to_cpu(prev_entry->de_len) +
            le16_to_cpu(res_entry->de_len));
        orca_memlock_block(sb, block_base);
    } else {
        orca_add_logentry(sb, trans, &res_entry->ino,
            sizeof(res_entry->ino), LE_DATA);
        orca_memunlock_block(sb, block_base);
        res_entry->ino = 0;
        orca_memlock_block(sb, block_base);
    }

    /* dir->i_version++; */
    dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;

    oi_dir = orca_get_inode(sb, dir->i_ino);
    orca_add_logentry(sb, trans, oi_dir, MAX_DATA_PER_LENTRY, LE_DATA);

    orca_memunlock_inode(sb, oi_dir);
    oi_dir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    oi_dir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
    orca_memunlock_inode(sb, oi_dir);

    ret = 0;

out:
    return ret;
}

static int
orca_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct orca_inode *oi;
    char *block_base;
    unsigned long offset;
    struct orca_direntry *de;
    ino_t ino;

    offset = ctx->pos & (sb->s_blocksize - 1);

    while (ctx->pos < inode->i_size) {
        unsigned long block = ctx->pos >> sb->s_blocksize_bits;
        block_base = orca_get_block(sb, orca_find_data_block(inode, block));

        if (!block_base) {
            orca_dbg("Directory %lu contains a hole at offset %lld\n",
                inode->i_ino, ctx->pos);
            ctx->pos += sb->s_blocksize - offset;
            continue;
        }

#if 0
        if (file->f_version != inode->i_version) {
            for (i = 0; i < sb->s_blocksize && i < offsetl; ) {
                de = (struct orca_direntry *)(block_base + i);

                /**
                 * It's too expensive to do a full dirent test each time
                 * round this loop, but we do have to test at least that
                 * it is non-zero. A failure will be detected in the
                 * dirent test below.
                **/
                if (le16_to_cpu(de->de_len) < ORCA_DIR_REC_LEN(1))
                    break;

                i += le16_to_cpu(de->de_len);
            }

            offset = i;
            ctx->pos = (ctx->pos & ~(sb->s_blocksize - 1)) | offset;
            file->f_version = inode->i_version;
        }
#endif

        while (ctx->pos < inode->i_size && offset < sb->s_blocksize) {
            de = (struct orca_direntry *)(block_base + 1);

            if (!orca_check_dir_entry("orca_readdir", inode, de, block_base,
                offset)) {
                    /* On error, skip to the next block */
                    ctx->pos = ALIGN(ctx->pos, sb->s_blocksize);
                    break;
            }

            offset += le16_to_cpu(de->de_len);

            if (de->ino) {
                ino = le64_to_cpu(de->ino);
                oi = orca_get_inode(sb, ino);

                if (!dir_emit(ctx, de->name, de->name_len, ino,
                    IF2DT(le16_to_cpu(oi->i_mode))))
                        return 0;
            }

            ctx->pos += le16_to_cpu(de->de_len);
        }

        offset = 0;
    }

    return 0;
}

const struct file_operations orca_dir_ops = {
    .read = generic_read_dir,
    .iterate = orca_readdir,
    .fsync = noop_fsync,
    .unlocked_ioctl = orca_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = orca_compat_ioctl,
#endif
};
