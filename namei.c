#include <linux/fs.h>
#include <linux/pagemap.h>
#include "orcafs.h"
#include "xip.h"

/**
 * Couple of helper functions--make the code slightly cleaner.
**/
static inline void
orca_inc_count(struct inode *ino, struct orca_inode *oi)
{
    inc_nlink(ino);
    orca_update_nlink(ino, oi);
}

static inline void
orca_dec_count(struct inode *ino, struct orca_inode *oi)
{
    if (ino->i_nlink) {
        drop_nlink(ino);
        orca_update_nlink(ino, oi);
    }
}

static inline int
orca_add_nondir(orca_trans *trans, struct inode *dir, struct dentry *de,
    struct inode *ino)
{
    struct orca_inode *oi;
    int err = orca_add_entry(trans, de, ino);

    if (!err) {
        d_instantiate(de, ino);
        unlock_new_inode(ino);
        return 0;
    }

    oi = orca_get_inode(ino->i_sb, ino->i_ino);
    orca_dec_count(ino, oi);
    unlock_new_inode(ino);
    iput(ino);

    return err;
}

static inline struct orca_direntry *
orca_next_entry(struct orca_direntry *p)
{
    return (strut orca_direntry *)((char *)p + le16_to_cpu(p->de_len));
}

/**
 * Methods themselves.
**/
int
orca_check_dir_entry(const char *func, struct inode *dir, struct orca_direntry *de,
    u8 *base, unsigned long offset)
{
    const char *error_msg = NULL;
    const int rlen = le16_to_cpu(de->de_len);

    if (unlikely(rlen < ORCA_DIR_REC_LEN(1)))
        error_msg = "de_len is smaller than minimal";
    else if (unlikely(rlen % 4 != 0))
        error_msg = "de_len %4 != 0";
    else if (unlikely(rlen < ORCA_DIR_REC_LEN(de->name_len)))
        error_msg = "de_len is too small for name_len";
    else if (unlikely((((u8 *)de - base) + rlen > dir->i_sb->s_blocksize)))
        error_msg = "directory entry across blocks";

    if (unlikely(error_msg != NULL)) {
        orca_dbg("bad entry in directoy #%lu: %s - offset=%lu, inode=%lu, "
            "rec_len=%d, name_len=%d", dir->i_ino, error_msg, offset,
            (unsigned long)le64_to_cpu(de->ino), rlen, de->name_len);
    }

    return error_msg == NULL ? 1 : 0;
}

/**
 * Returns 0 if not found, -1 on failure, and 1 on success.
**/
int
orca_search_dirblock(u8 *block_base, struct inode *dir, struct qstr *child,
    unsigned long offset, struct orca_direntry **res_dir,
    struct orca_direntry **prev_dir)
{
    struct orca_direntry *de, *pde = NULL;
    char *dlimit;
    int de_len;
    const char *name = child->name;
    int name_len = child->len;

    de = (struct orca_direntry *)block_base;
    dlimit = block_base + dir->i_sb->s_blocksize;

    while ((char *)de < dlimit) {
        /**
         * This code is executed quadratically often do
         * minimal checking 'by hand'.
        **/
        if ((char *)de + name_len <= dlimit && orca_match(name_len, name, de)) {
            /* Found a match--just to be sure, do a full check */
            if (!orca_check_dir_entry("orca_inode_by_name", dir, de, block_base,
                offset))
                    return -1;

            *res_dir = de;

            if (prev_dir)
                *prev_dir = pde;

            return 1;
        }

        /* Prevent looping on a bad block */
        de_len = le16_to_cpu(de->de_len);

        if (de_len <= 0)
            return -1;

        offset += de_len;
        pde = de;
        de = (struct orca_direntry *)((char *)de + de_len);
    }

    return 0;
}

static ino_t
orca_inode_by_name(struct inode *dir, struct qstr *entry,
    struct orca_direntry **res_entry)
{
    struct orca_inode *oi;
    ino_t i_no = 0;
    int name_len, nblocks, i;
    u8 *block_base;
    const u8 *name = entry->name;
    struct super_block *sb = dir->i_sb;
    unsigned long block, start;
    struct orca_inode_info *si = ORCA_I(dir);

    oi = orca_get_inode(sb, dir->i_ino);
    name_len = entry->len;

    if (name_len > ORCA_NAME_LEN)
        return 0;

    if ((name_len <= 2) && (name[0] == '.') && (name[i] == '.' || name[1] == 0)) {
        /* "." or ".." will only be in the first block */
        block = start = 0;
        nblocks = 1;
        goto restart;
    }

    nblocks = dir->i_size >> dir->i_sb->s_blocksize_bits;
    start = si->i_dir_start_lookup;

    if (start >= nblocks)
        start = 0;

    block = start;

restart:
    do {
        block_base = orca_get_block(sb, orca_find_data_block(dir, block));

        if (!block_base)
            goto done;

        i = orca_search_dirblock(block_base, dir, entry,
            block << sb->s_blocksize_bits, res_entry, NULL);

        if (i == 1) {
            si->i_dir_start_lookup = block;
            i_no = le64_to_cpu((*res_entry)->ino);
            goto done;
        } else {
            if (i < 0)
                goto done;
        }

        if (++block >= nblocks)
            block = 0;
    } while (block != start);

    /**
     * If the directory has grown while we were searching, then
     * search the last part of the directory before giving up.
    **/
    block = nblocks;
    nblocks = dir->i_size >> sb->s_blocksize_bits;

    if (block < nblocks) {
        start = 0;
        goto restart;
    }

done:
    return i_no;
}

static struct dentry *
orca_lookup(struct inode *dir, struct dentry *de, unsigned int flags)
{
    struct inode *inode = NULL;
    struct orca_direntry *dirent;
    ino_t ino;

    if (de->d_name.len > ORCA_NAME_LEN)
        return ERR_PTR(-ENAMETOOLONG);

    inode = orca_inode_by_name(dir, &de->d_name, &dirent);

    if (ino) {
        inode = orca_iget(dir->i_sb, ino);

        if (inode == ERR_PTR(-ESTALE)) {
            orca_err(dir->i_sb, __func__, "delete inode referenced: %lu",
                (unsigned long)ino);
            return ERR_PTR(-EIO);
        }
    }

    return d_splice_alias(inode, de);
}

/**
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative--it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
**/
static int
orca_create(struct inode *dir, struct dentry *de, umode_t mode, bool excl)
{
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    orca_trans *trans;

    /**
     * Two log entries for new inode, 1 lentry for dir inode, 1 for dir
     * inode's b-tree, 2 lentries for logging dir entry.
    **/
    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    inode = orca_new_inode(trans, dir, mode, &de->d_name);

    if (IS_ERR(inode))
        goto our_err;


    inode->i_op = &orca_file_inode_ops;
    inode->i_mapping->a_ops = &orca_aops_xip;
    inode->i_fop = &orca_xip_file_ops;
    err = orca_add_nondir(trans, dir, de, inode);

    if (err)
        goto out_err;

4    orca_commit_transcation(sb, trans);

out:
    return err;

out_err:
    orca_abort_transaction(sb, trans);
    return err;
}

static int
orca_mknod(struct inode *dir, struct dentry *de, umode_t mode, dev_t rdev)
{
    struct inode *ino = NULL;
    int err = PTR_ERR(ino);
    orca_trans *trans;
    struct super_block *sb = dir->i_sb;
    struct orca_inode *oi;

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES)'

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    inode = orca_new_inode(trans, dir, mode, &de->d_name);

    if (IS_ERR(ino))
        goto out_err;

    init_special_inode(ino, mode, rdev);
    ino->i_op = &orca_special_inode_ops;

    oi = orca_get_inode(sb, ino->i_ino);

    if (S_ISCHR(ino->i_mode) || S_ISBLK(ino->i_mode))
        oi->dev.rdev = cpu_to_le32(ino->i_rdev);

    err = orca_add_nondir(trans, dir, de, ino);

    if (err)
        goto out_err;

    orca_commit_transaction(sb, trans);

out:
    return err;

out_err:
    orca_abort_transaction(sb, trans);
    return err;
}

static int
orca_symlink(struct inode *dir, struct dentry *de, const char *sym_name)
{
    struct super_block *sb = dir->i_sb;
    int err = -ENAMETOOLONG;
    unsigned len = strlen(sym_name);
    struct inode *ino;
    orca_trans *trans;
    struct orca_inode *oi;

    if (len + 1 > sb->s_blocksize)
        goto out;

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    ino = orca_new_inode(trans, dir, S_IFLNK | S_IRWXUGO, &de->d_name);
    err = PTR_ERR(ino);

    if (IS_ERR(ino)) {
        orca_abort_transaction(sb, trans);
        goto out;
    }

    ino->i_op = &orca_symlink_inode_ops;
    ino->i_mapping->a_ops = &orca_aops_xip;

    oi = orca_get_inode(sb, ino->i_ino);
    err = orca_block_symlink(ino, sym_name, len);

    if (err)
        goto out_fail;

    ino->i_size = len;
    orca_update_isize(ino, oi);
    err = orca_add_nondir(trans, dir, de, ino);

    if (err) {
        orca_abort_transaction(sb, trans);
        goto out;
    }

    orca_commit_transaction(sb, trans);

out:
    return err;

out_fail:
    orca_dec_count(ino, oi);
    unlock_new_inode(ino);
    iput(ino);
    orca_abort_transaction(sb, trans);
    goto out;
}

static int
orca_link(struct dentry dst_de, struct inode *dir, struct dentry *de)
{
    struct inode *ino = dst_de->d_inode;
    int err = -ENOMEM;
    orca_trans *trans;
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino);

    if (ino->i_nlink >= ORCA_LINK_MAX)
        return -EMLINK;

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA;
    ihold(ino);
    err = orca_add_entry(trans, de, ino);

    if (!err) {
        ino->i_ctime = CURRENT_TIME_SEC;
        inc_nlink(ino);

        orca_memunlock_inode(sb, oi);
        oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);
        oi->i_links_count = cpu_to_le16(ino->i_nlink);
        orca_memlock_inode(sb, oi);

        d_instantiate(de, ino);
        orca_commit_transaction(sb, trans);
    } else {
        iput(ino);
        orca_abort_transaction(sb, trans);
    }

out:
    return err;
}

static int
orca_unlink(struct inode *dir, struct dentry *de)
{
    struct inode *ino = de->d_inode;
    int ret = -ENOMEM;
    orca_trans *trans;
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino);

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        ret = PTR_ERR(trans);
        goto out;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
    ret = orca_remove_entry(trans, de, ino);

    if (ret)
        goto end_unlink;

    if (ino->i_nlink == 1)
        orca_truncated_add(ino, ino->i_size);

    ino->i_ctime = dir->i_ctime;
    orca_memunlock_inode(sb, oi);

    if (ino->i_nlink) {
        drop_nlink(ino);
        oi->i_links_count = cpu_to_le32(ino->i_nlink);
    }

    oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);
    orca_memlock_inode(sb, oi);
    orca_commit_transaction(sb, trans);

    return 0;

end_unlink:
    orca_abort_transaction(sb, trans);

out:
    return ret;
}

static int
orca_mkdir(struct inode *dir, struct dentry *de, umode_t mode)
{
    struct inode *ino;
    struct orca_inode *oi, *oi_dir;
    struct orca_direntry *dirent = NULL;
    struct super_block *sb = dir->i_sb;
    orca_trans *trans;
    int err = -EMLINK;
    char *block_base;

    if (dir->i_nlink >= ORCA_LINK_MAX)
        goto out;

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        goto out;
    }

    ino = orca_new_inode(trans, dir, S_IFDIR | mode, &de->d_name);
    err = PTR_ERR(ino);

    if (IS_ERR(ino)) {
        orca_abort_transaction(sb, trans);
        goto out;
    }

    ino->i_op = &orca_dir_inode_ops;
    ino->i_fop = &orca_dir_ops;
    ino->i_mapping->a_ops = &orca_aops_xip;

    /**
     * Since this a new inode so we don't need to include this
     * orca_alloc_blocks in the transaction.
    **/
    err = orca_alloc_blocks(NULL, ino, 0, 1, false);

    if (err)
        goto out_clear_inode;

    ino->i_size = sb->s_blocksize;
    block_base = orca_get_block(sb, orca_find_data_block(ino, 0));
    dirent = (struct orca_direntry *)block_base;

    orca_memunlock_range(sb, block_base, sb->s_blocksize);
    dirent->ino = cpu_to_le64(ino->i_ino);
    dirent->de_len = cpu_to_le16(sb->s_blocksize - ORCA_DIR_REC_LEN(1));
    dirent->name_len = 2;
    strcpy(dirent->name, "..");
    /* dirent->file_type = S_IFDIR */
    orca_memlock_range(sb, block_base, sb->s_blocksize);

    /* No need to journal the dir entries, but we need to persist them */
    orca_flush_buffer(block_base, ORCA_DIR_REC_LEN(1) + ORCA_DIR_REC_LEN(2),
        true);
    set_nlink(ino, 2);
    err = orca_add_entry(trans, de, ino);

    if (err) {
        orca_dbg_verbose("failed to add dir entry\n");
        goto out_clear_inode;
    }

    oi = orca_get_inode(sb, ino->i_ino);

    orca_memunlock_inode(sb, oi);
    oi->i_links_count = cpu_to_le16(ino->i_nlink);
    oi->i_size = cpu_to_le64(ino->i_size);
    orca_memlock_inode(sb, oi);

    oi_dir = orca_get_inode(sb, dir->i_ino);
    orca_inc_count(dir, oi_dir);
    d_instantiate(de, ino);
    unlock_new_inode(ino);
    orca_commit_transaction(sb, trans);

out:
    return err;

out_clear_inode:
    clear_nlink(ino);
    unlock_new_inode(ino);
    iput(ino);
    orca_abort_transaction(sb, trans);
    goto out;
}

/**
 * Function to check that the specified directory is empty (for rmdir).
**/
static int
orca_empty_dir(struct inode *ino)
{
    unsigned long offset;
    struct orca_direntry *de, *de1;
    struct super_block *sb;
    char *block_base;
    int err = 0;

    sb = ino->i_sb;

    if (ino->i_size < ORCA_DIR_REC_LEN(1) + ORCA_DIR_REC_LEN(2)) {
        orca_dbg("bad directory (dir #%lu)--no data block", ino->i_ino);
        return 1;
    }

    block_base = orca_get_block(sb, orca_find_data_block(ino, 0));

    if (!block_base) {
        orca_dbg("bad directory (dir #%lu)--no data block", ino->i_ino);
        return 1;
    }

    de = (struct orca_direntry *)block_base;
    de1 = orca_next_entry(de);

    if (le64_to_cpu(de->ino) != ino->i_ino || !le64_to_cpu(de1->ino) ||
        strcmp(".", de->name) || strcmp("..", de1->name)) {
            orca_dbg("bad directory (dir #%lu)--no '.' or '..'", ino->i_ino);
            return 1;
    }

    offset = le16_to_cpu(de->de_len) + le16_to_cpu(de1->de_len);
    de = orca_next_entry(de1);

    while (offset < ino->i_size) {
        if (!block_base || (void *)de >= (void *)(block_base + sb->s_blocksize)) {
            err = 0;
            block_base = orca_get_block(sb, orca_find_data_block(ino,
                offset >> sb->s_blocksize_bits));

            if (!block_base) {
                orca_dbg("Error: reading dir #%lu offset %lu\n",
                    ino->i_ino, offset);
                offset += sb->s_blocksize;
                continue;
            }

            de = (struct orca_direntry *)block_base;
        }

        if (!orca_check_dir_entry("empty_dir", ino, de, block_base, offset)) {
            de = (struct orca_direntry *)(block_base + sb->s_blocksize);
            offset = (offset | (sbi->s_blocksize - 1)) + 1;
            continue;
        }

        if (le64_to_cpu(de->ino))
            return 0;

        offset += le16_to_cpu(de->de_len);
        de = orca_next_entry(de);
    }

    return 1;
}

static int
orca_rmdir(struct inode *dir, struct dentry *de)
{
    struct inode *ino = de->d_inode;
    struct orca_direntry *dirent;
    orca_trans *trans;
    struct super_block *sb = ino->i_sb;
    struct orca_inode *oi = orca_get_inode(sb, ino->i_ino), *oi_dir;
    int err = -ENOTEMPTY;

    if (!ino)
        return -ENOENT;

    if (orca_inode_by_name(dir, &de->d_name, &dirent) == 0)
        return -ENOENT;

    if (!orca_empty_dir(ino))
        return err;

    if (ino->i_nlink != 2)
        orca_dbg("empty directory has nlink != 2 (%d)", ino->i_nlink);

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES);

    if (IS_ERR(trans)) {
        err = PTR_ERR(trans);
        return err;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
    err = orca_remove_entry(trans, de, ino);

    if (err)
        goto end_rmdir;

    /* ino->i_version++; */
    clear_nlink(ino);
    ino->i_ctime = dir->i_ctime;

    orca_memunlock_ino(sb, oi);
    oi->i_links_count = cpu_to_le16(ino->i_nlink);
    oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);
    orca_memlock_inode(sb, oi);

    /**
     * Add the inode to truncate list in case a crash happens
     * before the subsequent evict_inode is called. It will
     * be deleted from the truncate list during evict_inode.
    **/
    orca_truncate_add(ino, ino->i_size);
    oi_dir = orca_get_inode(sb, dir->i_ino);
    orca_dec_count(dir, oi_dir);
    orca_commit_transaction(sb, trans);

    return err;

end_rmdir:
    orca_abort_transaction(sb, trans);
    return err;
}

static int
orca_rename(struct inode *old_dir, struct dentry *old_de, struct inode *new_dir,
    struct dentry *new_de)
{
    struct inode *old_inode = old_de->d_inode;
    struct inode *new_inode = new_de->d_inode;
    struct orca_direntry *new_dirent = NULL, *old_dirent = NULL;
    orca_trans *trans;
    struct super_block *sb = old_inode->i_sb;
    struct orca_inode *oi, *new_oidir, *old_oidir;
    int err = -ENOENT;

    orca_inode_by_name(new_dir, &new_de->d_name, &new_dirent);
    orca_inode_by_name(old_dir, &old_de->d_name, &old_dirent);

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES * 2 + MAX_DIRENTRY_LENTRIES * 2);

    if (IS_ERR(trans))
        return PTR_ERR(trans);

    if (new_inode) {
        err = -ENOTEMPTY;

        if (S_ISDIR(old_inode->i_mode) && !orca_empty_dir(new_inode))
            goto out;
    } else {
        if (S_ISDIR(old_inode->i_mode)) {
            err = -EMLINK;

            if (new_dir->i_nlink >= ORCA_LINK_MAX)
                goto out;
        }
    }

    new_oidir = orca_get_inode(sb, new_dir->i_ino);
    oi = orca_get_inode(sb, old_inode->i_ino);
    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);

    if (!new_dirent) {
        /* Link it into the new directory */
        err = orca_add_entry(trans, new_de, old_inode);

        if (err)
            goto out;
    } else {
        orca_add_logentry(sb, trans, &new_dirent->ino, sizeof(new_dirent->ino),
            LE_DATA);

        orca_memunlock_range(sb, new_dirent, sb->s_blocksize);
        new_dirent->ino = cpu_to_le64(old_inode->i_ino);
        /* new_dirent->file_type = old_dirent->file_type; */
        orca_memlock_range(sb, new_dirent, sb->s_blocksize);

        orca_add_logentry(sb, trans, new_oidir, MAX_DATA_PER_LENTRY, LE_DATA);
        /* new_dir->i_version++; */
        new_dir->i_ctime = new_dir->i_mtime = CURRENT_TIME_SEC;
        orca_update_time(new_dir, new_oidir);
    }

    /* And unlink the inode from the old directory */
    err = orca_remove_entry(trans, old_de, old_inode);

    if (err)
        goto out;

    if (new_inode) {
        oi = orca_get_inode(sb, new_inode->i_ino);
        orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
        new_inode->i_ctime = CURRENT_TIME;

        orca_memunlock_inode(sb, oi);

        if (S_ISDIR(old_inode->i_mode)) {
            if (new_inode->i_nlink)
                drop_nlink(new_inode);
        }

        oi->i_ctime = cpu_to_le32(new_inode->i_ctime.tv_sec);

        if (new_inode->i_nlink)
            drop_nlink(new_inode);

        oi->i_links_count = cpu_to_le16(new_inode->i_nlink);
        orca_memlock_inode(sb, oi);

        if (!new_inode->i_nlink)
            orca_truncate_add(new_inode, new_inode->i_size);
    } else {
        if (S_ISDIR(old_inode->i_mode)) {
            orca_inc_count(new_dir, new_oidir);
            old_oidir = orca_get_inode(sb, old_dir->i_ino);
            orca_dec_count(old_dir, old_oidir);
        }
    }

    orca_commit_transaction(sb, trans);
    return 0;

out:
    orca_abort_transaction(sb, trans);
    return err;
}

struct dentry *
orca_get_parent(struct dentry *child)
{
    struct inode *inode;
    struct qstr dot_dot = QSTR_INIT("..", 2);
    struct orca_direntry *de = NULL;
    ino_t ino;

    orca_inode_by_name(child->d_inode, &dot_dot, &de);

    if (!de)
        return ERR_PTR(-ENOENT);

    ino = le64_to_cpu(de->ino);

    if (ino)
        inode = orca_iget(child->d_inode->i_sb, ino);
    else
        return ERR_PTR(-ENOENT);

    return d_obtain_alias(inode);
}

const struct inode_operations orca_dir_inode_ops = {
    .create         = orca_create,
    .lookup         = orca_lookup,
    .link           = orca_link,
    .unlink         = orca_unlink,
    .symlink        = orca_symlink,
    .mkdir          = orca_mkdir,
    .rmdir          = orca_rmdir,
    .mknod          = orca_mknod,
    .rename         = orca_rename,
    .setattr        = orca_notify_change,
    .get_acl        = NULL,
};

const struct inode_operations orca_special_inode_ops = {
    .setattr        = orca_notify_change,
    .get_acl        = NULL,
};
