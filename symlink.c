#include <linux/fs.h>
#include "orcafs.h"

int
orca_block_symlink(struct inode *ino, const char *sym_name, int len)
{
    struct super_block *sb = ino->i_sb;
    u64 block;
    char *blockp;
    int err;

    err = orca_alloc_blocks(NULL, ino, 0, 1, false);

    if (err)
        return err;

    block = orca_find_data_block(ino, 0);
    blockp = orca_get_block(sb, block);

    orca_memunlock_block(sb, blockp);
    memcpy(blockp, sym_name, len);
    blockp[len] = '\0';
    orca_memlock_block(sb, blockp);
    orca_flush_buffer(blockp, len + 1, false);

    return 0;
}

static int
orca_readlink(struct dentry *de, char __user *buffer, int buf_len)
{
    struct inode *ino = de->d_inode;
    struct super_block *sb = ino->i_sb;
    u64 block;
    char *blockp;

    block = orca_find_data_block(ino, 0);
    blockp = orca_get_block(sb, block);

    return vfs_readlink(de, buffer, buf_len, blockp);
}

static void *
orca_follow_link(struct dentry *de, struct namei_data *nd)
{
    struct inode *ino = de->d_inode;
    struct super_block *sb = ino->i_sb;
    off_t block;
    int status;
    char *blockp;

    block = orca_find_data_block(ino, 0);
    blockp = orca_get_block(sb, block);
    status = vfs_follow_link(nd, blockp);

    return ERR_PTR(status);
}

const struct inode_operations orca_symlink_inode_ops = {
    .readlink           = orca_readlink,
    .follow_link        = orca_follow_link,
    .setattr            = orca_notify_change,
};
