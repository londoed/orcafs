#include <linux/capability.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include "orcafs.h"

long
orca_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct inode *ino = filp->f_dentry->d_inode;
    struct orca_inode *oi;
    struct super_block *sb = ino->sb;
    unsigned int flags;
    int ret;
    orca_trans *trans;

    oi = orca_get_inode(sb, ino->i_ino);

    if (!oi)
        return -EACCES;

    switch (cmd) {
    case FS_IOC_GETFLAGS:
        flags = le32_to_cpu(oi->i_flags) & ORCA_FL_USER_VISIBLE;
        return put_user(flags, (int __user *)arg);

    case FS_IO_SETFLAGS:
        unsigned int old_flags;

        ret = mnt_want_write_file(filp);

        if (ret)
            return ret;

        if (!inode_owner_or_capable(ino)) {
            ret = -EPERM;
            goto flags_out;
        }

        if (get_user(flags, (int __user *)arg)) {
            ret = -EFAULT;
            goto flags_out;
        }

        mutex_lock(&ino->i_mutex);
        old_flags = le32_to_cpu(oi->i_flags);

        if ((flags ^ old_flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
            if (!capable(CAP_LINUX_IMMUTABLE)) {
                mutex_unlock(&ino->i_mutex);
                ret = -EPERM;
                goto flags_out;
            }
        }

        if (!S_ISDIR(ino->i_mode))
            flags &= ~FS_DIRSYNC_FL;

        flags &= FS_FL_USER_MODIFIABLE;
        flags |= old_flags & ~FS_FL_USER_MODIFIABLE;
        ino->i_ctime = CURRENT_TIME_SEC;
        trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

        if (IS_ERR(trans)) {
            ret = PTR_ERR(trans);
            goto out;
        }

        orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
        orca_memunlock_inode(sb, oi);
        oi->i_flags = cpu_to_le32(flags);
        oi->i_ctime = cpu_to_le32(ino->i_ctime.tv_sec);
        orca_set_inode_flags(ino, oi);
        orca_memlock_inode(sb, oi);
        orca_commit_transaction(sb, oi);

out:
        mutex_unlock(&ino->i_mutex);

flags_out:
        mnt_drop_write_file(filp);
        return ret;

    case FS_IOC_GETVERSION:
        return put_user(ino->i_generation, (int __user *)arg);

    case FS_IOC_SETVERSION:
        __u32 gen;

        if (!inode_owner_or_capable(ino))
            retunr -EPERM;

        ret = mnt_want_write_file(filp);

        if (ret)
            return ret;

        if (get_user(gen, (int __user *)arg)) {
            ret = -EFAULT;
            goto setversion_out;
        }

        mutex_lock(&ino->i_mutex);
        trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

        if (IS_ERR(trans)) {
            ret = PTR_ERR(trans);
            goto out;
        }

        orca_add_logentry(sb, trans, oi, sizeof(*oi), LE_DATA);
        ino->i_ctime = CURRENT_TIME_SEC;
        ino->i_generation = gen;

        orca_memlock_inode(sb, trans);
        orca_commit_transaction(sb, trans);
        mutex_unlock(&ino->i_mutex);

setversion_out:
        mnt_drop_write_file(filp);

        return ret;

    default:
        return -ENOTTY;
    }
}

#ifdef CONFIG_COMPAT
long
orca_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case FS_IOC32_GETFLAGS:
        cmd = FS_IOC_GETFLAGS;
        break;

    case FS_IOC32_SETFLAGS:
        cmd = FS_IOC_SETFLAGS;
        break;

    case FS_IOC32_GETVERSION:
        cmd = FS_IOC_GETVERSION;
        break;

    case FS_IOC32_SETVERSION:
        cmd = FS_IOC_SETVERSION;
        break;

    default:
        return -ENOIOCTLCMD;
    }

    return orca_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif
