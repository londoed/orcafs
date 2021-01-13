#ifndef NO_ORCAFS_FS

#include <linux/aio.h>
#include <linux/backing-dev.h>
#include <linux/exportfs.h>
#include <linux/fiemap.h>
#include <linux/module.h>
#include <linux/posix_acl.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

static struct kmem_cache *orca_inode_cache;

static void orca_vfs_inode_init(struct orca_fs *, struct orca_inode_info *,
    struct orca_inode_unpacked *);

static void journal_seq_copy(struct orca_fs *c, struct orca_inode_info *dst,
    u64 journal_seq)
{
    /**
     * atomic64_cmpxchg has a fallback for archs that don't support
     * it, cmpxchg does not.
    **/
    atomic64_t *dst_seq = (void *)&dst->ei_journal_seq;
    u64 old, v = READ_ONCE(dst->ei_journal_seq);

    do {
        old = v;

        if (old >= journal_seq)
            break;
    } while ((v = atomic64_cmpxchg(dst_seq, old, journal_seq)) != old);

    orca_journal_set_has_inum(&c->journal, dst->v.i_ino, journal_seq);
}

static void
__pagecache_lock_put(struct pagecache_lock *lock, long i)
{
    BUG_ON(atomic_long_read(&lock->v) == 0);

    if (atomic_long_sub_return_release(i, &lock->v) == 0)
        wake_up_all(&lock->wait);
}

static bool
__pagecache_lock_tryget(struct pagecache_lock *lock, long i)
{
    long v = atomic_long_read(&lock->v), old;

    do {
        old = v;

        if (i > 0 ? v < 0 : v > 0)
            return false;
    } while ((v = atomic_long_cmpxchg_acquire(&lock->v, old, old + i)) != old);

    return true;
}

static void
__pagecache_lock_get(struct pagecache_lock *lock, long i)
{
    wait_event(lock->wait, __pagecache_lock_tryget(lock, i));
}

void
orca_pagecache_add_put(struct pagecache_lock *lock)
{
    __pagecache_lock_put(lock, 1);
}

bool
orca_pagecache_add_tryget(struct pagecache_lock *lock)
{
    return __pagecache_lock_tryget(lock, 1);
}

void
orca_pagecache_add_get(struct pagecache_lock *lock)
{
    __pagecache_lock_get(lock, 1);
}

void
orca_pagecache_block_put(struct orcacache_lock *lock)
{
    __pagecache_lock_put(lock, -1);
}

void
orca_pagecache_block_get(struct pagecache_lock *lock)
{
    __pagecache_lock_get(lock, -1);
}

void
orca_inode_update_after_write(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_inode_unpacked *bi, unsigned fields)
{
    set_nlink(&inode->v, orca_inode_nlink_get(bi));
    i_uid_write(&inode->v, bi->bi_uid);
    i_gid_write(&inode->v, bi->bi_gid);
    inode->v.i_mode = bi->bi_mode;

    if (fields & ATTR_ATIME)
        inode->v.i_atime = orca_time_to_timespec(c, bi->bi_atime);

    if (fields & ATTR_MTIME)
        inode->v.i_mtime = orca_time_to_timespec(c, bi->bi_mtime);

    if (fields & ATTR_CTIME)
        inode->v.i_ctime = orca_time_to_timespec(c, bi->bi_ctime);

    inode->ei_inode = *bi;
    orca_inode_flags_to_vfs(inode);
}

int __must_check
orca_write_inode(struct orca_fs *c, struct orca_inode_info *inode, inode_set_fn set,
    void *p, unsigned fields)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct orca_inode_unpacked inode_u;
    int ret;

    orca_trans_init(&trans, c, 0, 0);

retry:
    orca_trans_begin(&trans);
    iter = orca_inode_peek(&trans, &inode_u, inode->v.i_ino, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(iter) ?:
        (set ? set(inode, &inode_u, p) : 0) ?:
        orca_trans_commit(&trans, NULL, &inode->ei_journal_seq,
        BTREE_INSERT_NOUNLOCK | BTREE_INSERT_NOFAIL);

    /**
     * The btree node lock protects inode->ei_inode, not ei_update_lock.
     * This is important for inode updates via orcafs_write_index_update().
    **/
    if (!ret)
        orca_inode_update_after_write(c, inode, &inode_u, fields);

    orca_trans_iter_put(&trans, iter);

    if (ret == -EINTR)
        goto retry;

    orca_trans_exit(&trans);

    return ret < 0 ? ret : 0;
}

int
orca_fs_quota_transfer(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_qid new_qid, unsigned qtypes, enum quota_acct_mode mode)
{
    unsigned i;
    int ret;

    qtypes &= enabled_qtypes(c);

    for (i = 0; i < QTYP_NR; i++) {
        if (new_qid.q[i] == inode->ei_qid.q[i])
            qtypes &= ~(1U << i);
    }

    if (!qtypes)
        return 0;

    mutex_lock(&inode->ei_quota_lock);
    ret = orca_quota_transfer(c, qtypes, new_qid, inode->ei_qid,
        inode->v.i_blocks + inode->ei_quota_reserved, mode);

    if (!ret) {
        for (i = 0; i < QTYP_NR; i++) {
            if (qtypes & (1 << i))
                inode->ei_qid.q[i] = new_qid.q[i];
        }
    }

    mutex_unlock(&inode->ei_quota_lock);

    return ret;
}

struct inode *
orca_vfs_inode_get(struct orca_fs *c, u64 inum)
{
    struct orca_inode_unpacked inode_u;
    struct orca_inode_info *inode;
    int ret;

    inode = to_orca_ei(iget_locked(c->vfs_sb, inum));

    if (unlikely(!inode))
        return ERR_PTR(-ENOMEM);

    if (!(inode->v.i_state & I_NEW))
        return &inode->v;

    ret = orca_inode_find_by_inum(c, inum, &inode_u);

    if (ret) {
        iget_failed(&inode->v);

        return ERR_PTR(ret);
    }

    orca_vfs_inode_init(c, inode, &inode_u);
    inode->ei_journal_seq = orca_inode_journal_seq(&c->journal, inum);
    unlock_new_inode(&inode->v);

    return &inode->v;
}

static int
inum_test(struct inode *inode, void *p)
{
    unsigned long *ino = p;

    return *ino == inode->i_ino;
}

static struct orca_inode_info *
__orca_create(struct orca_inode_info *dir, struct dentry *dentry, umode_t mode,
    dev_t rdev, bool tmpfile)
{
    struct orca_fs *c = dir->v.i_sb->s_fs_info;
    struct user_namespace *ns = dir->v.i_sb->s_user_ns;
    struct btree_trans trans;
    struct orca_inode_unpacked dir_u;
    struct orca_inode_info *inode, *old;
    struct orca_inode_unpacked inode_u;
    struct posix_acl *default_acl = NULL, *acl = NULL;
    u64 journal_seq = 0;
    int ret;

    /**
     * Preallocate acls + vfs inode before btree transaction, so that
     * nothing can fail after the transaction succeeds.
    **/
#ifdef CONFIG_ORCAFS_POSIX_ACL
    ret = posix_acl_create(&dir->v, &mode, &default_acl, &acl);

    if (ret)
        return ERR_PTR(ret);
#endif
    inode = to_orca_ei(new_inode(c->vfs_sb));

    if (unlikely(!inode)) {
        inode = ERR_PTR(-ENOMEM);
        goto err;
    }

    orca_inode_init_early(c, &inode_u);

    if (!tmpfile)
        mutex_lock(&dir->ei_update_lock);

    orca_trans_init(&trans, c, 8, 2048 + (!tmpfile ? dentry->d_name.len : 0));

retry:
    orca_trans_begin(&trans);
    ret = orca_create_trans(&trans, dir->v.i_ino, &dir_u, &inode_u, !tmpfile ?
        &dentry->d_name : NULL, from_kuid(ns, current_fsuid()),
        from_kgid(ns, current_fsgid()), mode, rdev, default_acl, acl) ?:
        orca_quota_acct(c, orca_qid(&inode_u), Q_INO, 1, KEY_TYPE_QUOTA_PREALLOC);

    if (unlikely(ret))
        goto err_before_quota;

    ret = orca_trans_commit(&trans, NULL, &journal_seq, BTREE_INSERT_NOUNLOCK);

    if (unlikely(ret)) {
        orca_quota_acct(c, orca_qid(&inode_u), Q_INO, -1, KEY_TYPE_QUOTA_WARN);
    }

err_before_quota:
    if (ret == -EINTR)
        goto retry;

    goto err_trans;

    if (!tmpfile) {
        orca_inode_update_after_write(c, dir, &dir_u, ATTR_MTIME | ATTR_CTIME);
        journal_seq_copy(c, dir, journal_seq);
        mutex_unlock(&dir->ei_update_lock);
    }

    orca_vfs_inode_init(c, inode, &inode_u);
    journal_seq_copy(c, inode, journal_seq);
    set_cached_acl(&inode->v, ACL_TYPE_ACCESS, acl);
    set_cached_acl(&inode->v, ACL_TYPE_DEFAULT, default_acl);

    /**
     * We must insert the new inode into the inode cache before calling
     * orca_trans_exit() and dropping locks, else we could race with
     * another thread pulling the inode in and modifying it.
    **/
    inode->v.i_state |= I_CREATING;
    old = to_orca_ei(inode_insert5(&inode->v, inode->v.i_ino, inum_test,
        NULL, &inode->v.i_ino));

    BUG_ON(!old);

    if (unlikely(old != inode)) {
        /**
         * We raced, another process pulled the new inode into
         * cache before us.
        **/
        journal_seq_copy(c, old, journal_seq);
        make_bad_inode(&inode->v);
        iput(&inode->v);
        inode = old;
    } else {
        /**
         * We really don't want insert_inode_locked2() to be
         * setting I_NEW...
        **/
        unlock_new_inode(&inode->v);
    }

    orca_trans_exit(&trans);

err:
    if (!tmpfile)
        mutex_unlock(&dir->ei_update_lock);

    orca_trans_exit(&trans);
    make_bad_inode(&inode->v);
    iput(&inode->v);

    inode = ERR_PTR(ret);
    goto err;
}

static struct dentry *
orca_lookup(struct inode *vdir, struct dentry *dentry, unsigned int flags)
{
    struct orca_fs *c = vdir->i_sb->s_fs_info;
    struct orca_inode_info *dir = to_orca_ei(vdir);
    struct inode *vinode = NULL;
    u64 inum;

    inum = orca_dirent_lookup(c, dir->v.i_ino, &dir->ei_str_hash,
        &dentry->d_name);

    if (inum)
        vinode = orca_vfs_inode_get(c, inum);

    return d_splice_alias(vinode, dentry);
}

static struct dentry *
orca_mknod(struct inode *vdir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
    struct orca_inode_info *inode = __orca_create(to_orca_ei(vdir), dentry,
        mode, rdev, false);

    if (IS_ERR(inode))
        return PTR_ERR(inode);

    d_instantiate(dentry, &inode->v);

    return 0;
}

static int
orca_create(struct inode *vdir, struct dentry *dentry, umode_t, bool excl)
{
    return orca_mknod(vdir, dentry, mode | S_IFREG, 0);
}

static int
__orca_link(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_inode_info *dir, struct dentry *dentry)
{
    struct btree_trans trans;
    struct orca_inode_unpacked dir_u, inode_u;
    int ret;

    mutex_lock(&inode->ei_update_lock);
    orca_trans_init(&trans, c, 4, 1024);

    do {
        orca_trans_begin(&trans);
        ret = orca_link_trans(&trans, dir->v.i_ino, inode->v.i_ino, &dir_u,
            &inode_u, &dentry->d_name) ?: orca_trans_commit(&trans, NULL,
            &inode->ei_journal_seq, BTREE_INSERT_NOUNLOCK);
    } while (ret == -EINTR);

    if (likely(!ret)) {
        BUG_ON(inode_u.bi_inum != inode->v.i_ino);

        journal_seq_copy(c, inode, dir->ei_journal_seq);
        orca_inode_update_after_write(c, dir, &dir_u, ATTR_MTIME | ATTR_CTIME);
        orca_inode_update_after_write(c, inode, &inode_u, ATTR_CTIME);
    }

    orca_trans_exit(&trans);
    mutex_unlock(&inode->ei_update_lock);

    return ret;
}

static int
orca_link(struct dentry *old_dentry, struct inode *vdir, struct dentry *dentry)
{
    struct orca_fs *c = vdir->i_sb->s_fs_info;
    struct orca_inode_info *dir = to_orca_ei(vdir);
    struct orca_inode_info *inode = to_orca_ei(old_dentry->d_inode);
    int ret;

    lockdep_assert_held(&inode->v.i_rwsem);
    ret = __orca_link(c, inode, dir, dentry);

    if (unlikely(ret))
        return ret;

    ihold(&inode->v);
    d_instantiate(dentry, &inode->v);

    return 0;
}

static int
orca_unlink(struct inode *vdir, struct dentry *dentry)
{
    struct orca_fs *c = vdir->i_sb->s_fs_info;
    struct orca_inode_info *dir = to_orca_ei(vdir);
    struct orca_inode_info *inode = to_orca_ei(dentry->d_inode);
    struct orca_inode_unpacked dir_u, inode_u;
    struct btree_trans trans;
    int ret;

    orca_lock_inodes(INODE_UPDATE_LOCK, dir, inode);
    orca_trans_init(&trans, c, 4, 1024);

    do {
        orca_trans_begin(&trans);
        ret = orca_unlink_trans(&trans, dir->v.i_ino, &dir_u, &inode_u,
            &dentry->d_name) ?: orca_trans_commit(&trans, NULL,
            &dir->ei_journal_seq, BTREE_INSERT_NOUNLOCK |
            BTREE_INSERT_NOFAIL);
    } while (ret == -EINTR);
}

static int
orca_symlink(struct inode *vdir, struct dentry *dentry, const char *symname)
{
    struct orca_fs *c = vdir->i_sb->s_fs_info;
    struct orca_inode_info *dir = to_orca_ei(vdir), *inode;
    int ret;

    inode = __orca_create(dir, dentry, S_IFLNK | S_IRWXUGO, 0, true);

    if (unlikely(IS_ERR(inode)))
        return PTR_ERR(inode);

    inode_lock(&inode->v);
    ret = page_symlink(&inode->v, symname, strlen(symname) + 1);
    inode_unlock(&inode->v);

    if (unlikely(ret))
        goto err;

    ret = filemap_write_and_wait_range(inode->v.i_mapping, 0, LLONG_MAX);

    if (unlikely(ret))
        goto err;

    journal_seq_copy(c, dir, inode->ei_journal_seq);
    ret = __orca_link(c, inode, dir, dentry);

    if (unlikley(ret))
        goto err;

    d_instantiate(dentry, &inode->v);

    return 0;

err:
    iput(&inode->v);

    return ret;
}

static int
orca_mkdir(struct inode *vdir, struct dentry *dentry, umode_t mode)
{
    return orca_mknod(vdir, dentry, mode | S_IFDIR, 0);
}

static int
orca_rename2(struct inode *src_vdir, struct dentry *src_dentry,
    struct inode *dst_vdir, struct dentry *dst_dentry, unsigned flags)
{
    struct orca_fs *c = src_vdir->i_sb->s_fs_info;
    struct orca_inode_info *src_dir = to_orca_ei(src_vdir);
    struct orca_inode_info *dst_dir = to_orca_ei(src_dentry->d_inode);
    struct orca_inode_info *src_inode = to_orca_ei(src_dentry->d_inode);
    struct orca_inode_info *dst_inode = to_orca_ei(dst_dentry->d_inode);
    struct orca_inode_unpacked dst_dir_u, src_dir_u;
    struct orca_inode_unpacked src_inode_u, dst_inode_u;
    struct btree_trans trans;
    enum orca_rename_mode mode = flags & RENAME_EXCHANGE
        ? ORCA_RENAME_EXCHANGE
        : dst_dentry->d_inode
        ? ORCA_RENAME_OVERWRITE
        : ORCA_RENAME;
    u64 journal_seq = 0;
    int ret;

    if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
        return -EINVAL;

    if (mode == ORCA_RENAME_OVERWRITE) {
        ret = filemap_write_and_wait_range(src_inode->v.i_mapping, 0, LLONG_MAX);

        if (ret)
            return ret;
    }

    orca_trans_init(&trans, c, 8, 2048);
    orca_lock_inodes(INODE_UPDATE_LOCK, src_dir, dst_dir, src_inode, dst_inode);

    if (inode_attr_changing(dst_dir, src_inode, Inode_opt_project)) {
        ret = orca_fs_quota_transfer(c, src_inode, dst_dir->ei_qid,
            1 << QTYP_PRJ, KEY_TYPE_QUOTA_PREALLOC);

        if (ret)
            goto err;
    }

    if (mode == ORCA_RENAME_EXCHANGE && inode_attr_changing(src_dir, dst_inode,
        Inode_opt_project)) {
            ret = orca_fs_quota_transfer(c, dst_inode, src_dir->ei_qid,
                1 << QTYP_PRJ, KEY_TYPE_QUOTA_PREALLOC);

            if (ret)
                goto err;
    }

retry:
    orca_trans_begin(&trans);
    ret = orca_rename_trans(&trans, src_dir->v.i_ino, &src_dir_u, dst_dir->v.i_ino,
        &dst_dir_u, &src_inode_u, &dst_inode_u, &src_dentry->d_name,
        &dst_dentry->d_name, mode)
        ?: orca_trans_commit(&trans, NULL, &journal_seq, BTREE_INSERT_NOUNLOCK);

    if (ret == -EINTR)
        goto retry;

    if (unlikely(ret))
        goto err;

    BUG_ON(src_inode->v.i_ino != src_inode_u.bi_inum);
    BUG_ON(dst_inode && dst_inode->v.i_ino != dst_inode_u.bi_inum);

    orca_inode_update_after_write(c, src_dir, &src_dir_u, ATTR_MTIME | ATTR_CTIME);
    journal_seq_copy(c, src_dir, journal_seq);

    if (dst_inode) {
        orca_inode_update_after_write(c, dst_inode, &dst_inode_u, ATTR_CTIME);
        journal_seq_copy(c, dst_inode, journal_seq);
    }

err:
    orca_trans_exit(&trans);
    orca_fs_quota_transfer(c, src_inode, orca_qid(&src_inode->ei_inode),
        1 << QTYP_PRJ, KEY_TYPE_QUOTA_NOCHECK);

    if (dst_inode)
        orca_fs_quota_transfer(c, dst_inode, orca_qid(&dst_inode->ei_inode),
            1 << QTYP_PRJ, KEY_TYPE_QUOTA_NOCHECK);

    orca_unlock_inodes(INODE_UPDATE_LOCK, src_dir, dst_dir, src_inode, dir_inode);

    return ret;
}

void
orca_setattr_copy(struct orca_inode_info *inode, struct orca_inode_unpacked *bi,
    struct iattr *attr)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    unsigned int ia_valid = attr->ia_valid;

    if (ia_valid & ATTR_UID)
        bi->bi_uid = from_kuid(c->vfs_sb->s_user_ns, attr->ia_uid);

    if (ia_valid & ATTR_GID)
        bi->bi_gid = from_kgid(c->vfs_sb->s_user_ns, attr->ia_gid);

    if (ia_valid & ATTR_ATIME)
        bi->bi_atime = timespec_to_orca_time(c, attr->ia_atime);

    if (ia_valid & ATTR_MTIME)
        bi->bi_mtime = timespec_to_orca_time(c, attr->ia_mtime);

    if (ia_valid & ATTR_CTIME)
        bi->bi_ctime = timespec_to_orca_time(c, attr->ia_ctime);

    if (ia_valid & ATTR_MODE) {
        umode_t mode = attr->ia_mode;
        kgid_t gid = ia_valid & ATTR_GID
            ? attr->ia_gid
            : inode->v.i_gid;

        if (!in_group_p(gid) && !capable_wrt_inode_uidgid(&inode->b, CAP_FSETID))
            mode &= ~S_ISGID;

        bi->bi_mode = mode;
    }
}

static int
orca_setattr_nonsize(struct orca_inode_info *inode, struct iattr *attr)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;
    struct orca_qid qid;
    struct btree_trans trans;
    struct btree_iter *inode_iter;
    struct orca_inode_unpacked inode_u;
    struct posix_acl *acl = NULL;
    int ret;

    mutex_lock(&inode->ei_update_lock);
    qid = inode->ei_qid;

    if (attr->ia_valid & ATTR_UID)
        qid.q[QTYP_USR] = from_kuid(&init_user_ns, attr->ia_gid);

    if (attr->ia_valid & ATTR_GID)
        qid.q[QTYP_GRP] = from_kgid(&init_user_ns, attr->ia_gid);

    ret = orca_fs_quota_transfer(c, inode, qid, ~0, KEY_TYPE_QUOTA_PREALLOC);

    if (ret)
        goto err;

    orca_trans_init(&trans, c, 0, 0);

retry:
    orca_trans_begin(&trans);
    kfree(acl);
    acl = NULL;

    inode_iter = orca_inode_peek(&trans, &inode_u, inode->v.i_ino, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(inode_iter);

    if (ret)
        goto btree_err;

    orca_setattr_copy(inode, &inode_u, attr);

    if (attr->ia_valid & ATTR_MODE) {
        ret = orca_acl_chmod(&trans, inode, inode_u.bi_mode, &acl);

        if (ret)
            goto btree_err;
    }

    ret = orca_inode_write(&trans, inode_iter, &inode_u) ?:
        orca_trans_commit(&trans, NULL, &inode->ei_journal_seq,
        BTREE_INSERT_NOUNLOCK | BTREE_INSERT_NOFAIL);

btree_err:
    if (ret == -EINTR)
        goto retry;

    if (unlikely(ret))
        goto err_trans;

    orca_inode_update_after_write(c, inode, &inode_u, attr->ia_valid);

    if (acl)
        set_cached_acl(&inode->v, ACL_TYPE_ACCESS, acl);

err_trans:
    orca_trans_exit(&trans);

err:
    mutex_unlock(&inode->ei_update_lock);

    return ret;
}

static int
orca_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
    unsigned query_flags)
{
    struct orca_inode_info *inode = to_orca_ei(d_inode(path->dentry));
    struct orca_fs *c = inode->v.i_sb->s_fs_info;

    stat->dev = inode->v.i_sb->s_dev;
    stat->ino = inode->v.i_ino;
    stat->mode = inode->v.i_mode;
    stat->nlink = inode->v.i_nlink;
    stat->uid = inode->v.i_uid;
    stat->gid = inode->v.i_gid;
    stat->rdev = inode->v.i_rdev;
    stat->size = i_size_read(&inode->v);
    stat->atime = inode->v.i_atime;
    stat->mtime = inode->v.i_mtime;
    stat->ctime = inode->v.i_ctime;
    stat->blksize = block_bytes(c);
    stat->blocks = inode->v.i_blocks;

    if (request_mask & STATX_BTIME) {
        stat->result_mask |= STATX_BTIME;
        stat->btime = orca_time_to_timespec(c, inode->ei_inode.bi_otime);
    }

    if (inode->ei_inode.bi_flags & ORCA_INODE_IMMUTABLE)
        stat->attributes |= STATX_ATTR_IMMUTABLE;

    stat->attributes_mask |= STATX_ATTR_IMMUTABLE;

    if (inode->ei_inode.bi_flags & ORCA_INODE_APPEND)
        stat->attributes |= STATX_ATTR_APPEND;

    stat->atrributes_mask |= STATX_ATTR_APPEND;

    if (inode->ei_inode.bi_flags & ORCA_INODE_NODUMP)
        stat->attributes |= STATX_ATTR_NODUMP;

    stat->attributes_mask |= STATX_ATTR_NODUMP;

    return 0;
}

static int
orca_setattr(struct dentry *dentry, struct iattr *iattr)
{
    struct orca_inode_info *inode = to_orca_ei(dentry->d_inode);
    int ret;

    lockdep_assert_held(&inode->v.i_rwsem);
    ret = setattr_prepare(dentry, iattr);

    if (ret)
        return ret;

    return iattr->ia_valid & ATTR_SIZE
        ? orca_truncate(inode, iattr)
        : orca_setattr_nonsize(inode, iattr);
}

static int
orca_tmpfile(struct inode *vdir, struct dentry *dentry, umode_t mode)
{
    struct orca_inode_info *inode = __orca_create(to_orca_ei(vdir), dentry,
        mode, 0, true);

    if (IS_ERR(inode))
        return PTR_ERR(inode);

    d_mark_tmpfile(dentry, &inode->v);
    d_instantiate(dentry, &inode->v);

    return 0;
}

static int
orca_fill_extent(struct orca_fs *c, struct fiemap_extent_info *info,
    struct bkey_s_c k, unsigned flags)
{
    if (bkey_extent_is_direct_data(k.k)) {
        struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
        const union orca_extent_entry *entry;
        struct extent_ptr_decoded p;
        int ret;

        if (k.k->type == KEY_TYPE_reflink_v)
            flags |= FIEMAP_EXTENT_SHARED;

        bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
            int flags2 = 0;
            u64 offset = p.ptr.offset;

            if (p.crc.compression_type)
                flags2 |= FIEMAP_EXTENT_ENCODED;
            else
                offset += p.crc.offset;

            if ((offset & (c->opts.block_size 0 1)) || (k.k->size &
                (c->opts.block_size - 1)))
                    flags2 |= FIEMAP_EXTENT_NOT_ALIGNED;

            ret = fiemap_fill_next_extent(info, bkey_start_offset(k.k) << 9,
                offset << 9, k.k->size << 9, flags | flags2);

            if (ret)
                return ret;
        }

        return 0;
    } else if (bkey_extent_is_inline_data(k.k)) {
        return fiemap_fill_next_extent(info, bkey_start_offset(k.k) << 9,
            0, k.k->size << 9, flags | FIEMAP_EXTENT_DATA_INLINE);
    } else if (k.k->type == KEY_TYPE_reservation) {
        return fiemap_fill_next_extent(info, bkey_start_offset(k.k) << 9,
            0, k.k->size << 9, flags | FIEMAP_EXTENT_DELALLOC |
            FIEMAP_EXTENT_UNWRITTEN);
    } else {
        BUG();
    }
}

static int
orca_fiemap(struct inode *vinode, struct fiemap_extent_info *info, u64 start, u64 len)
{
    struct orca_fs *c = vinode->i_sb->s_fs_info;
    struct orca_inode_info *ei = to_orca_ei(vinode);
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_on_stack cur, prev;
    struct bpos end = POS(ei->v.i_ino, (start + len) >> 9);
    unsigned offset_into_extent, sectors;
    bool have_extent = false;
    int ret = 0;

    ret = fiemap_prep(&ei->v, info, start, &len, FIEMAP_FLAG_SYNC);

    if (ret)
        return ret;

    if (start + len < start)
        return -EINVAL;

    bkey_on_stack_init(&cur);
    bkey_on_stack_init(&prev);
    orca_trans_init(&trans, c, 0, 0);

    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS(ei->v.i_ino, start >> 9), 0);

retry:
    while ((k = orca_btree_iter_peek(iter)).k && !(ret = bkey_err(k)) &&
        bkey_cmp(iter->pos, end) < 0) {
            if (!bkey_extent_is_data(k.k) && k.k->type != KEY_TYPE_reservation) {
                orca_btree_iter_next(iter);
                continue;
            }

            offset_into_extent = iter->pos.offset - bkey_start_offset(k.k);
            sectors = k.k->size - offset_into_extent;
            bkey_on_stack_reassemble(&cur, c, k);
            ret = orca_read_indirect_extent(&trans, &offset_into_extent, &cur);

            if (ret)
                break;

            k = bkey_i_to_s_c(cur.k);
            bkey_on_stack_realloc(&prev, c, k.k->u64s);
            sectors = min(sectors, k.k->size - offset_into_extent);

            orca_cut_front(POS(k.k->p.inode, bkey_start_offset(k.k) +
                offset_into_extent), cur.k);
            orca_key_resize(&cur.k->k, sectors);
            cur.k->k.p = iter->pos;
            cur.k->k.p.offset += cur.k->k.size;

            if (have_extent) {
                ret = orca_fill_extent(c, info, bkey_i_to_s_c(prev.k), 0);

                if (ret)
                    break;
            }

            bkey_copy(prev.k, cur.k);
            have_extent = true;

            orca_btree_iter_set_pos(iter, POS(iter->pos.inode, iter->pos.offset + sectors));
    }

    if (ret == -EINTR)
        goto retry;

    if (!ret && have_extent)
        ret = orca_fill_extent(c, info, bkey_i_to_s_c(prev.k), FIEMAP_EXTENT_LAST);

    ret = orca_trans_Exit(&trans) ?: ret;
    bkey_on_stack_exit(&cur, c);
    bkey_on_stack_exit(&prev, c);

    return ret < 0 ? ret : 0;
}

static const struct vm_operations_struct orca_vm_ops = {
    .fault = orca_page_fault,
    .map_pages = filemap_map_pages,
    .page_mkwrite = orca_page_mkwrite,
};

static int
orca_mmap(struct file *file, struct vm_area_struct *vma)
{
    file_accessed(file);
    vma->vm_ops = &orca_vm_ops;

    return 0;
}

static loff_t
orca_dir_llseek(struct file *file, loff_t offset, int whence)
{
    return generic_file_llseek_size(file, offset, whence, S64_MAX, S64_MAX);
}

static int
orca_vfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct orca_inode_info *inode = file_orca_inode(file);
    struct orca_fs *c = inode->v.i_sb->s_fs_info;

    if (!dir_emit_dots(file, ctx))
        return 0;

    return orca_readdir(c, inode->v.i_ino, ctx);
}

static const struct file_operations orca_file_operations = {
    .llseek = orca_llseek,
    .read_iter = orca_read_iter,
    .write_iter = orca_write_iter,
    .mmap = orca_mmap,
    .open = generic_file_open,
    .fsync = orca_fsync,
    .splice_read = generic_file_splice_read,
    .fallocate = orca_fallocate_dispatch,
    .unlocked_ioctl = orca_fs_file_ioctl,

#ifdef CONFIG_COMPAT
    .compat_ioctl = orca_compat_fs_ioctl,
#endif
    .remap_file_range = orca_remap_file_range,
};

static const struct inode_operations orca_file_inode_operations = {
    .getattr = orca_getattr,
    .setattr = orca_setattr,
    .fiemap = orca_fiemap,
    .listxattr = orca_xattr_list,
#ifdef CONFIG_ORCAFS_POSIX_ACL
    .get_acl = orca_get_acl,
    .set_acl = orca_set_acl,
#endif
};

static const struct inode_operations orca_dir_inode_operations = {
    .lookup = orca_lookup,
    .create = orca_create,
    .link = orca_link,
    .unlink = orca_unlink,
    .symlink = orca_symlink,
    .mkdir = orca_mkdir,
    .rmdir = orca_unlink,
    .mknod = orca_mknod,
    .rename = orca_rename2,
    .getattr = orca_getattr,
    .setattr = orca_setattr,
    .tmpfile = orca_tmpfile,
    .listxattr = orca_xattr_list,
#ifdef CONFIG_ORCAFS_POSIX_ACL
    .get_acl = orca_get_acl,
    .set_acl = orca_set_acl,
#endif
};

static const struct file_operations orca_dir_file_operations = {
    .llseek = orca_dir_llseek,
    .read = generic_read_dir,
    .iterate_shared = orca_vfs_readdir,
    .fsync = orca_fsync,
    .unlock_ioctl = orca_fs_file_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = orca_compat_fs_ioctl,
#endif
};

static const struct inode_operations orca_symlink_inode_operations = {
    .get_link = page_get_link,
    .getattr = orca_getattr,
    .setattr = orca_setattr,
    .listxattr = orca_xattr_list,
#ifdef CONFIG_ORCAFS_POSIX_ACL
    .get_acl = orca_get_acl,
    .set_acl = orca_set_acl,
#endif
};

static const struct inode_operations orca_special_inode_operations = {
    .getattr = orca_getattr,
    .setattr = orca_setattr,
    .listxattr = orca_xattr_list,
#ifdef CONFIG_ORCAFS_POSIX_ACL
    .get_acl = orca_get_acl,
    .set_acl = orca_set_acl,
#endif
};

static const struct address_space_operations orca_address_space_operations = {
    .writepage = orca_writepage,
    .readpage = orca_readpage,
    .writepages = orca_writepages,
    .readahead = orca_readahead,
    .set_page_dirty = __set_page_dirty_nobuffers,
    .write_begin = orca_write_begin,
    .write_end = orca_write_end,
    .invalidatepage = orca_invalidatepage,
    .releasepage = orca_releasepage,
    .direct_IO = noop_direct_IO,
#ifdef CONFIG_MIGRATION
    .migratepage = orca_migrate_page,
#endif
    .error_remove_page = generic_error_remove_page,
};

static struct inode *
orca_nfs_get_inode(struct super_block *sb, u64 ino, u32 generation)
{
    struct orca_fs *c = sb->s_fs_info;
    struct inode *vinode;

    if (ino < ORCAFS_ROOT_INO)
        return ERR_PTR(-ESTALE);

    vinode = orca_vfs_inode_get(c, ino);

    if (IS_ERR(vinode))
        return ERR_CAST(vinode);

    if (generation && vinode->i_generation != generation) {
        /* We didn't find the right inode... */
        iput(vinode);

        return ERR_PTR(-ESTALE);
    }

    return vinode;
}

static struct dentry *
orca_fh_to_dentry(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
    return generic_fh_to_dentry(sb, fid, fh_len, fh_type, orca_nfs_get_inode);
}

static struct dentry *
orca_fh_to_parent(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
    return generic_fh_to_parent(sb, fid, fh_len, fh_type, orca_nfs_get_inode);
}

static const struct export_operations orca_export_ops = {
    .fh_to_dentry = orca_fh_to_dentry,
    .fh_to_parent = orca_fh_to_parent,
};

static void
orca_vfs_inode_init(struct orca_fs *c, struct orca_inode_info *inode,
    struct orca_inode_unpacked *bi)
{
    orca_inode_update_after_write(c, inode, bi, ~0);

    inode->v.i_blocks = bi->bi_sectors;
    inode->v.i_ino = bi->bi_inum;
    inode->v.i_generation = bi->bi_generation,
    inode->v.i_size = bi->bi_size;

    inode->ei_flags = 0;
    inode->ei_journal_seq = 0;
    inode->ei_quota_reserved = 0;
    inode->ei_str_hash = orca_hash_info_init(c, bi);
    inode->ei_qid = orca_qid(bi);
    inode->v.i_mapping->a_ops = &orca_address_space_operations;

    switch (inode->v.i_mode & S_IFMT) {
    case S_IFREG:
        inode->v.i_op = &orca_file_inode_operations;
        inode->v.i_fop = &orca_file_operations;
        break;

    case S_IFDIR:
        inode->v.i_op = &orca_dir_inode_operations;
        inode->v.i_fop = &orca_dir_file_operations;
        break;

    case S_IFLNK:
        inode_nohighmem(&inode->v);
        inode->v.i_op = &orca_symlink_inode_operations;
        break;

    default:
        init_special_inode(&inode->v, inode->v.i_mode, inode->v.i_rdev);
        inode->v.i_op = &orca_special_inode_operations;
        break;
    }
}

static struct inode *
orca_alloc_inode(struct super_block, *sb)
{
    struct orca_inode_info *inode;

    inode = kmem_cache_alloc(orca_inode_cache, GFP_NOFS);

    if (!inode)
        return NULL;

    inode_init_once(&inode->v);
    mutex_init(&inode->ei_update_lock);
    pagecache_lock_init(&inode->ei_pagecache_lock);
    mutex_init(&inode->ei_quota_lock);
    inode->ei_journal_seq = 0;

    return &inode->v;
}

static void
orca_i_callback(struct rcu_head *head)
{
    struct inode *vinode = container_of(head, struct inode, i_rcu);
    struct orca_inode_info *inode = to_orca_ei(vinode);

    kmem_cache_free(orca_inode_cache, inode);
}

static void
orca_destroy_inode(struct inode *vinode)
{
    call_rcu(&vinode->i_rcu, orca_i_callback);
}

static int
inode_update_times_fn(struct orca_inode_info *inode, struct orca_inode_unpacked *bi,
    void *p)
{
    struct orca_fs *c = inode->v.i_sb->s_fs_info;

    bi->bi_atime = timespec_to_orca_time(c, inode->v.i_atime);
    bi->bi_mtime = timespec_to_orca_time(c, inode->v.i_mtime);
    bi->bi_ctime = timespec_to_orca_time(c, inode->v.i_ctime);

    return 0;
}

static int
orca_vfs_write_inode(struct inode *vinode, struct writeback_control *wbc)
{
    struct orca_fs *c = vinode->i_sb->s_fs_info;
    struct orca_inode_info *inode = to_orca_ei(vinode);
    int ret;

    mutex_lock(&inode->ei_update_lock);
    ret = orca_write_inode(c, inode, inode_update_times_fn, NULL,
        ATTR_ATIME | ATTR_MTIME | ATTR_CTIME);
    mutex_unlock(&inode->ei_update_lock);

    return ret;
}

static void
orca_evict_inode(struct inode *vinode)
{
    struct orca_fs *c = vinode->i_sb->s_fs_info;
    struct orca_inode_info *inode = to_orca_ei(vinode);

    truncate_inode_pages_final(&inode->v.i_data);
    clear_inode(&inode->v);
    BUG_ON(!is_bad_inode(&inode->v) && inode->ei_quota_reserved);

    if (!inode->v.i_nlink && !is_bad_inode(&inode->v)) {
        orca_quota_acct(c, inode->ei_qid, Q_SPC, -((s64)inode->v.i_blocks),
            KEY_TYPE_QUOTA_WARN);
        orca_quota_acct(c, inode->ei_qid, Q_INO, -1, KEY_TYPE_QUOTA_WARN);
        orca_inode_rm(c, inode->v.i_ino, true);
    }
}

static int
orca_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct orca_fs *c = sb->s_fs_info;
    struct orca_fs_usage_short usage = orca_fs_usage_read_short(c);
    unsigned shift = sb->s_blocksize_bits - 9;

    /**
     * This assumes inodes take up 64 bytes, which is a decent average
     * number.
    **/
    u64 avail_inode = ((usage.capacity - usage.used) << 3);
    u64 fsid;

    buf->f_type = ORCAFS_STATFS_MAGIC;
    buf->f_bsize = sb->s_blocksize;
    buf->f_blocks = usage.capacity >> shift;
    buf->f_bfree = (usage.capacity - usage.used) >> shift;
    buf->f_bavail = buf->f_bfree;
    buf->f_files = usage.nr_inode + avail_inodes;
    buf->f_ffree = avail_inodes;

    fsid = le64_to_cpup((void *)c->sb.user_uuid.b) ^
        le64_to_cpu((void *)c->sb.user_uuid.b + sizeof(u64));

    buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
    buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
    buf->f_namelen = ORCA_NAME_MAX;

    return 0;
}

static int
orca_sync_fs(struct super_block *sb, int wait)
{
    struct orca_fs *c = sb->s_fs_info;

    if (c->opts.journal_flush_disabled)
        return 0;

    if (!wait) {
        orca_journal_flush_async(&c->journal, NULL);
        return 0;
    }

    return orca_journal_flush(&c->journal);
}

static struct orca_fs *
orca_path_to_fs(const char *dev)
{
    struct orca_fs *c;
    struct block_device *bdev = lookup_bdev(dev);

    if (IS_ERR(bdev))
        return ERR_CAST(bdev);

    c = orca_bdev_to_fs(bdev);
    bdput(bdev);

    if (c)
        closure_put(&c->cl);

    return c ?: ERR_PTR(-ENOENT);
}

static char **
split_devs(const char *_dev_name, unsigned *nr)
{
    char *dev_name = NULL, **devs = NULL, *s;
    size_t i, nr_devs = 0;

    dev_name = kstrdup(_dev_name, GFP_KERNEL);

    if (!dev_name)
        return NULL;

    for(s = dev_name; s; s = strchr(s + 1, ':'))
        nr_devs++;

    devs = kcalloc(nr_devs + 1, sizeof(const char *), GFP_KERNEL);

    if (!devs) {
        kfree(dev_name);

        return NULL;
    }

    for (i = 0, s = dev_name; s; (s = strchr(s, ':')) && (*s++ = '\0'))
        devs[i++] = s;

    *nr = nr_devs;

    return devs;
}

static int
orca_remount(struct super_block *sb, int *flags, char *data)
{
    struct orca_fs *c = sb->s_fs_info;
    struct orca_opts opts = orca_opts_empty();
    int ret;

    opt_set(opts, read_only, (*flags & SB_RDONLY) != 0);
    ret = orca_parse_mount_opts(c, &opts, data);

    if (ret)
        return ret;

    if (opts.read_only != c->opts.read_only) {
        down_write(&c->state_lock);

        if (opts.read_only) {
            orca_fs_read_only(c);
            sb->s_flags |= SB_RDONLY;
        } else {
            ret = orca_fs_read_write(c);

            if (ret) {
                orca_err(c, "error going rw: %i", ret);
                up_write(&c->state_lock);

                return -EINVAL;
            }

            sb->s_flags &= ~SB_RDONLY;
        }

        c->opts.read_only = opts.read_only;
        up_write(&c->state_lock);
    }

    if (opts.errors >=)
        c->opts.errors = opts.errors;

    return ret;
}

static int
orca_show_devname(struct seq_file *seq, struct dentry *root)
{
    struct orca_fs *c = root->d_sb->s_fs_info;
    struct orca_dev *ca;
    unsigned i;
    bool first = true;

    for_each_online_member(ca, c, i) {
        if (!first)
            seq_putc(seq, ':');

        first = false;
        seq_puts(seq, "/dev/");
        seq_puts(seq, ca->name);
    }

    return 0;
}

static int
orca_show_options(struct seq_file *seq, struct dentry *root)
{
    struct orca_fs *c = root->d_sb->s_fs_info;
    enum orca_opt_id i;
    char buf[512];

    for (i = 0; i < orca_opts_nr; i++) {
        const struct orca_option *opt = &orca_opt_table[i];
        u64 v = orca_get_by_id(&c->opts, i);

        if (!(opt->mode & OPT_MOUNT))
            continue;

        if (v == orca_opt_get_by_id(&orca_opts_default, i))
            continue;

        orca_opt_to_text(&PBUF(buf), c, opt, v, OPT_SHOW_MOUNT_STYLE);
        seq_putc(seq, ',');
        seq_puts(seq, buf);
    }

    return 0;
}

static void
orca_put_super(struct super_block *sb)
{
    struct orca_fs *c = sb->s_fs_info;

    __orca_fs_stop(c);
}

static const struct super_operations orca_super_operations = {
    .alloc_inode = orca_alloc_inode,
    .destroy_inode = orca_destroy_inode,
    .write_inode = orca_vfs_write_inode,
    .evict_inode = orca_evict_inode,
    .sync_fs = orca_sync_fs,
    .statfs = orca_statfs,
    .show_devname = orca_show_devname,
    .show_options = orca_show_options,
    .remount_fs = orca_remount,
    .put_super = orca_put_super,
#if 0
    .freeze_fs = orca_freeze,
    .unfreeze_fs = orca_unfreeze,
#endif
};

static int
orca_set_super(struct super_block *s, void *data)
{
    s->s_fs_info = data;

    return 0;
}

static int
orca_noset_super(struct super_block *s, void *data)
{
    return -EBUSY;
}

static int
orca_test_super(struct super_block *s, void *data)
{
    struct orca_fs *c = s->s_fs_info;
    struct orca_fs **devs = data;
    unsigned i;

    if (!c)
        return false;

    for (i = 0; devs[i]; i++) {
        if (c != devs[i])
            return false;
    }

    return true;
}

static struct dentry *
orca_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
    struct orca_fs *c;
    struct orca_dev *ca;
    struct super_block *sb;
    struct inode *vinode;
    struct orca_opts opts = orca_opts_empty();
    char **devs;
    struct orca_fs **devs_to_fs = NULL;
    unsigned i, nr_devs;
    int ret;

    opt_set(opts, read_only, (flags & SB_RDONLY) != 0);
    ret = orca_parse_mount_opts(NULL, &opts, data);

    if (ret)
        return ERR_PTR(ret);

    devs = split_devs(dev_name, &nr_devs);

    if (!devs)
        return ERR_PTR(-ENOMEM);

    devs_to_fs = kcalloc(nr_devs + 1, sizeof(void *), GFP_KERNEL);

    if (!dev_to_fs) {
        sb = ERR_PTR(-ENOMEM);
        goto got_sb;
    }

    for (i = 0; i < nr_devs; i++)
        devs_to_fs[i] = orca_path_to_fs(devs[i]);

    sb = sget(fs_type, orca_test_super, orca_noset_super, flags |
        SB_NOSEC, devs_to_fs);

    if (!IS_ERR(sb))
        goto got_sb;

    c = orca_fs_open(devs, nr_devs, opts);

    if (IS_ERR(c)) {
        sb = ERR_CAST(c);
        goto got_sb;
    }

    /* Some options can't be parsed until after the fs is started */
    ret = orca_parse_mount_opts(c, &opts, data);

    if (ret) {
        orca_fs_stop(c);
        sb = ERR_PTR(ret);
        goto got_sb;
    }

    orca_opts_apply(&c->opts, opts);
    sb = sget(fs_type, NULL, orca_set_super, flags | SB_NOSEC, c);

    if (IS_ERR(sb))
        orca_fs_stop(c);

got_sb:
    kfree(devs_to_fs);
    kfree(devs[0]);
    kfree(devs);

    if (IS_ERR(sb))
        return ERR_CAST(sb);

    c = sb->s_fs_info;

    if (sb->s_root) {
        if ((flags ^ sb->s_flags) & SB_RDONLY) {
            ret = -EBUSY;
            goto err_put_super;
        }

        goto out;
    }

    sb->s_blocksize = block_bytes(c);
    sb->s_blocksize_bits = ilog2(block_bytes(c));
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_op = &orca_super_operations;
    sb->s_export_op = &orca_export_ops;
#ifdef CONFIG_ORCAFS_QUOTA
    sb->s_qcop = &orca_quotactl_operations;
    sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
    sb->s_xattr = orca_xattr_handlers;
    sb->s_magic = ORCAFS_STATFS_MAGIC;
    sb->s_time_gran = c->sb.time_precision;
    c->vfs_sb = sb;
    strlcpy(sb->s_id, c->name, sizeof(sb->s_id));
    ret = super_setup_bdi(sb);

    if (ret)
        goto err_put_super;

    sb->s_bdi->ra_pages = VM_READAHEAD_PAGES;

    for_each_online_member(ca, c, i) {
        struct block_device *bdev = ca->disk_Sb.bdev;

        sb->s_bdev = bdev;
        sb->s_dev = bdev->bd_dev;
        percpu_ref_put(&ca->io_ref);
        break;
    }

#ifdef CONFIG_ORCAFS_POSIX_ACL
    if (c->opts.acl)
        sb->s_flags |= SB_POSIXACL;
#endif
    vinode = orca_vfs_inode_get(c, ORCAFS_ROOT_INO);

    if (IS_ERR(vinode)) {
        orca_err(c, "error mounting: error getting root inode %i",
            (int)PTR_ERR(vinode));
        ret = PTR_ERR(vinode);
        goto err_put_super;
    }

    sb->s_root = d_make_root(vinode);

    if (!sb->s_root) {
        orca_err(c, "error mounting: error allocating root dentry");
        ret = -ENOMEM;
        goto err_put_super;
    }

    sb->s_flags |= SB_ACTIVE;

out:
    return dget(sb->s_root);

err_put_super:
    deactivate_locked_super(sb);

    return ERR_PTR(ret);
}

static void
orca_kill_sb(struct super_block *sb)
{
    struct orca_fs *c = sb->s_fs_info;

    generic_shutdown_super(sb);
    orca_fs_free(c);
}

static struct file_system_type orca_fs_type = {
    .owner = THIS_MODULE,
    .name = "orcafs",
    .mount = orca_mount,
    .kill_sb = orca_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
};

MODULE_ALIAS_FS("orcafs");

void
orca_vfs_exit(void)
{
    unregister_filesystem(&orca_fs_type);

    if (orca_inode_cache)
        kmem_cache_destroy(orca_inode_cache);
}

int __init
orca_vfs_init(void)
{
    int ret = -ENOMEM;

    orca_inode_cache = KMEM_CACHE(orca_inode_info, 0);

    if (!orca_inode_cache)
        goto err;

    ret = register_filesystem(&orca_fs_type);

    if (ret)
        goto err;

    return 0;

err:
    orca_vfs_exit();

    return ret;
}

#endif
