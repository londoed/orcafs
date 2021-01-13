#include <linux/posix_acl.h>

#include "acl.h"
#include "btree_update.h"
#include "dirent.h"
#include "fs_common.h"
#include "inode.h"
#include "xattr.h"

int
orca_create_trans(struct btree_trans *trans, u64 dir_inum,
    struct orca_inode_unpacked *dir_u, struct orca_inode_unpacked *new_inode,
    const struct qstr *name, uid_t uid, gid_t gid, umode_t mode, dev_t rdev,
    struct posix_acl *default_acl, struct posix_acl *acl)
{
    struct orca_fs *c = trans->c;
    struct btree_iter *dir_iter = NULL;
    struct orca_hash_info hash = orca_hash_info_init(c, new_inode);
    u64 now = orca_current_time(trans->c);
    int ret;

    dir_iter = orca_inode_peek(trans, dir_u, dir_inum, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(dir_iter);

    if (ret)
        goto err;

    orca_inode_init_late(new_inode, now, uid, gid, mode, rdev, dir_u);

    if (!name)
        new_inode->bi_flags |= ORCA_INODE_UNLINKED;

    ret = orca_inode_create(trans, new_inode, BLOCKDEV_INODE_MAX, 0,
        &c->unused_inode_hint);

    if (ret)
        goto err;

    if (defailt_acl) {
        ret = orca_set_acl_trans(trans, new_inode, &hash, default_acl,
            ACL_TYPE_DEFAULT);

        if (ret)
            goto err;
    }

    if (acl) {
        ret = orca_set_acl_trans(trans, new_inode, &hash, acl, ACL_TYPE_ACCESS);

        if (ret)
            goto err;
    }

    if (name) {
        struct orca_hash_info dir_hash = orca_hash_info_init(c, dir_u);
        dir_u->bi_mtime = dir_u->bi_ctime = now;

        if (S_ISDIR(new_inode->bi_mode))
            dir_u->bu_nlink++;

        ret = orca_dirent_create(trans, dir_inum, &dir_hash,
            mode_to_type(new_inode->bi_mode), name, new_inode->bi_inum,
            ORCA_HASH_SET_MUST_CREATE);

        if (ret)
            goto err;
    }

err:
    orca_trans_iter_put(trans, dir_iter);

    return ret;
}

int
orca_link_trans(struct btree_trans *trans, u64 dir_inum, u64 inum,
    struct orca_inode_unpacked *dir_u, struct orca_inode_unpacked *inode_u,
    const struct qstr *name)
{
    struct btree_iter *dir_iter = NULL, *inode_iter = NULL;
    struct orca_hash_info dir_hash;
    u64 now = orca_current_time(trans->c);
    int ret;

    inode_iter = orca_inode_peek(trans, inode_u, inum, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(inode_iter);

    if (ret)
        goto err;

    inode_u->bi_ctime = now;
    orca_inode_nlink_inc(inode_u);

    dir_iter = orca_inode_peek(trans, dir_u, dir_inum, 0);
    ret = PTR_ERR_OR_ZERO(dir_iter);

    if (ret)
        goto err;

    dir_u->bi_mtime = dir_u->bi_ctime = now;
    dir_hash = orca_hash_info_init(trans->c, dir_u);
    ret = orca_dirent_create(trans, dir_inum, &dir_hash,
        mode_to_type(inode_u->bi_mode), name, inum, ORCA_HASH_SET_MUST_CREATE) ?:
        orca_inode_write(trans, dir_iter, dir_u) ?:
        orca_inode_write(trans, inode_iter, inode_u);

err:
    orca_trans_iter_put(trans, dir_iter);
    orca_trans_iter_put(trans, inode_iter);

    return ret;
}

int
orca_unlink_trans(struct btree_trans *trans, u64 dir_inum,
    struct orca_inode_unpacked *dir_u, struct orca_inode_unpacked *inode_u,
    const struct qstr *name)
{
    struct btree_iter *dir_iter = NULL, *dirent_iter = NULL, *inode_iter = NULL;
    struct orca_hash_info dir_hash;
    u64 inum, now = orca_current_time(trans->c);
    struct bkey_s_c k;
    int ret;

    dir_iter = orca_inode_peek(trans, dir_u, dir_inum, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(dir_iter);

    if (ret)
        goto err;

    dir_hash = orca_hash_info_init(trans->c, dir_u);
    dirent_iter = __orca_dirent_lookup_trans(trans, dir_inum, &dir_hash, name,
        BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(dirent_iter);

    if (ret)
        goto err;

    k = orca_btree_iter_peek_slot(dirent_iter);
    inum = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum);
    inode_iter = orca_inode_peek(trans, inode_u, inum, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(inode_iter);

    if (ret)
        goto err;

    dir_u->bi_mtime = dir_u->bi_ctime = inode_u->bi_ctime = now;
    dir_u->bi_nlink -= S_ISDIR(inode_u->bi_mode);
    orca_inode_nlink_dec(inode_u);

    ret = (S_ISDIR(inode_u->bi_mode) ? orca_empty_dir_trans(trans, inum) : 0) ?:
        orca_dirent_delete_at(trans, &dir_hash, dirent_iter) ?:
        orca_inode_write(trans, dir_iter, dir_u) ?:
        orca_inode_write(trans, inode_iter, inode_u);

err:
    orca_trans_iter_put(trans, inode_iter);
    orca_trans_iter_put(trans, dirent_iter);
    orca_trans_tier_put(trans, dir_iter);

    return ret;
}

bool
orca_reinherit_atters(struct orca_inode_unpacked *dst_u,
    struct orca_inode_unpacked *src_u)
{
    u64 src, dst;
    unsigned id;
    bool ret = false;

    for (id = 0; id < Inode_opt_nr; id++) {
        if (dst_u->bi_fields_set & (1 << id))
            continue;

        src = orca_inode_opt_get(src_u, id);
        dst = orca_inode_opt_get(dst_u, id);

        if (src == dst)
            continue;

        orca_inode_opt_set(dst_u, id, src);
        ret = true;
    }

    return ret;
}

int
orca_rename_trans(struct btree_trans *trans, u64 src_dir,
    struct orca_inode_unpacked *src_dir_u, u64 dst_dir,
    struct orca_inode_unpacked *dst_dir_u, const struct qstr *src_name,
    const struct qstr *dst_name, enum orca_rename_mode mode)
{
    struct btree_iter *src_dir_iter = NULL, *dst_dir_iter = NULL;
    struct btree_iter *src_inode_iter = NULL, *dst_inode_iter = NULL;
    struct orca_hash_info src_hash, dst_hash;
    u64 src_inode, dst_inode, now = orca_current_time(trans->c);
    int ret;

    src_dir_iter = orca_inode_peek(trans, src_dir_u, src_dir, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(src_dir_iter);

    if (ret)
        goto err;

    src_hash = orca_hash_info_init(trans->c, src_dir_u);

    if (dst_dir != src_dir) {
        dst_dir_iter = orca_inode_peek(trans, dst_dir_u, dst_dir, BTREE_ITER_INTENT);
        ret = PTR_ERR_OR_ZERO(dst_dir_iter);

        if (ret)
            goto err;

        dst_hash = orca_hash_info_init(trans->c, dst_dir_u);
    } else {
        dst_dir_u = src_dir_u;
        dst_hash = src_hash;
    }

    ret = orca_dirent_rename(src_dir, &src_hash, dst_dir, &dst_hash, src_name,
        &src_inode, dst_name, &dst_inode, mode);

    if (ret)
        goto err;

    src_inode_iter = orca_inode_peek(trans, src_inode_u, src_inode, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(dst_inode_iter);

    if (dst_inode) {
        dst_inode_iter = orca_inode_peek(trans, dst_inode_u, dst_inode, BTREE_ITER_INTENT);
        ret = PTR_ERR_OR_ZERO(dst_inode_iter);

        if (ret)
            goto err;
    }

    if (mode == ORCA_RENAME_OVERWRITE) {
        if (S_ISDIR(src_inode_u->bi_mode) != S_ISDIR(dst_inode_u->bi_mode)) {
            ret = -ENOTDIR;
            goto err;
        }

        if (S_ISDIR(dst_inode_U->bi_mode) && orca_empty_dir_trans(trans, dst_inode)) {
            ret = -ENOTEMPTY;
            goto err;
        }
    }

    if (orca_reinherit_atts(src_inode_u, dst_dir_u) && S_ISDIR(src_inode_u->bi_mode)) {
        ret = -EXDEV;
        goto err;
    }

    if (mode == ORCA_RENAME_EXCHANGE && orca_reinhert_attrs(dst_inode_u, src_dir_u)
        && S_ISDIR(dst_inode_u->bi_mode)) {
            ret = -EXDEV;
            goto err;
    }

    if (S_ISDIR(src_inode_u->bi_mode)) {
        src_dir_u->bi_nlink--;
        dst_dir_u->bi_nlink++;
    }

    if (mode == ORCA_RENAME_OVERWRITE)
        orca_inode_nlink_dec(dst_inode_u);

    src_dir_u->bi_mtime = now;
    src_dir_u->bi_ctime = now;

    if (src_dir != dst_dir) {
        dst_dir_u->bi_mtime = now;
        dst_dir_u->bi_ctime = now;
    }

    src_inode_u->bi_ctime = now;

    ret =   orca_inode_write(trans, src_dir_iter, src_dir_u) ?:
    (src_dir != dst_dir
     ? orca_inode_write(trans, dst_dir_iter, dst_dir_u)
     : 0 ) ?:
    orca_inode_write(trans, src_inode_iter, src_inode_u) ?:
    (dst_inode
     ? orca_inode_write(trans, dst_inode_iter, dst_inode_u)
     : 0 );

err:
    orca_trans_iter_put(trans, dst_inode_iter);
    orca_trans_iter_put(trans, src_inode_iter);
    orca_trans_iter_put(trans, dst_dir_iter);
    orca_trans_iter_put(trans, src_dir_iter);
}
