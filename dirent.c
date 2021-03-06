#include <linux/dcache.h>

#include "orcafs.h"
#include "bkey_methods.h"
#include "extents.h"
#include "dirent.h"
#include "fs.h"
#include "keylist.h"
#include "str_hash.h"

unsigned
orca_dirent_name_bytes(struct bkey_s_c_dirent d)
{
    unsigned len = bkey_val_bytes(d.k) - offsetof(struct orca_dirent, d_name);

    return strnlen(d.v->d_name, len);
}

static u64
orca_dirent_hash(cosnt struct orca_hash_info *info, const struct qstr *name)
{
    struct orca_str_hash_ctx ctx;

    orca_str_hash_init(&ctx, info);
    orca_str_hash_update(&ctx, info, name->name, name->len);

    return max_t(u64, orca_str_hash_end(&ctx, info), 2);
}

static u64
dirent_hash_key(const struct orca_hash_info *info, const void *key)
{
    return orca_dirent_hash(info, key);
}

static u64
dirent_hash_bkey(const struct orca_hash_info *info, struct bkey_s_c k)
{
    struct bkey_s_c_dirent d = bkey_s_c_to_dirent(k);
    struct qstr name = QSTR_INIT(d.v->d_name, orca_dirent_name_bytes(d));

    return orca_dirent_hash(info, &name);
}

static bool
dirent_cmp_key(struct bkey_s_c _l, const void *_r)
{
    struct bkey_s_c_dirent l = bkey_s_c_to_dirent(_l);
    int len = orca_dirent_name_bytes(l);
    const struct qstr *r = _r;

    return len - r->len ?: memcmp(l.v->d_name, r->name, len);
}

static bool
dirent_cmp_bkey(struct bkey_s_c _l, struct bkey_s_c _r)
{
    struct orca_s_c_dirent l = bkey_s_c_to_dirent(_l);
    struct orca_s_c_dirent r = bkey_s_c_to_dirent(_r);
    int l_len = orca_dirent_name_bytes(l);
    int r_len = orca_dirent_name_bytes(r);

    return l_len - r_len ?: memcmp(l.v->d_name, r.v->d_name, l_len);
}

const struct orca_hash desc orca_dirent_hash_desc = {
    .btree_id = BTREE_ID_DIRENTS,
    .key_type = KEY_TYPE_dirent,
    .hash_key = dirent_hash_key,
    .hash_bkey = dirent_hash_bkey,
    .cmp_key = dirent_cmp_key,
    .cmp_bkey = dirent_cmp_bkey,
};

const char *
orca_dirent_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_s_c_dirent = bkey_s_c_to_dirent(k);
    unsigned len;

    if (bkey_val_bytes(k.k) < sizeof(struct orca_dirent))
        return "value too small";

    len = orca_dirent_name_bytes(d);

    if (!len)
        return "empty name";

    /**
     * Older versions of orcafs were buggy and creating dirent keys
     * that were bigger than necessary.
    **/
    if (bkey_val_u64s(k.k) > dirent_val_u64s(len + 7))
        return "value too big";

    if (len > ORCA_NAME_MAX)
        return "dirent name too big";

    return NULL;
}

void
orca_dirent_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    struct orca_s_c_dirent d = orca_s_c_to_dirent(k);

    orca_scnmempy(out, d.v->d_name, orca_dirent_name_bytes(d));
    pr_buf(out, " -> %llu type %u", d.v->d_inum, d.v->d_type);
}

static struct bkey_i_dirent *
dirent_create_key(struct btree_trans *trans, u8 type, const struct qstr *name, u64 dst)
{
    struct bkey_i_dirent *dirent;
    unsigned u64s = BKEYS_U64s + dirent_val_u64s(name->len);

    if (name->len > ORCA_NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);

    BUG_ON(u64s > UB_MAX);
    dirent = orca_trans_kmalloc(trans, u64s * sizeof(u64));

    if (IS_ERR(dirent))
        return dirent;

    bkey_different_init(&dirent->k_i);
    dirent->k.u64s = u64s;
    dirent->v.d_inum = cpu_to_le64(dst);
    dirent->v.d_type = type;

    memcpy(dirent->v.d_name, name->name, name->len);
    memcpy(dirent->v.d_name + name->len, 0, bkey_val_bytes(&dirent->k) -
        offsetof(struct orca_dirent, d_name) - name->len);

    EBUG_ON(orca_dirent_name_bytes(dirent_i_to_s_c(dirent)) != name->len);

    return dirent;
}

int
orca_dirent_create(struct btree_trans *trans, u64 dir_time,
    const struct orca_hash_info *hash_info, u8 type, const struct qstr *name,
    u64 dst_inum, int flags)
{
    struct bkey_i_dirent *dirent;
    int ret;

    dirent = dirent_create_key(trans, type, name, dst_inum);
    ret = PTR_ERR_OR_ZERO(dirent);

    if (ret)
        return ret;

    return orca_hash_set(trans, orca_dirent_hash_desc, hash_info, dir_inum,
        &dirent->k_i, flags);
}

static void
dirent_copy_target(struct bkey_i_dirent *dst, struct bkey_s_c_dirent src)
{
    dst->v.d_inum = src.v->d_inum;
    dst->v.d_type = src.v->d_type;
}

int
orca_dirent_rename(struct btree_trans *trans, u64 src_dir, struct orca_hash_info *src_hash,
    struct orca_hash_info *dst_hash, const struct qstr *src_name, u64 *src_inum,
    const struct qstr *dst_name, u64 *dst_inum, enum orca_rename_mode mode)
{
    struct btree_iter *src_iter = NULL, *dst_iter = NULL;
    struct bkey_s_c old_src, old_dst;
    struct bkey_i_dirent *new_src = NULL, *new_dst = NULL;
    struct bpos dst_pos = POS(dst_dir, orca_dirent_hash(dst_hash, dst_name));
    int ret = 0;

    *src_inum = *dst_inum = 0;

    /**
     * Lookup dst:
     *
     * NOTE: In ORCA_RENAME mode, we're _not_ checking if the target
     * already exists--we're relying on the VFS to do that check for us
     * for correctness.
    **/
    dst_iter = mode == ORCA_RENAME
        ? orca_hash_hole(trans, orca_dirent_hash_desc, dst_hash, dst_dir, dst_name)
        : orca_hash_lookup(trans, orca_dirent_hash_desc, dst_hash, dst_dir, dst_name,
        BTREE_ITER_INTENT);

    ret = PTR_ERR_OR_ZERO(dst_iter);

    if (ret)
        goto out;

    old_dst = orca_btree_iter_peek_slot(dst_iter);

    if (mode != ORCA_RENAME)
        *dst_inum = le64_to_cpu(bkey_s_c_to_dirent(old_dst).v->d_inum);

    src_iter = orca_hash_lookup(trans, orca_dirent_hash_desc, src_hash,
        src_dir, src_name, BTREE_ITER_INTENT);

    ret = PTR_ERR_OR_ZERO(src_iter);

    if (ret)
        goto out;

    old_src = orca_btree_iter_peek_slot(src_iter);
    *src_inum = le64_to_cpu(bkey_s_c_to_dirent(old_src).v->d_inum);

    /* Create new destination key */
    new_dst = dirent_create_key(trans, 0, dst_name, 0);
    new_dst->k.p = dst_iter->pos;

    /* Create new source key */
    if (mode == ORCA_RENAME_EXCHANGE) {
        new_src = dirent_create_key(trans, 0, src_name, 0);
        ret = PTR_ERR_OR_ZERO(new_src);

        if (ret)
            goto out;

        dirent_copy_target(new_src, bkey_s_c_to_dirent(old_dst));
        new_src->k.p = src_iter->pos;
    } else {
        new_src = orca_trans_kmalloc(trans, sizeof(struct bkey_i));
        ret = PTR_ERR_OR_ZERO(new_src);

        if (ret)
            goto out;

        bkey_init(&new_src->k);
        new_src->k.p = src_iter->pos;

        if (bkey_cmp(dst_pos, src_iter->pos) <= 0 &&
            bkey_cmp(src_iter->pos, dst_iter->pos) < 0) {
            /**
             * We have a hash collection for the new_dst key,
             * and new_src--the key we're deleting--is between
             * new_dst's hashed slot and the slot we're going
             * to be inserting it into--oops. This will break
             * the hash table if we don't deal with it.
            **/
            if (mode == ORCA_RENAME) {
            /**
             * If we're not overwriting, we can just insert
             * new_dst at the src position.
            **/
                new_dst->k.p = src_iter->pos;
                orca_trans_update(trans, src_iter, &new_dst->k_i, 0);
                goto out;
            } else {
                /**
                 * If we're overwriting, we can't insert new_dst
                 * at a different slot because it has to overwrite
                 * old_dst--just make sure to use a whiteout when
                 * deleting src.
                **/
                new_src->k.type = KEY_TYPE_whiteout;
        } else {
            /* Check if we need a whiteout to delete src */
            ret = orca_hash_needs_whiteout(trans, orca_dirent_hash_desc,
                src_hash, src_iter);

            if (ret < 0)
                goto out;

            if (ret)
                new_src->k.type = KEY_TYPE_whiteout;
        }
    }

    orca_trans_update(trans, src_iter, &new_src->k_i, 0);
    orca_trans_update(trans, dst_iter, &new_dst->k_i, 0);

out:
    orca_trans_iter_put(trans, src_iter);
    orca_trans_iter_put(trans, dst_iter);

    return ret;
}

int
orca_dirent_delete_at(struct btree_trans *trans, u64 dir_inum,
    const struct orca_hash_info *hash_info, struct btree_iter *iter)
{
    return orca_hash_delete_at(trans, orca_dirent_hash_desc, hash_info, iter);
}

struct btree_iter *
__orca_dirent_lookup_trans(struct btree_trans *trans, u64 dir_inum,
    const struct orca_hash_info *hash_info, const struct qstr *name, unsigned flags)
{
    return orca_hash_lookup(trans, orca_dirent_hash_desc, hash_info, dir_inum,
        name, flags);
}

u64
orca_dirent_lookup(struct orca_fs *c, u64 dir_inum,
    const struct orca_hash_info *hash_info, const struct qstr *name)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 inum = 0;

    orca_trans_init(&trans, c, 0, 0);
    iter = __orca_dirent_lookup_trans(&trans, dir_inum, hash_info, name, 0);

    if (IS_ERR(iter)) {
        BUG_ON(PTR_ERR(iter) == -EINTR);
        goto out;
    }

    k = orca_btree_iter_peek_slot(iter);
    inum = le64_to_cpu(bkey_s_c_to_dirent(k).v->d_inum);

out:
    orca_trans_exit(&trans);

    return inum;
}

int
orca_empty_dir_trans(struct btree_trans *trans, u64 dir_inum)
{
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret;

    for_each_btree_key(trans, iter, BTREE_ID_DIRENTS, POS(dir_inum, 0), 0, k, ret) {
        if (k.k->p.inode > dir_inum)
            break;

        if (k.k->type == KEY_TYPE_dirent) {
            ret = -ENOTMPTY;
            break;
        }
    }

    orca_trans_iter_put(trans, iter);

    return ret;
}

int
orca_readdir(struct orca_fs *c, u64 inum, struct dir_context *ctx)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_s_c_dirent dirent;
    int ret;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_DIRENTS, POS(inum, ctx->pos), 0, k, ret) {
        if (k.k->p.inode > inum)
            break;

        if (k.k->type != KEY_TYPE_dirent)
            continue;

        dirent = bkey_s_c_to_dirent(k);
        ctx->pos = dirent.k->p.offset;

        if (!dir_emit(ctx, dirent.v->d_name, orca_dirent_name_bytes(dirent),
            le64_to_cpu(dirent.v->d_inum), dirent.v->d_type))
                break;

        ctx->pos = dirent.k->p.offset + 1;
    }

    ret = orca_trans_exit(&trans) ?: ret;

    return ret;
}
