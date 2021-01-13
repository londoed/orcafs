#include "orcafs.h"
#include "bkey_on_stack.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "extents.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "migrate.h"
#include "move.h"
#include "replicas.h"
#include "super-io.h"

static int
drop_dev_ptrs(struct orca_fs *c, struct bkey_s k, unsigned dev_idx, int flags,
    bool metadata)
{
    unsigned replicas = metadata ? c->opts.metadata_replicas : c->opts.data_replicas;
    unsigned lost = metadata ? ORCA_FORCE_IF_METADATA_LOST : ORCA_FORCE_IF_DATA_LOST;
    unsigned degraded = metadata ? ORCA_FORCE_IF_METADATA_DEGRADED : ORCA_FORCE_IF_DATA_DEGRADED;
    unsigned nr_good;

    orca_bkey_drop_device(k, dev_idx);
    nr_good = orca_bkey_durability(c, k.s_c);

    if ((!nr_good && !(flags & lost)) || (nr_good < replicas && !(flags & degraded)))
        return -EINVAL;

    return 0;
}

static int
__orca_dev_usrdata_drop(struct orca_fs *c, unsigned dev_idx, int flags,
    enum btree_id btree_id)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_on_stack sk;
    int ret = 0;

    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, BTREE_ITER_MAX, 0);
    iter = orca_trans_get_iter(&trans, btree_id, POS_MIN, BTREE_ITER_PREFETCH);

    while ((k = orca_btree_iter_peek(iter)).k && !(ret = bkey_err(k))) {
        if (!orca_bkey_has_device(k, dev_idx)) {
            orca_btree_iter_next(iter);
            continue;
        }

        orca_on_stack_reassemble(&sk, c, k);
        ret = drop_dev_ptrs(c, bkey_i_to_s(sk.k), dev_idx, flags, false);

        if (ret)
            break;

        /**
         * If the new extent no longer has any pointers, orca_extent_normalize()
         * will do the appropriate thing with it (turning it into a
         * KEY_TYPE_error key, or just a discard if it was a cached extent).
        **/
        orca_extent_normalize(c, bkey_i_to_s(sk.k));
        orca_btree_iter_set_pos(iter, bkey_start_pos(&sk.k->k));
        orca_trans_update(&trans, iter, sk.k, 0);
        ret = orca_trans_commit(&trans, NULL, NULL, BTREE_INSERT_NOFAIL);

        /**
         * Don't want to leave ret == -EINTR, since if we raced and
         * something else overwrote the key, we could spuriously return
         * -EINTR below.
        **/
        if (ret == -EINTR)
            ret = 0;

        if (ret)
            break;
    }

    ret = orca_trans_exit(&trans) ?: ret;
    bkey_on_stack_exit(&sk, c);
    BUG_ON(ret == -EINTR);

    return ret;
}

static int
orca_dev_usrdata_drop(struct orca_fs *c, unsigned dev_idx, int flags)
{
    return __orca_dev_usrdata_drop(c, dev_idx, flags, BTREE_ID_EXTENTS) ?:
        __orca_dev_usrdata_drop(c, dev_idx, flags, BTREE_ID_REFLINK);
}

static int
orca_dev_metadata_drop(struct orca_fs *c, unsigned dev_idx, int flags)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct closure cl;
    struct btree *b;
    unsigned id;
    int ret;

    /* Don't handle this yet */
    if (flags & ORCA_FORCE_IF_METADATA_LOST)
        return -EINVAL;

    orca_trans_init(&trans, c, 0, 0);
    closure_init_stack(&cl);

    for (id = 0; id < BTREE_ID_NR; id++) {
        for_each_btree_node(&trans, iter, id, POS_MIN, BTREE_ITER_PREFETCH, b) {
            __BKEY_PADDED(k, BKEY_BTREE_PTR_VAL_U64s_MAX) tmp;

retry:
            if (!orca_bkey_has_device(bkey_i_to_s_c(&b->key), dev_idx))
                continue;

            bkey_copy(&tmp.k, &b->key);
            ret = drop_dev_ptrs(c, bkey_i_to_s(&tmp.k), dev_idx, flags, true);

            if (ret) {
                orca_err(c, "Cannot drop device without losing data");
                goto err;
            }

            ret = orca_btree_node_update_key(c, iter, b, &tmp.k);

            if (ret == -EINTR) {
                b = orca_btree_iter_peek_node(iter);
                goto retry;
            }

            if (ret) {
                orca_err(c, "Error updating btree node key: %i", ret);
                goto err;
            }
        }

        orca_trans_iter_free(&trans, iter);
    }

    /* Flush relevant btree updates */
    closure_wait_event(&c->btree_interior_update_wait,
        !orca_btree_interior_updates_nr_pending(c));
    ret = 0;

err:
    ret = orca_trans_exit(&trans) ?: ret;
    BUG_ON(ret == -EINTR);

    return ret;
}

int
orca_dev_data_drop(struct orca_fs *c, unsigned dev_idx, int flags)
{
    return orca_dev_usrdata_drop(c, dev_idx, flags) ?:
        orca_dev_metadata_drop(c, dev_idx, flags);
}
