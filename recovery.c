#include <linux/sort.h>
#include <linux/stat.h>

#include "orcafs.h"
#include "alloc_background.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_io.h"
#include "buckets.h"
#include "dirent.h"
#include "ec.h"
#include "error.h"
#include "fs-common.h"
#include "fsck.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "journal_seq_blacklist.h"
#include "quota.h"
#include "recovery.h"
#include "replicas.h"
#include "super-io.h"

#define QSTR(n) { { { .len = strlen(n) } }, .name = n }

static struct journal_key *
journal_key_search(struct journal_key *journal_keys, enum btree_id id,
    unsigned level, struct bpos pos)
{
    size_t l = 0, r = journal_keys->nr, m;

    while (l < r) {
        m = l + ((r - l) >> 1);

        if ((cmp_int(id, journal_keys->d[m].btree_id) ?:
            cmp_int(level, journal_keys->d[m].level) ?:
            bkey_cmp(pos, journal_key->d[m].k->k.p)) > 0)
                l = m + 1;
        else
            r = m;
    }

    BUG_ON(l < journal_keys->nr && (cmp_int(id, journal_keys->d[l].btree_id) ?:
        cmp_int(level, journal_keys->d[l].level) ?:
        bkey_cmp(pos, journal_keys->d[l].k->k.p)) > 0);

    BUG_ON(l && (cmp_int(id, journal_keys->d[l - 1].btree_id) ?:
        cmp_int(level, journal_keys->d[l - 1].level) ?:
        bkey_cmp(pos, journal_keys->d[l - 1].k->k.p)) <= 0);

    return l < journal_keys->nr ? journal_keys->d + l : NULL;
}

static struct bkey_i *
orca_journal_iter_peek(struct journal_iter *iter)
{
    if (iter->k && iter->k < iter->keys->d + iter->keys->nr &&
        iter->k->btree_id == iter->btree_id &&
        iter->k->level == iter->level)
            return iter->k->k;

    iter->k = NULL;

    return NULL;
}

static void
orca_journal_iter_advance(struct journal_iter *iter)
{
    if (iter->k)
        iter->k++;
}

static void
orca_journal_hter_init(struct journal_iter *iter, struct journal_keys *journal_keys,
    enum btree_id id, unsigned level, struct bpos pos)
{
    iter->btree_id = id;
    iter->level = level;
    iter->keys = journal_keys;
    iter->k = journal_key_search(journal_keys, id, level, pos);
}

static struct bkey_s_c
orca_journal_iter_peek_btree(struct btree_and_journal_iter *iter)
{
    return iter->btree ? orca_btree_iter_peek(iter->btree) :
        orca_btree_node_iter_peek_unpack(&iter->node_iter, iter->b, &iter->unpacked);
}

static void
orca_journal_iter_advance_btree(struct btree_and_journal_iter *iter)
{
    if (iter->btree)
        orca_btree_iter_next(iter->btree);
    else
        orca_btree_node_iter_advance(&iter->node_iter, iter->b);
}

void
orca_btree_and_journal_iter_advance(struct btree_and_journal_iter *iter)
{
    switch (iter->last) {
    case none:
        break;

    case btree:
        orca_journal_iter_advance_btree(iter);
        break;

    case journal:
        orca_journal_iter_advance(&iter->journal);
        break;
    }

    iter->last = none;
}

struct bkey_s_c
orca_btree_and_journal_iter_peek(struct btree_and_journal_iter *iter)
{
    struct bkey_s_c ret;

    for (;;) {
        struct bkey_s_c btree_k = orca_journal_iter_peek_btree(iter);
        struct bkey_s_c journal_k =
            bkey_i_to_s_c(orca_journal_iter_peek(&iter->journal));

        if (btree_k.k && journal_k.k) {
            int cmp = bkey_cmp(btree_k.k->p, journal_k.k->p);

            if (!cmp)
                orca_journal_iter_advance_btree(iter);

            iter->last = cmp < 0 ? btree : journal;
        } else if (btree_k.k) {
            iter->last = btree;
        } else if (journal_k.k) {
            iter->last = journal;
        } else {
            iter->last = none;

            return bkey_s_c_null;
        }

        ret = iter->last == journal ? journal_k : btree_k;

        if (iter->b && bkey_cmp(ret.k->p, iter->b->data->max_key) > 0) {
            iter->journal.k = NULL;
            iter->last = none;

            return bkey_s_c_null;
        }

        if (!bkey_deleted(ret.k))
            break;

        orca_btree_and_journal_iter_advance(iter);
    }

    return ret;
}

struct bkey_s_c
orca_btree_and_journal_iter_next(struct btree_and_journal_iter *iter)
{
    orca_btree_and_journal_iter_advance(iter);

    return orca_btree_and_journal_iter_peek(iter);
}

void
orca_btree_and_journal_iter_init(struct btree_and_journal_iter *iter,
    struct btree_trans *trans, struct journal_keys *journal_keys,
    enum btree_id id, struct bpos pos)
{
    memset(iter, 0, sizeof(*iter));
    iter->btree = orca_trans_get_iter(trans, id, pos, 0);
    orca_journal_iter_init(&iter->journal, journal_keys, id, 0, pos);
}

void
orca_btree_and_journal_iter_init_node_iter(struct btree_and_journal_iter *iter,
    struct journal_keys *journal_keys, struct btree *b)
{
    memset(iter, 0, sizeof(*iter));
    iter->b = b;

    orca_btree_node_iter_init_from_start(&iter->node_iter, iter->b);
    orca_journal_iter_init(&iter->journal, journal_keys, b->c.btree_id,
        b->c.level, b->data->min_key);
}
static int
orca_btree_and_journal_walk_recurse(struct orca_fs *c, struct btree *b,
    struct journal_keys *journal_keys, enum btree_id btree_id,
    btree_walk_node_fn node_fn, btree_walk_key_fn key_fn)
{
    struct btree_and_journal_iter iter;
    struct bkey_s_c k;
    int ret = 0;

    orca_btree_and_journal_iter_init_node_iter(&iter, journal_keys, b);

    while ((k = orca_btree_and_journal_iter_peek(&iter)).k) {
        ret = key_fn(c, btree_id, b->c.level, k);

        if (ret)
            break;

        if (b->c.level) {
            struct btree *child;
            BKEY_PADDER(k) tmp;

            bkey_reassemble(&tmp.k, k);
            k = bkey_i_to_s_c(&tmp.k);
            orca_btree_and_journal_iter_advance(&iter);

            if (b->c.level > 0) {
                child = orca_btree_node_get_noiter(c, &tmp.k, b->c.btree_id,
                    b->c.level - 1);
                ret = PTR_ERR_OR_ZERO(child);

                if (ret)
                    break;

                ret = (node_fn ? node_fn(c, b) : 0) ?:
                    orca_btree_and_journal_walk_recurse(c, child, journal_keys,
                    btree_id, node_fn, key_fn);

                six_unlock_read(&child->c.lock);

                if (ret)
                    break;
            }
        } else {
            orca_btree_and_journal_iter_advance(&iter);
        }
    }

    return ret;
}

int
orca_btree_and_journal_walk(struct orca_fs *c, struct journal_keys *journal_keys,
    enum btree_id btree_id, btree_walk_node_fn node_fn, btree_walk_key_fn key_fn)
{
    struct btree *b = c->btree_roots[btree_id].b;
    int ret = 0;

    if (btree_node_fake(b))
        return 0;

    six_lock_read(&b->c.lock, NULL, NULL);
    ret = (node_fn ? node_fn(c, b) : 0) :?
        orca_btree_and_journal_walk_recurse(c, b, journal_keys, btree_id,
        node_fn, key_fn) ?:
        key_fn(c, btree_id, b->c.level + 1, bkey_i_to_s_c(&b->key));
    six_unlock_read(&b->c.lock);

    return ret;
}

/**
 * Sort and deduplicate all keys in the journal.
**/
void
orca_journal_entries_free(struct list_head *list)
{
    while (!list_empty(list)) {
        struct journal_replay *i = list_first_entry(list, struct journal_replay,
            list);
        list_del(&i->list);
        kvpfree(i, offsetof(struct journal_replay, j) + vstruct_bytes(&i->j));
    }
}

/**
 * When keys compare equal, oldest compares first.
**/
static int
journal_sort_key_cmp(const void *_l, const void *_r)
{
    const struct journal_key *l = _l;
    const struct journal_key *r = _r;

    return cmp_int(l->btree_id, r->btree_id) ?:
        cmp_int(l->level, r->level) ?:
        bkey_cmp(l->k->k.p, r->k->k.p) ?:
        cmp_int(l->journal_seq, r->journal_seq) ?:
        cmp_int(l->journal_offset, r->journal_offset);
}

void
orca_journal_keys_free(struct journal_keys *keys)
{
    kvfree(keys->d);
    keys->d = NULL;
    keys->nr = 0;
}

static struct journal_keys
journal_keys_sort(struct list_head *journal_entries)
{
    struct journal_replay *p;
    struct jset_entry *entry;
    struct bkey_i *k, *_n;
    struct journal_keys keys = { NULL };
    struct journal_key *src, *dst;
    size_t nr_keys = 0;

    if (list_empty(journal_entries))
        return keys;

    keys.journal_seq_base = le64_to_cpu(list_last_entry(journal_entries,
        struct journal_replay, list)->j.last_seq);

    list_for_each_entry(p, journal_entries, list) {
        if (le64_to_cpu(p->j.seq) < keys.journal_seq_base)
            continue;

        for_each_jset_key(k, _n, entry, &p->j)
            keys.d[keys.nr++] = (struct journal_key) {
                .btree_id = entry->btree_id,
                .level = entry->level,
                .k = k,
                .journal_seq = le64_to_cpu(p->j.seq) - keys.journal_seq_base,
                .journal_offset = k->_data - p->j._data,
            };
    }

    sort(keys.d, keys.nr, sizeof(keys.d[0]), journal_sort_key_cmp, NULL);
    src = dst = keys.d;

    while (src < keys.d + keys.nr) {
        while (src + 1 < keys.d + keys.nr && src[0].btree_id == src[1].btree_id &&
            src[0].level == src[1].level && !bkey_cmp(src[0].k->k.p, src[1].k->k.p))
                src++;

        *dst++ = *src++;
    }

    keys.nr = dst - keys.d;

err:
    return keys;
}

static void
replay_now_at(struct journal *j, u64 seq)
{
    BUG_ON(seq < j->replay_journal_seq);
    BUG_ON(seq > j->replay_journal_seq_end);

    while (j->replay_journal_seq < seq)
        orca_journal_pin_put(j, j->replay_journal_seq++);
}

static int
orca_extent_replay_key(struct orca_fs *c, enum btree_id btree_id, struct bkey_i *k)
{
    struct btree_trans trans;
    struct btree_iter *iter, *split_iter;

    /**
     * We might cause compressed extents to be split, so we need to pass in
     * a disk_reservation.
    **/
    struct disk_reservation disk_res = orca_disk_reservation_init(c, 0);
    struct bkey_i *split;
    struct bpos atomic_end;

    /**
     * Some extents aren't equivalent - w.r.t. what the triggers do
     * if they're split.
    **/
    bool remark_if_split = orca_bkey_sectors_compressed(bkey_i_to_s_c(k)) ||
        k->k.type == KEY_TYPE_reflink_p;
    bool remark = false;
    int ret;

    orca_trans_init(&trans, c, BTREE_ITER_MAX, 0);

retry:
    orca_trans_begin(&trans);
    iter = orca_trans_get_iter(&trans, btree_id, bkey_start_pos(&k->k),
        BTREE_ITER_INTENT);

    do {
        ret = orca_btree_iter_traverse(iter);

        if (ret)
            goto err;

        atomic_end = bpos_min(k->k.p, iter->l[0].b->key.k.p);
        split = orca_trans_kmalloc(&trans, bkey_bytes(&k->k));
        ret = PTR_ERR_OR_ZERO(split);

        if (ret)
            goto err;

        if (!remark && remark_if_split && bkey_cmp(atomic_end, k->k.p) < 0) {
            ret = orca_disk_reservation_add(c, &disk_res, k->k.size *
                orca_bkey_nr_ptrs_allocated(bkey_i_to_s_c(k)),
                ORCA_DISK_RESERVATION_NOFAIL);

            BUG_ON(ret);
            remark = true;
        }

        bkey_copy(split, k);
        orca_cut_front(iter->pos, split);
        orca_cut_back(atomic_end, split);

        split_iter = orca_trans_copy_iter(&trans, iter);
        ret = PTR_ERR_OR_ZERO(split_iter);

        if (ret)
            goto err;

        /**
         * It's important that we don't go through the extent_handle_overwrites()
         * and extent_update_to_keys() path here. Journal replay is supposed to
         * treat extents like regular keys.
        **/
        __orca_btree_iter_set_pos(split_iter, split->k.p, false);
        orca_trans_update(&trans, split_iter, split, BTREE_TRIGGER_NORUN);
        orca_btree_iter_set_pos(iter, split->k.p);

        if (remark) {
            ret = orca_trans_mark_key(&trans, bkey_i_to_s_c(split), 0,
                split->k.size, BTREE_TRIGGER_INSERT);

            if (ret)
                goto err;
        }
    } while (bkey_cmp(iter->pos, k->k.p) < 0);

    if (remark) {
        ret = orca_trans_mark_key(&trans, bkey_i_to_s_c(k), 0, -((s64)k->k.size),
            BTREE_TRIGGER_OVERWRITE);

        if (ret)
            goto err;
    }

    ret = orca_trans_commit(&trans, &disk_res, NULL, BTREE_INSERT_NOFAIL |
        BTREE_INSERT_LAZY_RW | BTREE_INSERT_JOURNAL_REPLAY);

err:
    if (ret == -EINTR)
        goto retry;

    orca_disk_reservation_put(c, &disk_res);

    return orca_trans_exit(&trans) ?: ret;
}

static int
__orca_journal_replay_key(struct btree_trans *trans, enum btree_id id, unsigned level,
    struct bkey_i *k)
{
    struct btree_iter *iter;
    int ret;

    iter = orca_trans_get_node_iter(trans, id, k->k.p, BTREE_MAX_DEPTH, level,
        BTREE_ITER_INTENT);

    if (IS_ERR(iter))
        return PTR_ERR(iter);

    /**
     * iter->flags & BTREE_ITER_IS_EXTENTS triggers the update path to run
     * extent_handle_overwrites() and extent_update_to_keys() - but, we don't
     * want that here, journal replay is supposed to treat extents like
     * regular keys
    **/
    __orca_btree_iter_set_pos(iter, k->k.p, false);
    ret = orca_btree_iter_traverse(iter) ?: orca_trans_update(trans, iter, k,
        BTREE_TRIGGER_NORUN);
    orca_trans_iter_put(trans, iter);

    return ret;
}

static int
orca_journal_replay_key(struct orca_fs *c, enum btree_id id, unsigned level,
    struct bkey_i *k)
{
    return orca_trans_do(c, NULL, NULL, BTREE_INSERT_NOFAIL |
        BTREE_INSERT_LAZY_RW | BTREE_INSERT_JOURNAL_REPLAY,
        __orca_journal_replay_key(&trans, id, level, k));
}

static int
__orca_alloc_replay_key(struct btree_trans *trans, struct bkey_i *k)
{
    struct btree_iter *iter;
    int ret;

    iter = orca_trans_get_iter(trans, BTREE_ID_ALLOC, k->k.p,
        BTREE_ITER_CACHED | BTREE_ITER_CACHED_NOFILL | BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(iter) ?:
        orca_trans_update(trans, iter, k, BTREE_TRIGGER_NORUN);

    orca_trans_iter_put(trans, iter);

    return ret;
}

static int
orca_alloc_replay_key(struct orca_fs *c, struct bkey_i *k)
{
    return orca_trans_do(c, NULL, NULL, BTREE_INSERT_NOFAIL |
        BTREE_INSERT_USE_RESERVE | BTREE_INSERT_LAZY_RW |
        BTREE_INSERT_JOURNAL_REPLAY, __orca_alloc_replay_key(&trans, k));
}

static int
journal_sort_seq_cmp(const void *_l, const void *_r)
{
    const struct journal_key *l = _l;
    const struct journal_key *r = _r;

    return cmp_int(r->level, l->level) ?:
        cmp_int(l->journal_seq, r->journal_seq) ?:
        cmp_int(l->btree_id, r->btree_id) ?:
        bkey_cmp(l->k->k.p, r->k->k.p);
}

static int
orca_journal_replay(struct orca_fs *c, struct journal_keys keys)
{
    struct journal *j = &c->journal;
    struct journal_key *i;
    u64 seq;
    int ret;

    sort(keys.d, keys.nr, sizeof(keys.d[0]), journal_sort_seq_cmp, NULL);

    if (keys.nr)
        replay_now_at(j, keys.journal_seq_base);

    seq = j->replay_journal_seq;

    /**
     * First replay updates to the alloc btree--these will only update the
     * btree key cache.
    **/
    for_each_journal_key(keys, i) {
        cond_resched();

        if (!i->level && i->btree_id == BTREE_ID_ALLOC) {
            j->replay_journal_seq = keys.journal_seq_base + l->journal_seq;
            ret = orca_alloc_replay_key(c, i->k);

            if (ret)
                goto err;
        }
    }

    /**
     * Next replay updates to interior btree nodes.
    **/
    for_each_journal_key(keys, i) {
        cond_resched();

        if (i->level) {
            j->replay_journal_seq = keys.journal_seq_base + i->journal_seq;
            ret = orca_journal_replay_key(c, i->btree_id, i->level, i->k);

            if (ret)
                goto err;
        }
    }

    /**
     * Now that the btree is in a consistent state, we can start journal
     * reclaim (which will be flushing entries from the btree key cache
     * back to the btree).
    **/
    set_bit(ORCA_FS_BTREE_INTERIOR_REPLAY_DONE, &c->flags);
    set_bit(JOURNAL_RECLAIM_STARTED, &j->flags);

    j->replay_journal_seq = seq;

    /* Now replay leaf node updates */
    for_each_journal_key(keys, i) {
        cond_resched();

        if (i->level || i->btree_id == BTREE_ID_ALLOC)
            continue;

        replay_now_at(j, keys.journal_seq_base + i->journal_seq);
        ret = i->k->k.size ? orca_extent_replay_key(c, i->btree_id, i->k) :
            orca_journal_replay_key(c, i->btree_id, i->level, i->k);

        if (ret)
            goto err;
    }

    replay_now_at(j, j->replay_journal_seq_end);
    j->replay_journal_seq = 0;

    orca_journal_set_replay_done(j);
    orca_journal_flush_all_pins(j);

    return orca_journal_error(j);

err:
    orca_err(c, "journal replay: error %d while replaying key", ret);

    return ret;
}

static bool
journal_empty(struct list_head *journal)
{
    return list_empty(journal) || journal_entry_empty(&list_last_entry(journal,
        struct journal_replay, list)->j);
}

static int
verify_journal_entries_not_blacklisted_or_missing(struct orca_fs *c,
    struct list_head *journal)
{
    struct journal_replay *i = list_last_entry(journal, struct journal_replay, list);
    u64 start_seq = le64_to_cpu(i->j.last_seq);
    u64 end_seq = le64_to_cpu(i->j.seq);
    u64 seq = start_seq;
    int ret = 0;

    list_for_each_entry(i, journal, list) {
        if (le64_to_cpu(i->j.seq) < start_seq)
            continue;

        fsck_err_on(seq != le64_to_cpu(i->j.seq), c,
            "journal entries %llu-%llu missing! (replaying %llu-%llu)",
            seq, le64_to_cpu(i->j.seq) - 1, start_seq, end_seq);

        seq = le64_to_cpu(i->j.seq);

        fsck_err_on(orca_journal_seq_is_blacklisted(c, seq, false), c,
            "found blacklisted journal entry %llu", seq);

        do {
            seq++;
        } while (orca_journal_seq_is_blacklisted(c, seq, false));
    }

fsck_err:
    return ret;
}

/* Journal replay early */
static int
journal_replay_entry_early(struct orca_fs *c, struct jset_entry *entry)
{
    int ret = 0;

    switch (entry->type) {
    case ORCA_JSET_ENTRY_btree_root:
        {
            struct btree_root *r;

            if (entry->btree_id >= BTREE_ID_NR) {
                orca_err(c, "filesystem has unknown btree type %u",
                    entry->btree_id);

                return -EINVAL;
            }

            r = &c->btree_roots[entry->btree_id];

            if (entry->u64s) {
                r->level = entry->level;
                bkey_copy(&r->key, &entry->start[0]);
                r->error = 0;
            } else {
                r->alive = true;
                break;
            }
        }

    case ORCA_JSET_ENTRY_usage:
        struct jset_entry_usage *u = container_of(entry, struct jset_entry_usage, entry);

        switch (entry->btree_id) {
        case FS_USAGE_RESERVED:
            if (entry->level < ORCA_REPLICAS_MAX)
                c->usage_base->persistent_reserved[entry->level] = le64_to_cpu(u->v);
            break;

        case FS_USAGE_INODES:
            c->usage_base->nr_inodes = le64_to_cpu(u->v);
            break;

        case FS_USAGE_KEY_VERSION:
            atomic64_set(&c->key_version, le64_to_cpu(u->v));
            break;
        }

        break;

        case ORCA_JSET_ENTRY_usage:
        {
            struct jset_entry_data_usage *u = container_of(entry,
                struct jset_entry_usage, entry);

            switch (entry->btree_id) {
            case FS_USAGE_RESERVED:
                if (entry->level < ORCA_REPLICAS_MAX)
                    c->usage_base->persistent_reserved[entry->level] =
                        le64_to_cpu(u->v);

                break;

            case FS_USAGE_INODES:
                c->usage_base->nr_inodes = le64_to_cpu(u->v);
                break;

            case FS_USAGE_KEY_VERSION:
                atomic64_set(&c->key_version, le64_to_cpu(u->v));
                break;
            }

            break;
        }

        case ORCA_JSET_ENTRY_data_usage:
        {
            struct jset_entry_data_usage *u = container_of(entry,
                struct jset_entry_data_usage, entry);
            ret = orca_replicas_set_usage(c, &u->r, le64_to_cpu(u->v));
            break;
        }

        case ORCA_JSET_ENTRY_blacklist:
        {
            struct jset_entry_blacklist *bl_entry = container_of(entry,
                struct jset_entry_blacklist, entry);
            ret = orca_journal_seq_blacklist_add(c, le64_to_cpu(bl_entry->seq),
                le64_to_cpu(bl_entry->seq) + 1);
            break;
        }

        case ORCA_JSET_ENTRY_blacklist_v2:
        {
            struct jset_entry_blacklist_v2 *bl_entry = container_of(entry,
                struct jset_entry_blacklist_v2, entry);
            ret = orca_journal_seq_blacklist_add(c, le64_to_cpu(bl_entry->start),
                le64_to_cpu(bl_entry->end) + 1);
            break;
        }
    }

    return ret;
}

static int
journal_replay_early(struct orca_fs *c, struct orca_sb_field_clean *clean,
    struct list_head *journal)
{
    struct jset_entry *entry;
    int ret;

    if (clean) {
        c->bucket_clock[READ].hand = le16_to_cpu(clean->read_clock);
        c->bucket_clock[WRITE].hand = le16_to_cpu(clean->write_clock);

        for (entry = clean->start; entry != vstruct_end(&clean->field);
            entry = vstruct_next(entry)) {
                ret = journal_replay_entry_early(c, entry);

                if (ret)
                    return ret;
        }
    } else {
        struct journal_replay *i = list_last_entry(journal,
            struct journal_replay, list);

        c->bucket_clock[READ].hand = le16_to_cpu(i->j.read_clock);
        c->bucket_clock[WRITE].hand = le16_to_cpu(i->j.write_clock);

        list_for_each_entry(i, journal, list) {
            vstruct_for_each(&i->j, entry) {
                ret = journal_replay_entry_early(c, entry);

                if (ret)
                    return ret;
            }
        }
    }

    orca_fs_usage_initialize(c);

    return 0;
}

/**
 * Super block clean section.
**/
static struct bkey_i *
btree_root_find(struct orca_fs *c, struct orca_sb_field_clean *clean, struct jset *j,
    enum btree_id id, unsigned *level)
{
    struct bkey_i *k;
    struct jset_entry *entry, *start, *end;

    if (clean) {
        start = clean->start;
        end = vstruct_end(&clean->field);
    } else {
        start = j->start;
        end = vstruct_last(j);
    }

    for (entry = start; entry < end; entry = vstruct_next(entry)) {
        if (entry->type == ORCA_JSET_ENTRY_btree_root && entry->btree_d == id))
            goto found;
    }

    return NULL;

found:

    if (!entry->u64s)
        return ERR_PTR(-EINVAL);

    k = entry->start;
    *level = entry->level;

    return k;
}

static int
verify_superblock_clean(struct orca_fs *c, struct orca_sb_field_clean **cleanp,
    struct jset *j)
{
    unsigned i;
    struct orca_sb_field_clean *clean = *cleanp;
    int ret = 0;

    if (!c->sb.clean || !j)
        return 0;

    if (mustfix_fsck_err_on(j->seq != clean->journal_seq, c, "
        superblock journal seq (%llu) doesn't match journal (%llu) after"
        " clean shutdown", le64_to_cpu(clean->journal_seq), le64_to_cpu(j->seq))) {
            kfree(clean);
            *cleanp = NULL;
            return 0;
    }

    mustfix_fsck_err_on(j->read_clock != clean->read_clock, c,
        "superblock read clock doesn't match journal after clean shutdown");

    mustfix_fsck_err_on(j->write_clock != clean->write_clock, c,
        "superblock read clock doesn't match journal after clean shutdown");

    for (i = 0; i < BTREE_ID_NR; i++) {
        char bufi[200], buf2[200];
        struct bkey_i *k1, *k2;
        unsigned li = 0, l2 = 0;

        k1 = btree_root_find(c, clean, NULL, i, &l1);
        k2 = btree_root_find(c, NULL, j, i, &l2);

        if (!k1 && !k2)
            continue;

        mustfix_fsck_err_on(!k1 || !k2 ||
    		IS_ERR(k1) ||
    		IS_ERR(k2) ||
    		k1->k.u64s != k2->k.u64s ||
    		memcmp(k1, k2, bkey_bytes(k1)) ||
    		l1 != l2, c,
    	    "superblock btree root %u doesn't match journal after clean shutdown\n"
    	    "sb:      l=%u %s\n"
    		"journal: l=%u %s\n", i,
    		l1, (bch2_bkey_val_to_text(&PBUF(buf1), c, bkey_i_to_s_c(k1)), buf1),
    		l2, (bch2_bkey_val_to_text(&PBUF(buf2), c, bkey_i_to_s_c(k2)), buf2));
    }

fsck_err:
    return ret;
}

static struct orca_sb_field_clean *
read_superblock_clean(struct orca_fs *c)
{
    struct orca_sb_field_clean *clean, *sb_clean;
    int ret;

    mutex_lock(&c->sb_lock);
    sb_clean = orca_sb_get_clean(c->disk_sb.sb);

    if (fsck_err_on(!sb_clean, c, "superblock marked clean, but clean section "
        "not present")) {
            SET_ORCA_SB_CLEAN(c->disk_sb.sb, false);
            c->sb.clean = false;
            mutex_unlock(&c->sb_lock);

            return NULL;
    }

    clean = kmemdup(sb_clean, vstruct_bytes(&sb_clean->field), GFP_KERNEL);

    if (!clean) {
        mutex_unlock(&c->sb_lock);
        return ERR_PTR(-ENOMEM);
    }

    if (le16_to_cpu(c->disk_sb.sb->version) < orcafs_metadata_version_bkey_renumber)
        orca_sb_clean_renumber(clean, READ);

    mutex_unlock(&c->sb_lock);

    return clean;

fsck_err:
    mutex_unlock(&c->sb_lock);
    return ERR_PTR(ret);
}

static int
read_btree_roots(struct orca_fs *c)
{
    unsigned i;
    int ret = 0;

    for (i = 0; i < BTREE_ID_NR; i++) {
        struct btree_root *r = &c->btree_roots[i];

        if (!r->alive)
            continue;

        if (i == BTREE_ID_ALLOC && c->opts.reconstruct_alloc) {
            c->sb.compat &= ~(1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO);
            continue;
        }

        if (r->error) {
            __fsck_err(c, i == BTREE_ID_ALLOC ? FSCK_CAN_IGNORE : 0,
                "invalid btree root %s", orca_btree_ids[i]);

            if (i == BTREE_ID_ALLOC)
                c->sb.compat &= ~(1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO);
        }

        ret = orca_btree_root_read(c, i, &r->key, r->level);

        if (ret) {
            __fsck_err(c, i == BTREE_ID_ALLOC ? FSCK_CAN_IGNORE : 0,
                "error reading btree root %s", orca_btree_ids[i]);

            if (i == BTREE_ID_ALLOC)
                c->sb.compat &= ~(1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO);
        }
    }

    for (i = 0; i < BTREE_ID_NR; i++) {
        if (!c->btree_roots[i].b)
            orca_btree_root_alloc(c, i);
    }

fsck_err:
    return ret;
}

int
orca_fs_recovery(struct orca_fs *c)
{
    const char *err = "cannot allocate memory";
    struct orca_sb_field_clean *clean = NULL;
    u64 journal_seq;
    bool write = false, write_sb = false;
    int ret;

    if (c->sb.clean)
        clean = read_superblock_clean(c);

    ret = PTR_ERR_OR_ZERO(clean);

    if (ret)
        goto err;

    if (c->sb.clean)
        orca_info(c, "recovering from clean shutdown, journal seq %llu",
            le64_to_cpu(clean->journal_seq));

    if (!c->replicas.entries || c->opts.rebuild_replicas) {
        orca_info(c, "building replicas info");
        set_bit(ORCA_FS_REBUILD_REPLICAS, &c->flags);
    }

    if (!c->sb.clean || c->opts.fsck || c->opts.keep_journal) {
        struct jset *j;

        ret = orca_journal_read(c &c->journal_entries);

        if (ret)
            goto err;

        if (mustfix_fsck_err_on(c->sb.clean && !journal_empty(&c->journal_entries),
            c, "filesystem marked clean, but journal not empty")) {
                c->sb.compat &= ~(1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO);
                SET_ORCA_SB_CLEAN(c->disk_sb.sb, false);
                c->sb.clean = false;
        }

        if (!c->sb.clean && list_empty(&c->journal_entries)) {
            orca_err(c, "no journal entries found");
            ret = ORCA_FSCK_REPAIR_IMPOSSIBLE;
            goto err;
        }

        c->journal_keys = journal_keys_sort(&c->journal_entries);

        if (!c->journal_keys.d) {
            ret = -ENOMEM;
            goto err;
        }

        j = &list_last_entry(&c->journal_entries, struct journal replay, list)->j;
        ret = verify_superblock_clean(c, &clean, j);

        if (ret)
            goto err;

        journal_seq = le64_to_cpu(j->seq) + 1;
    } else {
        journal_seq = le64_to_cpu(clean->journal_seq) + 1;
    }

    if (!c->sb.clean && !(c->sb.features & (1ULL << ORCA_FEATURE_extents_above_btree_updates))) {
        orca_err(c, "filesystem needs recovery from older versions; run fsck "
            "from older orcafs-tools to fix");
        ret = -EINVAL;
        goto err;
    }

    ret = journal_replay_early(c, clean, &c->journal_entries);

    if (ret)
        goto err;

    if (!c->sb.clean) {
        ret = orca_journal_seq_blacklist_add(c, journal_seq, journal_seq + 4);

        if (ret) {
            orca_err(c, "error creating new journal seq blacklist entry");
            goto err;
        }

        journal_seq += 4;

        /**
         * The superblock needs to be written before we do any btree
         * node writes--it will be in the read_write() path.
        **/
    }

    ret = orca_blacklist_table_initialize(c);

    if (!list_empty(&c->journal_entries)) {
        ret = verify_journal_entries_not_blacklisted_or_missing(c, &c->journal_entries);

        if (ret)
            goto err;
    }

    ret = orca_fs_journal_start(&c->journal, journal_seq, &c->journal_entries);

    if (ret)
        goto err;

    ret = read_btree_roots(c);

    if (ret)
        goto err;

    orca_verbose(c, "starting alloc read");
    err = "error reading allocation information";
    ret = orca_alloc_read(c, &c->journal_keys);

    if (ret)
        goto err;

    orca_verbose(c, "alloc read done");
    orca_verbose(c, "starting stripes_read");
    err = "error reading stripes";
    ret = orca_stripes_read(c, &c->journal_keys);

    if (ret)
        goto err;

    orca_verbose(c, "stripes_read done");
    set_bit(ORCA_FS_ALLOC_READ_DONE, &c->flags);

    if ((c->sb.compat & (1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO) &&
        !(c->sb.compat) & (1ULL << ORCA_COMPAT_FEAT_ALLOC_METADATA))) {
            /**
             * Interior btree node updates aren't consistent with the
             * journal. After an unclean shutdown, we have to walk all
             * pointers to metadata.
            **/
            orca_info(c, "starting metadata mark and sweep");
            err = "error in mark and sweep";
            ret = orca_gc(c, &c->journal_keys, true, true);

            if (ret)
                goto err;

            orca_verbose(c, "mark and sweep done");
    }

    if (c->opts.fsck || !(c->sb.compat & (1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO)) ||
        test_bit(ORCA_FS_REBUILD_REPLICAS, &c->flags)) {
            orca_info(c, "starting mark and sweep");
            err = "error in mark and sweep";
            ret = orca_gc(c, &c->journal_keys, true, false);

            if (ret)
                goto err;

            orca_verbose(c, "mark and sweep done");
    }

    clear_bit(ORCA_FS_REBUILD_REPLICAS, &c->flags);
    set_bit(ORCA_FS_INITIAL_GC_DONE, &c->flags);

    /**
     * Skip past versions that might have possibly been used (as nonces),
     * but hadn't had their pointers written.
    **/
    if (c->sb.encryption_type && !c->sb.clean)
        atomic64_add(1 << 16, &c->key_version);

    if (c->opts.recovery)
        goto out;

    orca_verbose(c, "starting journal replay");
    err = "journal replay failed";
    ret = orca_journal_replay(c, c->journal_keys);

    if (ret)
        goto err;

    orca_verbose(c, "journal replay done");

    if (!c->opts.nochanges) {
        /**
         * NOTE: Even when filesystem was clean, there might be work
         * to do here, if we ran gc (because of fsck), which
         * recalculated oldest_gen.
        **/
        orca_verbose(c, "writing allocation info");
        err = "error writing out alloc info";
        ret = orca_stripes_write(c, BTREE_INSERT_LAZY_RW, &wrote) ?:
            orca_alloc_write(c, BTREE_INSERT_LAZY_RW, &wrote);

        if (ret) {
            orca_err(c, "error writing alloc info");
            goto err;
        }

        orca_verbose(c, "alloc write done");
        set_bit(ORCA_FS_ALLOC_WRITTEN, &c->flags);
    }

    if (!c->sb.clean) {
        if (!(c->sb.features & (1 << ORCA_FEATURE_atomic_nlink))) {
            orca_info(c, "checking inode link counts");
            err = "error in recovery";
            ret = orca_fsck_inode_nlink(c);

            if (ret)
                goto err;

            orca_verbose(c, "check inodes done");
        } else {
            orca_verbose(c, "checking for deleted inodes");
            err = "error in recovery";
            ret = orca_fsck_walk_inodes_only(c);

            if (ret)
                goto err;

            orca_verbose(c, "checking inodes done");
        }
    }

    if (c->opts.fsck) {
        orca_info(c, "starting fsck");
        err = "error in fsck";
        ret = orca_fsck_full(c);

        if (ret)
            goto err;

        orca_verbose(c, "fsck done");
    }

    if (enabled_qtype(c)) {
        orca_verbose(c, "reading quotas");
        ret = orca_fs_quota_read(c);

        if (ret)
            goto err;

        orca_verbose(c, "quotas done");
    }

    mutex_lock(&c->sb_lock);

    if (c->opts.version_upgrade) {
        if (c->sb.version < orcafs_metadata_version_new_versioning)
            c->disk_sb.sb->version_min = le16_to_cpu(orcafs_metadata_version_min);

        c->disk_sb.sb->version = le16_to_cpu(orcafs_metadata_version_current);
        c->disk_sb.sb->features[0] |= ORCA_SB_FEATURES_ALL;
        write_sb = true;
    }

    if (!test_bit(ORCA_FS_ERROR, &c->flags)) {
        c->disk_sb.sb->compat[0] |= ORCA_COMPAT_FEAT_ALLOC_INFO;
        write_sb = true;
    }

    if (c->opts.fsck && !test_bit(ORCA_FS_ERROR, &c->flags)) {
        c->disk_sb.sb->features[0] |= 1ULL << ORCA_FEATURE_atomic_nlink;
        SET_ORCA_SB_HAS_ERRORS(c->disk_sb.sb, 0);
        write_sb = true;
    }

    if (write_sb)
        orca_write_super(c);

    mutex_unlock(&c->sb_lock);

    if (c->journal_seq_blacklist_table && c->journal_seq_blacklist_table->nr > 128)
        queue_work(system_log_wq, &c->journal_seq_blacklist_gc_work);

out:
    ret = 0;

err:
fsck_err:
    set_bit(ORCA_FS_FSCK_DONE, &c->flags);
    orca_flush_fsck_errs(c);

    if (!c->opts.keep_journal) {
        orca_journal_keys_free(&c->journal_keys);
        orca_journal_entries_free(&c->journal_entries);
    }

    kfree(clean);

    if (ret)
        orca_err(c, "error in recovery: %s (%i)", err, ret);
    else
        orca_verbose(c, "ret %i", ret);
}

int
orca_fs_initialize(struct orca_fs *c)
{
    struct orca_inode_unpacked root_inode, lostfound_inode;
    struct bkey_inode_buf packed_inode;
    struct qstr lostfound = QSTR("lost+found");
    const char *err = "cannot allocate memory";
    struct orca_dev *ca;
    LIST_HEAD(journal);
    unsigned i;
    int ret;

    orca_notice(c, "initializing new filesystem");
    mutex_lock(&c->sb_lock);

    for_each_online_member(ca, c, i)
        orca_mark_dev_superblock(c, ca, 0);

    mutex_unlock(&c->sb_lock);

    mutex_lock(&c->sb_lock);
    c->disk_sb.sb->version = c->disk_sb.sb->version_min =
        le16_to_cpu(orcafs_metadata_version_current);
    c->disk_sb.sb->features[0] |= 1ULL << ORCA_FEATURE_atomic_nlink;
    c->disk_sb.sb->features[0] |= ORCA_SB_FEATURES_ALL;

    orca_write_super(c);
    mutex_unlock(&c->sb_lock);

    set_bit(ORCA_FS_ALLOC_READ_DONE, &c->flags);
    set_bit(JOURNAL_RECLAIM_STARTED, &c->journal.flags);

    err = "unable to allocate journal buckets";

    for_each_online_member(ca, c, i) {
        ret = orca_dev_journal_alloc(ca);

        if (ret) {
            percpu_ref_put(&ca->io_ref);
            goto err;
        }
    }

    /**
     * journal_res_get() will crash if called before this has set
     * up the journal.pin FIFO and journal.cur pointer.
    **/
    orca_fs_journal_start(&c->journal, 1, &journal);
    orca_journal_set_replay_done(&c->journal);

    orca_inode_init(c, &root_inode, 0, 0, S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,
        0, NULL);
    root_inode.bi_inum = ORCAFS_ROOT_INO;
    orca_inode_pack(&packed_inode, &root_inode);

    err = "error creating root directory";
    ret = orca_btree_insert(c, BTREE_ID_INODES, &packed_inode.inode.k_i, NULL,
        NULL, BTREE_INSERT_LAZY_RW);

    if (ret)
        goto err;

    orca_inode_init_early(c, &lostfound_inode);
    err = "error creating lost+found";
    ret = orca_trans_do(c, NULL, NULL, 0, orca_create_trans(&trans, ORCAFS_ROOT_INO,
        &root_inode, &lostfound_inode, &lostfound, 0, 0, S_IFDIR | 0700, 0, NULL, NULL));

    if (ret)
        goto err;

    if (enabled_qtypes(c)) {
        ret = orca_fs_quota_read(c);

        if (ret)
            goto err;
    }

    err = "error writing first journal entry";
    ret = orca_journal_meta(&c->journal);

    if (ret)
        goto err;

    mutex_lock(&c->sb_lock);
    SET_ORCA_SB_INITIALIZED(c->disk_sb.sb, true);
    SET_ORCA_SB_CLEAN(c->disk_sb.sb, false);

    orca_write_super(c);
    mutex_unlock(&c->sb_lock);

    return 0;

err:
    pr_err("error initializing new filesystem: %s (%i)", err, ret);

    return ret;
}
