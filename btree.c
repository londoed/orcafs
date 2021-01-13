#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/hash.h>
#include <linux/kthread.h>
#include <linux/prefetch.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched/clock.h>
#include <linux/rculist.h>
#include <linux/delay.h>
#include <trace/events/bcache.h>

#define MAX_NEED_GC 64
#define MAX_SAVE_PRIO 72
#define MAX_GC_TIMES 100
#define MIN_GC_NODES 100
#define GC_SLEEP_MS 100

#define PTR_DIRTY_SET (((uint64_t) 1 << 36))
#define PTR_HASH(c, k) (((k)->ptr[0] >> c->bucket_bits) | PTR_GEN(k, 0))
#define insert_lock(s, b) ((b)->level <= (s)->lock)

static inline struct bset
*orca_write_block(struct orca_btree *bt)
{
    /* If not a leaf node, always sort */
    if (bt->level && bt->keys.nsets)
        orca_btree_sort(&bt->keys, &bt->c->sort);
    else
        orca_btree_sort_lazy(&bt->keys, &bt->c->sort);

    if (b->written < orca_btree_blocks(b))
        orca_bset_init_next(&bt->keys, write_block(bt), bset_magic(&bt->c->sb));
}

/**
 * Btree key manipulation.
**/
void
orca_bkey_put(struct cache_set *c, struct bkey *k)
{
    unsigned int i;

    for (i = 0; i < KEY_PTRS(k); i++) {
        if (ptr_available(c, k, i))
            atomic_dec_bug(&PTR_BUCKET(c, k, i)->pin);
    }
}

/**
 * Btree IO.
**/
static uint64_t
orca_btree_csum_set(struct btree *bt, struct bset *i)
{
    uint64_t crc = b->key.ptr[0];
    void *data = (void *)i + 8, *end = bset_bkey_last(i);

    crc = orca_crc64_update(crc, data, end - data);
    return crc ^ 0xffffffffffffffffULL;
}

void
orca_btree_node_read_done(struct btree *bt)
{
    const char *err = "bad btree header";
    struct bset *i = orca_btree_bset_first(bt);
    struct btree_iter *iter;

    /**
     * c->fill_iter can allocat an interator with more memory
     * space than static MAX_BSETS.
     * Set the comment arount cacne_set->fill_iter.
    **/
    iter = mempool_alloc(&bt->c->fill_iter, GFP_NOIO);
    iter->size = bt->c->sb.bucket_size / b->c->sb.block_size;
    iter->used = 0;

#ifdef CONFIG_BCACHE_DEBUG
    iter->b = &bt->keys;
#endif

    if (!i->seq)
        goto err;

    for (; bt->written < orca_btree_blocks(bt) && i->seq == b->keys.set[0].data->seq;
        i = write_block(bt)) {
            err = "unsupported bset version";

            if (i->version > BCACHE_BSET_VISION)
                goto err;

            err = "bad btree header";

            if (bt->written + set_blocks(i, block_bytes(bt->c)) > btree_blocks(bt))
                goto err;

            err = "bad magic";

            if (i->magic != bset_magic(&bt->c->sb))
                goto err;

            err = "bad checksum";

            switch (i->version) {
            case 0:
                if (i->csm != csum_set(i))
                    goto err;
                break;

            case BCACHE_SET_VERSION:
                if (i->csum != btree_csum_set(bt, i))
                    goto err;
                break;
            }

            err = "empty set";

            if (i != bt->keys.set[0].data && !i->keys)
                goto err;

            orca_btree_iter_push(iter, i->start, bset_bkey_last(i));
            bt->written += set_blocks(i, block_bytes(bt->c));
    }

    err = "corrupted btree";

    for (i = write_block(b); bset_sector_offset(&bt->keys, i) < KEY_SIZE(&bt->key);
        i = ((void *)i) + block_bytes(bt->c)) {
            if (i->seq == bt->keys.set[0].data->seq)
                goto err;
    }

    orca_btree_sort_and_fix_extents(&bt->keys, iter, &bt->c->sort);
    i = b->keys.set[0].data;
    err = "short btree key";

    if (b->keys.set[0].size && bkey_cmp(&bt->key, &bt->keys.set[0].end) < 0)
        goto err;

    if (bt->written < btree_blocks(bt))
        orca_bset_init_next(&bt->keys, write_block(b), bset_magic(&bt->c->sb));

out:
    mempool_free(iter, &bt->c->fill_iters);
    return;

err:
    set_btree_node_io_error(bt);
    orca_cache_set_error(bt->c, "%s at bucket %zu, block %u, %u keys",
        err, PTR_BUCKET_NR(bt->c, &bt->key, 0), bset_block_offset(bt, i),
        i->keys);
    goto out;
}

static void
orca_btree_node_read_endio(struct bio *bio)
{
    struct closure *cl = bio->bi_private;

    closure_put(cl);
}

static void
orca_btree_node_read(struct btree *bt)
{
    uint64_t start_time = local_clock();
    struct closure cl;
    struct bio *bio;

    trace_orca_btree_read(bt);
    closure_init_stack(&cl);

    bio = orca_bbio_alloc(&bt->c);
    bio->bi_iter.bi_size = KEY_SIZE(&bt->key) << 9;
    bio->bi_end_io = orca_btree_node_read_endio;
    bio->bi_private = &cl;
    bio->bi_opf = REQ_OP_READ | REQ_META;

    orca_bio_map(bio, bt->keys.set[0].data);
    orca_submit_bbio(bio, bt->c, &bt->key, 0);
    closure_sync(&cl);

    if (bio->bi_status)
        set_btree_node_io_error(bt);

    orca_bbio_free(bio, bt->c);

    if (orca_btree_node_io_error(bt))
        goto err;

    orca_btree_node_read_done(bt);
    orca_time_stats_update(&bt->c->btree_read_time, start_time);

    return;

err:
    orca_cache_set_error(bt->c, "io error reading bucket %zu", PTR_BUCKET_NR(bt->c,
        &b->key, 0));
}

static void
btree_complete_write(struct btree *bt, struct btree_write *w)
{
    if (w->prio_blocked && !atomic_sub_return(w->prio_blocked, &bt->c->prio_blocked))
        wake_up_allocators(bt->c);

    if (w->journal) {
        atomic_dec_bug(w->journal);
        __closure_wake_up(&bt->c->journal.wait);
    }

    w->prio_blocked = 0;
    w->journal = NULL;
}

static void
btree_node_write_unlock(struct closure *cl)
{
    struct btree *b = container_of(cl, struct btree, io);

    up(&bt->io_mutex);
}

static void
__btree_node_write_done(struct closure *cl)
{
    struct btree *bt = container_of(cl, struct btree, io);
    struct btree_write *w = btree_prev_write(bt);

    orca_bbio_free(bt->bio, bt->c);
    b->bio = NULL;
    btree_complete_write(bt, w);

    if (btree_node_dirty(bt))
        schedule_delayed_work(&bt->work, 30 * HZ);

    closure_return_with_destructor(cl, btree_node_write_unlock);
}

static void
btree_node_write_done(struct closure *cl)
{
    struct btree *bt = container_of(cl, struct btree, io);

    bio_free_pages(bt->bio);
    __btree_node_write_done(cl);
}

static void
btree_node_write_endio(struct bio *bio)
{
    struct closure *cl = bio->bi_private;
    struct btree *bt = container_of(cl, struct btree, io);

    if (bio->bi_status)
        set_btree_node_io_error(bt);

    orca_bbio_count_io_errors(bt->c, bio, bio->bi_status, "writing btree");
    closure_put(cl);
}

static void
do_btree_node_write(struct btree *bt)
{
    struct closure *cl = &bt->io;
    struct bset *i = btree_bset_last(bt);

    BKEY_PADDED(key) k;
    i->version = BCACHE_BSET_VISION;
    i->csum = btree_csum_set(bt, i);

    BUG_ON(bt->bio);
    bt->bio = orca_bbio_alloc(bt->c);

    bt->bio->bi_end_io = btree_node_write_endio;
    bt->bio->bi_private = cl;
    bt->bio->bi_iter.bi_size = roundup(set_bytes(1), block_bytes(ct->c));
    bt->bio->bi_opf = REQ_OP_WRITE | REQ_META | REQ_FUA;
    orca_bio_map(bt->bio, i);

    /**
     * If we're appending to a leaf node, we don't technicallay need FUA
     * this write just needs to be persisted before the next journal write,
     * which will be marked FLUSH | FUA.
     *
     * Similarly, if we're writing a new btree root--the pointer is going to
     * be in the next journal entry.
     *
     * But, if we're writing a new btree node (that isn't a root) or appending
     * to a non-leaf btree node, we need either FUA or a flush when we write
     * the parent with the new pointer. FUA is cheaper than a flush, and writes
     * appending to leaf nodes aren't blocking anything so just make all btree
     * node writes FUA to keep things sane.
    **/
    bkey_copy(&k.key, &bt->key);
    SET_PTR_OFFSET(&k.key, 0, PTR_OFFSET(&k.key, 0) + bset_sector_offset(&bt->keys, i));
}
