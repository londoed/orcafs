#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/sched/mm.h>
#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "alloc_background.h"
#include "bkey_on_stack.h"
#include "bset.h"
#include "btree_update.h"
#include "buckets.h"
#include "checksum.h"
#include "compress.h"
#include "clock.h"
#include "debug.h"
#include "disk_groups.h"
#include "ec.h"
#include "error.h"
#include "extent_update.h"
#include "inode.h"
#include "io.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "rebalance.h"
#include "super.h"
#include "super_io.h"

const char *
orca_blk_status_to_str(blk_status_t status)
{
    if (status == BLK_STS_REMOVED)
        return "device removed";

    return blk_status_to_str(status);
}

static bool
orca_target_congested(struct orca_fs *c, u16 target)
{
    const struct orca_devs_mask *devs;
    unsigned n, nr = 0, total = 0;
    u64 now = local_clock(), last;
    s64 congested;
    struct orca_dev *ca;

    if (!target)
        return false;

    rcu_read_lock();
    devs = orca_target_to_mask(c, target) ?: &c->rw_devs[ORCA_DATA_user];

    for_each_set_bit(d, devs->d, ORCA_SB_MEMBERS_MAX) {
        ca = rcu_dereference(c->devs[d]);

        if (!ca)
            continue;

        congested = atomic_read(&ca->congested);
        last = READ_ONCE(ca->congested_last);

        if (time_after64(now, last))
            congested -= (now - last) >> 12;

        total += max(congested, 0LL);
        nr++;
    }

    rcu_read_unlock();

    return orca_rand_range(nr * CONGESTED_MAX) < total;
}

static inline void
orca_congested_acct(struct orca_dev *ca, u64 io_latency, u64 now, int rw)
{
    u64 latency_capable = ca->io_latency[rw].quantiles.entries[QUANTILE_IDX(1)].m;
    /**
     * Ideally, we'd be taking into account the device's variance here.
    **/
    u64 latency_threshold = latency_capable << (rw == READ ? 2 : 3);
    u64 latency_over = io_latency - latency_threshold;

    if (latency_threshold && latency_over > 0) {
        /**
         * Bump up congested by approximately latency_over * 4 /
         * latency_threashold--we don't need much accuracy here so
         * don't bother with the divide.
        **/
        if (atomic_read(&ca->congested) < CONGESTED_MAX)
            atomic_add(latency_over >> max_t(int, ilog2(latency_threashold) - 2, 0),
                &ca->congested);

        ca->congested_last = now;
    } else if (atomic_read(&ca->congested) > 0) {
        atomic_dec(&ca->congested);
    }
}

void
orca_latency_acct(struct orca_dev *ca, u64 submit_time, int rw)
{
    atomic64_t *latency = &ca->cur_latency[rw];
    u64 now = local_clock();
    u64 io_latency = time_after64(now, submit_time)
        ? now - submit_time
        : 0;
    u64 old, new, v = atomic64_read(latency);

    do {
        old = v;

        /**
         * If the IO latency was reasonably close to the current latency.
         * skip doing the update and atomic operation--most of the time.
        **/
        if (abs((int)(old - io_latency)) < (old >> 1) && now & ~(~0 << 5))
            break;

        new = ewma_add(old, io_latency, 5);
    } while ((v = atomic64_cmpxchg(latency, old, new)) != old);

    orca_congested_acct(ca, io_latency, now, rw);
    __orca_time_stats_update(&ca->io_latency[rw], submit_time, now);
}

void
orca_bio_free_pages_pool(struct orca_fs *c, struct bio *bio)
{
    struct bvec_iter_all iter;
    struct bio_vec *bv;

    bio_for_each_segment_all(bv, bio, iter) {
        if (bv->bv_page != ZERO_PAGE(0))
            mempool_free(bv->bv_page, &c->bio_bounce_pages);
    }

    bio->bi_vcnt = 0;
}

static struct page *
__bio_alloc_page_pool(struct orca_fs *c, bool *using_mempool)
{
    struct page *page;

    if (likely(!*using_mempool)) {
        page = alloc_page(GFP_NOIO);

        if (unlikely(!page)) {
            mutex_lock(&c->bio_bounce_pages_lock);
            *using_mempool = true;
            goto pool_alloc;
        }
    } else {
pool_alloc:
        page = mempool_alloc(&c->bio_bounce_pages, GFP_NOIO);
    }

    return page;
}

void
orca_bio_alloc_pages_pool(struct orca_fs *c, struct bio *bio, size_t size)
{
    bool using_mempool = false;

    while (size) {
        struct page *page = __bio_alloc_page_pool(c, &using_mempool);
        unsigned len = min_t(size_t, PAGE_SIZE, size);

        BUG_ON(!bio_add_page(bio, page, len, 0));
        size -= len;
    }

    if (using_mempool)
        mutex_unlock(&c->bio_bounce_pages_lock);
}

static int
sum_vector_overwrites(struct btree_trans *trans, struct btree_iter *extent_iter,
    struct bkey_i *new, bool may_allocate, bool *maybe_extending, s64 *delta)
{
    struct btree_iter *iter;
    struct bkey_s_c old;
    int ret = 0;

    *maybe_extending = true;
    *delta = 0;

    iter = orca_trans_copy_iter(trans, extent_iter);

    for_each_btree_key_continue(iter, BTREE_ITER_SLOTS, old, ret) {
        if (!may_allocate && orca_bkey_nr_ptrs_fully_allocated(old) <
            orca_bkey_nr_ptrs_allocated(bkey_i_to_s_c(new))) {
                ret = -ENOSPC;
                break;
        }

        *delta += (min(new->k.p.offset, old.k->p.offset) - max(bkey_start_offset(old.k))) *
            (bkey_extent_is_allocation(&new->k) - bkey_extent_is_allocation(old.k));

        if (bkey_cmp(old.k->p, new->k.p) >= 0) {
            /**
             * Check if there's already data above where we're going to be
             * writing to--this means we're going to be writing to, because
             * i_size could be up to one block less.
            **/
            if (!bkey_cmp(old.k->p, new->k.p))
                old = orca_btree_iter_next(iter);

            if (old.k && !bkey_err(old) && old.k->p.inode == extent_iter->pos.inode &&
                bkey_extent_is_data(old.k))
                    *maybe_extending = false;

            break;
        }
    }

    orca_trans_iter_put(trans, iter);

    return ret;
}

int
orca_extent_update(struct btree_trans *trans, struct btree_iter *iter,
    struct bkey_i *k, struct disk_reservation *disk_res, u64 *journal_seq,
    u64 new_i_size, s64 *i_sectors_delta)
{
    /* This must live until after orca_trans_commit() */
    struct bkey_inode_buf inode_p;
    bool extending = false;
    s64 delta = 0;
    int ret;

    ret = orca_extent_trim_atomic(k, iter);

    if (ret)
        return ret;

    ret = sum_sector_overwrites(trans, iter, k, disk_res && disk_res->sectors != 0,
        &extending, &delta);

    if (ret)
        return ret;

    new_i_size = extending
        ? min(k->k.p.offset << 9, new_i_size)
        : 0;

    if (delta || new_i_size) {
        struct btree_iter *inode_iter;
        struct orca_inode_unpacked inode_u;

        inode_iter = orca_inode_peek(trans, &inode_u, k->k.p.inode, BTREE_ITER_INTENT);

        if (IS_ERR(inode_iter))
            return PTR_ERR(inode_iter);

        /**
         * Writeback can race a bit with truncate because truncate first
         * updates the inode then truncates the pagecache. This is ugly,
         * but lets us preserve the invariant that the in memory i_size is
         * always >= the on-disk i_size.
        **/
        BUG_ON(new_i_size > inode_u.bi_size && !extending);

        if (!(inode_u.bi_flags & ORCA_INODE_I_SIZE_DIRTY) && new_i_size > inode_u.bi_size)
            inode_u.bi_size = new_i_size;
        else
            new_i_size = 0;

        inode_u.bi_sectors += delta;

        if (delta || new_i_size) {
            orca_inode_pack(trans->c, &inode_p, &inode_u);
            orca_trans_update(trans, inode_iter, &inode_p.inode.k_i, 0);
        }

        orca_trans_iter_put(trans, inode_iter);
    }

    orca_trans_update(trans, iter, k, 0);
    ret = orca_trans_commit(trans, disk_res, journal_seq, BTREE_INSERT_NOCHECK_RW |
        BTREE_INSERT_NOFAIL | BTREE_INSERT_USE_RESERVE);

    if (!ret && i_sectors_delta)
        *i_sectors_delta += delta;

    return ret;
}

int
orca_fpunch_at(struct btree_trans *trans, struct btree_iter *iter, struct bpos end,
    u64 *journal_seq, s64 *i_sectors_delta)
{
    struct orca_fs *c = trans->c;
    unsigned max_sectors = KEY_SIZE_MAX & (~0 << c->clock_bits);
    struct bkey_s_c k;
    int ret = 0, ret2 = 0;

    while ((k = orca_btree_iter_peek(iter)).k && bkey_cmp(iter->pos, end) < 0) {
        struct disk_reservation disk_res = orca_disk_reservation_init(c, 0);
        struct bkey_i delete;

        orca_trans_begin(trans);
        ret = bkey_err(k);

        if (ret)
            goto btree_err;

        bkey_init(&delete.k);
        delete.k.p = iter->pos;

        /* Create the biggest key we can */
        orca_key_resize(&delete.k, max_sectors);
        orca_cut_back(end, &delete);
        ret = orca_extent_update(trans, iter, &delete, &disk_res, journal_seq,
            0, i_sectors_delta);
        orca_disk_reservation_put(c, &disk_res);

btree_err:
        if (ret == -EINTR) {
            ret2 = ret;
            ret = 0;
        }

        if (ret)
            break;
    }

    if (bkey_cmp(iter->pos, end) > 0) {
        orca_btree_iter_set_pos(iter, end);
        ret = orca_btree_iter_traverse(iter);
    }

    return ret ?: ret2;
}

int
orca_fpunch(struct orca_fs *c, u64 inum, u64 start, u64 end, u64 journal_seq,
    s64 *i_sectors_delta)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    int ret = 0;

    orca_trans_init(&trans, c, BTREE_ITER_MAX, 1024);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS(inum, start),
        BTREE_ITER_INTENT);
    ret = orca_fpunch_at(&trans, iter, POS(inum, end), journal_seq, i_sectors_delta);
    orca_trans_exit(&trans);

    if (ret == -EINTR)
        ret = 0;

    return ret;
}

int
orca_write_index_default(struct orca_write_op *op)
{
    struct orca_fs *c = op->c;
    struct bkey_on_stack sk;
    struct keylist *keys = &op->insert_keys;
    struct bkey_i *k = orca_keylist_front(keys);
    struct btree_trans trans;
    struct btree_iter *iter;
    int ret;

    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, BTREE_ITER_MAX, 1024);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, bkey_start_pos(&k->k),
        BTREE_ITER_SLOTS | BTREE_ITER_INTENT);

    do {
        orca_trans_begin(&trans);
        k = orca_keylist_front(keys);
        bkey_on_stack_realloc(&sk, c, k->k.u64s);
        bkey_copy(sk.k, k);
        orca_cut_front(iter->pos, sk.k);
        ret = orca_extent_update(&trans, iter, sk.k, &op->res, op_journal_seq(op),
            op->new_i_size, &op->i_sectors_delta);

        if (ret == -EINTR)
            continue;

        if (ret)
            break;

        if (bkey_cmp(iter->pos, k->k.p) >= 0)
            orca_keylist_pop_front(keys);
    } while (!orca_keylist_empty(keys));

    orca_trans_exit(&trans);
    bkey_on_stack_exit(&sk, c);

    return ret;
}

void
orca_sumbit_wbio_replicas(struct orca_write_bio *wbio, struct orca_fs *c,
    enum orca_data_type type, const struct bkey_i *k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(bkey_i_to_s_c(k));
    const struct orca_extent_ptr *ptr;
    struct orca_write_bio *n;
    struct orca_dev *ca;

    BUG_ON(c->opts.nochanges);

    bkey_for_each_ptr(ptrs, ptr) {
        BUG_ON(ptr->dev >= ORCA_SB_MEMBERS_MAX || !c->devs[ptr->dev]);
        ca = orca_dev_bkey_exists(c, ptr->dev);

        if (to_entry(ptr + 1) < ptrs.end) {
            n = to_wbio(bio_clone_fast(&wbio->bio, GFP_NOIO, &ca->replica_set));
            n->bio.bi_end_io = wbio->bio.bi_private;
            n->parent = wbio;
            n->split = true;
            n->bounce = false;
            n->put_bio = true;
            n->bio.bi_opf = wbio->bio.bi_opf;
            bio_inc_remaining(&wbio->bio);
        } else {
            n = wbio;
            n->split = false;
        }

        n->c = c;
        n->dev = ptr->dev;
        n->have_ioref = orca_dev_get_ioref(ca, type == ORCA_DATA_btree
            ? READ
            : WRITE);
        n->submit_time = local_clock();
        n->bio.bi_iter.bi_sector = ptr->offset;

        if (!journal_flushes_device(ca))
            n->bio.bi_opf |= REQ_FUA;

        if (likely(n->have_ioref)) {
            this_cpu_add(ca->io_done->sectors[WRITE][type], bio_sectors(&n->bio));
            bio_set_dev(&n->bio, ca->disk_sb.bdev);
            submit_bio(&n->bio);
        } else {
            n->bio.bi_status = BLK_STS_REMOVED;
            bio_endio(&n->bio);
        }
    }
}

static void __orca_write(struct closure *);

static void
orca_write_done(struct closure *cl)
{
    struct orca_write_op *op = container_of(cl, struct orca_write_op, cl);
    struct orca_fs *c = op->c;

    if (!op->error && (op->flags & ORCA_WRITE_FLUSH))
        op->error = orca_journal_error(&c->journal);

    orca_disk_reservation_put(c, &op->res);
    percpu_ref_put(&c->writes);
    orca_keylist_free(&op->insert_keys, op->inline_keys);
    orca_time_stats_update(&c->times[ORCA_TIME_data_write], op->start_time);

    if (!(op->flags & ORCA_WRITE_FROM_INTERNAL))
        up(&c->io_in_flight);

    if (op->end_io) {
        EBUG_ON(cl->parent);
        closure_debug_destroy(cl);
        op->end_io(op);
    } else {
        closure_return(cl);
    }
}

/**
 * After a write, update index to point to new data.
**/
static void
__orca_write_index(struct orca_write_op *op)
{
    struct orca_fs *c = op->c;
    struct keylist *keys = &op->insert_keys;
    struct orca_extent_ptr *ptr;
    struct bkey_i *src, *dst = keys->keys, *n, *k;
    unsigned dev;
    int ret;

    for (src = keys->keys; src != keys->top; src = n) {
        n = bkey_next(src);

        if (bkey_extent_is_direct_data(&src->k)) {
            orca_bkey_drop_ptrs(bkey_i_to_s(src), ptr, test_bit(ptr->dev,
                op->failed.d));

            if (!orca_bkey_nr_ptrs(bkey_i_to_s_c(src))) {
                ret = -EIO;
                goto err;
            }
        }

        if (dst != src)
            memmove_u64s_down(dst, src, src->u64s);

        dst = bkey_next(dst);
    }

    keys->top = dst;

    /**
     * Probably not the ideal place to hook this in, but I don't
     * particularly want to plumb io_opts all the way through the
     * btree update stack right now.
    **/
    for_each_keylist_key(keys, k) {
        orca_rebalance_add_key(c, bkey_i_to_s_c(k), &op->opts);

        if (orca_bkey_is_incompressible(bkey_i_to_s_c(k)))
            orca_check_set_feature(op->c, ORCA_FEATURE_incompressible);
    }

    if (!orca_keylist_empty(keys)) {
        u64 sectors_start = keylist_sectors(keys);
        int ret = op->index_update_fn(op);

        BUG_ON(ret == -EINTR);
        BUG_ON(keylist_sector(keys) && !ret);

        op->written += sectors_start - keylist_sectors(keys);

        if (ret) {
            orca_err_inum_ratelimited(c, op->pos.inode, "write error %i "
                "from btree update", ret);
            op->error = ret;
        }
    }

out:
    /* If some bucket wasn't written, we can't erasure code it */
    for_each_set_bit(dev, op->failed.d, ORCA_SB_MEMBERS_MAX)
        orca_open_bucket_write_error(c, &op->open_buckets, dev);

    orca_open_buckets_put(c, &op->open_buckets);

    return;

err:
    keys->top = keys->keys;
    op->error = ret;
    goto out;
}

static void
orca_write_index(struct closure *cl)
{
    struct orca_write_op *op = container_of(cl, struct orca_write_op, cl);
    struct orca_fs *c = op->c;

    __orca_write_index(op);

    if (!(op->flags & ORCA_WRITE_DONE)) {
        continue_at(cl, __orca_write, index_update_wq(op));
    } else if (!op->error && (op->flags & ORCA_WRITE_FLUSH)) {
        orca_journal_flush_seq_async(&c->journal, *op_journal_seq(op), cl);
        continue_at(cl, orca_write_done, index_update_wq(op));
    } else {
        continue_at_nobarrier(cl, orca_write_done, NULL);
    }
}

static void
orca_write_endio(struct bio *bio)
{
    struct closure *cl = bio->bi_private;
    struct orca_write_op *op = container_of(cl, struct orca_write_op, cl);
    struct orca_write_bio *wbio = to_wbio(bio);
    struct orca_write_bio *parent = wbio->split ? wbio->parent : NULL;
    struct orca_fs *c = wbio->c;
    struct orca_dev *ca = orca_dev_bkey_exists(c, wbio->dev);

    if (orca_dev_inum_io_err_on(bio->bi_status, ca, op->pos.inode, op->pos.offset -
        bio_sectors(bio), "data write error: %s", orca_blk_status_to_str(bio->bi_status)))
            set_bit(wbio->dev, op->failed.d);

    if (wbio->have_ioref) {
        orca_latency_acct(ca, wbio->submit_time, WRITE);
        percpu_ref_put(&ca->io_ref);
    }

    if (wbio->bounce)
        orca_bio_free_pages_pool(c, bio);

    if (wbio->put_bio)
        bio_put(bio);

    if (parent)
        bio_endio(&parent->bio);
    else if (!(op->flags & ORCA_WRITE_SKIP_CLOSURE_PUT))
        closure_put(cl);
    else
        continue_at_nobarrier(cl, orca_write_index, index_update_wq(op));
}

static void
init_append_extent(struct orca_write_op *op, struct write_point *wp,
    struct bversion version, struct orca_extent_crc_unpacked crc)
{
    struct orca_fs *c = op->c;
    struct bkey_i_extent *e;
    struct open_bucket *ob;
    unsigned i;

    BUG_ON(crc.compressed_size > wp->sectors_free);
    wp->sectors_free -= crc.compressed_size;
    op->pos.offset += crc.uncompressed_size;

    e = bkey_extent_init(op->insert_keys.top);
    e->k.p = op->pos;
    e->k.size = crc.uncompressed_size;
    e->k.version = version;

    if (crc.csum_type || crc.compression_type || crc.nonce)
        orca_extent_crc_append(&e->k_i, crc);

    open_bucket_for_each(c, &wp->ptrs, ob, j) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);
        union orca_extent_entry *end = bkey_val_end(bkey_i_to_s(&e->k_i));

        end->ptr = ob->ptr;
        end->ptr.type = 1 << ORCA_EXTENT_ENTRY_ptr;
        end->ptr.cached = !ca->mi.durability || (op->flags & ORCA_WRITE_CACHED) != 0;
        end->ptr.offset += ca->mi.bucket_size - ob->sectors_free;
        e->k.u64s++;

        BUG_ON(crc.compressed_size > ob->sectors_free);
        ob->sectors_free -= crc.compressed_size;
    }

    orca_keylist_push(&op->insert_keys);
}

static struct bio *
orca_write_bio_alloc(struct orca_fs *c, struct write_point *wp, struct bio *src,
    bool *page_alloc_failed, void *buf)
{
    struct orca_write_bio *wbio;
    struct bio *bio;
    unsigned output_available = min(wp->sectors_free << 9, src->bi_iter.bi_size);
    unsigned pages = DIV_ROUND_UP(output_available + (buf
        ? ((unsigned long)buf & (PAGE_SIZE - 1))
        : 0), PAGE_SIZE);

    bio = bio_alloc_bioset(GFP_NOIO, pages, &c->bio_write);
    wbio = wbio_init(bio);
    wbio->bio.bi_opf = src->bi_opf;

    if (buf) {
        orca_bio_map(bio, buf, output_available);
        return bio;
    }

    wbio->bounce = true;

    /**
     * We can't use mempool for more than c->sb.encoded_extent_max worth of
     * pages, but we'd like to allocate more if we can.
    **/
    orca_bio_alloc_pages_pool(c, bio, min_t(unsigned, output_available,
        c->sb.encoded_extent_max << 9));

    if (bio->bi_iter.bi_size < output_available)
        *page_alloc_failed = orca_bio_alloc_pages(bio, output_available -
            bio->bi_iter.bi_size, GFP_NOGF) != 0;

    return bio;
}

static int
orca_write_rechecksum(struct orca_fs *c, struct orca_write_op *op,
    unsigned new_csum_type)
{
    struct bio *bio = &op->wbio.bio;
    struct orca_extent_crc_unpacked new_crc;
    int ret;

    /* orca_rechecksum_bio() can't encrypt or decrypt data */
    if (orca_csum_type_is_encryption(op->crc.csum_type) !=
        orca_csum_type_is_encryption(new_csum_type))
            new_csum_type = op->crc.csum_type;

    ret = orca_rechecksum_bio(c, bio, op->version, op->crc, NULL, &new_crc,
        op->crc.offset, op->crc.live_size, new_csum_type);

    if (ret)
        return ret;

    bio_advance(bio, op->crc.offset << 9);
    bio->bi_iter.bi_size = op->crc.live_size << 9;
    op->crc = new_crc;

    return 0;
}

static int
orca_write_decrypt(struct orca_write_op *op)
{
    struct orca_fs *c = op->c;
    struct nonce nonce = extent_nonce(op->version, op->crc);
    struct orca_csum csum;

    if (!orca_csum_type_is_encryption(op->crc.csum_type))
        return 0;

    /**
     * If we need to decrypt data in the write path, we'll no longer be able
     * to verify the existing checmsum (poly1305 mac, in this case) after
     * it's decrypted--this is the last point we'll be able to reverify
     * the checksum.
    **/
    csum = orca_checksum_bio(c, op->crc.csum_type, nonce, &op->wbio.bio);

    if (orca_crc_cmp(op->crc.csum, csum))
        return -EIO;

    orca_encrypt_bio(c, op->crc.csum_type, nonce, &op->wbio.bio);
    op->crc.csum_type = 0;
    op->crc.csum = (struct orca_csum) { 0, 0 };

    return 0;
}

static enum prep_encoded_ret {
    PREP_ENCODED_OK,
    PREP_ENCODED_ERR,
    PREP_ENCODED_CHECKSUM_ERR,
    PREP_ENCODED_DO_WRITE,
} orca_write_prep_encoded_data(struct orca_write_op *op, struct write_point *wp)
{
    struct orca_fs *c = op->c;
    struct bio *bio = &op->wbio.bio;

    if (!(op->flags & ORCA_WRITE_DATA_ENCODED))
        return PREP_ENCODED_OK;

    BUG_ON(bio_sectors(bio) != op->crc.compressed_size);

    /* Can we just write the entire extent as is? */
    if (op->crc.uncompressed_size == op->crc.live_size &&
        op->crc.compressed_size <= wp->sectors_free &&
        (op->crc.compression_type == op->compression_type ||
        op->incompressible)) {
            if (!crc_is_compressed(op->crc) && op->csum_type != op.crc.csum_type &&
                orca_write_rechecksum(c, op, op->csum_type))
                    return PREP_ENCODED_CHECKSUM_ERR;

            return PREP_ENCODED_DO_WRITE;
    }

    /**
     * If the data is compressed and we couldn't write the entire extent
     * as is, we have to decompress it.
    **/
    if (crc_is_compressed(op->crc)) {
        struct orca_csum csum;

        if (orca_write_decrypt(op))
            return PREP_ENCODED_CHECKSUM_ERR;

        /* Last point we can still verify checksum */
        csum = orca_checksum_bio(c, op->crc.csum_type, extent_nonce(op->version,
            op->crc), bio);

        if (orca_crc_cmp(op->crc.csum, csum))
            return PREP_ENCODED_CHECKSUM_ERR;

        if (orca_bio_uncompress_inplace(c, bio, &op->crc))
            return PREP_ENCODED_ERR;
    }

    /**
     * No longer have compressed data after this point--data might be
     * encrypted.
     *
     * If the data is checksummed and we're only writing a subset,
     * rechecksum and adjust bio to point to currently live data.
    **/
    if ((op->crc.live_size != op.crc.uncompressed_size ||
        op->crc.csum_type != op->csum_type) &&
        orca_write_rechecksum(c, op, op->csum_type))
            return PREP_ENCODED_CHECKSUM_ERR;

    /**
     * If we want to compress the data, it has to be decrypted.
    **/
    if ((op->compression_type || orca_csum_type_is_encryption(op->crc.csum_type) !=
        orca_csum_type_is_encryption(op->csum_type)) && orca_write_decrypt(op))
            return PREP_ENCODED_CHECKSUM_ERR;

    return PREP_ENCODED_OK;
}

static int
orca_write_extent(struct orca_write_op *op, struct write_point *wp,
    struct bio **_dst)
{
    struct orca_fs *c = op->c;
    struct bio *src = &op->wbio.bio, *dst = src;
    struct bvec_iter saved_iter;
    void *ec_buf;
    struct bpos ec_pos = op->pos;
    unsigned total_output = 0, total_input = 0;
    bool bounce = false;
    bool page_alloc_failed = false;
    int ret, more = 0;

    BUG_ON(!bio_sectors(src));

    ec_buf = orca_writepoint_ec_buf(c, wp);

    switch (orca_write_prep_encoded_data(op, wp)) {
    case PREP_ENCODED_OK:
        break;

    case PREP_ENCODED_ERR:
        ret = -EIO;
        goto err;

    case PREP_ENCODED_CHECKSUM_ERR:
        BUG();
        goto csum_err;

    case PREP_ENCODED_DO_WRITE:
        if (ec_buf) {
            dst = orca_write_bio_alloc(c, wp, src, &page_alloc_failed, ec_buf);
            bio_copy_data(dst, src);
            bounce = true;
        }

        init_append_extent(op, wp, op->version, op->crc);
        goto do_write;
    }

    if (ec_buf || op->compression_type || (op->csum_type &&
        !(op->flags & ORCA_WRITE_PAGES_STABLE)) ||
        (orca_csum_type_is_encryption(op->csum_type) &&
        !(op->flags & ORCA_WRITE_PAGES_OWNED))) {
            dst = orca_write_bio_alloc(c, wp, src, &page_alloc_failed, ec_buf);
            bounce = true;
    }

    saved_iter = dst->bi_iter;

    do {
        struct orca_extent_crc_unpacked crc = (struct orca_extent_crc_unpaced) { 0 };
        struct bversion version = op->version;
        size_t dst_len, src_len;

        if (page_alloc_failed && bio_sectors(dst) < wp->sectors_free &&
            bio_sectors(dst) < c->sb.encoded_extent_max)
                break;

        BUG_ON(op->compression_type && (op->flags & ORCA_WRITE_DATA_ENCODED) &&
            orca_csum_type_is_encryption(op->crc.csum_type));
        BUG_ON(op->compression_type && !bounce);

        crc.compression_type = op->incompressible
            ? ORCA_COMPRESSION_TYPE_incompressible
            : op->compression_type
            ? orca_bio_compress(c, dst, *dst_len, src, &src_len, op->compression_type)
            : 0;

        if (!crc_is_compressed(crc)) {
            dst_len = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);
            dst_len = min_t(unsigned, dst_len, wp->sectors_free << 9);

            if (op->csum_type)
                dst_len = min_t(unsigned, dst_len, c->sb.encoded_extent_max << 9);

            if (bounce) {
                swap(dst->bi_iter.bi_size, dst_len);
                bio_copy_data(dst, src);
                swap(dst->bi_iter.bi_size, dst_len);
            }

            src_len = dst_len;
        }

        BUG_ON(!src_len || !dst_len);

        if (orca_csum_type_is_encryption(op->csum_type)) {
            if (bversion_zero(version)) {
                version.lo = atomic64_inc_return(&c->key_version);
            } else {
                crc.nonce = op->nonce;
                op->nonce += src_len >> 9;
            }
        }

        if ((op->flags & ORCA_WRITE_DATA_ENCODED) && !crc_is_compressed(crc) &&
            orca_csum_type_is_encryption(op->crc.csum_type) ==
            orca_csum_type_is_encryption(op->csum_type)) {
                /**
                 * When we're using rechecksum(), we need to be checksumming
                 * @src, because it has all the data our existing checksum
                 * covers--if we bounced (because we were trying to compress),
                 * @dst will only have the part of the data the new checksum
                 * will cover.
                 *
                 * But, normally, we want to be checksumming post bounce,
                 * because part of the reason for bouncing is so the data can't
                 * be modified (by userspace) while its in flight.
                **/
                if (orca_rechecksum_bio(c, src, version, op->crc, &crc, &op->crc,
                    src_len >> 9, bio_sectors(src) - (src_len >> 9), op->csum_type))
                        goto csum_err;
        } else {
            if ((op->flags & ORCA_WRITE_DATA_ENCODED) &&
                orca_rechecksum_bio(c, src, version, op->crc, NULL, &op->crc,
                src_len >> 9, bio_sectors(src) - (src_len >> 9),
                op->crc.csum_type))
                    goto csum_err;

            crc.compressed_size = dst_len >> 9;
            crc.uncompressed_size = src_len >> 9;
            crc.live_size = src_len >> 9;

            swap(dst->bi_iter.bi_size, dst_len);
            orca_encrypt_bio(c, op->csum_type, extent_nonce(version, crc), dst);
            crc.csum = orca_checksum_bio(c, op->csum_type,
                extent_nonce(version, crc), dst);
            crc.csum_type = op->csum_type;
            swap(dst->bi_iter.bi_size, dst_len);
        }

        init_append_extent(op, wp, version, crc);

        if (dst != src)
            bio_advance(dst, dst_len);

        bio_advance(src, src_len);
        total_output += dst_len;
        total_input += src_len;
    } while (dst->bi_iter.bi_size && src->bi_iter.bi_size && wp->sectors_free &&
        !orca_keylist_realloc(&op->insert_keys, op->inline_keys, ARRAY_SIZE(op->inline_keys),
        BKEY_EXTENT_U64s_MAX));

    more = src->bi_iter.bi_size != 0;
    dst->bi_iter = saved_iter;

    if (dst == src && more) {
        BUG_ON(total_output != total_input);

        dst = bio_split(src, total_input >> 9, GFP_NOIO, &c->bio_write);
        wbio_init(dst)->put_bio = true;
        dst->bi_opf = src->bi_opf;
    }

    dst->bi_iter.bi_size = total_output;

do_write:
    /* Might have done a realloc... */
    orca_ec_add_backpointer(c, wp, ec_pos, total_input >> 9);
    *_dst = dst;

    return more;

csum_err:
    orca_err(c, "error verifying existing checksum while "
        "rewriting existing data (memory corruption?)");
    ret = -EIO;

err:
    if (to_wbio(dst)->bounce)
        orca_bio_free_pages_pool(c, dst);

    if (to_wbio(dst)->put_bio)
        bio_put(dst);

    return ret;
}

static void
__orca_write(struct closure *cl)
{
    struct orca_write_op *op = container_of(cl, struct orca_write_op, cl);
    struct orca_fs *c = op->c;
    struct write_point *wp;
    struct bio *bio;
    bool skip_put = true;
    unsigned nofs_flags;
    int ret;

    nofs_flags = memalloc_nofs_save();

again:
    memset(&op->failed, 0, sizeof(op->failed));

    do {
        struct bkey_i *key_to_write;
        unsigned key_to_write_offset = op->insert_keys.top_p -
            op->insert_keys.keys_p;

        /* +1 for possible cache device */
        if (op->open_buckets.nr + op->nr_replicas + 1 > ARRAY_SIZE(op->open_buckets.v))
            goto flush_io;

        if (orca_keylist_realloc(&op->insert_keys, op->inline_keys,
            ARRAY_SIZE(op->inline_keys), BKEY_EXTENT_U64s_MAX))
                goto flush_io;

        if ((op->flags & ORCA_WRITE_FROM_INTERNAL) && percpu_ref_is_dying(&c->writes)) {
            ret = -EROFS;
            goto err;
        }

        /**
         * The copygc thread is now global, which means it's no longer freeing
         * up space on specific disks, which means that allocations for
         * specific disks may hang arbitrarily long.
        **/
        wp = orca_alloc_sectors_start(c, op->target, op->opts.erasure_code,
            op->write_point, &op->devs_have, op->nr_replicas,
            op->nr_replicas_required, op->alloc_reserve, op->flags,
            (op->flags & (ORCA_WRITE_ALLOC_NOWAIT |
            ORCA_WRITE_ONLY_SPECIFIED_DEVS)) ? NULL : cl);

        EBUG_ON(!wp);

        if (unlikely(IS_ERR(wp))) {
            if (unlikely(PTR_ERR(wp) != -EAGAIN)) {
                ret = PTR_ERR(wp);
                goto err;
            }

            goto flush_io;
        }

        /**
         * It's possible for the allocator to fail, put us on the freelist
         * waitlist, and then succeed in one of various retry paths. If that
         * happens, we need to disable the skip_put optimization because
         * otherwise there won't necessarily be a barrier before we free
         * the orca_write_op.
        **/
        if (atomic_read(&cl->remaining) & CLOSURE_WAITING)
            skip_put = false;

        orca_open_bucket_get(c, wp, &op->open_buckets);
        ret = orca_write_extent(op, wp, &bio);
        orca_alloc_sectors_done(c, wp);

        if (ret < 0)
            goto err;

        if (ret) {
            skip_put = false;
        } else {
            /**
             * For the skip_put optimization, this has to be set before we
             * submit the bio.
            **/
            op->flags |= ORCA_WRITE_DONE;
        }

        bio->bi_end_io = orca_write_endio;
        bio->bi_private = &op->cl;
        bio->bi_opf |= REQ_OP_WRITE;

        if (!skip_put)
            closure_get(bio->bi_private);
        else
            op->flags |= ORCA_WRITE_SKIP_CLOSURE_PUT;

        key_to_write = (void *)(op->insert_keys.keys_p + key_to_write_offset);
        orca_submit_wbio_replicas(to_wbio(bio), c, ORCA_DATA_user, key_to_write);
    } while (ret);

    if (!skip_put)
        continue_at(cl, orca_write_index, index_update_wq(op));

out:
    memalloc_nofs_restore(nofs_flags);
    return;

err:
    op->error = ret;
    op->flags |= ORCA_WRITE_DONE;
    continue_at(cl, orca_write_index, index_update_wq(op));
    goto out;

flush_io:
    /**
     * If the write can't all be submitted at once, we generally want to
     * block synchronously as that signals backpressure to the caller.
     *
     * However, if we're running out of a workqueue, we can't block here
     * because we'll be blocking other work items from completing.
    **/
    if (current->flags & PF_WQ_WORKER) {
        continue_at(cl, orca_write_index, index_update_wq(op));
        goto out;
    }

    closure_sync(cl);

    if (!orca_keylist_empty(&op->insert_keys)) {
        __orca_write_index(op);

        if (op->error) {
            op->flags |= ORCA_WRITE_DONE;
            continue_at_nobarrier(cl, orca_write_done, NULL);
            goto out;
        }
    }

    goto again;
}

static void
orca_write_data_inline(struct orca_write_op *op, unsigned data_len)
{
    struct closure *cl = &op->cl;
    struct bio *bio = &op->wbio.bio;
    struct bvec_iter iter;
    struct bkey_i_inline_data *id;
    unsigned sectors;
    int ret;

    orca_check_set_feature(op->c, ORCA_FEATURE_inline_data);
    ret = orca_keylist_realloc(&op->insert_keys, op->inline_keys,
        ARRAY_SIZE(op->inline_keys), BKEY_U64s + DIV_ROUND_UP(data_len, 8));

    if (ret) {
        op->error = ret;
        goto err;
    }

    sectors = bio_sectors(bio);
    op->pos.offset += sectors;

    id = bkey_inline_data_init(op->insert_keys.top);
    id->k.p = op->pos;
    id->k.version = op->version;
    id->k.size = sectors;

    iter = bio->bi_iter;
    iter.bi_size = data_len;
    memcpy_from_bio(id->v.data, bio, iter);

    while (data_len & 7)
        id->v.data[data_len++] = '\0';

    set_bkey_val_bytes(&id->k, data_len);
    orca_keylist_push(&op->insert_keys);

    op->flags |= ORCA_WRITE_WROTE_DATA_INLINE;
    op->flags |= ORCA_WRITE_DONE;

    continue_at_nobarrier(cl, orca_write_index, NULL);
    return;

err:
    orca_write_done(&op->cl);
}

/**
 * Handle a write to a cache device or flash-only volume.
 *
 * This is the starting point for any data to end up in a cache device;
 * it could be from a normal write, or a writeback write, or a write to
 * a flash only volume--it's also used by the moving garbage collector to
 * compact data in mostly empty buckets.
 *
 * It first writes the data to the cache, creating a list of keys to be
 * inserted (if the data won't fit in a single open bucket, there will
 * be multiple keys); after the data is written it call orca_journal(),
 * and after the keys have been added to the next journal write they're
 * inserted into the btree.
 *
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by op->bio and op->inode.
**/
void
orca_write(struct closure *cl)
{
    struct orca_write_op *op = container_of(cl, struct orca_write_op, cl);
    struct bio *bio = &op->wbio.bio;
    struct orca_fs *c = op->c;
    unsigned data_len;

    BUG_ON(!op->nr_replicas);
    BUG_ON(!op->write_point.v);
    BUG_ON(!bkey_cmp(op->pos, POS_MAX));

    op->start_time = local_clock();
    orca_keylist_init(&op->insert_keys, op->inline_keys);
    wbio_init(bio)->put_bio = false;

    if (bio_sectors(bio) & (c->opts.block_size - 1)) {
        orca_err_inum_ratelimited(c, op->pos.inode, "misaligned write");
        op->error = -EIO;
        goto err;
    }

    if (c->opts.nochanges || !percpu_ref_tryget(&c->writes)) {
        op->error = -EROFS;
        goto err;
    }

    /**
     * Can't ratelimit copygc--w're deadlock.
    **/
    if (!(op->flags & ORCA_WRITE_FROM_INTERNAL))
        down(&c->io_in_flight);

    orca_increment_clock(c, bio_sectors(bio), WRITE);
    data_len = min_t(u64, bio->bi_iter.bi_size, op->new_i_size -
        (op->pos.offset << 9));

    if (c->opts.inline_data && data_len <= min(block_bytes(c) / 2, 1-24U)) {
        orca_write_data_inline(op, data_len);
        return;
    }

    continue_at_nobarrier(cl, __orca_write, NULL);

err:
    orca_disk_reservation_put(c, &op->res);

    if (op->end_io) {
        EBUG_ON(cl->parent);
        closure_debug_destroy(cl);
        op->end_io(op);
    } else {
        closure_return(cl);
    }
}

/**
 * Cache promotion on read.
**/
struct promote_op {
    struct closure cl;
    struct rcu_head rcu;
    u64 start_time;
    struct rhash_head hash;
    struct bpos pos;
    struct migrate_write write;
    struct bio_vec bi_inline_vecs[0]; /* Must be last */
};

static const struct rhashtable_params orca_promote_params = {
    .head_offset = offsetof(struct promote_op, hash),
    .key_offset = offsetof(struct promote_op, pos),
    .key_len = sizeof(struct bpos),
};

static inline bool
should_promote(struct orca_fs *c, struct bkey_s_c k, struct bpos pos,
    struct orca_io_opts opts, unsigned flags)
{
    if (!(flags & ORCA_READ_MAY_PROMOTE))
        return false;

    if (!opts.promote_target)
        return false;

    if (orca_bkey_has_target(c, k, opts.promote_target))
        return false;

    if (orca_target_congested(c, opts.promote_target))
        return false;

    if (rhashtable_lookup_fast(&c->promote_table, &pos, orca_promote_params))
        return false;

    return true;
}

static void
promote_free(struct orca_fs *c, struct promote_op *op)
{
    int ret;

    ret = rhashtable_remove_fast(&c->promote_table, &op->hash, orca_promote_params);

    BUG_ON(ret);
    percpu_ref_put(&c->writes);
    kfree_rcu(op, rcu);
}

static void
promote_done(struct closure *cl)
{
    struct promote_op *op = container_of(cl, struct promote_op, cl);
    struct orca_fs *c = op->write.op.c;

    orca_time_stats_update(&c->times[ORCA_TIME_data_promote], op->start_time);
    orca_bio_free_pages_pool(c, &op->write.op.wbio.bio);
    promote_free(c, op);
}

static void
promote_start(struct promote_op *op, struct orca_read_bio *rbio)
{
    struct orca_fs *c = rbio->c;
    struct closure *cl = &op->cl;
    struct bio *bio = &op->write.op.wbio.bio;

    trace_promote(&rbio->bio);

    /* We now own pages */
    BUG_ON(!rbio->bounce);
    BUG_ON(rbio->bio.bi_vcnt > bio->bi_max_vecs);

    memcpy(bio->bi_io_vec, rbio->bio.bio_io_vec, sizeof(struct bio_vec) *
        rbio->bio.bi_vcnt);
    swap(bio->bi_vcnt, rbio->bio.bi_vcnt);
    orca_migrate_read_done(&op->write, rbio);

    closure_init(cl, NULL);
    closure_call(&op->write.op.cl, orca_write, c->wq, cl);
    closure_return_with_destructor(cl, promote_done);
}

static struct promote_op *
__promote_alloc(struct orca_fs *c, enum btree_id btree_id, struct bkey_s_c k,
    struct bpos pos, struct extent_ptr_decoded *pick, struct orca_io_opts opts,
    unsigned sectors, struct orca_read_bio **rbio)
{
    struct promote_op *op = NULL;
    struct bio *bio;
    unsigned pages = DIV_ROUND_UP(sectors, PAGE_SECTORS);
    int ret;

    if (!percpu_ref_tryget(&c->writes))
        return NULL;

    op = kzalloc(sizeof(*op) + sizeof(struct bio_vec) * pages, GFP_NOIO);

    if (!op)
        goto err;

    op->start_time = local_clock();
    op->pos = pos;

    /**
     * We don't use the mempool here because extents that aren't
     * checksummed or compressed can be too big for the mempool.
    **/
    *rbio = kzalloc(sizeof(struct orca_read_bio) + sizeof(struct bio_vec) * pages,
        GFP_NOIO);

    if (!*rbio)
        goto err;

    rbio_init(&(*rbio)->bio, opts);
    bio_init(&(*rbio)->bio, (*rbio)->bio.bi_inline_vecs, pages);

    if (orca_bio_alloc_pages(&(*rbio)->bio, sectors << 9, GFP_NOIO))
        goto err;

    (*rbio)->bounce = true;
    (*rbio)->split = true;
    (*rbio)->kmalloc = true;

    if (rhashtable_lookup_insert_fast(&c->promote_table, &op->hash,
        orca_promote_params))
            goto err;

    bio = &op->write.op.wbio.bio;
    bio_init(bio, bio->bi_inline_vecs, pages);

    ret = orca_migrate_write_init(c, &op->write,
        writepoint_hashed((unsigned long)current), opts, DATA_PROMOTE,
            (struct data_opts) {
                .target = opts.promote_target,
                .nr_replicas = 1,
            },
            btree_id, k);

    BUG_ON(ret);

    return op;

err:
    if (*rbio)
        bio_free_pages(&(*rbio)->bio);

    kfree(*rbio);
    *rbio = NULL;
    kfree(op);
    percpu_ref_put(&c->writes);

    return NULL;
}

noinline static struct promote_op *
promote_alloc(struct orca_fs *c, struct bvec_iter iter, struct bkey_s_c k,
    struct extent_ptr_decoded *pick, struct orca_io_opts opts, unsigned flags,
    struct orca_read_bio **rbio, bool *bounce, bool *read_full)
{
    bool promote_full = *read_full || READ_ONCE(c->promote_whole_extents);
    unsigned sectors = promote_full
        ? max(pick->crc.compressed_size, pick->crc.live_size)
        : bvec_iter_sectors(iter);
    struct bpos pos = promote_full
        ? bkey_start_pos(k.k)
        : POS(k.k->p.inode, iter.bi_sectors);
    struct promote_op *promote;

    if (!should_promote(c, k, pos, opts, flags))
        return NULL;

    promote = __promote_alloc(c, k.k->type == KEY_TYPE_reflink_v
        ? BTREE_ID_REFLINK : BTREE_ID_EXTENTS, k, pos, pick, opts,
        sectors, rbio);

    if (!promote)
        return NULL;

    *bounce = true;
    *read_full = promote_full;

    return promote;
}

#define READ_RETRY_AVOID 1
#define READ_RETRY 2
#define READ_ERR 3

enum rbio_context {
    RBIO_CONTEXT_NULL,
    RBIO_CONTEXT_HIGHPRI,
    RBIO_CONTEXT_UNBOUND,
};

static inline struct orca_read_bio *
orca_rbio_parent(struct orca_read_bio *rbio)
{
    return rbio->split ? rbio->parent : rbio;
}

__always_inline static void
orca_rbio_punt(struct orca_read_bio *rbio, work_func_t fn,
    enum rbio_context context, struct workqueue_struct *wq)
{
    if (context <= rbio->context) {
        fn(&rbio->work);
    } else {
        rbio->work.func = fn;
        rbio->context = context;
        queue_work(wq, &rbio->work);
    }
}

static inline struct orca_read_bio *
orca_rbio_free(struct orca_read_bio *rbio)
{
    BUG_ON(rbio->bounce && !rbio->split);

    if (rbio->promote)
        promote_free(rbio->c, rbio->promote);

    rbio->promote = NULL;

    if (rbio->bounce)
        orca_bio_free_pages_pool(rbio->c, &rbio->bio);

    if (rbio->split) {
        struct orca_read_bio *parent = rbio->parent;

        if (rbio->kmalloc)
            kfree(rbio);
        else
            bio_put(&rbio->bio);

        rbio = parent;
    }

    return rbio;
}

/**
 * Only called on a top level orca_read_bio to complete an entire read
 * request, not a split.
**/
static void
orca_rbio_done(struct orca_read_bio *rbio)
{
    if (rbio->start_time)
        orca_time_stats_update(&rbio->c->times[ORCA_TIME_data_read],
            rbio->start_time);

    bio_endio(&rbio->bio);
}

static void
orca_read_retry_nodecode(struct orca_fs *c, struct orca_read_bio *rbio,
    struct bvec_iter bvec_iter, u64 inode, struct orca_io_failures *failed,
    unsigned flags)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_on_stack sk;
    struct bkey_s_c k;
    int ret;

    flags &= ~ORCA_READ_LAST_FRAGMENT;
    flags |= ORCA_READ_MUST_CLONE;

    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, 0, 0);

    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, rbio->pos, BTREE_ITER_SLOTS);

retry:
    rbio->bio.bi_status = 0;
    k = orca_btree_iter_peek_slot(iter);
    orca_trans_unlock(&trans);

    if (!orca_bkey_matches_ptr(c, k, rbio->pick.ptr, rbio->pos.offset -
        rbio->pick.crc.offset)) {
            /* Extent we wanted to read no longer exists */
            rbio->hole = true;
            goto out;
    }

    ret = __orca_read_extent(&trans, rbio, bvec_iter, k, 0, failed, flags);

    if (ret == READ_RETRY)
        goto retry;

    if (ret)
        goto err;

out:
    orca_rbio_done(rbio);
    orca_trans_exit(&trans);
    bkey_on_stack_exit(&sk, c);
    return;

err:
    rbio->bio.bi_status = BLK_STS_IOERR;
    goto out;
}

static void
orca_read_retry(struct orca_fs *c, struct orca_read_bio *rbio,
    struct bvec_iter bvec_iter, u64 inode, struct orca_io_failures *failed,
    unsigned flags)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_on_stack sk;
    struct bkey_s_c k;
    int ret;

    flags &= ~ORCA_READ_LAST_FRAGMENT;
    flags |= ORCA_READ_MUST_CLONE;

    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, 0, 0);

retry:
    orca_trans_begin(&trans);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS(inode, bvec_iter.bi_sector),
        BTREE_ITER_SLOTS, k, ret) {
            unsigned bytes, sectors, offset_into_extent;

            bkey_on_stack_reassemble(&sk, c, k);
            offset_into_extent = iter->pos.offset - bkey_start_offset(k.k);
            sectors = k.k->size - offset_into_extent;
            ret = orca_read_indirect_extent(&trans, &offset_into_extent, &sk);

            if (ret)
                break;

            k = bkey_i_to_s_c(sk.k);
            sectors = min(sectors, k.k->size - offset_into_extent);
            orca_trans_unlock(&trans);
            bytes = min(sectors, bvec_iter_sectors(bvec_iter)) << 9;
            swap(bvec_iter.bi_size, bytes);

            ret = __orca_read_extent(&trans, rbio, bvec_iter, k, offset_into_extent,
                failed, flags);

            switch (ret) {
            case READ_RETRY:
                goto retry;

            case READ_ERR:
                goto err;
            };

            if (bytes == bvec_iter.bi_size)
                goto out;

            swap(bvec_iter.bi_size, bytes);
            bio_advance_iter(&rbio->bio, &bvec_iter, bytes);
    }

    if (ret == -EINTR)
        goto retry;

    /**
     * If we get here, it better have been because there was an error
     * reading btree node.
    **/
    BUG_ON(!ret);
    orca_err_inum_ratelimited(c, inode, "read error %i from btree lookup", ret);

err:
    rbio->bio.bi_status = BLK_STS_IOERR;

out:
    orca_trans_exit(&trans);
    bkey_on_stack_exit(&sk, c);
    orca_rbio_done(rbio);
}

static void
orca_rbio_retry(struct work_struct *work)
{
    struct orca_read_bio *rbio = container_of(work, struct orca_read_bio, work);
    struct orca_fs *c = rbio->c;
    struct bvec_iter iter = rbio->bvec_iter;
    unsigned flags = rbio->flags;
    u64 inode = rbio->pos.inode;
    struct orca_io_features failed = { .nr = 0 };

    trace_read_retry(&rbio->bio);

    if (rbio->retry == READ_RETRY_AVOID)
        orca_mark_io_failure(&failed, &rbio->pick);

    rbio->bio.bi_status = 0;

    flags |= ORCA_READ_IN_RETRY;
    flags &= ~ORCA_READ_MAY_PROMOTE;

    if (flags & ORCA_READ_NODECODE)
        orca_read_retry_nodecode(c, rbio, iter, inode, &failed, flags);
    else
        orca_read_retry(c, rbio, iter, inode, &failed, flags);
}

static void
orca_rbio_error(struct orca_read_bio *rbio, int retry, blk_status_t error)
{
    rbio->retry = retry;

    if (rbio->flags & ORCA_READ_IN_RETRY)
        return;

    if (retry == READ_ERR) {
        rbio = orca_bio_free(rbio);
        rbio->bio.bi_status = error;
        orca_rbio_done(rbio);
    } else {
        orca_rbio_punt(rbio, orca_rbio_retry, RBIO_CONTEXT_UNBOUND,
            system_unbound_wq);
    }
}

static int
__orca_rbio_narrow_crcs(struct btree_trans *trans, struct orca_read_bio *rbio)
{
    struct orca_fs *c = rbio->c;
    u64 data_offset = rbio->pos.offset - rbio->pick.crc.offset;
    struct orca_extent_crc_unpacked new_crc;
    struct btree_iter *iter = NULL;
    struct bkey_i *new;
    struct bkey_s_c k;
    int ret = 0;

    if (crc_is_compressed(rbio->pick.crc))
        return 0;

    iter = orca_trans_get_iter(trans, BTREE_ID_EXTENTS, rbio->pos,
        BTREE_ITER_SLOT | BTREE_ITER_INTENT);
    k = orca_btree_iter_peek_slot(iter);

    if ((ret = bkey_err(k)))
        goto out;

    /**
     * Going to be temporarily appending another checksum entry.
    **/
    new = orca_trans_kmalloc(trans, bkey_bytes(k.k) + BKEY_EXTENT_U64s_MAX * 8);

    if ((ret = PTR_ERR_OR_ZERO(new)))
        goto out;

    bkey_reassemble(new, k);
    k = bkey_i_to_s_c(new);

    if (bversion_cmp(k.k->version, rbio->version) ||
        !orca_bkey_matches_ptr(c, k, rbio->pick.ptr, data_offset))
            goto out;

    if (orca_rechecksum_bio(c, &rbio->bio, rbio->version, rbio->pick.crc,
        NULL, &new_crc, bkey_start_offset(k.k) - data_offset, k.k->size,
        rbio->pick.crc.csum_type)) {
            orca_err(c, "error verifying existing checksum while narrowing "
                "checksum (memory corruption?)");
            ret = 0;
            goto out;
    }

    if (!orca_bkey_narrow_crcs(new, new_crc))
        goto out;

    orca_trans_update(trans, iter, new, 0);

out:
    orca_trans_iter_put(trans, iter);

    return ret;
}

static noinline void
orca_rbio_narrow_crcs(struct orca_read_bio *rbio)
{
    orca_trans_do(rbio->c, NULL, NULL, BTREE_INSERT_NOFAIL,
        __orca_rbio_narrow_crcs(&trans, rbio));
}

/**
 * Inner part that may run in process context.
**/
static void
__orca_read_endio(struct work_struct *work)
{
    struct orca_read_bio *rbio = container_of(work, struct orca_read_bio, work);
    struct orca_fs *c = rbio->c;
    struct orca_dev *ca = orca_dev_bkey_exists(c, rbio->pick.ptr.dev);
    struct bio *src = &rbio->bio;
    struct bio *dst = &orca_rbio_parent(rbio)->bio;
    struct bvec_iter dst_iter = rbio->bvec_iter;
    struct orca_extent_crc_unpacked crc = rbio->pick.crc;
    struct nonce nonce = extent_nonce(rbio->version, crc);
    struct orca_csum csum;

    /* Reset iterator for checksumming and copying bounced data */
    if (rbio->bounce) {
        src->bi_iter.bi_size = crc.compressed_size << 9;
        src->bi_iter.bi_idx = 0;
        src->bi_iter.bi_bvec_done = 0;
    } else {
        src->bi_iter = rbio->bvec_iter;
    }

    csum = orca_checksum_bio(c, crc.csum_type, nonce, src);

    if (orca_crc_cmp(csum, rbio->pick.crc.csum))
        goto csum_err;

    if (unlikely(rbio->narrow_crc))
        orca_rbio_narrow_crcs(rbio);

    if (rbio->flags & ORCA_READ_NODECODE)
        goto nodecode;

    /* Adjust crc to point to subset of data we want */
    crc.offset += rbio->offset_into_extent;
    crc.live_size = bvec_iter_sectors(rbio->bvec_iter);

    if (crc_is_compressed(crc)) {
        orca_encrypt_bio(c, crc.csum_type, nonce, src);

        if (orca_bio_uncompress(c, src, dst, dst_iter, crc))
            goto decompression_err;
    } else {
        /* Don't need to decrypt the entire bio */
        nonce = nonce_add(nonce, crc.offset << 9);
        bio_advance(src, crc.offset << 9);

        BUG_ON(src->bi_iter.bi_size < dst_iter.bi_size);
        src->bi_iter.bi_size = dst_iter.bi_size;
        orca_encrypt_bio(c, crc.csum_type, nonce, src);

        if (rbio->bounce) {
            struct bvec_iter src_iter = src->bi_iter;
            bio_copy_data_iter(dst, &dst_iter, src, &src_iter);
        }
    }

    if (rbio->promote) {
        /**
         * Re-encrypt data we decrypted, so it's consistent
         * with rbio->crc.
        **/
        orca_encrypt_bio(c, crc.csum_type, nonce, src);
        promote_start(rbio->promote, rbio);
        rbio->promote = NULL;
    }

nodecode:
    if (likely(!(rbio->flags & ORCA_READ_IN_RETRY))) {
        rbio = orca_rbio_free(rbio);
        orca_rbio_done(rbio);
    }

    return;

csum_err:
    /**
     * Checksum error if the bio wasn't bounced, we may have been
     * reading into buffers owned by userspace (that userspace can
     * scribble over)--retry the read, bouncing it this time.
    **/
    if (!rbio->bounce && (rbio->flags & ORCA_READ_USER_MAPPED)) {
        rbio->flags |= ORCA_READ_MUST_BOUNCE;
        orca_rbio_error(rbio, READ_RETRY, BLK_STS_IOERR);
        return;
    }

    orca_dev_inum_io_error(ca, rbio->pos.inode, (u64)rbio->bvec_iter.bi_sector,
        "data checksum error: expected %0llx:%0llx got %0llx:%0llx (type %u)",
        rbio->pick.crc.sum.hi, rbio->pick.crc.csum.lo, csum.hi, csum.lo,
        crc.csum_type);
    orca_rbio_error(rbio, READ_RETRY_AVOID, BLK_STS_IOERR);

    return;

decompression_err:
    orca_err_inum_ratelimited(c, rbio->pos.inode, "decompression error");
    orca_rbio_error(rbio, READ_ERR, BLK_STS_IOERR);

    return;
}

static void
orca_read_endio(struct bio *bio)
{
    struct orca_read_bio *rbio = container_of(bio, struct orca_read_bio, bio);
    struct orca_fs *c = rbio->c;
    struct orca_dev *ca = orca_dev_bkey_exists(c, rbio->pick.ptr.dev);
    struct workqueue_struct *wq = NULL;
    enum rbio_context context = RBIO_CONTEXT_NULL;

    if (rbio->have_ioref) {
        orca_latency_acct(ca, rbio->submit_time, READ);
        percpu_ref_put(&ca->io_ref);
    }

    if (!rbio->split)
        rbio->bio.bi_end_io = rbio->end_io;

    if (orca_dev_inum_io_err_on(bio->bi_status, ca, rbio->pos.inode, rbio->pos.offset,
        "data read error: %s", orca_blk_status_to_str(bio->bi_status))) {
            orca_rbio_error(rbio, READ_RETRY_AVOID, bio->bi_status);
            return;
    }

    if (rbio->pick.ptr.cached && (((rbio->flags & ORCA_READ_RETRY_IF_STALE) &&
        race_fault()) || ptr_stale(ca, &rbio->pick.ptr))) {
            atomic_long_inc(&c->read_realloc_races);

            if (rbio->flags & ORCA_READ_RETRY_IF_STALE)
                orca_rbio_error(rbio, READ_RETRY, BLK_STS_AGAIN);
            else
                orca_rbio_error(rbio, READ_ERR, BLK_STS_AGAIN);

            return;
    }

    if (rbio->narrow_crcs || crc_is_compressed(rbio->pick.crc) ||
        orca_csum_type_is_encryption(rbio->pick.crc.csum_type))
            context = RBIO_CONTEXT_UNBOUND, wq = system_unbound_wq;
    else if (rbio->pick.crc.csum_type)
            context = RBIO_CONTEXT_HIGHPRI, wq = system_highpri_wq;

    orca_rbio_punt(rbio, __orca_read_endio, context, wq);
}

int
__orca_read_indirect_extent(struct btree_trans *trans, unsigned *offset_into_extent,
    struct bkey_on_stack *orig_k)
{
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 reflink_offset;
    int ret;

    reflink_offset = le64_to_cpu(bkey_i_to_reflink_p(orig_k->k)->v.idx) +
        *offset_into_extent;
    iter = orca_trans_get_iter(trans, BTREE_ID_REFLINK, POS(0, reflink_offset),
        BTREE_ITER_SLOTS);
    k = orca_btree_iter_peek_slot(iter);
    ret = bkey_err(k);

    if (ret)
        goto err;

    if (k.k->type != KEY_TYPE_reflink_v && k.k->type != KEY_TYPE_indirect_inline_data) {
        orca_err_inum_ratelimited(trans->c, orig_k->k->k.p.inode,
            "pointer to non-existant indirect extent");
        ret = -EIO;
        goto err;
    }

    *offset_into_extent = iter->pos.offset - bkey_start_offset(k.k);
    bkey_on_stack_reassemble(orig_k, trans->c, k);

err:
    orca_trans_iter_put(trans, iter);

    return ret;
}

int
__orca_read_extent(struct btree_trans *trans, struct orca_read_bio *orig,
    struct bvec_iter iter, struct bkey_s_c k, unsigned offset_into_extent,
    struct orca_io_failures *failed, unsigned flags)
{
    struct orca_fs *c = trans->c;
    struct extent_ptr_decode pick;
    struct orca_read_bio *rbio = NULL;
    struct orca_dev *ca;
    struct promote_op *promote = NULL;
    bool bounce = false, read_full = false, narrow_crcs = false;
    struct bpos pos = bkey_start_pos(k.k);
    int pick_ret;

    if (bkey_extent_is_inline_data(k.k)) {
        unsigned bytes = min_t(unsigned, iter.bi_size, bkey_inline_data_bytes(k.k));

        swap(iter.bi_size, bytes);
        memcpy_to_bio(&orig->bio, iter, bkey_inline_data_p(k));
        swap(iter.bi_size, bytes);
        bio_advance_iter(&orig->bio, &iter, bytes);
        zero_fill_bio_iter(&orig->bio, iter);

        goto out_read_done;
    }

    /* Hole or reservation--just zero fill */
    pick_ret = orca_bkey_pick_read_device(c, k, failed, &pick);

    if (!pick_ret)
        goto hole;

    if (pick_ret < 0) {
        orca_err_inum_ratelimited(c, k.k->p.inode, "no device to read from");
        goto err;
    }

    if (pick_ret > 0)
        ca = orca_dev_bkey_exists(c, pick.ptr.dev);

    if (flags & ORCA_READ_NODECODE) {
        /**
         * Can happen if we retry, and the extent we were going to read
         * has been merged in the meantime.
        **/
        if (pick.crc.compressed_size > orig->bio>bi_vcnt * PAGE_SECTORS)
            goto hole;

        iter.bi_size = pick.crc.compressed_size << 9;
        goto get_bio;
    }

    if (!(flags & ORCA_READ_LAST_FRAGMENT) || bio_flagged(&orig->bio, BIO_CHAIN))
        flags |= ORCA_READ_MUST_CLONE;

    narrow_crcs = !(flags & ORCA_READ_IN_RETRY) &&
        orca_can_narrow_extent_crcs(k, pick.crc);

    if (narrow_crcs && (flags & ORCA_READ_USER_MAPPED))
        flags |= ORCA_READ_MUST_BOUNCE;

    EBUG_ON(offset_into_extent + bvec_iter_sectors(iter) > k.k->size);

    if (crc_is_compressed(pick.crc) || (pick.crc.csum_type != ORCA_CSUM_NONE &&
        (bvec_iter_sectors(iter) != pick.crc.csum_type) &&
        (flags & ORCA_READ_USER_MAPPED)) || (flags & ORCA_READ_MUST_BOUNCE)) {
            read_full = true;
            bounce = true;
    }

    if (orig->opts.promote_target)
        promote = promote_alloc(c, iter, k, &pick, orig->opts, flags, &rbio,
            &bounce, &read_full);

    if (!read_full) {
        EBUG_ON(crc_is_compressed(pick.crc));
        EBUG_ON(pick.crc.csum_type && (bvec_iter_sectors(iter) !=
            pick.crc.uncompressed_size || bvec_iter_sectors(iter) !=
            pick.crc.live_size || pick.crc.offset || offset_into_extent));

        pos.offset += offset_into_extent;
        pick.ptr.offset += pick.crc.offset + offset_into_extent;
        pick.crc.uncompressed_size = bvec_iter_sectors(iter);
        pick.crc.live_size = bvec_iter_sectors(iter);
        offset_into_extent = 0;
    }

get_bio:
    if (rbio) {
        /**
         * Promote already allocated bounce role.
         *
         * Promote needs to allocate a bio big enough for uncompressing
         * data in the write path, but we're not going to use it all
         * here.
        **/
        EBUG_ON(rbio->bio.bi_iter.bi_size < pick.crc.compressed_size << 9);
        rbio->bio.bi_iter.bi_size = pick.crc.compressed_size << 9;
    } else if (bounce) {
        unsigned sectors = pick.crc.compressed_size;

        rbio = rbio_init(bio_alloc_bioset(GFP_NOIO, DIV_ROUND_UP(sectors,
            PAGE_SECTORS), &c->bio_read_split), orig->opts);
        orca_bio_alloc_pages_pool(c, &rbio->bio, sectors << 9);
        rbio->bounce = true;
        rbio->split = true;
    } else if (flags & ORCA_READ_MUST_CLONE) {
        /**
         * Have to clone if there were any splits, due to error reporting
         * issues (if a split errored, and retrying didn't work, when it
         * reports the error to its parent (us) we don't know if the error
         * was from our bio, and we should retry, or from the whole bio,
         * in which case we don't want to retry and lose the error).
        **/
        rbio = rbio_init(bio_clone_fast(&orig->bio, GFP_NOIO, &c->bio_read_split),
            orig->opts);
        rbio->bio.bi_iter = iter;
        rbio->split = true;
    } else {
        rbio = orig;
        rbio->bio.bi_iter = iter;
        EBUG_ON(bio_flagged(&rbio->bio, BIO_CHAIN));
    }

    EBUG_ON(bio_sectors(&rbio->bio) != pick.crc.compressed_size);

    rbio->c = c;
    rbio->submit_time = local_clock();

    if (rbio->split)
        rbio->parent = orig;
    else
        rbio->parent = orig;

    rbio->bvec_iter = iter;
    rbio->offset_into_extent = offset_into_extent;
    rbio->flags = flags;
    rbio->have_ioref = pick_ret > 0 && orca_dev_get_ioref(ca, READ);
    rbio->narrow_crcs = narrow_crcs;
    rbio->hole = 0;
    rbio->retry = 0;
    rbio->context = 0;
    rbio->devs_have = orca_bkey_devs(k);
    rbio->pick = pick;
    rbio->pos = pos;
    rbio->version = k.k->version;
    rbio->promote = promote;

    INIT_WORK(&rbio->work, NULL);

    rbio->bio.bi_opf = orig->bio.bi_opf;
    rbio->bio.bi_iter.bi_sector = pick.ptr.offset;
    rbio->bio.bi_end_io = orca_read_endio;

    if (rbio->bounce)
        trace_read_bounce(&rbio->bio);

    if (pick.ptr.cached)
        orca_bucket_io_time_reset(trans, pick.ptr.dev, PTR_BUCKET_NR(ca, &pick.ptr), READ);

    if (!(flags & (ORCA_READ_IN_RETRY | ORCA_READ_LAST_FRAGMENT))) {
        bio_inc_remaining(&orig->bio);
        trace_read_split(&orig->bio);
    }

    if (!rbio->pick.idx) {
        if (!rbio->have_ioref) {
            orca_err_inum_ratelimited(c, k.k->p.inode, "no device to read from");
            orca_rbio_error(rbio, READ_RETRY_AVOID, BLK_STS_IOERR);
            goto out;
        }

        this_cpu_add(ca->io_done->sectors[READ][ORCA_DATA_user],
            bio_sectors(&rbio->bio));
        bio_set_dev(&rbio->bio, ca->disk_sb.bdev);

        if (likely(!(flags & ORCA_READ_IN_RETRY)))
            submit_bio(&rbio->bio);
        else
            submit_bio_wait(&rbio->bio);
    } else {
        /* Attempting reconstruct read */
        if (orca_ec_read_extent(c, rbio)) {
            orca_rbio_error(rbio, READ_RETRY_AVOID, BLK_STS_IOERR);
            goto out;
        }

        if (likely(!(flags & ORCA_READ_IN_RETRY)))
            bio_endio(&rbio->bio);
    }

out:
    if (likely(!(flags & ORCA_READ_IN_RETRY))) {
        return 0;
    } else {
        int ret;

        rbio->context = RBIO_CONTEXT_UNBOUND;
        orca_read_endio(&rbio->bio);
        ret = rbio->retry;
        rbio = orca_rbio_free(rbio);

        if (ret == READ_RETRY_AVOID) {
            orca_mark_io_features(failed, &pick);
            ret = READ_RETRY;
        }

        return ret;
    }

err:
    if (flags & ORCA_READ_IN_RETRY)
        return READ_ERR;

    orig->bio.bi_status = BLK_STS_IOERR;
    goto out_read_done;

hole:
    /**
     * Won't normally happen in ORCA_READ_NODECODE (orca_move_extent()) path,
     * but if we retry and the extent we wanted to read no longer exists we
     * have to signal that.
    **/
    if (flags & ORCA_READ_NODECODE)
        orig->hole = true;

    zero_fill_bio_iter(&orig->bio, iter);

out_read_done:
    if (flags & ORCA_READ_LAST_FRAGMENT)
        orca_rbio_done(orig);

    return 0;
}

void
orca_read(struct orca_fs *c, struct orca_read_bio *rbio, u64 inode)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_on_stack sk;
    struct bkey_s_c k;
    unsigned flags = ORCA_READ_RETRY_IF_STALE | ORCA_READ_MAY_PROMOTE |
        ORCA_READ_USER_MAPPED;
    int ret;

    BUG_ON(rbio->_state);
    BUG_ON(flags & ORCA_READ_NODECODE);
    BUG_ON(flags & ORCA_READ_IN_RETRY);

    rbio->c = c;
    rbio->start_time = local_clock();
    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, 0, 0);

retry:
    orca_trans_begin(&trans);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS(inode,
        rbio->bio.bi_iter.bi_sector), BTREE_ITER_SLOTS);

    for (;;) {
        unsigned bytes, sectors, offset_into_extent;

        orca_btree_iter_set_pos(iter, POS(inode, rbio->bio.bi_iter.bi_sector));
        k = orca_btree_iter_peek_slot(iter);
        ret = bkey_err(k);

        if (ret)
            goto err;

        offset_into_extent = iter->pos.offset - bkey_start_offset(k.k);
        sectors = k.k->size - offset_into_extent;
        bkey_on_stack_reassemble(&sk, c, k);
        ret = orca_read_indirect_extent(&trans, &offset_into_extent, &sk);

        if (ret)
            goto err;

        k = bkey_i_to_s_c(sk.k);

        /**
         * With indirect extents, the amount of data to read is the min
         * of the original extent and the indirect extent.
        **/
        sectors = min(sectors, k.k->size - offset_into_extent);

        /**
         * Unlock the iterator while the btree node's lock is still in
         * cache, before doing the IO.
        **/
        orca_trans_unlock(&trans);
        bytes = min(sectors, bio_sectors(&rbio->bio)) << 9;
        swap(rbio->bio.bi_iter.bi_size, bytes);

        if (rbio->bio.bi_iter.bi_size == bytes)
            flags |= ORCA_READ_LAST_FRAGMENT;

        orca_read_extent(&trans, rbio, k, offset_into_extent, flags);

        if (flags & ORCA_READ_LAST_FRAGMENT)
            break;

        swap(rbio->bio.bi_iter.bi_size, bytes);
        bio_advance(&rbio->bio, bytes);
    }

out:
    orca_trans_exit(&trans);
    bkey_on_stack_exit(&sk, c);
    return;

err:
    if (ret == -EINTR)
        goto retry;

    orca_err_inum_ratelimited(c, inode, "read error %i from btree lookup", ret);
    rbio->bio.bi_status = BLK_STS_IOERR;
    orca_rbio_done(rbio);
    goto out;
}

void
orca_fs_io_exit(struct orca_fs *c)
{
    if (c->promote_table.tbl)
        rhashtable_destroy(&c->promote_table);

    mempool_exit(&c->bio_bounce_pages);
    bioset_exit(&c->bio_write);
    bioset_exit(&c->bio_read_split);
    bioset_exit(&c->bio_read);
}

int
orca_fs_io_init(struct orca_fs *c)
{
    if (bioset_init(&c->bio_read, 1, offsetof(struct orca_read_bio, bio),
        BIOSET_NEED_BVECS) || bioset_init(&c->bio_read_split, 1,
        offsetof(struct orca_read_bio, bio), BIOSET_NEED_BVECS) ||
        bioset_init(&c->bio_write, 1, offsetof(struct orca_write_bio, bio),
        BIOSET_NEED_BVECS) || mempool_init_page_pool(&c->bio_bounce_pages,
        max_t(unsigned, c->opts.btree_node_size, c->sb.encoded_extent_max) /
        PAGE_SECTORS, 0) || rhashtable_init(&c->promote_table,
        &orca_promote_params))
            return -ENOMEM;

    return 0; 
}
