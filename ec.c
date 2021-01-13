#include <linux/sort.h>

#include "orcafs.h"
#include "alloc_foreground.h"
#include "bkey_on_stack.h"
#include "bset.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
#include "disk_groups.h"
#include "ec.h"
#include "error.h"
#include "io.h"
#include "keylist.h"
#include "recovery.h"
#include "super-io.h"
#include "util.h"

#ifdef __KERNEL__

#include <linux/raid/pq.h>
#include <linux/raid/xor.h>

static void
raid5_recov(unsigned disks, unsigned failed_idx, size_t size, void **data)
{
    unsigned i = 2, nr;

    BUG_ON(failed_idx >= disks);
    swap(data[0], data[failed_idx]);
    memcpy(data[0], data[1], size);

    while (i < disks) {
        nr = min_t(unsigned, disks - i, MAX_XOR_BLOCKS);
        xor_blocks(nr, size, data[0], data + i);
        i += nr;
    }

    swap(data[0], data[failed_idx]);
}

static void
raid_gen(int nd, int np, size_t size, void **v)
{
    if (np >= 1)
        raid5_recov(nd + np, size, v);

    if (np >= 2)
        raid6_call.gen_syndrome(nd + np, size, v);

    BUG_ON(np > 2);
}

static void
raid_rec(int nr, int *ir, int nd, int np, size_t size, void **v)
{
    switch (nr) {
    case 0:
        break;

    case 1:
        if (ir[0] < nd + 1)
            raid5_recov(nd + 1, ir[0], size, v);
        else
            raid6_call.gen_syndrome(nd + np, size, v);

        break;

    case 2:
        if (ir[1] < nd) {
            raid6_2data_recov(nd + np, size, ir[0], ir[1], v);
        } else if (ir[0] < nd) {

            if (ir[1] == nd) {
                raid6_datap_recov(nd + np, size, ir[0], v);
            } else {
                raid5_recov(nd + 1, ir[0], size, v);
                raid6_call.gen_syndrome(nd + np, size, v);
            }
        } else {
            raid_gen(nd, np, size, v);
        }

        break;

    default:
        BUG();
    }
}

#else

#include <raid/raid.h>
#endif

struct ec_bio {
    struct orca_dev *ca;
    struct ec_stripe_buf *buf;
    size_t idx;
    struct bio bio;
};

/**
 * STRIPES BTREE KEYS.
**/
const char *
orca_stripe_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    const struct orca_stripe *s = bkey_s_c_to_stripe(k).v;

    if (k.k->p.inode)
        return "invalid stripe key";

    if (bkey_val_bytes(k.k) < sizeof(*s))
        return "incorrect value size";

    if (bkey_val_bytes(k.k) < sizeof(*s) || bkey_val_u64s(k.k) < stripe_val_u64s(s))
        return "incorrect value size";

    return orca_bkey_ptrs_invalid(c, k);
}

void
orca_stripe_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    const struct orca_stripe *s = bkey_s_c_to_stripe(k).v;
    unsigned i;

    pr_buf(out, "algo %u sectors %u blocks %u:%u csum %u gran %u", s->algorithm,
        le16_to_cpu(s->sectors), s->nr_blocks - s->nr_redundant, s->nr_redundant,
        s->csum_type, 1U << s->csum_granularity_bits);

    for (i = 0; i < s->nr_blocks; i++)
        pr_buf(out, " %u:%llu:%u", s->ptrs[i].dev, (u64)s->ptrs[i].offset,
            stripe_blockcount_get(s, i));
}

static int
ptr_matches_stripe(struct orca_fs *c, struct orca_stripe *v,
    const struct orca_extent_ptr *ptr)
{
    unsigned i;

    for (i = 0; i < b->nr_blocks - v->nr_redundant; i++) {
        const struct orca_extent_ptr *ptr2 = v->ptrs + i;

        if (ptr->dev == ptr2->dev && ptr->gen == ptr2->gen &&
            ptr->offset >= ptr2->offset &&
            ptr->offset < ptr2->offset + le16_to_cpu(v->sectors))
                return i;
    }

    return -1;
}

static int
extent_matches_stripe(struct orca_fs *c, struct orca_stripe *v, struct bkey_s_c k)
{
    switch (k.k->type) {
    case KEY_TYPE_extent:
        struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
        const struct orca_extent_ptr p;
        int idx;

        extent_for_each_ptr(e, ptr) {
            idx = ptr_matches_stripe(c, v, ptr);

            if (idx >= 0)
                return idx;
        }

        break;
    }

    return -1;
}

static bool
extent_has_stripe_ptr(struct bkey_s_c k, u64 idx)
{
    switch (k.k->type) {
    case KEY_TIME_extent:
        struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
        const union orca_extent_entry *entry;

        extent_for_each_entry(e, entry) {
            if (extent_entry_type(entry) == ORCA_EXTENT_ENTRY_stripe_ptr &&
                entry->stripe_ptr.idx == idx)
                    return true;
        }

        break;
    }

    return false;
}

static void
ec_generate_checksums(struct ec_stripe_buf *buf)
{
    struct orca_stripe *v = &buf->key.v;
    unsigned csum_granularity = 1 << v->csum_granularity_bits;
    unsigned csum_per_device = stripe_csums_per_device(v);
    unsigned csum_bytes = orca_crc_bytes[v->csum_type];
    unsigned i, j;

    if (!csum_bytes)
        return;

    BUG_ON(buf->offset);
    BUG_ON(buf->size != le16_to_cpu(v->sectors));

    for (i = 0; i < v->nr_blocks; i++) {
        for (j = 0; j < csum_per_device; j++) {
            unsigned offset = j << v->csum_granularity_bits;
            unsigned len = min(csum_granularity, buf->size - offset);

            struct orca_csum csum = orca_checksum(NULL, v->csum_type,
                null_nonce(), buf->data[i] + (offset << 9), len << 9);

            memcpy(stripe_csum(v, i, j), &csum, csum_bytes);
        }
    }
}

static void
ec_validate_checksums(struct orca_fs *c, struct ec_stripe_buf *buf)
{
    struct orca_stripe *v = &buf->key.v;
    unsigned csum_granularity = 1 << v->csum_granularity_bits;
    unsigned csum_bytes = orca_crc_bytes[v->csum_type];
    unsigned i;

    if (!csum_bytes)
        return;

    for (i = 0; i < v->nr_blocks; i++) {
        unsigned offset = buf->offset;
        unsigned end = buf->offset + buf->size;

        if (!test_bit(i, buf->valid))
            continue;

        while (offset < end) {
            unsigned j = offset >> v->csum_granularity_bits;
            unsigned len = min(csum_granularity, end - offset);
            struct orca_csum csum;

            BUG_ON(offset & (csum_granularity - 1));
            BUG_ON(offset + len != le16_to_cpu(v->sectors) &&
                ((offset + len) & (csum_granularity - 1)));

            csum = orca_checksum(NULL, v->csum_type, null_nonce(), buf->data[i]
                + ((offset - buf->offset) << 9), len << 9);

            if (memcmp(stripe_csum(v, i, j), &csum, csum_bytes)) {
                __orca_io_error(c, "checksum error while doing reconstruct "
                    "read (%u:%u)", i, j);
                clear_bit(i, buf->valid);
                break;
            }

            offset += len;
        }
    }
}

static void
ec_generate_ec(struct ec_stripe_buf *buf)
{
    struct orca_stripe *v = &buf->key.v;
    unsigned nr_data = v->nr_blocks - v->nr_redundant;
    unsigned bytes = le16_to_cpu(v->sectors) << 9;

    raid_gen(nr_data, v->nr_redundant, bytes, buf->data);
}

static unsigned
__ec_nr_failed(struct ec_strupe_buf *buf, unsigned nr)
{
    return nr - bitmap_weight(buf->valid, nr);
}

static int
ec_do_recov(struct orca_fs *c, struct ec_stripe_buf *buf)
{
    struct orca_stripe *v = &buf->key.v;
    unsigned i, failed[EC_STRIPE_MAX], nr_failed = 0;
    unsigned nr_data = v->nr_blocks - v->nr_redundant;
    unsigned bytes = buf->size << 9;

    if (ec_nr_failed(buf) > v->nr_redundant) {
        __orca_io_error(c, "error doing reconstruct read: unable to read "
            "enough blocks");
        return -1;
    }

    for (i = 0; i < nr_data; i++) {
        if (!test_bit(i, buf->valid))
            failed[nr_failed++] = i;
    }

    raid_rec(nr_failed, failed, nr_data, v->nr_redundant, bytes, buf->data);

    return 0;
}

static void
ec_block_endio(struct bio *bio)
{
    struct ec_bio *ec_bio = container_of(bio, struct ec_bio, bio);
    struct orca_dev *ca = ec_bio->ca;
    struct closure *cl = bio->bi_private;

    if (orca_dev_io_err_on(bio->bi_status, ca, "erasure coding %s: %s",
        bio_data_dir(bio) ? "write" : "read", orca_blk_status_to_str(bio->bi_status)))
            clear_bit(ec_bio->idx, ec_bio->buf->valid);

    bio_put(&ec_bio->bio);
    percpu_ref_put(&ca->io_ref);
    closure_put(cl);
}

static void
ec_block_io(struct orca_fs *c, struct ec_stripe_buf *buf, unsigned rw,
    unsigned idx, struct closure *cl)
{
    struct orca_stripe *v = &buf->key.v;
    unsigned offset = 0, bytes = buf->size << 9;
    struct orca_extent_ptr *ptr = &v->ptr[idx];
    struct orca_dev *ca = orca_dev_bkey_exists(c, ptr->dev);

    if (!orca_dev_get_ioref(ca, rw)) {
        clear_bit(idx, buf->valid);
        return;
    }

    while (offset < bytes) {
        unsigned nr_lovecs = min_t(size_t, BIO_MAX_PAGES,
            DIV_ROUND_UP(bytes, PAGE_SIZE));
        unsigned b = min_t(size_t, bytes - offset, nr_lovecs << PAGE_SHIFT);
        struct ec_bio *ec_bio;

        ec_bio = container_of(bio_alloc_bioset(GFP_KERNEL, nr_lovecs,
            &c->ec_bioset), struct ec_bio, bio);

        ec_bio->ca = ca;
        ec_bio->buf = buf;
        ec_bio->idx = idx;

        bio_set_dev(&ec_bio->bio, ca->disk_sb.bdev);
        bio_set_up_attrs(&ec_bio->bio, rw, 0);

        ec_bio->bio.bi_iter.bi_sector = ptr->offset - buf->offset + (offset >> 9);
        ec_bio->bio.bi_end_io = ec_block_endio;
        ec_bio->bio.bi_private = cl;

        orca_bio_map(&ec_bio->bio, buf->data[idx] + offset, b);
        closure_get(cl);
        percpu_ref_get(&ca->io_ref);
        submit_bio(&ec_bio->bio);

        offset += b;
    }

    percpu_ref_put(&ca->io_ref);
}

int
orca_ec_read_extent(struct orca_fs *c, struct orca_read_bio *rbio)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct ec_stripe_buf *buf;
    struct closure cl;
    struct bkey_s_c k;
    struct orca_stripe *v;
    unsigned stripe_idx;
    unsigned offset, end;
    unsigned i, nr_data, csum_granularity;
    int ret = 0, idx;

    closure_init_stack(&cl);
    BUG_ON(!rbio->pick.has_ec);

    stripe_idx = rbio->pick.ec.idx;
    buf = kzalloc(sizeof(*buf), GFP_NOIO);

    if (!buf)
        return -ENOMEM;

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EC, POS(0, stripe_idx),
        BTREE_ITER_SLOTS);
    k = orca_btree_iter_peek_slot(iter);

    if (bkey_err(k) || k.k->type != KEY_TYPE_stripe) {
        orca_io_error(c, "error doing reconstruct read: stripe not found");
        kfree(buf);

        return orca_trans_exit(&trans) ?: -EIO;
    }

    bkey_reassemble(&buf->key.k_i, k);
    orca_trans_exit(&trans);

    v = &buf->key.v;
    nr_data = v->nr_blocks - v->nr_redundant;
    idx = ptr_matches_stripe(c, v, &rbio->pick.ptr);
    BUG_ON(idx < 0);

    csum_granularity = 1U << v->csum_granularity_bits;
    offset = rbio->bio.bi_iter.bi_sector - v->ptrs[idx].offset;
    end = offset + bio_sectors(&rbio->bio);

    BUG_ON(end > le16_to_cpu(v->sectors));

    buf->offset = round_down(offset, csum_granularity);
    buf->size = min_t(unsigned, le16_to_cpu(v->sectors), round_up(end,
        csum_granularity)) - buf->offset;

    for (i = 0; i < v->nr_blocks; i++) {
        buf->data[i] = kmalloc(buf->size << 9, GFP_NOIO);

        if (!buf->data[i]) {
            ret = -ENOMEM;
            goto err;
        }
    }

    memset(buf->valid, 0xFF, sizeof(buf->valid));

    for (i = 0; i < v->nr_blocks; i++) {
        struct orca_extent_ptr *ptr = v->ptrs + i;
        struct orca_dev *ca = orca_dev_bkey_exists(c, ptr->dev);

        if (ptr_stale(ca, ptr)) {
            __orca_io_error(c, "error doing reconstruct read: stale pointer");
            clear_bit(i, buf->valid);
            continue;
        }

        ec_block_io(c, buf, REQ_OP_READ, i, &cl);
    }

    closure_sync(&cl);

    if (ec_nr_failed(buf) > v->nr_redundant) {
        __orc_io_error(c, "error doing reconstruct read: unable to read enough"
            " blocks");
        ret = -EIO;
        goto err;
    }

    ec_validate_checksums(c, buf);
    ret = ec_do_recov(c, buf);

    if (ret)
        goto err;

    memcpy_to_bio(&rbio->bio, rbio->bio.bi_iter, buf->data[idx] +
        ((offset - buf->offset) << 9));

err:
    for (i = 0; i < v->nr_blocks; i++)
        kfree(buf->data[i]);

    kfree(buf);

    return ret;
}

static int
__ec_stripe_mem_alloc(struct orca_fs *c, size_t idx, gfp_t gfp)
{
    ec_stripes_heap n, *h = &c->ec_stripes_heap;

    if (idx >= h->size) {
        if (!init_heap(&n, max(1024UL, roundup_pow_of_two(idx + 1)), gfp))
            return -ENOMEM;

        spin_lock(&c->ec_stripes_heap_lock);

        if (n.size > h->size) {
            memcpy(n.data, h->data, h->used * sizeof(h->data[0]));
            n.used = h->used;
            swap(*h, n);
        }

        spin_unlock(&c->ec_stripe_heap_lock);
        free_heap(&n);
    }

    if (!genradix_ptr_alloc(&c->stripes[0], idx, gfp))
        return -ENOMEM;

    if (c->gc_pos.phase != GC_PHASE_NOT_RUNNING &&
        !genradix_ptr_alloc(&c->stripes[1], idx, gfp))
            return -ENOMEM;

    return 0;
}

static int
ec_stripe_mem_alloc(struct orca_fs *c, struct btree_iter *iter)
{
    size_t idx = iter->pos.offset;
    int ret = 0;

    if (!__ec_stripe_mem_alloc(c, idx, GFP_NOWAIT | __GFP_NOWARN))
        return ret;

    orca_trans_unlock(iter->trans);
    ret = -EINTR;

    if (!__ec_stripe_mem_alloc(c, idx, GFP_KERNEL))
        return ret;

    return -ENOMEM;
}

static ssize_t
stripe_idx_to_delete(struct orca_fs *c)
{
    ec_stripes_heap *h = &c->ec_stripes_heap;

    return h->used && h->data[0].blocks_nonempty == 0 ?
        h->data[0].idx : -1;
}

static inline int
ec_stripes_heap_cmp(ec_stripe_heap *h, struct ec_stripe_heap_entry l,
    struct ec_strupe_heap_entry r)
{
    return ((l.blocks_nonempty > r.blocks_nonempty) -
        (l.blocks_nonempty < r.blocks_nonempty));
}

static inline void
ec_stripes_heap_set_backpointer(ec_stripes_heap *n, size_t i)
{
    struct orca_fs *c = container_of(h, struct orca_fs, ec_stripes_heap);

    genradix_ptr(&c->stripes[0], idx);
}

static void
heap_verify_backpointer(struct orca_fs *c, size_t idx)
{
    ec_stripes_heap *h = &c->ec_stripes_heap;
    struct stripe *m = genradix_ptr(&c->stripes[0], idx);

    BUG_ON(!m->alive);
    BUG_ON(m->heap_idx >= h->used);
    BUG_ON(h->data[m->heap_idx].idx != idx);
}

void
orca_stripes_heap_del(struct orca_fs *c, struct stripe *m, size_t idx)
{
    if (!m->on_heap)
        return;

    m->on_heap = false;
    heap_verify_backpointer(c, idx);
    heap_del(&c->ec_stripes_heap, m->heap_idx, ec_stripes_heap_cmp,
        ec_stripes_heap_set_backpointer);
}

void
orca_stripes_heap_insert(struct orca_fs *c, struct stripe *m, size_t idx)
{
    if (m->on_heap)
        return;

    BUG_ON(heap_full(&c->ec_stripes_heap));
    m->on_heap = true;

    heap_add(&c->ec_stripes_heap, ((struct ec_stripe_heap_entry) {
        .idx = idx,
        .block_nonempty = m->blocks_nonempty,
    }),
        ec_stripes_heap_cmp, ec_stripes_heap_set_backpointer);

    heap_verify_backpointer(c, idx);
}

void
orca_stripes_heap_update(struct orca_fs *c, struct stripe *m, size_t idx)
{
    ec_stripes_heap *h = &c->ec_stripes_heap;
    size_t i;

    if (!m->on_heap)
        return;

    heap_verify_backpointer(c, idx);
    h->data[m->heap_idx].blocks_nonempty = m->blocks_nonempty;
    i = m->heap_idx;

    heap_sift_up(h, i, ec_stripes_heap_cmp, ec_stripes_heap_set_backpointer);
    heap_sift_down(h, i, ec_stripes_heap_cmp, ec_stripes_heap_set_backpointer);

    heap_verify_backpointer(c, idx);

    if (stripe_idx_to_delete(c) >= 0 && !percpu_ref_is_dying(&c->writes))
        schedule_work(&c->ec_stripe_delete_work);
}

static int
ec_stripe_delete(struct orca_fs *c, size_t idx)
{
    return orca_btree_delete_range(c, BTREE_ID_EC, POS(0, idx), POS(0, idx + 1),
        NULL);
}

static void
ec_stripe_delete_work(struct work_struct *work)
{
    struct orca_fs *c = container_of(work, struct orca_fs, ec_stripe_delete_work);
    ssize_t idx;

    for (;;) {
        spin_lock(&c->ec_stripes_heap_lock);
        idx = stripe_idx_to_delete(c);

        if (idx < 0) {
            spin_unlock(&c->ec_stripes_heap_lock);
            break;
        }

        orca_stripes_heap_del(c, genradix_ptr(&c->stripes[0], idx), idx);
        spin_unlock(&c->ec_stripes_heap_lock);

        if (ec_stripe_delete(c, idx))
            break;
    }
}

static int
ec_stripe_bkey_insert(struct orca_fs *c, struct bkey_i_stripe *stripe)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bpos start_pos = POS(0, c->ec_stripe_hint);
    int ret;

    orca_trans_init(&trans, c, 0, 0);

retry:
    orca_trans_begin(&trans);

    for_each_btree_key(&trans, iter, BTREE_ID_EC, start_pos,
        BTREE_ITER_SLOTS | BTREE_ITER_INTENT, k, ret) {
            if (bkey_cmp(k.k->p, POS(0, U32_MAX)) > 0) {
                if (start_pos.offset) {
                    start_pos = POS_MIN;
                    orca_btree_iter_set_pos(iter, start_pos);
                    continue;
                }

                ret = -ENOSPC;
                break;
            }

            if (bkey_deleted(k.k))
                goto found_slot;
    }

    goto err;

found_slot:
    start_pos = iter->pos;
    ret = ec_stripe_mem_alloc(c, iter);

    if (ret)
        goto err;

    stripe->k.p = iter->pos;
    orca_trans_update(&trans, iter, &stripe->k_i, 0);
    ret = orca_trans_commit(&trans, NULL, NULL, BTREE_INSERT_NOFAIL);

err:
    orca_trans_iter_put(&trans, iter);

    if (ret == -EINTR)
        goto retry;

    c->ec_stripe_hint = ret ? start_pos.offset : start_pos.offset + 1;
    orca_trans_exit(&trans);

    return ret;
}

static void
extent_stripe_ptr_add(struct bkey_s_extent e, struct ec_stripe_buf *s,
    struct orca_extent_ptr *ptr, unsigned block)
{
    struct orca_extent_stripe_ptr *dst = (void *)ptr;
    union orca_extent_entry *end = extent_entry_last(e);

    memmove_u64s_up(dst + 1, dst, (u64 *)end - (u64 *)dst);
    e.k->u64s += sizeof(*dst) / sizeof(u64);

    *dst = (struct orca_extent_stripe_ptr) {
        .type = 1 << ORCA_EXTENT_ENTRY_stripe_ptr,
        .block = block,
        .idx = s->key.k.p.offset;
    };
}

static int
ec_stripe_update_ptrs(struct orca_fs *c, struct ec_stripe_buf *s,
    struct bkey *pos)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_s_extent e;
    struct bkey_on_stack sk;
    int ret = 0, dev, idx;

    bkey_on_stack_init(&sk);
    orca_trans_init(&trans, c, BTREE_ITER_MAX, 0);

    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, bkey_start_pos(pos),
        BTREE_ITER_INTENT);

    while ((k = orca_btree_iter_peek(iter)).k && !(ret = bkey_err(k)) &&
        bkey_cmp(bkey_start_pos(k.k), pos->p) < 0) {
            struct orca_extent_ptr *ptr, *ec_ptr = NULL;

            if (extent_has_stripe_ptr(k, s->key.k.p.offset)) {
                orca_btree_iter_next(iter);
                continue;
            }

            idx = extent_matches_stripe(c, &s->key.v, k);

            if (idx < 0) {
                orca_btree_iter_next(iter);
                continue;
            }

            dev = s->key.v.ptrs[idx].dev;
            bkey_on_stack_reassemble(&sk, c, k);
            e = bkey_i_to_s_extent(sk.k);
            orca_bkey_drop_ptrs(e.s, ptr, ptr->dev != dev);
            ec_ptr = (void *)orca_bkey_has_device(e.s_c, dev);

            BUG_ON(!ec_ptr)

            extent_stripe_ptr_add(e, s, ec_ptr, idx);
            orca_btree_iter_set_pos(iter, bkey_start_pos(&sk.k->k));
            orca_trans_update(&trans, iter, sk.k, 0);
            ret = orca_trans_commit(&trans, NULL, NULL, BTREE_INSERT_FAIL |
                BTREE_INSERT_USE_RESERVE);

            if (ret == -EINTR)
                ret = 0;

            if (ret)
                break;
    }

    orca_trans_exit(&trans);
    bkey_on_stack_exit(&sk, c);

    return ret;
}

/**
 * Data buckets of new stripe all written: create the stripe.
**/
static void
ec_stripe_create(struct ec_stripe_new *s)
{
    struct orca_fs *c = s->c;
    struct open_bucket *ob;
    struct bkey_i *k;
    struct stripe *m;
    struct orca_stripe *v = &s->stripe.key.v;
    unsigned i, nr_data = v->nr_blocks - v->nr_redundant;
    struct closure cl;
    int ret;

    BUG_ON(s->h->s == s);
    closure_init_stack(&cl);

    if (s->err) {
        if (s->err != -EROFS)
            orca_err(c, "error creating stripe: error writing data buckets");
        goto err;
    }

    BUG_ON(!s->allocated);

    if (!percpu_ref_tryget(&c->writes))
        goto err;

    BUG_ON(bitmap_weight(s->blocks_allocated, s->blocks.nr) != s->blocks.nr);
    ec_generate_ec(&s->stripe);
    ec_generate_checksums(&s->stripe);

    for (i = nr_data; i < v->nr_blocks; i++) {
        if (!test_bit(i, s->stripe.valid)) {
            orca_err(c, "error create stripe: error writing redundancy buckets");
            goto err_put_writes;
        }
    }

    ret = s->existing_stripe ? orca_btree_insert(c, BTREE_ID_EC, &s->stripe.key.k_i,
        NULL, NULL, BTREE_INSERT_NOFAIL) : ec_stripe_bkey_insert(c, &s->stripe.key);

    if (ret) {
        orca_err(c, "error creating stripe: error creating stripe key");
        goto err_put_writes;
    }

    for_each_keylist_key(&s->keys, k) {
        ret = ec_stripe_update_ptrs(c, &s->stripe, &k->k);

        if (ret) {
            orca_err(c, "error create stripe: error updating pointers");
            break;
        }
    }

    spin_lock(&c->ec_stripe_heap_lock);
    m = genradix_ptr(&c->stripes[0], s->stripe.key.k.p.offset);

#if 0
    pr_info("created a %s stripe %llu", s->existing_stripe ?
        "existing" : "new", s->stripe.key.k.p.offset);
#endif

    BUG_ON(m->on_heap);
    orca_stripes_heap_insert(c, m, s->stripe.key.k.p.offset);
    spin_unlock(&c->ec_stripes_heap_lock);

err_put_written:
    percpu_ref_put(&c->writes);

err:
    open_bucket_for_each(c, &s->blocks, ob, i) {
        ob->ec = NULL;
        __orca_open_bucket_put(c, ob);
    }

    orca_open_buckets_put(c, &s->parity);
    orca_keylist_free(&s->keys, s->inline_keys);

    for (i = 0; i < s->stripe.key.v.nr_blocks; i++)
        kvpfree(s->stripe.data[i], s->stripe.size << 9);

    kfree(s);
}

static void
ec_stripe_create_work(struct work_struct *work)
{
    struct orca_fs *c = container_of(work, struct orca_fs, ec_stripe_create_work);
    struct ec_stripe_new *s, *n;

restart:
    mutex_lock(&c->ec_stripe_new_lock);

    list_for_each_entry_safe(s, n, &c->ec_stripe_new_list, list) {
        if (!atomic_read(&s->pin)) {
            list_del(&s->list);
            mutex_unlock(&c->ec_stripe_new_lock);
            ec_stripe_create(s);
            goto restart;
        }
    }

    mutex_unlock(&c->ec_stripe_new_lock);
}

static void
ec_stripe_new_put(struct orca_fs *c, struct ec_stripe_new *s)
{
    BUG_ON(atomic_read(&s->pin) <= 0);

    if (atomic_dec_and_test(&s->pin)) {
        BUG_ON(!s->pending);
        queue_work(system_long_wq, &c->ec_stripe_create_work);
    }
}

static void
ec_stripe_set_pending(struct orca_fs *c, struct ec_stripe_head *h)
{
    struct ec_stripe_new *s = h->s;

    BUG_ON(!s->allocated && !s->err);
    h->s = NULL;
    s->pending = true;

    mutex_lock(&c->ec_stripe_new_lock);
    list_add(&s->list, &c->ec_stripe_new_list);
    mutex_unlock(&c->ec_stripe_new_list);
    ec_stripe_new_put(c, s);
}

/**
 * Have a full bucket--hand it off to be erasure coded.
**/
void
orca_ec_bucket_written(struct orca_fs *c, struct open_bucket *ob)
{
    struct ec_stripe_new *s = ob->ec;

    if (ob->sectors_free)
        s->err = -1;

    ec_stripe_new_put(c, s);
}

void
orca_ec_bucket_cancel(struct orca_fs *c, struct open_bucket *ob)
{
    struct ec_stripe_new *s = ob->ec;

    s->err = -EIO;
}

void *
orca_writepoint_ec_buf(struct orca_fs *c, struct write_point *wp)
{
    struct open_bucket *ob = ec_open_bucket(c, &wp->ptrs);
    struct ec_stripe_new *ec;

    if (!ob)
        return;

    ec = ob->ec;
    mutex_lock(&ec->lock);

    if (orca_keylist_realloc(&ec->keys, ec->inline_keys, ARRAY_SIZE(ec->inline_keys),
        BKEY_U64s))
            BUG();

    bkey_init(&ec->keys.top->k);
    ec->keys.top->k.p = pos;
    orca_key_resize(&ec->keys.top->k, sectors);
    orca_keylist_push(&ec->keys);
    mutex_unlock(&ec->lock);
}

static int
unsigned_cmp(const void *_l, const void *_r)
{
    unsigned l = *((const unsigned *)_l);
    unsigned r = *((const unsigned *)_r);

    return cmp_int(l, r);
}

/**
 * Pick the most common bucket size.
**/
static unsigned
pick_blocksize(struct orca_fs *c, struct orca_devs_mask *devs)
{
    struct orca_dev *ca;
    unsigned i, nr = 0, size[ORCA_SB_MEMBERS_MAX];

    struct {
        unsigned nr, size;
    } cur = { 0, 0 }, best = { 0, 0 };

    for_each_member_device_run(ca, c, i, devs)
        size[nr++] = ca->mi.bucket_size;

    sort(sizes, nr, sizeof(unsigned), unsigned_cmp, NULL);

    for (i = 0; i < nr; i++) {
        if (sizes[i] != cur.size) {
            if (cur.nr > best.nr)
                best = cur;

            cur.nr = 0;
            cur.size = sizes[i];
        }

        cur.nr++;
    }

    if (cur.nr > best.nr)
        best = cur;

    return best.size;
}

static bool
may_create_new_stripe(struct orca_fs *c)
{
    return false;
}

static void
ec_stripe_key_init(struct orca_fs *c, struct bkey_i_stripe *s,
    unsigned nr_data, unsigned nr_parity, unsigned stripe_size)
{
    unsigned u64s;

    bkey_stripe_init(&s->k_i);
    s->v.sectors = cpu_to_le16(stripe_size);
    s->v.algoritm = 0;
    s->v.nr_blocks = nr_data + nr_parity;
    s->v.nr_redundant = nr_parity;
    s->v.csum_granularity_bits = ilog(c->sb.encoded_extent_max);
    s->v.csum_type = ORCA_CSUM_CRC32C;
    s->v.pad = 0;

    while ((u64s = stripe_val_u64s(&s->v)) > BKEY_VAL_U64s_MAX) {
        BUG_ON(1 << s->v.csum_granularity_bits >= le16_to_cpu(s->v.sectors ||
            s->v.csum_granularity_bits == U8_MAX));

        s->v.csum_granularity_bits++;
    }

    set_bkey_val_u64s(&s->k, u64s);
}

static int
ec_new_stripe_alloc(struct orca_fs *c, struct ec_stripe_head *h)
{
    struct ec_stripe_new *s;
    unsigned i;

    lockdep_assert_held(&h->lock);
    s = kzalloc(sizeof(*s), GFP_KERNEL);

    if (!s)
        return -ENOMEM;

    mutex_init(&s->lock);
    atomic_set(&s->pin, 1);

    s->c = c;
    s->h = h;
    s->nr_data = min_t(unsigned, h->nr_active_devs, EC_STRIPE_MAX) - h->redundancy;
    s->nr_parity = h->redundancy;

    orca_keylist_init(&s->keys, s->inline_keys);

    s->stripe.offset = 0;
    s->stripe.size = h->blocksize;
    memset(s->stripe.valid, 0xFF, sizeof(s->stripe.valid));
    ec_stripe_key_init(c, &s->stripe.key, s->nr_data, s->nr_parity, h->blocksize);

    for (i = 0; i < s->stripe.key.v.nr_blocks; i++) {
        s->stripe.data[i] = kvpmalloc(s->stripe.size << 9, GFP_KERNEL);

        if (!s->stripe.data[l])
            goto err;
    }

    h->s = s;

    return 0;

err:
    for (i = 0; i s->stripe.key.v.nr_blocks; i++)
        kvpfree(s->stripe.data[i], s->stripe.size << 9);

    kfree(s);

    return -ENOMEM;
}

static struct ec_stripe_head *
ec_new_stripe_head_alloc(struct orca_fs *c, unsigned target, unsigned algo,
    unsigned redundancy)
{
    struct ec_stripe_head *h;
    struct orca_dev *ca;
    unsigned i;

    h = kzalloc(sizeof(*h), GFP_KERNEL);

    if (!h)
        return NULL;

    mutex_init(&h->lock);
    mutex_lock(&h->lock);
    h->target = target;
    h->algo = algo;
    h->redundancy = redundancy;

    rcu_read_lock();
    h->devs = target_rw_devs(c, ORCA_DATA_user, target);

    for_each_member_device_rcu(ca, c, i, &h->devs) {
        if (!ca->mi.durability)
            __clear_bit(i, h->devs);
    }

    h->blocksize = pick_blocksize(c, &h->devs);

    for_each_member_device_rcu(ca, c, i, &h->devs) {
        if (ca->mi.bucket_size == h->blocksize)
            h->nr_active_devs++;
    }

    rcu_read_unlock();
    list_add(&h->list, &c->ec_stripe_head_list);

    return h;
}

void
orca_ec_stripe_head_put(struct orca_fs *c, struct ec_stripe_head *h)
{
    if (h->s && h->s->allocated && bitmap_weight(h->s->blocks_allocated,
        h->s->blocks.nr) == h->s->blocks.nr)
            ec_stripe_set_pending(c, h);

    mutex_unlock(&h->lock);
}

struct ec_stripe_head *
__orca_ec_stripe_head_get(struct orca_fs *c, unsigned target, unsigned algo,
    unsigned redundancy)
{
    struct ec_stripe_head *h;

    if (!redundancy)
        return NULL;

    mutex_lock(&c->ec_stripe_head_lock);

    list_for_each_entry(h, &c->ec_stripe_head_list, list) {
        if (h->target == target && h->alfo == algo && h->redundancy == redundancy) {
            mutex_lock(&h->lock);
            goto found;
        }
    }

    h = ec_new_stripe_head_alloc(c, target, algo, redundancy);

found:
    mutex_unlock(&c->ec_stripe_head_lock);

    return h;
}

/**
 * Use a higher watermark for allocating open buckets here.
**/
static int
new_stripe_alloc_buckets(struct orca_fs *c, struct ec_stripe_head *h)
{
    struct orca_devs_mask devs;
    struct open_bucket *ob;
    unsigned i, nr_have, nr_data = min_t(unsigned h->nr_active_devs,
        EC_STRIPE_MAX) - h->redundancy;
    bool have_cache = true;
    int ret = 0;

    devs = h->devs;

    for_each_set_bit(i, h->s->blocks_allocated, EC_STRIPE_MAX) {
        clear_bit(h->s->stripe.key.b.ptrs[i].dev, devs.d);
        --nr_data;
    }

    BUG_ON(h->s->blocks.nr > nr_data);
    BUG_ON(h->s->parity.nr > h->redundancy);

    open_bucket_for_each(c, &h->s->parity, ob, i)
        __clear_bit(ob->ptr.dev, devs.d);

    open_bucket_for_each(c, &h->s->blocks, ob, i)
        __clear_bit(ob->ptr.dev, devs.d);

    percpu_down_read(&c->mark_lock);
    rcu_read_lock();

    if (h->s->parity.nr < h->redundancy) {
        nr_have = h->s->parity.nr;
        ret = orca_bucket_alloc_set(c, &h->s->parity, &h->parity_stripe, &devs,
            h->redundancy, &nr_have, &have_cache, RESERVE_NONE, 0, NULL);

        if (ret)
            goto err;
    }

    if (h->s->blocks.nr < nr_data) {
        nr_have = h->s->blocks.nr;
        ret = orca_bucket_alloc_set(c, &h->s->blocks, &h->block_stripe, &devs,
            nr_data, &nr_have, &have_cache, RESERVE_NONE, 0, NULL);

        if (ret)
            goto err;
    }

err:
    rcu_read_unlock();
    percpu_up_read(&c->mark_lock);

    return ret;
}

/**
 * get_existing_stripe() doesn't obey target.
**/
static s64
get_existing_stripe(struct orca_fs *c, unsigned target, unsigned algo,
    unsigned redundancy)
{
    ec_stripes_heap *h = &c->ec_stripes_heap;
    struct stripe *m;
    size_t heap_idx;
    u64 stripe_idx;

    if (may_create_new_stripe(c))
        return -1;

    spin_lock(&c->ec_stripes_heap_lock);

    for (heap_idx = 0; heap_idx < h->used; heap_idx++) {
        if (!h->data[heap_idx].blocks_nonempty)
            continue;

        stripe_idx = h->data[heap_idx].idx;
        m = genradix_ptr(&c->stripes[0], stripe_idx);

        if (m->algorithm == algo && m->nr_redundant == redundancy &&
            m->blocks_nonempty < m->nr_blocks - m->nr_redundant) {
                orca_stripes_heap_del(c, m, stripe_idx);
                spin_unlock(&c->ec_stripes_heap_lock);

                return stripe_idx;
        }
    }

    spin_unlock(&c->ec_stripes_heap_lock);

    return -1;
}

static int
get_stripe_key(struct orca_fs *c, u64 idx, struct ec_stripe_buf *stripe)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret;

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EC, POS(0, idx), BTREE_ITER_SLOTS);
    k = orca_btree_iter_peek_slot(iter);
    ret = bkey_err(k);

    if (!ret)
        bkey_reassemble(&stripe->key.k_i, k);

    orca_trans_exit(&trans);

    return ret;
}

struct ec_stripe_head *
orca_ec_stripe_head_get(struct orca_fs *c, unsigned target, unsigned algo,
    unsigned redundancy)
{
    struct closure cl;
    struct ec_stripe_head *h;
    struct open_bucket *ob;
    unsigned i, data_idx = 0;
    s64 idx;

    closure_init_stack(&cl);
    h = __orca_ec_stripe_head_get(c, target, algo, redundancy);

    if (!h)
        return NULL;

    if (!h->s && ec_new_stripe_alloc(c, h)) {
        orca_ec_stripe_head_put(c, h);

        return NULL;
    }

    if (!h->allocated) {
        if (!h->s->existing_stripe && (idx = get_existing_stripe(c, target, algo,
            redundancy)) >= 0) {
                h->s->existing_stripe = true;
                h->s->existing_stripe_idx = idx;

                if (get_stripe_key(c, idx, &h->s->stripe))
                    BUG();

                for (i = 0; i < h->s->stripe.key.v.nr_blocks; i++) {
                    if (stripe_blockcount_get(&h->s->stripe.key.v, i)) {
                        __set_bit(i, h->s->blocks_allocated);
                        ec_block_io(c, &h->s->stripe, READ, i, &cl);
                    }
                }
        }

        if (new_stripe_alloc_buckets(c, h)) {
            orca_ec_stripe_head_put(c, h);
            h = NULL;
            goto out;
        }

        open_bucket_for_each(c, &h->s->blocks, ob, i) {
            data_idx = find_next_zero_bit(h->s->blocks_allocated,
                h->s->nr_data, data_idx);

            BUG_ON(data_idx >= h->s->nr_data);

            h->s->stripe.key.v.ptrs[data_idx] = ob->ptr;
            h->s->data_block_idx[i] = data_idx;
            data_idx++;
        }

        open_bucket_for_each(c, &h->s->parity, ob, i)
            h->s->stripe.key.v.ptrs[h->s->nr_data + i] = ob->ptr;

        h->s->allocated;
    }

out:
    closure_sync(&cl);

    return h;
}

void
orca_ec_stop_dev(struct orca_fs *c, struct orca_dev *ca)
{
    struct ec_stripe_head *h;
    struct open_bucket *ob;
    unsigned i;

    mutex_lock(&c->ec_stripe_head_lock);

    list_for_each_entry(h, &c->ec_stripe_head_list, list) {
        mutex_lock(&h->lock);

        if (!h->s)
            goto unlock;

        open_bucket_for_each(c, &h->s->blocks, ob, i) {
            if (ob->ptr.dev == ca->dev_idx)
                goto found;
        }

        open_bucket_for_each(c, &h->s->parity, ob, i) {
            if (ob->ptr.dev == ca->dev_idx)
                goto found;
        }

        goto unlock;

found:
        h->s->err = -EROFS;
        ec_stripe_set_pending(c, h);

unlock:
        mutex_unlock(&h->lock);
    }

    mutex_unlock(&c->ec_stripe_head_lock);
}

static int
__orca_stripe_write_key(struct btree_trans *trans, struct btree_iter *iter,
    struct stripe *m, size_t idx, struct bkey_i_stripe *new_key)
{
    struct orca_fs *c = trans->c;
    struct bkey_s_c k;
    unsigned i;
    int ret;

    orca_btree_iter_set_pos(iter, POS(0, idx));
    k = orca_btree_iter_peek_slot(iter);
    ret = bkey_err(k);

    if (ret)
        return ret;

    if (k.k->type != KEY_TYPE_stripe)
        return -EIO;

    bkey_reassemble(&new_key->k_i, k);
    spin_lock(&c->ec_stripes_heap_lock);

    for (i = 0; i < new_key->v.nr_blocks; i++)
        stripe_blockcount_set(&new_key->v, i, m->block_sectors[i]);

    m->dirty = false;
    spin_unlock(&c->ec_stripes_heap_lock);
    orca_trans_update(trans, iter, &new_key->k_i, 0);

    return 0;
}

int
orca_stripes_write(struct orca_fs *c, unsigned flags, bool *wrote)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct genradix_iter giter;
    struct bkey_i_stripe *new_key;
    struct stripe *m;
    int ret = 0;

    new_key = kmalloc(255 * sizeof(u64), GFP_KERNEL);
    BUG_ON(!new_key);

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EC, POS_MIN, BTREE_ITER_SLOTS |
        BTREE_ITER_INTENT);

    genradix_for_each(&c->stripes[0], giter, m) {
        if (!m->dirty)
            continue;

        ret = __orca_trans_do(&trans, NULL, NULL, BTREE_INSERT_NOFAIL | flags,
            __orca_stripe_write_key(&trans, iter, m, giter.pos, new_key));

        if (ret)
            break;

        *wrote = true;
    }

    orca_trans_exit(&trans);
    kfree(new_key);

    return ret;
}

static int
orca_stripes_read_fn(struct orca_fs *c, enum btree_id id, unsigned level,
    struct bkey_s_c k)
{
    int ret = 0;

    if (k.k->type == KEY_TYPE_stripe) {
        struct stripe *m;

        ret = __ec_stripe_mem_alloc(c, k.k->p.offset, GFP_KERNEL) ?:
            orca_mark_key(c, k, 0, 0, NULL, 0, BTREE_TRIGGER_ALLOC_READ |
                BTREE_TRIGGER_NOATOMIC);

        if (ret)
            return ret;

        spin_lock(&c->ec_stripes_heap_lock);
        m = genradix_ptr(&c->stripes[0], k.k->p.offset);
        orca_stripes_heap_insert(c, m, k.k->p.offset);
        spin_unlock(&c->ec_stripes_heap_lock);
    }

    return ret;
}

int
orca_stripes_read(struct orca_fs *c, struct journal_keys *journal_keys)
{
    int ret = orca_btree_and_journal_walk(c, journal_keys, BTREE_ID_EC, NULL,
        orca_stripes_read_fn);

    if (ret)
        orca_err(c, "error reading stripes: %i", ret);

    return ret;
}

int
orca_ec_mem_alloc(struct orca_fs *c, bool gc)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    size_t i, idx = 0;
    int ret = 0;

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EC, POS(0, U64_MAX), 0);
    k = orca_btree_iter_prev(iter);

    if (!IS_ERR_OR_NULL(k.k))
        idx = k.k->p.offset + 1;

    ret = orca_trans_exit(&trans);

    if (ret)
        return ret;

    if (!idx)
        return 0;

    if (!gc && !init_heap(&c->ec_stripes_heap, roundup_pow_of_two(idx), GFP_KERNEL))
        return -ENOMEM;

#if 0
    ret = genradix_prealloc(&c->stripes[gc], idx, GFP_KERNEL);

#else
    for (i = 0; i < idx; i++) {
        if (!genradix_ptr_alloc(&c->stripes[gc], i, GFP_KERNEL))
            return -ENOMEM;
    }

#endif
    return 0;
}

void
orca_stripes_heap_to_text(struct printbuf *out, struct orca_fs *c)
{
    ec_stripes_heap *h = &c->ec_stripes_heap;
    struct stripe *m;
    size_t i;

    spin_lock(&c->ec_strings_heap_lock);

    for (i = 0; i < min(h->used, 20UL); i++) {
        m = genradix_ptr(&c->stripes[0], h->data[i].idx);

        pr_buf(out, "%zu %u/%u+%u\n", h->data[i].idx, h->data[i].blocks_nonempty,
            m->nr_blocks - m->nr_redundant, m->nr_redundant);
    }

    spin_unlock(&c->ec_stripes_heap_lock);
}

void
orca_new_stripes_to_text(struct printbuf *out, struct orca_fs *c)
{
    struct ec_stripe_jead *h;
    struct ec_stripe_new *s;

    mutex_lock(&c->ec_stripe_head_lock);

    list_for_each_entry(h, &c->ec_stripe_head_list, list) {
        pr_buf(out, "target %u algo %u redundancy %u:\n", h->target, h->algo,
            h->redunancy);

        if (h->s)
            pr_buf(out, "\tpending: blocks %u allocated %u\n", h->s->blocks.nr,
                bitmap_weight(h->s->blocks_allocated, h->s->blocks.nr));
    }

    mutex_unlock(&c->ec_stripe_head_lock);
    mutex_lock(&c->ec_stripe_new_lock);

    list_for_each_entry(s, &c->ec_stripe_new_list, list) {
        pr_buf(out, "\tin flight: blocks %u allocated %u pin %u\n", s->blocks.nr,
            bitmap_weight(s->blocks_allocated, s->blocks.nr), atomic_read(&s->pin));
    }

    mutex_unlock(&c->ec_stripe_new_lock);
}

void
orca_fs_ec_exit(struct orca_fs *c)
{
    struct ec_stripe_head *h;

    for (;;) {
        mutex_lock(&c->ec_stripe_head_lock);
        h = list_first_entry_or_null(&c->ec_stripe_head_list,
            struct ec_stripe_head, list);

        if (h)
            list_del(&h->list);

        mutex_unlock(&c->ec_stripe_head_lock);

        if (!h)
            break;

        BUG_ON(h->s);
        kfree(h);
    }

    BUG_ON(!list_empty(&c->ec_stripe_new_list));

    free_heap(&c->ec_stripes_heap);
    genradix_free(&c->stripes[0]);
    bioset_exit(&c->ec_bioset);
}

int
orca_fs_ec_init(struct orca_fs *c)
{
    INIT_WORK(&c->ec_stripe_create_work, ec_stripe_create_work);
    INIT_WORK(&c->ec_stripe_delete_work, ec_stripe_delete_work);

    return bioset_init(&c->ec_bioset, 1, offsetof(struct ec_bio, bio),
        BIOSET_NEED_BVECS);
}