#include <linux/math64.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "debug.h"
#include "disk_groups.h"
#include "ec.h"
#include "io.h"

/**
 * Open buckets represent a bucket that's currently being allocated from.
 * They serve two purposes:
 *
 * They track buckets that have been partially allocated, allowing for
 * sub-bucket sized allocations--they're used by the sector allocator
 * below.
 *
 * They provide a reference to the buckets they own that mark and sweep
 * GC can find, until the new allocation has a pointer to it inserted
 * into the btree.
 *
 * When allocating some space with the sector allocator, the allocation
 * comes with a reference to an open bucket--the caller is required to
 * put that reference __after__ doing the index update that makes its
 * allocation reacheable.
**/
void
__orca_open_bucket_put(struct orca_fs *c, struct open_bucket *ob)
{
    struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);

    if (ob->ec) {
        orca_ec_bucket_written(c, ob);
        return;
    }

    percpu_down_read(&c->mark_lock);
    spin_lock(&ob->lock);
    orca_mark_alloc_bucket(c, ca, PTR_BUCKET_NR(ca, &ob->ptr), false,
        gc_pos_alloc(c, ob), 9);

    ob->valid = false;
    ob->type = 0;

    spin_unlock(&ob->lock);
    percpu_up_read(&c->mark_lock);
    spin_lock(&c->freelist_lock);

    ob->freelist = c->open_buckets_freelist;
    c->open_buckets_freelist = ob - c->open_bucket;
    c->open_buckets_nr_free++;
    spin_unlock(&c->freelist_lock);
    closure_wake_up(&c->open_buckets_wait);
}

void
orca_open_bucket_write_error(struct orca_fs *c, struct open_buckets *obs,
    unsigned dev)
{
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, obs, ob, i) {
        if (ob->ptr.dev == dev && ob->ec)
            orca_ec_bucket_cancel(c, ob);
    }
}

static struct open_bucket *
orca_open_bucket_alloc(struct orca_fs *c)
{
    struct open_bucket *ob;

    BUG_ON(!c->open_buckets_freelist || !c->open_buckets_nr_free);

    ob = c->open_buckets + c->open_buckets_freelist;
    c->open_buckets_freelist = ob->freelist;
    atomic_set(&ob->pin, 1);
    ob->type = 0;
    c->open_buckets_nr_free--;

    return ob;
}

static void
open_bucket_free_unused(struct orca_fs *c, struct write_point *wp,
    struct open_bucket *ob)
{
    struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);
    bool may_realloc = wp->type == ORCA_DATA_user;

    BUG_ON(ca->open_buckets_partial_nr > ARRAY_SIZE(ca->open_buckets_partial));

    if (ca->open_buckets_partial_nr < ARRAY_SIZE(ca->open_buckets_partial) &&
        may_realloc) {
            spin_lock(&c->freelist_lock);
            ob->on_partial_list = true;
            ca->open_buckets_partial[ca->open_buckets_partial_nr++] =
                ob - c->open_buckets;
            spin_unlock(&c->freelist_lock);

            closure_wake_up(&c->open_buckets_wait);
            closure_wake_up(&c->freelist_wait);
    } else {
        orca_open_bucket_put(c, ob);
    }
}

static void
verify_not_stale(struct orca_fs *c, const struct open_buckets *obs)
{
#ifdef CONFIG_ORCAFS_DEBUG
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, obs, ob, i) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);

        BUG_ON(ptr_stale(ca, &ob->ptr));
    }
#endif
}

long
orca_bucket_alloc_new_fs(struct orca_fs *ca)
{
    struct bucket_array *buckets;
    ssize_t b;

    rcu_read_lock();
    buckets = bucket_array(ca);

    for (b = ca->mi.first_bucket; b < ca->mi.nbuckets; b++) {
        if (is_available_bucket(buckets->b[b].mark))
            goto success;
    }

    b = -1;

success:
    rcu_read_unlock();

    return b;
}

static inline unsigned
open_buckets_reserved(enum alloc_reserve reserve)
{
    switch (reserve) {
    case RESERVE_ALLOC:
        return 0;

    case RESERVE_BTREE:
        return OPEN_BUCKETS_COUNT / 4;

    default:
        return OPEN_BUCKETS_COUNT / 2;
    }
}

/**
 * Allocates a single bucket from a specific device.
 *
 * Returns index of bucket on success, 0 on failure.
**/
struct open_bucket *
orca_bucket_alloc(struct orca_fs *c, struct orca_dev *ca, enum alloc_reserve reserve,
    bool may_alloc_partial, struct closure *cl)
{
    struct bucket_array *buckets;
    struct open_bucket *ob;
    long bucket = 0;

    spin_lock(&c->freelist_lock);

    if (may_alloc_partial) {
        int i;

        for (i = ca->open_buckets_partial_nr - 1; i >= 0; --i) {
            ob = c->open_buckets + ca->open_buckets_partial[i];

            if (reserve <= ob->alloc_reserve) {
                array_remove_item(ca->open_buckets_partial,
                    ca->open_buckets_partial_nr, i);

                ob->on_partial_list = false;
                ob->alloc_reserve = reserve;
                spin_unlock(&c->freelist_lock);

                return ob;
            }
        }
    }

    if (unlikely(c->open_buckets_nr_free <= open_buckets_reserved(reserve))) {
        if (cl)
            closure_wait(&c->open_buckets_wait, cl);

        if (!c->blocked_allocate_open_bucket)
            c->blocked_allocate_open_bucket = local_clock();

        spin_unlock(&c->freelist_lock);
        trace_open_bucket_alloc_fail(ca, reserve);

        return ERR_PTR(-OPEN_BUCKETS_EMPTY);
    }

    if (likely(fifo_pop(&ca->free[RESERVE_NONE], bucket)))
        goto out;

    switch (reserve) {
    case RESERVE_ALLOC:
        if (fifo_pop(*ca->free[RESERVE_BTREE], bucket))
            goto out;

        break;

    case RESERVE_BTREE:
        if (fifo_used(&ca->free[RESERVE_BTREE]) * 2 >= ca->free[RESERVE_BTREE].size &&
            fifo_pop(&ca->free[RESERVE_BTREE], bucket))
                goto out;

        break;

    case RESERVE_MOVINGGC:
        if (fifo_pop(&ca->free[RESERVE_MOVINGGC], bucket))
            goto out;

        break;

    default:
        break;
    }

    if (cl)
        closure_wait(&c->freelist_wait, cl);

    if (!c->blocked_allocate)
        c->blocked_allocate = local_clock();

    spin_unlock(&c->freelist_lock);
    trace_bucket_alloc_fail(ca, reserve);

    return ERR_PTR(-FREELIST_EMPTY);
}
#include <linux/math64.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "alloc_background.h"
#include "alloc_foreground.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "debug.h"
#include "disk_groups.h"
#include "ec.h"
#include "io.h"

/**
 * Open buckets represent a bucket that's currently being allocated from.
 * They serve two purposes:
 *
 * They track buckets that have been partially allocated, allowing for
 * sub-bucket sized allocations--they're used by the sector allocator
 * below.
 *
 * They provide a reference to the buckets they own that mark and sweep
 * GC can find, until the new allocation has a pointer to it inserted
 * into the btree.
 *
 * When allocating some space with the sector allocator, the allocation
 * comes with a reference to an open bucket--the caller is required to
 * put that reference __after__ doing the index update that makes its
 * allocation reacheable.
**/
void
__orca_open_bucket_put(struct orca_fs *c, struct open_bucket *ob)
{
    struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);

    if (ob->ec) {
        orca_ec_bucket_written(c, ob);
        return;
    }

    percpu_down_read(&c->mark_lock);
    spin_lock(&ob->lock);
    orca_mark_alloc_bucket(c, ca, PTR_BUCKET_NR(ca, &ob->ptr), false,
        gc_pos_alloc(c, ob), 9);

    ob->valid = false;
    ob->type = 0;

    spin_unlock(&ob->lock);
    percpu_up_read(&c->mark_lock);
    spin_lock(&c->freelist_lock);

    ob->freelist = c->open_buckets_freelist;
    c->open_buckets_freelist = ob - c->open_bucket;
    c->open_buckets_nr_free++;
    spin_unlock(&c->freelist_lock);
    closure_wake_up(&c->open_buckets_wait);
}

void
orca_open_bucket_write_error(struct orca_fs *c, struct open_buckets *obs,
    unsigned dev)
{
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, obs, ob, i) {
        if (ob->ptr.dev == dev && ob->ec)
            orca_ec_bucket_cancel(c, ob);
    }
}

static struct open_bucket *
orca_open_bucket_alloc(struct orca_fs *c)
{
    struct open_bucket *ob;

    BUG_ON(!c->open_buckets_freelist || !c->open_buckets_nr_free);

    ob = c->open_buckets + c->open_buckets_freelist;
    c->open_buckets_freelist = ob->freelist;
    atomic_set(&ob->pin, 1);
    ob->type = 0;
    c->open_buckets_nr_free--;

    return ob;
}

static void
open_bucket_free_unused(struct orca_fs *c, struct write_point *wp,
    struct open_bucket *ob)
{
    struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);
    bool may_realloc = wp->type == ORCA_DATA_user;

    BUG_ON(ca->open_buckets_partial_nr > ARRAY_SIZE(ca->open_buckets_partial));

    if (ca->open_buckets_partial_nr < ARRAY_SIZE(ca->open_buckets_partial) &&
        may_realloc) {
            spin_lock(&c->freelist_lock);
            ob->on_partial_list = true;
            ca->open_buckets_partial[ca->open_buckets_partial_nr++] =
                ob - c->open_buckets;
            spin_unlock(&c->freelist_lock);

            closure_wake_up(&c->open_buckets_wait);
            closure_wake_up(&c->freelist_wait);
    } else {
        orca_open_bucket_put(c, ob);
    }
}

static void
verify_not_stale(struct orca_fs *c, const struct open_buckets *obs)
{
#ifdef CONFIG_ORCAFS_DEBUG
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, obs, ob, i) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);

        BUG_ON(ptr_stale(ca, &ob->ptr));
    }
#endif
}

long
orca_bucket_alloc_new_fs(struct orca_fs *ca)
{
    struct bucket_array *buckets;
    ssize_t b;

    rcu_read_lock();
    buckets = bucket_array(ca);

    for (b = ca->mi.first_bucket; b < ca->mi.nbuckets; b++) {
        if (is_available_bucket(buckets->b[b].mark))
            goto success;
    }

    b = -1;

success:
    rcu_read_unlock();

    return b;
}

static inline unsigned
open_buckets_reserved(enum alloc_reserve reserve)
{
    switch (reserve) {
    case RESERVE_ALLOC:
        return 0;

    case RESERVE_BTREE:
        return OPEN_BUCKETS_COUNT / 4;

    default:
        return OPEN_BUCKETS_COUNT / 2;
    }
}

/**
 * Allocates a single bucket from a specific device.
 *
 * Returns index of bucket on success, 0 on failure.
**/
struct open_bucket *
orca_bucket_alloc(struct orca_fs *c, struct orca_dev *ca, enum alloc_reserve reserve,
    bool may_alloc_partial, struct closure *cl)
{
    struct bucket_array *buckets;
    struct open_bucket *ob;
    long bucket = 0;

    spin_lock(&c->freelist_lock);

    if (may_alloc_partial) {
        int i;

        for (i = ca->open_buckets_partial_nr - 1; i >= 0; --i) {
            ob = c->open_buckets + ca->open_buckets_partial[i];

            if (reserve <= ob->alloc_reserve) {
                array_remove_item(ca->open_buckets_partial,
                    ca->open_buckets_partial_nr, i);

                ob->on_partial_list = false;
                ob->alloc_reserve = reserve;
                spin_unlock(&c->freelist_lock);

                return ob;
            }
        }
    }

    if (unlikely(c->open_buckets_nr_free <= open_buckets_reserved(reserve))) {
        if (cl)
            closure_wait(&c->open_buckets_wait, cl);

        if (!c->blocked_allocate_open_bucket)
            c->blocked_allocate_open_bucket = local_clock();

        spin_unlock(&c->freelist_lock);
        trace_open_bucket_alloc_fail(ca, reserve);

        return ERR_PTR(-OPEN_BUCKETS_EMPTY);
    }

    if (likely(fifo_pop(&ca->free[RESERVE_NONE], bucket)))
        goto out;

    switch (reserve) {
    case RESERVE_ALLOC:
        if (fifo_pop(*ca->free[RESERVE_BTREE], bucket))
            goto out;

        break;

    case RESERVE_BTREE:
        if (fifo_used(&ca->free[RESERVE_BTREE]) * 2 >= ca->free[RESERVE_BTREE].size &&
            fifo_pop(&ca->free[RESERVE_BTREE], bucket))
                goto out;

        break;

    default:
        break;
    }

    if (cl)
        closure_wait(&c->freelist_wait, cl);

    if (!c->blocked_allocate)
        c->blocked_allocate = local_clock();

    spin_unlock(&c->freelist_lock);
    trace_bucket_alloc_fail(ca, reserve);

    return ERR_PTR(-FREELIST_EMPTY);

out:
    verify_not_on_freelist(c, ca, bucket);
    ob = orca_open_bucket_alloc(c);
    spin_lock(&ob->lock);
    buckets = bucket_array(ca);

    ob->valid = true;
    ob->sectors_free = ca->mi.bucket_size;
    ob->alloc_reserve = reserve;
    ob->ptr = (struct orca_extent_ptr) {
        .type = 1 << ORCA_EXTENT_ENTRY_ptr,
        .gen = buckets->b[bucket].mark.gen,
        .offset = bucket_to_sector(ca, bucket),
        .dev = ca->dev_idx,
    };

    spin_unlock(&ob->lock);

    if (c->blocked_allocate_open_bucket) {
        orca_time_stats_update(&c->times[ORCA_TIME_blocked_allocate_open_bucket],
            c->blocked_allocate_open_bucket);

        c->blocked_allocate_open_bucket = 0;
    }

    if (c->blocked_allocate) {
        orca_time_stats_update(&c->times[ORCA_TIME_blocked_allocate],
            c->blocked_allocate_open_bucket);

        c->blocked_allocate = 0;
    }

    spin_unlock(&c->freelist_lock);
    orca_wake_allocator(ca);
    trace_bucket_alloc(ca, reserve);

    return ob;
}

static int
__dev_stripe_cmp(struct dev_stripe_state *stripe, unsigned i, unsigned r)
{
    return ((stripe->next_alloc[i] > stripe->next_alloc[r]) -
        (stripe->next_alloc[i] < stripe->next_alloc[r]));
}

#define dev_stripe_cmp(l, r) __dev_stripe_cmp(stripe, l, r)

struct dev_alloc_list
orca_dev_alloc_list(struct orca_fs *c, struct dev_stripe_state *stripe,
    struct orca_devs_mask *devs)
{
    struct dev_alloc_list ret = { .nr = 0 };
    unsigned i;

    for_each_set_bit(i, devs->d, ORCA_SB_MEMBERS_MAX)
        ret.devs[ret.nr++] = i;

    bubble_sort(ret.devs, ret.nr, dev_stripe_cmd);

    return ret;
}

void
orca_dev_stripe_increment(struct orca_dev *ca, struct dev_stripe_state *stripe)
{
    u64 *v = stripe->next_alloc + ca->dev_idx;
    u64 free_space = dev_buckets_free(ca);
    u64 free_space_inv = free_space ? div64_u64(1ULL << 48, free_space) :
        1ULL << 48;
    u64 scale = *v / 4;

    if (*v + free_space_inv >= *v)
        *v += free_space_inv;
    else
        *v = U64_MAX;

    for (v = stripe->next_alloc; v < stripe->next_alloc + ARRAY_SIZE(stripe->next_alloc); v++)
        *v = *v < scale ? 0 : *v - scale;
}

#define BUCKET_MAY_ALLOC_PARTIAL (1 << 0)
#define BUCKET_ALLOC_USE_DURABILITY (1 << 1)

static void
add_new_bucket(struct orca_fs *c, struct open_buckets *ptrs,
    struct orca_dev_mask *devs_may_alloc, unsigned *nr_effective, bool *have_cache,
    unsigned flags, struct open_bucket *ob)
{
    unsigned durability = orca_dev_bkey_exists(c, ob->ptr.dev)->mi.durability;

    __clear_bit(ob->ptr.dev, devs_may_alloc->d);
    *nr_effective += (flags & BUCKET_ALLOC_USE_DURABILITY) ? durability : 1;
    *have_cache |= !durability;

    ob_push(c, ptrs, ob);
}

enum bucket_alloc_ret
orca_bucket_alloc_set(struct orca_fs *c, struct open_buckets *ptrs,
    struct dev_stripe_state *stripe, struct orca_devs_mask *devs_may_alloc,
    unsigned nr_replicas, unsigned *nr_effective, bool *have_cache,
    enum alloc_reserve reserve, unsigned flags, struct closure *cl)
{
    struct dev_alloc_list devs_sorted = orca_dev_alloc_list(c, stripe, devs_may_alloc);
    struct orca_dev *ca;
    enum bucket_alloc_ret ret = INSUFFICIENT_DEVICES;
    unsigned i;

    BUG_ON(*nr_effective >= nr_replicas);

    for (i = 0; i < devs_sorted.nr; i++) {
        struct open_bucket *ob;

        ca = rcu_dereference(c->devs[devs_sorted.devs[i]]);

        if (!ca)
            continue;

        if (!ca->mi.durability && *have_cache)
            continue;

        ob = orca_bucket_alloc(c, ca, reserve, flags & BUCKET_MAY_ALLOC_PARTIAL, cl);

        if (IS_ERR(ob)) {
            ret = -PTR_ERR(ob);

            if (cl)
                return ret;

            continue;
        }

        add_new_bucket(c, ptrs, devs_may_alloc, nr_effective, have_cache, flags, ob);
        orca_dev_stripe_increment(ca, stripe);

        if (*nr_effective >= nr_replicas)
            return ALLOC_SUCCESS;
    }

    return ret;
}

/**
 * Allocate from stripes.
 *
 * If we can't allocate a new stripe because there are already too many
 * partially filled stripes, force allocating from an existing stripe
 * even when it's to a device we don't wait.
**/
static void
bucket_alloc_from_stripe(struct orca_fs *c, struct open_buckets *ptrs,
    struct write_point *wp, struct orca_devs_mask *devs_may_alloc,
    u16 target, unsigned erasure_code, unsigned nr_replicas,
    unsigned *nr_effective, bool *have_cache, unsigned flags)
{
    struct dev_alloc_list devs_sorted;
    struct ec_stripe_head *h;
    struct open_bucket *ob;
    struct orca_dev *ca;
    unsigned i, ec_idx;

    if (!erasure_code)
        return;

    if (nr_replicas < 2)
        return;

    if (ec_open_bucket(c, ptrs))
        return;

    h = orca_ec_stripe_head_get(c, target, 0, nr_replicas - 1);

    if (!h)
        return;

    devs_sorted = orca_dev_alloc_list(c, &wp->stripe, devs_may_alloc);

    for (i = 0; i < devs_sorted.nr; i++) {
        open_bucket_for_each(c, &h->s->blocks, ob, ec_idx) {
            if (ob->ptr.dev == devs_sorted.devs[i] &&
                !test_and_set_bit(h->s->data_block_idx[ec_idx], h->s->blocks_allocated))
                    goto got_bucket;
        }
    }

    goto out_put_head;

got_bucket:
    ca = orca_dev_bkey_exists(c, ob->ptr.dev);
    ob->ec_idx = h->s->data_block_idx[ec_idx];
    ob->ec = h->s;

    add_new_bucket(c, ptrs, devs_may_alloc, nr_effective, have_cache, flags, ob);
    atomic_inc(&h->s->pin);

out_put_head:
    orca_ec_stripe_head_put(c, h);
}

/* Sector allocator */
static void
get_buckets_from_writepoint(struct orca_fs *c, struct open_bucket *ptrs,
    struct write_point *wp, struct orca_devs_mask *devs_may_alloc,
    unsigned nr_replicas, unsigned *nr_effective, bool *have_cache, unsigned flags,
    bool need_ec)
{
    struct open_buckets ptrs_skip = { .nr = 0 };
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, &wp->ptrs, ob, i) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);

        if (*nr_effective < nr_replicas && test_bit(ob->ptr.dev, devs_may_alloc->d) &&
            (ca->mi.durability || (wp->type == ORCA_DATA_user && !*have_cache)) &&
            (ob->ec || !need_ec)) {
                add_new_bucket(c, ptrs, devs_may_alloc, nr_effective, have_cache,
                flags, ob);
        } else {
            ob_push(c, &ptrs_skip, ob);
        }
    }

    wp->ptrs = ptrs_skip;
}

static enum bucket_alloc_ret
open_bucket_add_buckets(struct orca_fs *c, struct open_buckets *ptrs,
    struct write_point *wp, struct orca_devs_list *devs_have, u16 target,
    unsigned erasure_code, unsigned nr_replicas, unsigned *nr_effective,
    bool *have_cache, enum alloc_reserve reserve, unsigned flags,
    struct closure *_cl)
{
    struct orca_devs_mask devs;
    struct open_bucket *ob;
    struct closure *cl = NULL;
    enum bucket_alloc_ret ret;
    unsigned i;

    rcu_read_lock();
    devs = target_rw_devs(c, wp->type, target);
    rcu_read_unlock();

    /* Don't allocate from devices we already have pointers */
    for (i = 0; i < devs_have->nr; i++)
        __clear_bit(devs_have->devs[i], devs.d);

    open_bucket_for_each(c, ptrs, ob, i)
        __clear_bit(ob->ptr.dev, devs.d);

    if (erasure_code) {
        if (!ec_open_bucket(c, ptrs)) {
            get_buckets_from_writepoint(c, ptrs, wp, &devs, nr_replicas,
                nr_effective, have_cache, flags, true);

            if (*nr_effective >= nr_replicas)
                return 0;
        }

        if (!ec_open_bucket(c, ptrs)) {
            bucket_alloc_from_stripe(c, ptrs, wp, &devs, target, erasure_code,
                nr_replicas, nr_effective, have_cache, flags);

            if (*nr_effective >= nr_replicas)
                return 0;
        }
    }

    get_buckets_from_writepoint(c, ptrs, wp, &devs, nr_replicas, nr_effective,
        have_cache, flags, false);

    if (*nr_effective >= nr_replicas)
        return 0;

    percpu_down_read(&c->mark_lock);
    rcu_read_lock();

retry_blocking:
    /**
     * Try non-blocking first, so that if one device is full, we'll try
     * from other devices.
    **/
    ret = orca_bucket_alloc_set(c, ptrs, &wp->stripe, &devs, nr_replicas,
        nr_effective, have_cache, reserve, flags, cl);

    if (ret && ret != INSUFFICIENT_DEVICES && !cl && _cl) {
        cl = _cl;
        goto retry_blocking;
    }

    rcu_read_unlock();
    percpu_up_read(&c->mark_lock);

    return ret;
}

void
orca_open_buckets_stop_dev(struct orca_fs *c, struct orca_dev *ca,
    struct open_buckets *obs)
{
    struct open_buckets ptrs = { .nr = 0 };
    struct open_bucket *ob, *ob2;
    unsigned i, j;

    open_bucket_for_each(c, obs, ob, i) {
        bool drop = !ca || ob->ptr.dev == ca->dev_idx;

        if (!drop && ob->ec) {
            mutex_lock(&ob->ec->lock);

            open_bucket_for_each(c, &ob->ec->blocks, ob2, j)
                drop |= ob2->ptr.dev == ca->dev_idx;

            open_bucket_for_each(c, &ob->ec->parity, ob2, j)
                drop |= ob2->ptr.dev == ca->dev_idx;

            mutex_unlock(&ob->ec->lock);
        }

        if (drop)
            orca_open_bucket_put(c, ob);
        else
            ob_push(c, &ptrs, ob);
    }

    *obs = ptrs;
}

void
orca_writepoint_stop(struct orca_fs *c, struct orca_dev *ca, struct write_point *wp)
{
    mutex_lock(&wp->lock);
    orca_open_buckets_stop_dev(c, ca, &wp->ptrs);
    mutex_unlock(&wp->lock);
}

static inline struct hlist_head *
writepoint_hash(struct orca_fs *c, unsigned long write_point)
{
    unsigned hash = hash_long(write_point, ilog2(ARRAY_SIZE(c->write_points_hash)));

    return &c->write_points_hash[hash];
}

static struct write_point *
__writepoint_find(struct hlist_head *head, unsigned long write_point)
{
    struct write_point *wp;

    hlist_for_each_entry_rcu(wp, head, node) {
        if (wp->write_point == write_point)
            return wp;
    }

    return NULL;
}

static inline bool
too_many_writepoints(struct orca_fs *c, unsigned factor)
{
    u64 stranded = c->write_points_nr * c->bucket_size_max;
    u64 free = orca_fs_usage_read_short(c).free;

    return stranded * factor > free;
}

static bool
try_increase_writepoints(struct orca_fs *c)
{
    struct write_point *wp;

    if (c->write_points_nr == ARRAY_SIZE(c->write_points) ||
        too_many_writepoints(c, 32))
            return false;

    wp = c->write_points + c->write_points_nr++;
    hlist_add_head_rcu(&wp->node, writepoint_hash(c, wp->write_point));

    return true;
}

static bool
try_decrease_writepoints(struct orca_fs *c, unsigned old_nr)
{
    struct write_point *wp;

    mutex_lock(&c->write_points_hash_lock);

    if (c->write_points_nr < old_nr) {
        mutex_unlock(&c->write_points_hash_lock);

        return true;
    }

    if (c->write_points_nr == 1 || !too_many_writepoints(c, 8)) {
        mutex_unlock(&c->write_points_hash_lock);

        return false;
    }

    wp = c->write_points + --c->write_points_nr;
    hlist_del_rcu(&wp->node);
    mutex_unlock(&c->write_points_hash_lock);
    orca_writepoint_stop(c, NULL, wp);

    return true;
}

static struct write_point *
writepoint_find(struct orca_fs *c, unsigned long write_point)
{
    struct write_point *wp, *oldest;
    struct hlist_head *head;

    if (!(write_point & 1UL)) {
        wp = (struct write_point *)write_point;
        mutex_lock(&wp->lock);

        return wp;
    }

    head = writepoint_hash(c, write_point);

restart_find:
    wp = __writepoint_find(head, write_point);

    if (wp) {
lock_wp:
        mutex_lock(&wp->lock);

        if (wp->write_point == write_point)
            goto out;

        mutex_unlock(&wp->lock);
        goto restart_lock;
    }

restart_find_oldest:
    oldest = NULL;

    for (wp = c->write_points; wp < c->write_points + c->write_points_nr; wp++) {
        if (!oldest || time_before64(wp->last_used, oldest->last_used))
            oldest = wp;
    }

    mutex_lock(&oldest->lock);
    mutex_lock(&c->write_points_hash_lock);

    if (oldest >= c->write_points + c->write_points_nr || try_increase_writepoints(c)) {
        mutex_unlock(&c->write_points_hash_lock);
        mutex_unlock(&oldest->lock);
        goto restart_find_oldest;
    }

    wp = __writepoint_find(head, write_point);

    if (wp && wp != oldest) {
        mutex_unlock(&c->write_points_hash_lock);
        mutex_unlock(&oldset->lock);
        goto lock_wp;
    }

    wp = oldest;
    hlist_del_rcu(&wp->node);
    wp->write_point = write_point;
    hlist_add_head_rcu(&wp->node, head);
    mutex_unlock(&c->write_points_hash_lock);

out:
    wp->last_used = sched_clock();

    return wp;
}

/**
 * Get us an open_bucket we can allocate from, return with it locked.
**/
struct write_point *
orca_alloc_sectors_start(struct orca_fs *c, unsigned target, unsigned erasure_code,
    struct write_point_specifier write_point, struct orca_dev_list *devs_have,
    unsigned nr_replicas, nr_replicas_required, enum alloc_reserve reserve,
    unsigned flags, struct closure *cl)
{
    struct write_point *wp;
    struct open_bucket *ob;
    struct open_buckets ptrs;
    unsigned nr_effective, write_points_nr;
    unsigned ob_flags = 0;
    bool have_cache;
    enum bucket_alloc_ret ret;
    int i;

    if (!(flags & ORCA_WRITE_ONLY_SPECIFIED_DEVS))
        ob_flags |= BUCKET_ALLOC_USE_DURABILITY;

    BUG_ON(!nr_replicas || !nr_replicas_required);

retry:
    ptrs.nr = 0;
    nr_effective = 0;
    write_points_nr = c->write_points_nr;
    have_cache = false;
    wp = writepoint_find(c, write_point.v);

    if (wp->type == ORCA_DATA_user)
        ob_flags |= BUCKET_MAY_ALLOC_PARTIAL;

    /* Metadata may not allocate on cacne devices */
    if (wp->type != ORCA_DATA_user)
        have_cache = true;

    if (!target || (flags & ORCA_WRITE_ONLY_SPECIFIED_DEVS)) {
        ret = open_bucket_add_buckets(c, &ptrs, wp, devs_have, target,
            erasure_code, nr_replicas, &nr_effective, &have_cache, reserve,
            ob_flags, cl);
    } else {
        ret = open_bucket_add_buckets(c, &ptrs, wp, devs_have, target,
            erasure_code, nr_replicas, &nr_effective, &have_cache, reserve,
            ob_flags, cl);

        if (!ret)
            goto alloc_done;

        ret = open_bucket_add_buckets(c, &ptrs, wp, devs_have, 0, erasure_code,
            nr_replicas, &nr_effective, &have_cache, reserve, ob_flags, cl);
    }

alloc_done:
    BUG_ON(!ret && nr_effective < nr_replicas);

    if (erasure_code && !ec_open_bucket(c, &ptrs))
        pr_debug("failed to get ec bucket: ret %u", ret);

    if (ret == INSUFFICIENT_DEVICES && nr_effective >= nr_replicas_required)
        ret = 0;

    if (ret)
        goto err;

    /* Free buckets we didn't use */
    open_buckets_for_each(c, &wp->ptrs, ob, i)
        open_bucket_free_unused(c, wp, ob);

    wp->ptrs = ptrs;
    wp->sectors_free = UINT_MAX;

    open_bucket_for_each(c, &wp->ptrs, ob, i)
        wp->sectors_free = min(wp->sectors_free, ob->sectors_free);

    BUG_ON(!wp->sectors_free || wp->sectors_free == UINT_MAX);
    verify_not_stale(c, &wp->ptrs);

    return wp;

err:
    open_bucket_for_each(c, &wp->ptrs, ob, i) {
        if (ptrs.nr < ARRAY_SIZE(ptrs.v))
            ob_push(c, &ptrs, ob);
        else
            open_bucket_free_unused(c, wp, ob);
    }

    wp->ptrs = ptrs;
    mutex_unlock(&wp->lock);

    if (ret == FREELIST_EMPTY && try_decrease_writepoints(c, write_points_nr))
        goto retry;

    switch (ret) {
    case OPEN_BUCKETS_EMPTY:
    case FREELIST_EMPTY:
        return cl ? ERR_PTR(-EAGAIN) : ERR_PTR(-ENOSPC);

    case INSUFFICIENT_DEVICES:
        return ERR_PTR(-EROFS);

    default:
        BUG();
    }
}

/**
 * Append pointers to the space we just allocated to @k, and mark @sectors space
 * as allocated out of @ob.
**/
void
orca_alloc_sectors_append_ptrs(struct orca_fs *c, struct write_point *wp,
    struct bkey_i *k, unsigned sectors)
{
    struct open_bucket *ob;
    unsigned i;

    BUG_ON(sectors > wp->sectors_free);
    wp->sectors_free -= sectors;

    open_bucket_for_each(c, &wp->ptrs, ob, i) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, ob->ptr.dev);
        struct orca_extent_ptr tmp = ob->ptr;

        tmp.cached = !ca->mi.durability && wp->type == ORCA_DATA_user;
        tmp.offset += ca->mi.bucket_size - ob->sectors_free;

        orca_bkey_append_ptr(k, tmp);
        BUG_ON(sectors > ob->sectors_free);
        ob->sectors_free -= sectors;
    }
}

/**
 * Append pointers to the space we just allocated to @k, and mark @sectors
 * space as allocated of @ob.
**/
void
orca_alloc_sectors_done(struct orca_fs *c, struct write_point *wp)
{
    struct open_buckets ptrs = { .nr 0 }, keep = { .nr = 0 };
    struct open_bucket *ob;
    unsigned i;

    open_bucket_for_each(c, &wp->ptrs, ob, i)
        ob_push(c, !ob->sectors_free ? &ptrs : &keep, ob);

    wp->ptrs = keep;
    mutex_unlock(&wp->lock);
    orca_open_buckets_put(c, &ptrs);
}

static inline void
writepoint_init(struct write_point *wp, enum orca_data_type type)
{
    mutex_init(&wp->lock);
    wp->type = type;
}

void
orca_fs_allocator_foreground_init(struct orca_fs *c)
{
    struct open_bucket *ob;
    struct write_point *wp;

    mutex_init(&c->write_points_hash_lock);
    c->write_points_nr = ARRAY_SIZE(c->write_points);

    /* Open bucket 0 is a sentinal NULL */
    spin_lock_init(&c->open_buckets[0].lock);

    for (ob = c->open_buckets + 1; ob < c->open_buckets + ARRAY_SIZE(c->open_buckets); ob++) {
        spin_lock_init(&ob->lock);
        c->open_buckets_nr_free++;

        ob->freelist = c->open_buckets_freelist;
        c->open_buckets_freelist = ob - c->open_buckets;
    }

    writepoint_init(&c->btree_write_point, ORCA_DATA_btree);
    writepoint_init(&c->rebalance_write_point, ORCA_DATA_user);
    writepoint_init(&c->copygc_write_point, ORCA_DATA_user);

    for (wp = c->write_points; wp < c->write_points + c->write_points_nr; wp++) {
        writepoint_init(wp, ORCA_DATA_user);
        wp->last_used = sched_clock();
        wp->write_point = (unsigned long)wp;
        hlist_add_head_rcu(&wp->node, writepoint_hash(c, wp->write_point));
    }
}
