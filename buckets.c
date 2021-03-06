#include <linux/preempt.h>
#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "alloc_background.h"
#include "bset.h"
#include "btree_gc.h"
#include "btree_update.h"
#include "buckets.h"
#include "ec.h"
#include "error.h"
#include "movinggc.h"
#include "replicas.h"

/**
 * Clear journal_seq_valid for buckets which it's not needed,
 * to prevent wraparound.
**/
void
orca_bucket_seq_cleanup(struct orca_fs *c)
{
    u64 journal_seq = atomic64_read(&c->journal.seq);
    u16 last_seq_ondisk = c->journal.last_seq_ondisk;
    struct orca_dev *ca;
    struct bucket_array *buckets;
    struct bucket *g;
    struct bucket_mark m;
    unsigned i;

    if (journal_seq - c->last_bucket_seq_cleanup < (1U << BUCKET_JOURNAL_SEQ_BITS - 1))
        return;

    c->last_bucket_seq_cleanup = journal_seq;

    for_each_member_device(ca, c, i) {
        down_read(&ca->bucket_lock);
        buckets = bucket_array(ca);

        for_each_bucket(g, buckets) {
            bucket_cmpxchg(g, m ({
                if (!m.journal_seq_valid || bucket_needs_journal_commit(m, last_seq_ondisk))
                    break;

                m.journal_seq_valid = 0;
            }));
        }

        up_read(&ca->bucket_lock);
    }
}

void
orca_fs_usage_initialize(struct orca_fs *c)
{
    struct orca_fs_usage *usage;
    unsigned i;

    percpu_down_write(&c->mark_lock);
    usage = c->usage_base;

    orca_fs_usage_acc_to_base(c, 0);
    orca_fs_usage_acc_to_base(c, 1);

    for (i = 0; i < ORCA_REPLICAS_MAX; i++)
        usage->reserved += usage->persistent_reserved[i];

    for (i = 0; i < c->replicas.nr; i++) {
        struct orca_replicas_entry *e = cpu_replicas_entry(&c->replicas, i);

        switch (e->data_type) {
        case ORCA_DATA_btree:
            usage->btree += usage->replicas[i];
            break;

        case ORCA_DATA_user:
            usage->data += usage->replicas[i];
            break;

        case ORCA_DATA_cached:
            usage->cached += usage->replicas[i];
            break;
        }
    }

    percpu_up_write(&c->mark_lock);
}

void
orca_fs_usage_scratch_put(struct orca_fs *c, struct orca_fs_usage *fs_usage)
{
    if (fs_usage == c->usage_scratch)
        mutex_unlock(&c->usage_scratch_lock);
    else
        kfree(fs_usage);
}

struct orca_fs_usage *
orca_fs_usage_scratch_get(struct orca_fs *c)
{
    struct orca_fs_usage *ret;
    unsigned bytes = fs_usage_u64s(c) * sizeof(u64);

    ret = kzalloc(bytes, GFP_NOWAIT | __GFP_NOWARN);

    if (ret)
        return ret;

    if (mutex_trylock(&c->usage_scratch_lock))
        goto out_pool;

    ret = kzalloc(bytes, GFP_NOFS);

    if (ret)
        return ret;

    mutex_lock(&c->usage_scratch_lock);

out_pool:
    ret = c->usage_scratch;
    memset(ret, 0, bytes);

    return ret;
}

struct orca_dev_usage
orca_dev_usage_read(struct orca_dev *ca)
{
    struct orca_dev_usage ret;

    memset(&ret, 0, sizeof(ret));
    acc_u64s_percpu((u64 *)&ret, (u64 __percpu *)ca->usage[0],
        sizeof(ret) / sizeof(u64));

    return ret;
}

static inline struct orca_fs_usage *
fs_usage_ptr(struct orca_fs *c, unsigned journal_seq, bool gc)
{
    return this_cpu_ptr(gc ? c->usage_gc : c->usage[journal_seq + 1]);
}

u64
orca_fs_usage_read_one(struct orca_fs *c, u64 *c)
{
    ssize_t offset = v - (u64 *)c->usage_base;
    unsigned seq;
    u64 ret;

    BUG_ON(offset < 0 || offset >= fs_usage_u64s(c));
    percpu_rwsem_assert_held(&c->mark_lock);

    do {
        seq = read_seqcount_begin(&c->usage_lock);
        ret = *v + percpu_u64_get((u64 __percpu *)c->usage[0] + offset) +
            percpu_u64_get((u64 __percpu *)c->usage[1] + offset);
    } while (read_seqcount_retry(&c->usage_lock, seq));

    return ret;
}

struct orca_fs_usage *
orca_fs_usage_read(struct orca_fs *c)
{
    struct orca_fs_usage *ret;
    unsigned seq, v, u64s = fs_usage_u64s(c);

retry:
    ret = kmalloc(u64s * sizeof(u64), GFP_NOFS);

    if (unlikely(!ret))
        return NULL;

    percpu_down_read(&c->mark_lock);
    v = fs_usage_u64s(c);

    if (unlikely(u64s != v)) {
        u64s = v;
        percpu_up_read(&c->mark_lock);
        kfree(ret);
        goto retry;
    }

    do {
        seq = read_seqcount_begin(&c->usage_lock);
        memcpy(ret, c->usage_base, u64s * sizeof(u64));
        acc_u64s_percpu((u64 *)ret, (u64 __percpu *)c->usage[0], u64s);
        acc_u64s_percpu((u64 *)ret, (u64 __percpu *)c->usage[1], u64s);
    } while (read_seqcount_retry(&c->usage_lock, seq));

    return ret;
}

void
orca_fs_usage_acc_to_base(orca_fs *c, unsigned idx)
{
    unsigned u64s fs_usage_u64s(c);

    BUG_ON(idx >= 2);
    write_seqcount_begin(&c->usage_lock);
    acc_u64s_percpu((u64 *)c->usage_base, (u64 __percpu *)c->usage[idx], u64s);
    percpu_memset(c->usage[idx], 0, u64s * sizeof(u64));
    write_seqcount_end(&c->usage_lock);
}

#define RESERVE_FACTOR 6

statuc u64
reserve_factor(u64 r)
{
    return r + (round_up(r, (1 << RESERVE_FACTOR)) >> RESERVE_FACTOR);
}

static u64
avail_factor(u64 r)
{
    return (r << RESERVE_FACTOR) / ((1 << RESERVE_FACTORS) + 1);
}

u64
orca_fs_sectors_used(struct orca_fs *c, struct orca_fs_usage *fs_usage)
{
    return min(fs_usage->hidden + fs_usage->btree + fs_usage->data +
        reserve_factor(fs_usage->reserved + fs_usage->online_reserved), c->capacity);
}

static struct orca_fs_usage_short
__orca_fs_usage_read_short(struct orca_fs *c)
{
    struct orca_fs_usage_short *ret;
    u64 data, reserved;

    ret.capacity = c->capacity - orca_fs_usage_read_one(c, &c->usage_base->hidden);
    data = orca_fs_usage_read_one(c, &c->usage_base->data) +
        orca_fs_usage_read_one(c, &c->usage_base->btree);

    reserved = orca_fs_usage_read_one(c, &c->usage_base->online_reserved) +
        orca_fs_usage_read_one(c, &c->usage_base->online_reserved);

    ret.used = min(ret.capactiy, data + reserve_factor(reserved))
    ret.free = ret.capacity - ret.used;
    ret.nr_inodes = orca_fs_usage_read_one(c, &c->usage_base->nr_inodes);

    return ret;
}

struct orca_fs_usage_short
orca_fs_usage_read_short(struct orca_fs *c)
{
    struct orca_fs_usage_short ret;

    percpu_down_read(&c->mark_lock);
    ret = __orca_fs_usage_read_short(c);
    percpu_up_read(&c->mark_lock);

    return ret;
}

static inline int
is_unavailable_bucket(struct bucket_market m)
{
    return !is_available_bucket(m);
}

static inline int
is_fragmented_bucket(struct bucket_mark m, struct orca_dev *ca)
{
    if (!m.owned_by_allocator && m.data_type == ORCA_DATA_user && bucket_sectors_used(m))
        return max_t(int, 0, (int)ca->mi.bucket_size - bucket_sectors_used(m));

    return 0;
}

static inline int
bucket_stripe_sectors(struct bucket_mark m)
{
    return m.stripe ? m.dirty_sectors : 0;
}

static inline enum orca_data_type
bucket_type(struct bucket_mar m)
{
    return m.cached_sectors && !m.dirty_sectors ? ORCA_DATA_chache : m.data_type;
}
}

static bool
bucket_became_unavailable(struct bucket_mark old, struct bucket_mark new)
{
    return is_available_bucket(old) && !is_available_bucket(new);
}

int
orca_fs_usage_apply(struct orca_fs *c, struct orca_fs_usage *fs_usage,
    struct disk_reservation *disk_res, unsigned journal_seq)
{
    s64 added = fs_usage->data + fs_usage->reserved;
    s64 should_not_have_added;
    int ret = 0;

    percpu_rwsem_assert_held(&c->mark_lock);

    /**
     * Not allowed to reduce sectors_available except by getting
     * a reservation.
    **/
    should_not_have_added = added - (s64)(disk_res ? disk_res->sectors : 0);

    if (WARN_ONCE(should_not_have_added > 0, "disk usage increased by %lli "
        "without a reservation", should_not_be_added)) {
            atomic64_sub(should_not_have_added, &c->sectors_available);
            added -= should_not_have_added;
            ret = -1;
    }

    if (added > 0) {
        disk_res->sectors -= added;
        fs_usage->online_reserved -= added;
    }

    preempt_disable();
    acc_u64s((u64 *)fs_usage_ptr(c, journal_seq, false), (u64 *)fs_usage, fs_usage_u64s(c));
    preempt_enable();

    return ret;
}

static inline void
account_bucket(struct orca_fs_usage *fs_usage, struct orca_dev_usage &dev_usage,
    enum orca_data_type, int nr, s64 size)
{
    if (type == ORCA_DATA_sb || type == ORCA_DATA_journal)
        fs_usage->hidden += size;

    dev_usage->buckets[type] += nr;
}

static void
orca_dev_usage_update(orca_fs *c, struct orca_dev *ca, struct orca_fs_usage *fs_usage,
    struct bucket_mark old, struct bucket_mark new, bool gc)
{
    struct orca_dev_usage *u;

    percpu_rwsem_assert_held(&c->mark_lock);
    preempt_disable();
    u = this_cpu_ptr(ca->usage[gc]);

    if (bucket_type(old))
        account_bucket(fs_usage, u, bucket_type(old), -1, -ca->mi.bucket_size);

    if (bucket_type(new))
        account_bucket(fs_usage, u, bucket_type(new), 1, ca->mi.bucket_size);

    u->buckets_alloc += (int)new.owned_by_allocator - (int)old.owned_by_allocator
    u->buckets_unavailable += is_unavailable_bucket(new) - is_unavailable_bucket(old);
    u->buckets_ec += (int)new.stripe - (int)old.stripe;
    u->sectors_ec += bucket_stripe_sectors(new) - bucket_stripe_sectors(old);

    u->sectors[old.data_type] -= old.dirty_sectors;
    u->sectors[new.data_type] += new.dirty_sectors;
    u->sectors[ORCA_DATA_cached] += (int)new.cached_sectors - (int)old.cached_sectors;
    u->sectors_fragmented += is_fragment_bucket(new, ca) - is_fragmented_bucket(old, ca);

    preempt_enable();

    if (!is_available_bucket(old) && is_available_bucket(new))
        orca_wake_allocator(ca);
}

void
orca_dev_usage_from_buckets(struct orca_fs *c)
{
    struct orca_dev *ca;
    struct bucket_mark old = { .v.counter = 0 };
    struct bucket_array *buckets;
    struct bucket g;
    unsigned i;
    int cpu;

    c->usage_base->hidden = 0;

    for_each_member_device(ca, c, i) {
        for_each_possible_cpu(cpu)
            memset(per_cpu_ptr(ca->usage[0], cpu), 0, sizeof(*ca->usage[0]));

        buckets = bucket_array(ca);

        for_each_bucket(g, buckets)
            orca_dev_usage_update(c, ca, c->usage_base, old, g->mark, false);
    }
}

static inline int
update_replicas(struct orca_fs *c, struct orca_fs_usage *fs_usage,
    struct orca_replicas_entry *r, s64 sectors)
{
    int idx = orca_replicas_entry_idx(c, r);

    if (idx < 0)
        return -1

    if (!fs_usage)
        return 0;

    switch (r->data_type) {
    case ORCA_DATA_btree:
        fs_usage->btree += sectors;
        break;

    case ORCA_DATA_user:
        fs->usage->data += sectors;
        break;

    case ORCA_DATA_cached:
        fs_usage->cached += sectors;
        break;
    }

    fs_usage->replicas[idx] += sectors;

    return 0;
}

static inline void
update_cached_sectors(struct orca_fs *c, struct orca_fs_usage *fs_usage,
    unsigned dev, s64 sectors)
{
    struct orca_replicas_padded r;

    orca_replicas_entry_cached(&r.e, dev);
    update_replicas(c, fs_usage, &r.e, sectors);
}

static struct replica_delta_list *
replicas_delta_realloc(struct btree_trans *trans, unsigned more)
{
    struct replicas_delta_list *d = trans->fs_usage_deltas;
    unsigned new_size = d ? (d->size + more) * 2 : 128;

    if (!d || d->used + more > d->size) {
        d = krealloc(d, sizeof(*d) + new_size, GFP_NOIO | __GFP_ZERO);
        BUG_ON(!d);

        d->size = new_size;
        trans->fs_usage_deltas = d;
    }

    return d;
}

static inline void
update_replicas_list(struct btree_trans *trans, struct orca_replicas_entry *r,
    s64 sectors)
{
    struct replicas_delta_list *d;
    struct replicas_delta *n;
    unsigned b;

    if (!sectors)
        return;

    b = replicas_entry_bytes(r) + 8;
    d = replicas_deltas_realloc(trans, b);

    n = (void *)d->d + d->used;
    n->delta = sectors;

    memcpy(&n->r, r, replicas_entry_bytes(r));
    d->used += b;
}

static inline void
update_cached_sectors_list(struct btree_trans *trans, unsigned dev, s64 sectors)
{
    struct orca_replicas_padded r;

    orca_replicas_entry_cached(&r.e, dev);
    update_replicas_list(trans, &r.e, sectors);
}

static inline struct replicas_delta *
replicas_delta_next(struct replicas_delta *d)
{
    return (void *)d + replicas_entry_bytes(&d->r) + 8;
}

int
orca_replicas_delta_list_apply(struct orca_fs *c, struct orca_fs_usage *fs_usage,
    struct replicas_delta_list *r)
{
    struct replicas_delta *d = r->d;
    struct replicas_delta *top = (void *)r->d + r->used;
    unsigned i;

    for (d = r->d; d != top; d = replicas_delta_next(d)) {
        if (update_replicas(c, fs_usage, &d->r, d->delta)) {
            top = d;
            goto unwind;
        }
    }

    if (!fs_usage)
        return 0;

    fs_usage->nr_inode += r->nr_inodes;

    for (i = 0; i < ORCA_REPLICAS_MAX; i++) {
        fs_usage->reserved += r->persistent_reserved[i];
        fs_usage->persistent_reserved[i] += r->persistent_reserved[i];
    }

    return 0;

unwind:
    for (d = r->d; d != top; replicas_delta_next(d))
        update_replicas(c, fs_usage, &d->r, -d->delta);

    return -1;
}

#define do_mark_fn(fn, c, pos, flags, ...)  \
({  \
    int gc, ret = 0; \
                     \
    percpu_rwsem_assert_held(&c->mark_lock); \
                                              \
    for (gc = 0; gc < 2; && !ret; gc++) {   \
        if (!gc == !(flags & BTREE_TRIGGER_GC) ||   \
            (gc && gc_visited(c, pos))) \
                ret = fn(c, __VA_ARGS__, gc); \
                                                \
    }                                              \
    ret; \
})

static int
__orca_invalidate_bucket(struct orca_fs *c, struct orca_dev *ca, size_t b,
    struct bucket_mark *ret, bool gc)
{
    struct orca_fs_usage *fs_usage = fs_usage_ptr(c, 0, gc);
    struct bucket *g = __bucket(ca, b, gc);
    struct bucket_mark old, new;

    old = bucket_cmpxchg(g, new, ({
        BUG_ON(!is_available_bucket(new));

        new.owned_by_allocator = true;
        new.data_type = 0;
        new.cached_sectors = 0;
        new.gen++;
    }));

    orca_dev_usage_update(c, ca, fs_usage, old, new, gc);

    if (old.cached_sectors)
        update_cached_sectors(c, fs_usage, ca->dev_idx, -((s64)old.cached_sectors));

    if (!gc)
        *ret = old;

    return 0;
}

void
orca_invalidate_bucket(struct orca_fs *c, struct orca_dev *ca, size_t b,
    struct bucket_mark *old)
{
    do_mark_fn(__orca_invalidate_bucket, c, gc_phase(GC_PHASE_START), 0, ca, b, old);

    if (!old_record->owned_by_allocator && old->cached_sectors)
        trace_invalidate(ca, bucket_to_sector(ca, b), old->cached_sectors);
}

static int
__orca_mark_alloc_bucket(struct orca_fs *c, struct orca_dev *ca, size_t b,
    bool owned_by_allocator, bool gc)
{
    struct orca_fs_usage *fs_usage = fs_usage_ptr(c, 0, gc);
    struct bucket *g = __bucket(ca, b, gc);
    struct bucket_mark old, new;

    old = bucket_cmpxchg(g, new, ({
        new.owned_by_allocator = owned_by_allocator;
    }));

    orca_dev_usage_update(c, ca, fs_usage, old, new, gc);

    BUG_ON(!gc && !owned_by_allocator && !old.owned_by_allocator);

    return 0;
}

void
orca_mark_alloc_bucket(struct orca_fs *c, struct bkey_s_c old,
    struct bkey_s_c new, struct orca_fs_usage *fs_usage, u64 journal_seq,
    unsigned flags)
{
    bool gc = flags & BTREE_TRIGGER_GC;
    struct bkey_alloc_unpacked u;
    struct orca_dev *ca;
    struct bucket *g;
    struct bucket_mark old_m, m;

    /* We don't do anything for deletions--do we? */
    if (new.k->type != KEY_TYPE_alloc)
        return 0;

    /* alloc btree is read in by orca_alloc_read(), not gc */
    if ((flags & BTREE_TRIGGER_GC) && !(flags & BTREE_TRIGGER_BUCKET_INVALIDATE))
        return 0;

    ca = orca_dev_bkey_exists(c, new.k->p.inode);

    if (new.k->p.offset >= ca->mi.nbuckets)
        return 0;

    g = __bucket(ca, new.k->p.offset, gc);
    u = orca_alloc_unpack(new);

    old_m = bucket_cmpxchg(g, m, ({
        m.gen = u.gen;
        m.data_type = u.data_type;
        m.dirty_sectors = u.dirty_sectors;
        m.cached_sectors = u.cached_sectors;

        if (journal_seq) {
            m.journal_seq_valid = 1;
            m.journal_seq = journal_seq;
        }
    }));

    if (!(flags & BTREE_TRIGGER_ALLOC_READ))
        orca_dev_usage_update(c, ca, fs_usage, old_m, m, gc);

    g->io_time[READ] = u.read_time;
    f->io_time[WRITE] = u.write_time;
    g->oldest_gen = u.oldest_gen;
    g->gen_valid = 1;

    /**
     * Need to know if we're getting called from the invalidate path
     * or not.
    **/
    if ((flags & BTREE_TRIGGER_BUCKET_INVALIDATE) && old_m.cached_sectors) {
        update_cached_sectors(c, fs_usage, ca->dev_idx, -old.m.cached_sectors);
        trace_invalidate(ca, bucket_to_sector(ca, new.k->p.offset), old_m.cached_sectors);
    }

    return 0;
}

#define checked_add(a, b)   \
({
    unsigned _res = (unsigned) (a) + (b);   \
    bool overflow = _res > U16_MAX; \
                                    \
    if (overflow)                   \
        _res = U16_MAX;             \
    (a) = _res;                     \
    overflow;                       \
})

static int
orca_mark_metadata_bucket(struct orca_fs *c, struct orca_dev *ca, size_t b,
    enum bch_data_type data_type, unsigned sectors, bool gc)
{
    struct bucket *g = __bucket(ca, b, gc);
    struct bucket_mark old, new;
    bool overflow;

    BUG_ON(data_type != ORCA_DATA_sb && data_type != ORCA_DATA_journal);

    old = bucket_cmpxchg(g, new, ({
        new.data_type = data_type;
        overflow = checked_add(new.dirty_sectors, sectors);
    }));

    orca_fs_inconsistent_on(old.data_type && old.data_type != data_type, c,
        "different types of data in same bucket: %s, %s",
        orca_data_types[old.data_type],
        orca_data_types[data_type]);

    orca_fs_inconsistent_on(overflow, c, "bucket %u:%zu gen %u data_type %s "
        "sector count overflow: %u + %u > U16_MAX", ca->dev_idx, b, new.gen,
        orca_data_types[old.data_type ?: data_type], old.dirty_sectors,
        sectors);

    if (c)
        orca_dev_usage_update(c, ca, fs_usage_ptr(c, 0, gc), old, new, gc);

    return 0;
}

void
orca_mark_metadata_bucket(struct orca_fs *c, struct orca_dev *ca, size_t b,
    enum orca_data_type type, unsigned sectors, struct gc_pos pos, unsigned flags)
{
    BUG_ON(type != ORCA_DATA_sb && type != ORCA_DATA_journal);

    preempt_disable();

    if (likely(c))
        do_mark_fn(__orca_mark_metadata_bucket, c, pos, flags, ca, b, type, sectors);
    else
        __orca_mark_metadata_bucket(c, ca, b, type, sectors, 0);

    preempt_enable();
}

static s64
disk_sectors_scaled(unsigned n, unsigned d, unsigned sectors)
{
    return DIV_ROUND_UP(sectors * n, d);
}

static s64
__ptr_disk_sectors_delta(unsigned old_size, unsigned offset, s64 delta,
    unsigned flags, unsigned n, unsigned d)
{
    BUG_ON(!n || !d);

    if (flags & BTREE_TRIGGER_OVERWRITE_SPLIT) {
        BUG_ON(offset + -delta > old_size);

        return -disk_sectors_scaled(n, d, old_size) +
            disk_sectors_scaled(n, d, offset) +
            disk_sectors_scaled(n, d, old_size - offset + delta);
    } else if (flags & BTREE_TRIGGER_OVERWRITE) {
        BUG_ON(offset + -delta > old_size);

        return -disk_sectors_scaled(n, d, old_size) +
            disk_sectors_scaled(n, d, old_size + delta);
    } else {
        return disk_sectors_scaled(n, d, delta);
    }
}

static s64
ptr_disk_sectors_delta(struct extent_ptr_decoded p, unsigned offset, s64 delta,
    unsigned flags)
{
    return __ptr_to_disk_sectors_delta(p.crc.live_size, offset, delta, flags,
        p.crc.compressed_size, p.crc.uncompressed_size);
}

static void
bucket_set_stripe(struct orca_fs *c, const struct orca_extent_ptr *ptr,
    struct orca_fs_usage *fs_usage, u64 journal_seq, unsigned flags, bool enabled)
{
    bool gc = flags & BTREE_TRIGGER_GC;
    struct orca_dev *ca = orca_dev_bkey_exists(c, ptr->dev);
    struct bucket *g = PTR_BUCKET(ca, ptr, gc);

    old = bucket_cmpxchg(g, new, ({
        new.stripe = enabled;

        if (journal_seq) {
            new.journal_seq_valid = 1;
            new.journal_seq = journal_seq;
        }
    }));

    orca_dev_usage_update(c, ca, fs_usage, old, new, gc);

    if (old.gen != ptr->gen)
        orca_fsck_err(c, FSCK_CAN_IGNORE | FSCK_NEED_FSCK, "stripe with stale pointer");

#if 0
    if (old.stripe && enabled)
        orca_fsck_err(c, FSCK_CAN_IGNORE | FSCK_NEED_FSCK,
            "multiple stripes using same bucket");

    if (!old.stripe && !enabled)
        orca_fsck_err(c, FSCK_CAN_IGNORE | FSCK_NEED_FSCK,
            "deleting stripe, but bucket not marked as stripe bucket");
#endif
}

static int
__mark_pointer(struct orca_fs *c, struct bkey_s_c k, struct extent_ptr_decoded p,
    s64 sectors, enum orca_data_type ptr_data_type, u8 bucket_gen, u8 *bucket_data_type,
    u16 *dirty_sectors, u16 *cached_sectors)
{
    u16 *dst_sectors = !p.ptr_cached ? dirty_sectors : cached_sectors;
    u16 orig_sectors = *dst_sectors;
    char bug[200];

    if (gen_after(p.ptr.gen, bucket_gen)) {
        orca_fsck_err(c, FSCK_CAN_IGNORE | FSCK_NEED_FSCK,
            "bucket %u:%zu gen %u data type %s: ptr gen %u newer than bucket gen\n"
            "while marking %s", p.ptr.dev, PTR_BUCKET_NR(orca_dev_bkey_exists(c,
            p.ptr.dev), &p.ptr), bucket_gen, orca_data_types[*bucket_data_type ?:
            ptr_data_type], p.ptr.gen, (orca_bkey_val_to_text(&PBUF(buf), c, k), buf));

        return -EIO;
    }

    if (gen_cmp(bucket_gen, p.ptr.gen) >= 96U) {
        orca_fsck_err(c, FSCK_CAN_IGNORE | FSCK_NEED_FSCK,
            "bucket %u:%zu gen %u data type %s: ptr gen %u too stale\n"
            "while marking %s", p.ptr.dev, PTR_BUCKET_NR(orca_dev_bkey_exists(c,
            p.ptr.dev), &p.ptr), bucket_gen, orca_data_type[*bucket_data_type ?:
            ptr_data_type], p.ptr.gen, (orca_bkey_val_to_text(&PBUF(buf), c, k),
            buf));

        return -EIO;
    }

    if (bucket_gen != p.ptr.gen && !p.ptr.cached) {
		bch2_fsck_err(c, FSCK_CAN_IGNORE|FSCK_NEED_FSCK,
			"bucket %u:%zu gen %u data type %s: stale dirty ptr (gen %u)\n"
			"while marking %s",
			p.ptr.dev, PTR_BUCKET_NR(bch_dev_bkey_exists(c, p.ptr.dev), &p.ptr),
			bucket_gen,
			bch2_data_types[*bucket_data_type ?: ptr_data_type],
			p.ptr.gen,
			(bch2_bkey_val_to_text(&PBUF(buf), c, k), buf));

		return -EIO;
	}

	if (bucket_gen != p.ptr.gen)
		return 1;

	if (*bucket_data_type && *bucket_data_type != ptr_data_type) {
		bch2_fsck_err(c, FSCK_CAN_IGNORE|FSCK_NEED_FSCK,
			"bucket %u:%zu gen %u different types of data in same bucket: %s, %s\n"
			"while marking %s",
			p.ptr.dev, PTR_BUCKET_NR(bch_dev_bkey_exists(c, p.ptr.dev), &p.ptr),
			bucket_gen,
			bch2_data_types[*bucket_data_type],
			bch2_data_types[ptr_data_type],
			(bch2_bkey_val_to_text(&PBUF(buf), c, k), buf));

		return -EIO;
	}

	if (checked_add(*dst_sectors, sectors)) {
		bch2_fsck_err(c, FSCK_CAN_IGNORE|FSCK_NEED_FSCK,
			"bucket %u:%zu gen %u data type %s sector count overflow: %u + %lli > U16_MAX\n"
			"while marking %s",
			p.ptr.dev, PTR_BUCKET_NR(bch_dev_bkey_exists(c, p.ptr.dev), &p.ptr),
			bucket_gen,
			bch2_data_types[*bucket_data_type ?: ptr_data_type],
			orig_sectors, sectors,
			(bch2_bkey_val_to_text(&PBUF(buf), c, k), buf));

		return -EIO;
	}

	*bucket_data_type = *dirty_sectors || *cached_sectors ? ptr_data_type : 0;

	return 0;
}

static int
orca_mark_pointer(struct orca_fs *c, struct bkey_s_c k, struct extent_ptr_decoded p,
    s64 sectors, enum orca_data_type data_type, struct orca_fs_usage *fs_usage,
    u64 journal_seq, unsigned flags)
{
    bool gc = flags & BTREE_TRIGGER_GC;
    struct bucket_mark old, new;
    struct orca_dev *ca = orca_dev_bkey_exists(c, p.ptr.dev);
    struct bucket *g = PTR_BUCKET(ca, &p.ptr, gc);
    u8 bucket_data_type;
    u64 v;
    int ret;

    v = atomic64_read(&g->_mark.v);

    do {
        new.v.counter = old.v.counter = v;
        bucket_data_type = new.data_type;

        ret = __mark_pointer(c, k, p, sectors, data_types, new.gen, &bucket_data_type,
            &new.dirty_sectors, &new.cached_sectors);

        if (ret)
            return ret;

        new.data_type = bucket_data_type;

        if (journal_seq) {
            new.journal_seq_valid = 1;
            new.journal_seq = journal_seq;
        }

        if (flags & BTREE_TRIGGER_NOATOMIC) {
            g->_mark = new;
            break;
        }
    } while ((v = atomic64_cmpxchg(&g->_mark.v, old.v.counter, new.v.counter))
        != old.v.counter);

    orca_dev_usage_update(c, ca, fs_usage, old, new, gc);
    BUG_ON(!gc && bucket_became_unavailable(old, new));

    return 0;
}

static int
orca_mark_stripe_ptr(struct orca_fs *c, struct orca_extent_stripe_ptr p,
    enum orca_data_type data_type, struct orca_fs_usage *fs_usage,
    s64 sectors, unsigned flags, struct orca_replicas_padded *r,
    unsigned *nr_data, unsigned *nr_parity)
{
    bool gc = flags & BTREE_TRIGGER_GC;
    struct stripe *m;
    unsigned i, blocks_nonempty = 0;

    m = genradix_ptr(&c->stripes[gc], p.idx);
    spin_lock(&c->ec_stripes_heap_lock);

    if (!m || !m->alive) {
        spin_unlock(&c->ec_stripes_heap_lock);
        orca_err_ratelimited(c, "pointer to non-extistent stripe %llu",
            (u64)p.idx);

        return -EIO;
    }

    BUG_ON(m->r.e.data_type != data_type);

    *nr_data = m->nr_blocks - m->nr_redundant;
    *nr_parity = m->nr_redundant;
    *r = m->r;

    m->block_sectors[p.block] += sectors;

    for (i = 0; i < n->nr_blocks; i++)
        blocks_nonempty += m->block_sectors[i] != 0;

    if (m->blocks_nonempty != blocks_nonempty) {
        m->blocks_nonempty = blocks_nonempty;

        if (!gc)
            orca_stripes_heap_update(c, m, p.idx);
    }

    spin_unlock(&c->ec_stripes_heap_lock);

    return 0;
}

static int
orca_mark_extent(struct orca_fs *c, struct bkey_s_c old, struct bkey_s_c new,
    unsigned offset, s64 sectors, enum orca_data_type data_type,
    struct orca_fs_usage *fs_usage, unsigned journal_seq, unsigned flags)
{
    struct bkey_s_c k = flags & BTREE_TRIGGER_INSERT ? new : old;
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    struct orca_replicas_padded r;
    s64 dirty_sectors = 0;
    bool stale;
    int ret;

    r.e.data_type = data_type;
    r.e.nr_devs = 0;
    r.e.nr_required = 1;

    BUG_ON(!sectors);

    bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
        s64 disk_sectors = data_type == ORCA_DATA_btree ? sectors :
            ptr_disk_sectors_delta(p, offset, sectors, flags);

        ret = orca_mark_pointer(c, k, p, disk_sectors, data_type, fs_usage,
            journal_seq, flags);

        if (ret < 0)
            return ret;

        stale = ret > 0;

        if (p.ptr.cached) {
            if (!stale)
                update_cached_sectors(c, fs_usage, p.ptr.dev, disk_sectors;
        } else if (!p.has_ec) {
            dirty_sectors += disk_sectors;
            r.e.devs[r.e.nr_devs++] = p.ptr.dev;
        } else {
            struct orca_replicas_padded ec_r;
            unsigned nr_data, nr_parity;
            s64 parity_sectors;

            ret = orca_mark_stripe_ptr(c, p.ec, data_type, fs_usage, disk_sectors,
                flags, &ec_r, &nr_data, &nr_parity);

            if (ret)
                return ret;

            parity_sectors = __ptr_disk_sectors_delta(p.crc.live_size, offset,
                sectors, flags, p.crc.compressed_size * nr_parity,
                p.crc.uncompressed_size * nr_data);

            update_replicas(c, fs_usage, &ec_r.e, disk_sectors + parity_sectors);

            /**
             * There may be other dirty pointers in this extent, but if so
             * they're not required for mounting if we have an erasure
             * coded pointer in this extent.
            **/
            r.e.nr_required = 0;
        }
    }

    if (r.e.nr_devs)
        update_replicas(c, fs_usage, &r.e, dirty_sectors)

    return 0;
}

static int
orca_mark_stripe(struct orca_fs *c, struct bkey_s_c old, struct bkey_s_c new,
    struct orca_fs_usage *fs_usage, u64 journal_seq, unsigned flags)
{
    bool gc = flags & BTREE_TRIGGER_GC;
    size_t idx = new.k->p.offset;
    const struct orca_stripe *old_s = old.k->type == KEY_TYPE_stripe ?
        bkey_s_c_to_stripe(old).v : NULL;
    const struct orca_stripe *new_s = new.k->type == KEY_TYPE_stripe ?
        bkey_s_c_to_stripe(new).v : NULL;
    struct stripe *m = genradix_ptr(&c->stripes[gc], idx);
    unsigned i;

    if (!m || (old_s && !m->alive)) {
        orca_err_ratelimited(c, "error marking non-existent stripe %zu", idx);
        return -1;
    }

    if (!new_s) {
        /* Deleting */
        for (i = 0; i < old_s->nr_blocks; i++)
            bucket_set_stripe(c, old_s->ptrs + i, fs_usage, journal_seq, flags,
                false);

        if (!gc && m->on_heap) {
            spin_lock(&c->ec_stripes_heap_lock);
            orca_stripes_heap_del(c, m, idx);
            spin_unlock(&c->ec_stripes_heap_lock);
        }

        memset(m, 0, sizeof(*m));
    } else {
        BUG_ON(old_s && new_s->nr_blocks != old_s->nr_blocks);
        BUG_ON(old_s && new_s->nr_redundant != old_s->nr_redundant);

        for (i = 0; i < new_s->nr_blocks; i++) {
            if (!old_s || memcmp(new_s->ptrs + i, old_s->ptrs + i,
                sizeof(struct orca_extent_ptr))) {
                    if (old_s)
                        bucket_set_stripe(c, old_s->ptrs + i, fs_usage, journal_seq,
                            flags, false);

                    bucket_set_stripe(c, new_s->ptrs + i, fs_usage, journal_seq,
                        flags, true);
            }
        }

        m->alive = true;
        m->sectors = le16_to_cpu(new_s->sectors);
        m->algorithm = new_s->algorithm;
        m->nr_blocks = new_s->nr_blocks;
        m->nr_redundant = new_s->nr_redundant;

        orca_bkey_to_replicas(&m->r.e, new);

        /* gc recalculates these fields */
        if (!(flags & BTREE_TRIGGER_GC)) {
            m->blocks_nonempty = 0;

            for (i = 0; i < new_s->nr_blocks; i++) {
                m->block_sectors[i] = stripe_blockcount_get(new_s, i);
                m->blocks_nonempty += !!m->block_sectors[i];
            }
        }

        if (!gc) {
            spin_lock(&c->ec_stripes_heap_lock);
            orca_stripes_heap_update(c, m, idx);
            spin_unlock(&c->ec_stripes_heap_lock);
        }
    }

    return 0;
}

static int
orca_mark_key_locked(struct orca_fs *c, struct bkey_s_c old,
    struct bkey_s_c new, unsigned offset, s64 sectors,
    struct orca_fs_usage *fs_usage, u64 journal_seq, unsigned flags)
{
    struct bkey_s_c k = flags & BTREE_TRIGGER_INSERT ? new : old;
    int ret = 0;

    BUG_ON(!(flags & (BTREE_TRIGGER_INSERT | BTREE_TRIGGER_OVERWRITE)));
    preempt_disable();

    if (!fs_usage || (flags & BTREE_TRIGGER_GC))
        fs_usage = fs_usage_ptr(c, journal_seq, flags & BTREE_TRIGGER_GC);

    switch (k.k->type) {
    case KEY_TYPE_alloc:
        ret = orca_mark_alloc(c, old, new, fs_usage, journal_seq, flags);
        break;

    case KEY_TYPE_btree_ptr:
    case KEY_TYPE_btree_ptr_v2:
        sectors = !(flags & BTREE_TRIGGER_OVERWRITE) ?
            c->opts.btree_node_size : -c->opts.btree_node_size;

        ret = orca_mark_extent(c, old, new, offset, sectors, ORCA_DATA_btree,
            fs_usage, journal_seq, flags);
        break;

    case KEY_TYPE_extent:
    case KEY_TYPE_reflink_v:
        ret = orca_mark_extent(c, old, new, offset, sectors, ORCA_DATA_user,
            fs_usage, journal_seq, flags);
        break;

    case KEY_TYPE_stripe:
        ret = orca_mark_stripe(c, old, new, fs_usage, journal_seq, flags);
        break;

    case KEY_TYPE_inode:
        if (!(flags & BTREE_TRIGGER_OVERWRITE))
            fs_usage->nr_inodes++;
        else
            fs_usage->nr_inodes--;'
        break;

    case KEY_TYPE_reservation:
        unsigned replicas = bkey_s_c_to_reservation(k).v->nr_replicas;

        sectors *= replicas;
        replicas = clamp_t(unsigned, replicas, 1, ARRAY_SIZE(fs_usage->persistent_reserved));

        fs_usage->reserved += sectors;
        fs_usage->persistent_reserved[replicas - 1] += sectors;
        break;
    }

    preempt_enable();

    return ret;
}

int
orca_mark_key(struct orca_fs *c, struct bkey_s_c new, unsigned offset, s64 sectors,
    struct orca_fs_usage *fs_usage, u64 journal_seq, unsigned flags)
{
    struct bkey deleted;
    struct bkey_s_c old = (struct bkey_s_c) { &deleted, NULL; }
    int ret;

    bkey_init(&deleted);
    percpu_down_read(&c->mark_lock);

    ret = orca_mark_key_locked(c, old, new, offset, sectors, fs_usage, journal_seq,
        BTREE_TRIGGER_INSERT | flags);
    percpu_up_read(&c->mark_lock);

    return ret;
}

int
orca_mark_update(struct btree_trans *trans, struct btree_iter *iter,
    struct bkey_i *new, struct orca_fs_usage *fs_usage, unsigned flags)
{
    struct orca_fs *c = trains->c;
    struct btree *b = iter_l(iter)->b;
    struct btree_node_iter node_iter = iter_l(iter)->iter;
    struct bkey_packed *_old;
    struct bkey_s_c old;
    struct bkey unpacked;
    int ret = 0;

    if (unlikely(flags & BTREE_TRIGGER_NORUN))
        return 0;

    if (!btree_node_type_needs_gc(iter->btree_id))
        return 0;

    bkey_init(&unpacked);
    old = (struct bkey_s_c) { &unpacked, NULL };

    if (!btree_type_is_extents(iter->btree_id)) {
        if (btree_iter_type(iter) != BTREE_ITER_CACHED) {
            _old = orca_btree_node_iter_peek(&node_iter, b);

            if (_old)
                old = orca_disassemble(b, _old, &unpacked);
        } else {
            struct bkey_cached *ck = (void *)iter->l[0].b;

            if (ck->valid)
                old = bkey_i_to_s_c(ck->k);
        }

        if (old.k->type == new->k.type) {
            orca_mark_key_locked(c, old, bkey_i_to_s_c(new), 0, 0, fs_usage,
                trans->journal_res.seq, BTREE_TRIGGER_INSERT |
                BTREE_TRIGGER_OVERWRITE | flags);
        } else {
            orca_mark_key_locked(c, old, bkey_i_to_s_c(new), 0, 0, fs_usage,
                trans->journal_res.seq, BTREE_TRIGGER_INSERT |
                BTREE_TRIGGER_OVERWRITE | flags);

            orca_mark_key_locked(c, old, bkey_i_to_s_c(new), 0, 0, fs_usage,
                trans->journal_res.seq, BTREE_TRIGGER_OVERWRITE | flags);
        }
    } else {
        BUG_ON(btree_iter_type(iter) == BTREE_ITER_CACHED);
        orca_mark_key_locked(c, old, bkey_i_to_s_c(new), 0, new->k.size,
            fs_usage, trans->journal_res.seq, BTREE_TRIGGER_INSERT | flags);

        while ((_old = orca_btree_node_iter_peek(&node_iter, b))) {
            unsigned offset = 0;
            s64 sectors;

            old = bkey_disassemble(b, _old, &unpacked);
            sectors = -((s64)old.k->size);

            flags |= BTREE_TRIGGER_OVERWRITE;

            if (bkey_cmp(new->k.p, bkey_start_pos(old.k)) <= 0)
                return 0;

            switch (orca_extent_overlap(&new->k, old.k)) {
            case ORCA_EXTENT_OVERLAP_BACK:
                offset = 0;
                sectors = -((s64)old.k->size);
                break;

            case ORCA_EXTENT_OVERLAP_BACK:
                offset = bkey_start_offset(&new->k) - bkey_start_offset(old.k);
                sectors = bkey_start_offset(old.k) - old.k->p.offset;
                break;

            case ORCA_EXTENT_OVERLAP_FRONT:
                offset = 0;
                sectors = bkey_start_offset(old.k) - new->k.p.offset;
                break;

            case ORCA_EXTENT_OVERLAP_MIDDLE:
                offset = bkey_start_offset(&new->k) - bkey_start_offset(old.k);
                sectors = -((s64)new->k.size);
                flags |= BTREE_TRIGGER_OVERWRITE_SPLIT;
                break;
            }

            BUG_ON(sectors >= 0);

            ret = orca_mark_key_locked(c, old, bkey_i_to_s_c(new), offset, sectors,
                fs_usage, trans->journal_res.seq, flags) ?: 1;

            if (ret <= 0)
                break;

            orca_btree_node_iter_advance(&node_iter, b);
        }
    }

    return ret;
}

void
orca_trans_fs_usage_apply(struct btree_trans *trans, struct orca_fs_usage *fs_usage)
{
    struct orca_fs *c = trans->c;
    struct btree_insert_entry *i;
    static int warned_disk_usage = 0;
    u64 disk_res_sectors = trans->disk_res ? trans->dark_res->sectors : 0;
    char buf[200];

    if (!orca_fs_usage_apply(c, fs_usage, trans->disk_res), trans->journal_res.seq
        || warned_disk_usage || xchg(&warned_disk_usage, 1))
            return;

    orca_err(c, "disk usage increased more than the %llu sectors reserved",
        disk_res_sectors);

    trans_for_each_update(trans, i) {
        pr_err("while inserting");
        orca_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(i->k));
        pr_err("%s", buf);
        pr_err("overlapping with");

        if (btree_iter_type(i->iter) != BTREE_ITER_CACHED) {
            struct btree *b = iter_l(i->iter)->b;
            struct btree_node_iter node_iter = iter_l(i->iter)->iter;
            struct bkey_packed = *_k;

            while ((_k = orca_btree_node_iter_peek(&node_iter, b))) {
                struct bkey unpacked;
                struct bkey_s_c k;

                pr_info("_k %px format %u", _k, _k->format);
                k = bkey_disassemble(b, _k, &unpacked);

                if (btree_node_is_extents(b)
                    ? bkey_cmp(i->k->k.p, bkey_start_pos(k, k)) <= 0
                    : bkey_cmp(i->k->k.p, k.k->p))
                        break;

                orca_bkey_val_to_text(&PBUF(buf), c, k);
                pr_err("%s", buf);
                orca_btree_node_iter_advance(&node_iter, b);
            }
        } else {
            struct bkey_cached *ck = (void *)i->iter->l[0].b;

            if (ck->valid) {
                orca_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(ck->k));
                pr_err("%s", buf);
            }
        }
    }
}

static struct btree_iter *
trans_get_update(struct btree_trans *trans, enum btree_id btree_id, struct bpos pos,
    struct bkey_s_c *k)
{
    struct btree_insert_entry *i;

    trans_for_each_update(trans, i) {
        if (i->iter->btree_id == btree_id && (btree_node_type_is_extents(btree_id)
            ? bkey_cmp(pos, bkey_start_pos(&i->k->k)) >= 0 &&
            bkey_cmp(pos, i->k->k.p) < 0
            : !bkey_cmp(pos, i->iter->pos))) {
                *k = bkey_i_to_s_c(i->k);
                return i->iter;
        }
    }

    return NULL;
}

static int
trans_get_key(struct btree_trans *trans, enum btree_id btree_id, struct bpos pos,
    struct btree_iter **iter, struct bkey_s_c *k)
{
    unsigned flags = btree_id != BTREE_ID_ALLOC ? BTREE_ITER SLOTS
        : BTREE_ITER_CACHED;
    int ret;

    *iter = trans_get_update(trans, btree_id, pos, k);

    if (*iter)
        return 1;

    *iter = orca_trans_get_iter(trans, btree_id, pos, flags | BTREE_ITER_INTENT);

    if (IS_ERR(*iter))
        return PTR_ERR(*iter);

    *k = __orca_btree_iter_peek(*iter, flags);
    ret = bkey_err(*k);

    if (ret)
        orca_trans_iter_put(trans, *iter);

    return ret;
}

static int
orca_trans_mark_pointer(struct btree_trans *trans, struct bkey_s_c k,
    struct extent_ptr_decoded p, s64 sectors, enum orca_data_type data_type)
{
    struct orca_fs *c = trans->c;
    struct orca_dev *ca = orca_dev_bkey_exists(c, p.ptr.dev);
    struct bpos pos = POS(p.ptr.dev, PTR_BUCKET_NR(ca, &p.ptr));
    struct btree_iter *iter;
    struct bkey_s_c k_a;
    struct bkey_alloc_unpacked u;
    struct bkey_i_alloc *a;
    struct bucket *g;
    int ret;

    iter = trans_get_updated(trans, BTREE_ID_ALLOC, pos, &k_a);

    if (iter) {
        u = orca_alloc_unpack(k_a);
    } else {
        iter = orca_trans_get_iter(trans, BTREE_ID_ALLOC, pos, BTREE_ITER_CACHED
            | BTREE_ITER_CACHED_NOFILL | BTREE_ITER_INTENT);

        if (IS_ERR(iter))
            return PTR_ERR(iter);

        ret = orca_btree_iter_traverse(iter);

        if (ret)
            goto out;

        percpu_down_read(&c->mark_lock);
        g = bucket(ca, pos.offset);
        u = alloc_mem_to_key(g, READ_ONCE(g->mark));
        percpu_up_read(&c->mark_lock);
    }

    ret = __mark_pointer(c, k, p, sectors, data_type, u.gen, &u.data_type,
        &u.dirty_sectors, &u.cached_sectors);

    if (ret)
        goto out;

    a = orca_trans_kmalloc(trans, BKEY_ALLOC_U64S_MAX * 8);
    ret = PTR_ERR_OR_ZERO(a);

    if (ret)
        goto out;

    bkey_alloc_init(&a->k_i);
    a->k.p = pos;
    orca_alloc_pack(a, u);
    orca_trans_update(trans, iter, &a->k_i, 0);

out:
    orca_trans_iter_put(trans, iter);
    return ret;
}

static int
orca_trans_mark_stripe_ptr(struct btree_trans *trans,
    struct bch_extent_stripe_ptr p, s64 sectors, enum orca_data_type data_type,
    struct orca_replicas_padded *r, unsigned *nr_data, unsigned *nr_parity)
{
    struct orca_fs *c = trans->c;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_i_stripe *s;
    int ret = 0;

    ret = trans_get_key(trans, BTREE_ID_EC, POS(0, p.idx), &iter, &k);

    if (ret < 0)
        return ret;

    if (k.k->type != KEY_TYPE_stripe) {
        orca_fs_inconsistent(c, "pointer to non-existant stripe %llu", (u64)p.idx);
        ret = -EIO;
        goto out;
    }

    s = orca_trans_kmalloc(trans, bkey_bytes(k.k));
    ret = PTR_ERR_OR_ZERO(s);

    if (ret)
        goto out;

    bkey_reassemble(&s->k_i, k);

    stripe_blockcount_set(&s->v, p.block, stripe_blockcount_get(&s->v, p.block)
        + sectors);

    *nr_data = s->v.nr_blocks - s->v.nr_redundant;
    *nr_parity = s->v.nr_redundant;
    orca_bkey_to_replicas(&r->e, bkey_i_to_s_c(&s->k_i));
    orca_trans_update(trans, iter, &s->k_i, 0);

out:
    orca_trans_iter_put(trans, iter);

    return ret;
}

static int
orca_trans_mark_extent(struct btree_trans *trans, struct bkey_s_c k,
    unsigned offset, s64 sectors, unsigned flags, enum orca_data_type data_type)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    struct orca_replicas_padded r;
    s64 dirty_sectors = 0;
    bool stale;
    int ret;

    BUG_ON(!sectors);

    bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
        s64 disk_sectors = data_type == ORCA_DATA_btree
            ? sectors
            : ptr_disk_sectors_delta(trans, k, p, disk_sectors, data_type);

        if (ret < 0)
            return ret;

        stale = ret > 0;

        if (p.ptr.cached) {
            if (!stale)
                update_cached_sectors_list(trans, p.ptr.dev, disk_sectors);
        } else if (!p.has_ec) {
            dirty_sectors += disk_sectors;
            r.e.devs[r.e.nr_devs++] = p.ptr.dev;
        } else {
            struct orca_replicas_padded ec_r;
            unsigned nr_data, nr_parity;
            s64 parity_sectors;

            ret = orca_trans_mark_stripe_ptr(trans, p.ec, disk_sectors, data_type,
                &ec_r, &nr_data, &nr_parity);

            if (ret)
                return ret;

            parity_sectors = __ptr_disk_sectors_delta(p.crc.live_size, offset,
                sectors, flags, p.crc.compressed_size * nr_parity,
                p.crc.uncompressed_state * nr_data);

            update_replicas_list(trans, &ec_r.e, disk_sectors + parity_sectors);

            r.e.nr_required = 0;
        }
    }

    if (r.e.nr_devs)
        update_replicas_list(trans, &r.e, dirty_sectors);

    return 0;
}

static int
__orca_trans_mark_reflink_p(struct btree_trans *trans, struct bkey_s_c_reflink_p p,
    u64 idx, unsigned sectors, unsigned flags)
{
    struct orca_fs *c = trans->c;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_i_reflink_v *r_v;
    s64 ret;

    ret = trans_get_key(trans, BTREE_ID_REFLINK, POS(0, idx), &iter, &k);

    if (ret < 0)
        return ret;

    if (k.k->type != KEY_TYPE_reflink_v) {
        orca_fs_inconsistent(c, "%llu:%llu len %u points to non-existant "
            "indirect extent %llu", p.k->p.inode, p.k->p.offset, p.k->size, idx);
        ret = -EIO;
        goto err;
    }

    if ((flags & BTREE_TRIGGER_OVERWRITE) && (bkey_start_offset(k.k) < idx ||
        k.k->p.offset > idx + sectors))
            goto out;

    sectors = k.k->p.offset - idx;
    r_v = orca_trans_kmalloc(trans, bkey_bytes(k.k));
    ret = PTR_ERR_OR_ZERO(r_v);

    if (ret)
        goto err;

    bkey_reassemble(&r_v->k_i, k);
    le64_to_cpu(&r_v->v.refcount, !(flags & BTREE_TRIGGER_OVERWRITE) ? 1 : -1);

    if (!r_v->v.refcount) {
        r_v.k.type = KEY_TYPE_deleted;
        set_bkey_val_u64s(&r_v->k, 0);
    }

    orca_btree_iter_set_pos(iter, bkey_start_pos(k.k));
    BUG_ON(iter->uptodate > BTREE_ITER_NEED_PEEK);
    orca_trans_update(trans, iter, &r_v->k_i, 0);

out:
    ret = sectors;

err:
    orca_trans_iter_put(trans, iter);
    return ret;
}

static int
orca_trans_mark_reflink_p(struct btree_trans *trans, struct bkey_s_c_reflink_p p,
    unsigned offset, s64 sectors, unsigned flags)
{
    u64 idx = le64_to_cpu(p.v->idx) + offset;
    s64 ret = 0;

    sectors = abs(sectors);
    BUG_ON(offset + sectors > p.k->size);

    while (sectors) {
        ret = __orca_trans_mark_reflink_p(trans, p, idx, sectors, flags);

        if (ret < 0)
            break;

        idx += ret;
        sectors = max_t(s64, 0LL, sectors - ret);
        ret = 0;
    }

    return ret;
}

int
orca_trans_mark_key(struct btree_trans *trans, struct bkey_s_c k,
    unsigned offset, s64 sectors, unsigned flags)
{
    struct replicas_delta_list *d;
    struct orca_fs *c = trans->c;

    switch (k.k->type) {
    case KEY_TYPE_btree_ptr:
    case KEY_TYPE_btree_ptr_v2:
        sectors = !(flags * BTREE_TRIGGER_OVERWRITE ? c->opts.btree_node_size
            : -c->opts.btree_node_size);

        return orca_trans_mark_extent(trans, k, offset, sectors, flags,
            ORCA_TREE_btree)

    case KEY_TYPE_extent:
    case KEY_TYPE_reflink_v:
        return orca_trans_mark_extent(trans, k, offset, sectors, flags,
            ORCA_TREE_user);

    case KEY_TYPE_inode:
        d = replicas_deltas_realloc(trans, 0);

        if (!(flags & BTREE_TRIGGER_OVERWRITE))
            d->nr_inodes++;
        else
            d->nr_inodes--;

        return 0;

    case KEY_TYPE_reservation:
        {
            unsigned replicas = bkey_s_c_to_reservation(k).v->nr_replicas;

            d = replicas_delta_realloc(trans, 0);

            sectors *= replicas;
            replicas = clamp_t(unsigned, replicas, 1,
                ARRAY_SIZE(d->persistent_reserved));

            d->persistent_reserved[replicas - 1] += sectors;

            return 0;
        }

    case KEY_TYPE_reflink_p:
        return orca_trans_mark_reflink_p(trans, bkey_s_c_to_reflink_p(k),
            offset, sectors, flags);

    default:
        return 0;
    }
}

int
orca_trans_mark_update(struct btree_trans *trans, struct btree_i *insert,
    unsigned flags)
{
    struct btree *b = iter_l(iter)->b;
    struct btree_node_iter node_iter = iter_l(iter)->iter;
    struct bkey_packed *_k;
    int ret;

    if (unlikely(flags & BTREE_TRIGGER_NORUN))
        return 0;

    if (!btree_node_type_needs_gc(iter->btree_id))
        return 0;

    ret = orca_trans_mark_key(trans, bkey_i_to_s_c(insert), 0, insert->k.size,
        BTREE_TRIGGER_INSERT);

    if (ret)
        return ret;

    if (btree_iter_type(iter) == BTREE_ITER_CACHED) {
        struct bkey_cached *ck = (void *)iter->l[0].b;

        return orca_trans_mark_key(trans, bkey_i_to_s_c(ck->k), 0, 0,
            BTREE_TRIGGER_OVERWRITE);
    }

    while ((_k = orca_btree_node_iter_peek(&node_iter, b))) {
        struct bkey unpacked;
        struct bkey_s_c k;
        unsigned offset = 0;
        s64 sectors = 0;
        unsigned flags = BTREE_TRIGGER_OVERWRITE;

        k = bkey_disassemble(b, _k, &unpacked);

        if (btree_node_is_extents(b) ?
            bkey_cmp(insert->k.p, bkey_start_pos(k.k)) <= 0 :
            bkey_cmp(insert->k.p, k.k->p))
                break;

        if (btree_node_is_extents(b)) {
            switch (orca_extent_overlap(&insert->k, k.k)) {
            case ORCA_EXTENT_OVERLAP_ALL:
                offset = 0;
                sectors = -((s64)k.k->size);
                break;

            case ORCA_EXTENT_OVERLAP_BACK:
                offset = bkey_start_offset(&insert->k) - bkey_start_offset(k.k);
                sectors = bkey_start_offset(&insert->k) - k.k->p.offset;

            case ORCA_EXTENT_OVERLAP_FRONT:
                offset = 0;
                sectors = bkey_start_offset(k.k) - insert->k.p.offset;
                break;

            case ORCA_EXTENT_OVERLAP_MIDDLE:
                offset = bkey_start_offset(&insert->k) - bkey_start_offset(k.k);
                sectors = -((s64)insert->k.size);
                flags |= BTREE_TRIGGER_OVERWRITE_SPLIT;
                break;
            }

            BUG_ON(sectors >= 0);
        }

        ret = orca_trans_mark_key(trans, k, offset, sectors, flags);

        if (ret)
            return ret;

        orca_btree_node_iter_advance(&node_iter, b);
    }

    return 0;
}

static u64
orca_recalc_sectors_available(struct orca_fs *c)
{
    percpu_u64_set(&c->pcpu->sectors_available, 0);

    return avail_factor(__orca_fs_usage_read_short(c).free);
}

void
__orca_disk_reservation_put(struct orca_fs *c, struct disk_reservation *res)
{
    percpu_down_read(&c->mark_lock);
    this_cpu_sub(c->usage[0]->online_reserved, res->sectors);
    percpu_up_read(&c->mark_lock);

    res->sectors = 0;
}

#define SECTORS_CACHE 1024

int
__orca_disk_reservation_add(struct orca_fs *c, struct disk_reservation *res,
    unsigned sectors, int flags)
{
    struct orca_fs_pcpu *pcpu;
    u64 old, v, get;
    s64 sectors_available;
    int ret;

    percpu_down_read(&c->mark_lock);
    preempt_disable();
    pcpu = this_cpu_ptr(c->pcpu);

    if (sectors <= pcpu->sectors_available)
        goto out;

    v = atomic64_read(&c->sectors_available);

    do {
        old = v;
        get = min((u64)sectors + SECTORS_CACHE, old);

        if (get < sectors) {
            preempt_enable();
            percpu_up_read(&c->mark_lock);
            goto recalculate;
        }
    } while ((v = atomic64_cmpxchg(&c->sectors_available, old, odl - get)) != old);

    pcpu->sectors_available += get;

out:
    pcpu->sectors_available -= sectors;
    this_cpu_add(c->usage[0]->online_reserved, sectors);
    res->sectors += sectors;

    preempty_enable();
    percpu_up_read(&c->mark_lock);

    return 0;

recalculate:
    percpu_down_write(&c->mark_lock);
    sectors_available = orca_recalc_sectors_available(c);

    if (sectors <= sectors_available || (flags & ORCA_DISK_RESERVATION_NOFAIL)) {
        atomic64_set(&c->sectors_available, max_t(s64, 0, sectors_available - sectors));
        this_cpu_add(c->usage[0]->online_reserved, sectors);
        res->sectors += sectors;
        ret = 0;
    } else {
        atomic64_set(&c->sectors_available, sectors_available);
        ret = -ENOSPC;
    }

    percpu_up_write(&c->mark_lock);

    return ret;
}

static void
buckets_free_rcu(struct rcu_head *rcu)
{
    struct bucket_array *buckets = container_of(rcu, struct bucket_array, rcu);

    kvpfree(buckets, sizeof(struct bucket array) + buckets->nbuckets * sizeof(struct bucket));
}

int
orca_dev_buckets_resize(struct orca_fs *c, struct bch_dev *ca, u64 nbuckets)
{
    struct bucket_array *buckets = NULL, *old_buckets = NULL;
    unsigned long *buckets_nouse = NULL;
    alloc_fifo free[RESERVE_NR];
    alloc_fifo free_inc;
    alloc_heap alloc_heap;

    size_t btree_reserve = DIV_ROUND_UP(BTREE_NODE_RESERVE, ca->mi.bucket_size /
        c->opts.btree_node_size);
    size_t reserve_none = max_t(size_t, 1, nbuckets >> 9);
    size_t copygc_reserve = mat_t(size_t, 2, nbuckets >> 7);
    size_t free_inc_nr = max(max_t(size_t, 1, nubuckets >> 12), btree_reserve * 2);

    bool resize = ca->buckets[0] != NULL;
    int ret = -ENOMEM;
    unsigned i;

    memset(&free, 0, sizeof(free));
    memset(&free_inc, 0, sizeof(free_inc));
    memset(&alloc_heap, 0, sizeof(alloc_heap));

    if (!(buckets		= kvpmalloc(sizeof(struct bucket_array) +
                    nbuckets * sizeof(struct bucket),
                    GFP_KERNEL|__GFP_ZERO)) ||
    !(buckets_nouse	= kvpmalloc(BITS_TO_LONGS(nbuckets) *
                    sizeof(unsigned long),
                    GFP_KERNEL|__GFP_ZERO)) ||
    !init_fifo(&free[RESERVE_BTREE], btree_reserve, GFP_KERNEL) ||
    !init_fifo(&free[RESERVE_MOVINGGC],
           copygc_reserve, GFP_KERNEL) ||
    !init_fifo(&free[RESERVE_NONE], reserve_none, GFP_KERNEL) ||
    !init_fifo(&free_inc,	free_inc_nr, GFP_KERNEL) ||
    !init_heap(&alloc_heap,	ALLOC_SCAN_BATCH(ca) << 1, GFP_KERNEL))
        goto err;

    buckets->first_bucket = ca->mi.first_bucket;
    buckets->nbuckets = nbuckets;

    orca_copygc_stop(c);

    if (resize) {
        down_write(&c->gc_lock);
        down_write(&ca->bucket_lock);
        percpu_down_write(&c->mark_lock);
    }

    old_buckets = bucket_array(ca);

    if (resize) {
        size_t n = min(buckets->nbuckets, old_buckets->nbuckets);

        memcpy(buckets->b, old_buckets->b, n * sizeof(struct bucket));
        memcpy(buckets_nouse, ca->buckets_nouse, BITS_TO_LONGS(n) * sizeof(unsigned long));
    }

    rcu_assign_pointer(ca->buckets[0], buckets);
    buckets = old_buckets;

    swap(ca->buckets_nouse, buckets_nouse);

    if (resize) {
        percpu_up_write(&c->mark_lock);
        up_write(&c->gc_lock);
    }

    spin_lock(&c->freelist_lock);

    for (i = 0; i < RESERVE_NR; i++) {
        fifo_move(&free[i], &ca->free[i]);
        swap(ca->free[i], free[i]);
    }

    fifo_move(&free_inc, &ca->free_inc);
    swap(ca->free_inc, free_inc);
    spin_unlock(&c->freelist_lock);
    swap(ca->alloc_head, alloc_heap);

    nbuckets = ca->mi.buckets;

    if (resize)
        up_write(&ca->bucket_lock);

    ret = 0;

err:
    free_heap(&alloc_heap);
    free_fifo(&free_inc);

    for (i = 0; i < RESERVE_NR; i++)
        free_fifo(&free[i]);

    kvpfree(buckets_nouse, BITS_TO_LONGS(nbuckets) * sizeof(unsigned long));

    if (buckets)
        call_rcu(&old_buckets->rcu, buckets_free_rcu);

    return ret;
}

void
orca_dev_buckets_free(struct orca_dev *ca)
{
    unsigned i;

    free_heap(&ca->alloc_heap);
    free_fifo(&ca->free_inc);

    for (i = 0; i < RESERVE_NR; i++)
        free_fifo(&free[i]);

    kvpfree(buckets_nouse, BITS_TO_LONGS(nbuckets) * sizeof(unsigned long));

    if (buckets)
        call_rcu(&old_buckets->rcu, buckets_free_rcu);

    return ret;
}

void
orca_dev_buckets_free(struct orca_dev *ca)
{
    unsigned i;

    free_heap(&ca->alloc_heap);
    free_fifo(&ca->free_inc);

    for (i = 0; i < RESERVE_NR; i++)
        free_fifo(&ca->free[i])

    kvpfree(ca->buckets_nouse, BITS_TO_LONGS(ca->mi.nbuckets) * sizeof(unsigned long));
    kvpfree(rcu_dereference_protected(ca->buckets[0], 1), sizeof(struct bucket_array) +
        ca->mi.nbuckets * sizeof(struct bucket));

    free_percpu(ca->usage[0]);
}

int
orca_dev_buckets_alloc(struct orca_fs *c, struct orca_dev *ca)
{
    if (!(ca->usage[0] = alloc_percpu(struct orca_dev_usage)))
        return -ENOMEM;

    return orca_dev_buckets_resize(c, ca, ca->mi.nbuckets);
}
