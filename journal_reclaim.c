#include <linux/kthread.h>
#include <linux/sched.h>
#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "btree_key_cache.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "replicas.h"
#include "super.h"

/**
 * FREE SPACE CALCULATIONS.
**/
static unsigned
journal_space_from(struct journal_device *ja, enum journal_space_from from)
{
    switch (from) {
    case journal_space_discarded:
        return ja->discard_idx;

    case journal_space_clean_ondisk:
        return ja->dirty_idx_ondisk;

    case journal_space_clean:
        return ja->dirty_idx;

    default:
        BUG();
    }
}

unsigned
orca_journal_dev_buckets_available(struct journal *, struct journal_device *ja,
    enum journal_space_from from)
{
    unsigned available = (journal_space_from(ja, from) - ja->cur_idx - 1 +
        ja->nr) % ja->nr;

    /**
     * Don't use the last bucket unless writing the new last_seq
     * will make another bucket available.
    **/
    if (available && ja->dirty_idx_ondisk == ja->dirty_idx)
        --available;

    return available;
}

static void
journal_set_remaining(struct journal *j, unsigned u64s_remaining)
{
    union journal_preres_state old, new;
    u64 v = atomic64_read(&j->prereserved.counter);

    do {
        old.v = new.v = v;
        new.remaining = u64s_remaining;
    } while ((v = atomic64_cmpxchg(&j->prereserved.counter, old.v, new.v)) != old.v);
}

static inline unsigned
get_unwritten_sectors(struct journal *j, unsigned *idx)
{
    unsigned sectors = 0;

    while (!sectors && *idx != j->reservations.idx) {
        sectors = j->buf[*idx].sectors;
        *idx = (*idx + 1) & JOURNAL_BUF_MASK;
    }

    return sectors;
}

static struct journal_space
jouranl_dev_space_available(struct journal *j, struct orca_dev *ca,
    enum journal_space_from from)
{
    struct journal_device *ja = &ca->journal;
    unsigned sectors, buckets, unwritten, idx = j->reservations.unwritten_idx;

    if (from == journal_space_total)
        return (struct journal_space) {
            .next_entry = ca->mi.bucket_size,
            .total = ca->mi.bucket_size * ja->nr,
        };

    buckets = orca_journal_dev_buckets_available(j, ja, from);
    sectors = ja->sectors_free;

    /**
     * We that we don't allocate the space for a journal entry
     * until we write it out--thus, account for it here.
    **/
    while ((unwritten = get_unwritten_sectors(j, &idx))) {
        if (unwritten >= sectors) {
            if (!buckets) {
                sectors = 0;
                break;
            }

            buckets--;
            sectors = ca->mi.bucket_size;
        }

        sectors -= unwritten;
    }

    if (sectors < ca->mi.bucket_size && buckets) {
        buckets--;
        sectors = ca->mi.bucket_size;
    }

    return (struct journal_space) {
        .next_entry = sectors,
        .total = sectors + buckets * ca->mi.bucket_size,
    };
}

static struct journal_space
__journal_space_available(struct journal *j, unsigned nr_devs_want,
    enum journal_space_from from)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct orca_dev *ca;
    unsigned i, pos, nr_devs = 0;
    struct journal_space space, dev_space[ORCA_SB_MEMBERS_MAX];

    BUG_ON(nr_devs_want > ARRAY_SIZE(dev_space));
    rcu_read_lock();

    for_each_member_device_rcu(ca, c, i, &c->rw_devs[ORCA_DATA_journal]) {
        if (!ca->journal.nr)
            continue;

        space = journal_dev_space_available(j, ca, from);

        if (!space.next_entry)
            continue;

        for (pos = 0; pos < nr_devs; pos++) {
            if (space.total > dev_space[pos].total)
                break;
        }

        array_insert_item(dev_space, nr_devs, pos, space);
    }

    rcu_read_unlock();

    if (nr_devs < nr_devs_want)
        return (struct journal_space) { 0, 0 };

    /**
     * We sorted largest to smallest, and we want the smallest out of the
     * @nr_devs_want largest devices.
    **/
    return dev_space[nr_devs_want - 1];
}

void
orca_journal_space_available(struct journal *j)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct orca_dev *ca;
    unsigned clean, clean_ondisk, total;
    unsigned overhead, u64s_remaining = 0;
    unsigned max_entry_size = min(j->buf[0].buf_size >> 9, j->buf[1].buf_size >> 9);
    unsigned i, nr_online = 0, nr_devs_want;
    bool can_discard = false;
    int ret = 0;

    lockdep_assert_held(&j->lock);
    rcu_read_lock();

    for_each_member_device_rcu(ca, c, i, &c->rw_devs[ORCA_DATA_journal]) {
        struct journal_device *ja = &ca->journal;

        if (!ja->nr)
            continue;

        while (ja->dirty_idx != ja->cur_idx && ja->bucket_seq[ja->dirty_idx] <
            journal_last_seq(j))
                ja->dirty_idx = (ja->dirty_idx + 1) % ja->nr;

        while (ja->dirty_idx_ondisk != ja->dirty_idx &&
            ja->bucket_seq[ja->dirty_idx_ondisk] < j->last_seq_ondisk)
                ja->dirty_idx_ondisk = (ja->dirty_idx_ondisk + 1) % ja->nr;

        if (ja->discard_idx != ja->dirty_idx_ondisk)
            can_discard = true;

        max_entry_size = min_t(unsigned, max_entry_size, ca->mi.bucket_size);
        nr_online++;
    }

    rcu_read_unlock();
    j->can_discard = can_discard;

    if (nr_online < c->opts.metadata_replicas_required) {
        ret = cur_entry_insufficient_devices;
        goto out;
    }

    nr_devs_want = min_t(unsigned, nr_online, c->opts.metadata_replicas);

    for (i = 0; i < journal_space_nr; i++)
        j->space[i] = __journal_space_available(j, nr_devs_want, i);

    clean_ondisk = j->space[journal_space_clean_ondisk].total;
    clean = j->space[journal_space_clean].total;
    total = j->space[journal_space_total].total;

    if (!j->space[journal_space_discarded].next_entry)
        ret = cur_entry_journal_full;
    else if (!fifo_free(&j->pin))
        ret = cur_entry_journal_pin_full;

    if ((clean - clean_ondisk <= total / 8) && (clean_ondisk * 2 > clean))
        set_bit(JOURNAL_MAY_SKIP_FLUSH, &j->flags);
    else
        clear_bit(JOURNAL_MAY_SKIP_FLUSH, &j->flags);

    overhead = DIV_ROUND_UP(clean, max_entry_size) * journal_entry_overhead(j);
    u64s_remaining = clean << 6;
    u64s_remaining = max_t(int, 0, u64s_remaining - overhead);
    u64s_remaining /= 4;

out:
    j->cur_entry_sectors = !ret ? j->space[journal_space_discarded].next_entry : 0;
    j->cur_entry_error = ret;
    journal_set_remaining(j, u64s_remaining);
    journal_check_may_get_unreserved(j);

    if (!ret)
        journal_wake(j);
}

static bool
should_discard_bucket(struct journal *j, struct journal_device *ja)
{
    bool ret;

    spin_lock(&j->lock);
    ret = ja->discard_idx != ja->dirty_idx_ondisk;
    spin_unlock(&j->lock);

    return ret;
}

/**
 * Advance ja->discard_idx as long as it points to buckets that are no
 * longer dirty, issuing discards if necessary.
**/
void
orca_journal_do_discards(struct journal *j)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct orca_dev *ca;
    unsigned iter;

    mutex_lock(&j->discard_lock);

    for_each_rw_member(ca, c, iter) {
        struct journal_device *ja = &ca->journal;

        while (should_discard_bucket(j, ja)) {
            if (ca->mi.discard && blk_queue_discard(bdev_get_queue(ca->disk_sb.bdev)))
                blkdev_issue_discard(ca->disk_sb.bdev, bucket_to_sector(ca,
                    ja->buckets[ja->discard_idx]), ca->mi.bucket_size, GFP_NOIO, 0);

            spin_lock(&j->lock);
            ja->discard_idx = (ja->discard_idx + 1) % ja->nr;
            orca_journal_space_available(j);
            spin_unlock(&j->lock);
        }
    }

    mutex_unlock(&j->discard_lock);
}

/**
 * Journal entry pinning--machinery for holding a reference on a given
 * journal entry, holding it open to ensure it gets replayed during recovery.
**/
static void
orca_journal_reclaim_fast(struct journal *j)
{
    struct journal_entry_pin_list temp;
    bool popped = false;

    lockdep_assert_held(&j->lock);

    /**
     * Unpin journal entries whose reference counts reached zero,
     * meaning all btree nodes got written out.
    **/
    while (!fifo_empty(&j->pin) && !atomic_read(&fifo_peek_front(&j->pin).count)) {
        BUG_ON(!list_empty(&fifo_peek_front(&j->pin).list));
        BUG_ON(!list_empty(&fifo_peek_front(&j->pin).flushed));
        BUG_ON(!fifo_pop(&j->pin, temp));
        popped = true;
    }

    if (popped)
        orca_journal_space_available(j);
}

void
__orca_journal_pin_put(struct journal *j, u64 seq)
{
    struct journal_entry_pin_list *pin_list = journal_seq_pin(j, seq);

    if (atomic_dec_and_test(&pin_list->count))
        orca_journal_reclaim_fast(j);
}

void
orca_journal_pin_put(struct journal *j, u64 seq)
{
    struct journal_entry_pin_list *pin_list = journal_seq_pin(j, seq);

    if (atomic_dec_and_test(&pin_list->count)) {
        spin_lock(&j->lock);
        orca_journal_reclaim_fast(j);
        spin_unlock(&j->lock);
    }
}

static inline void
__journal_pin_drop(struct journal *j, struct journal_entry_pin *pin)
{
    struct journal_entry_pin_list *pin_list;

    if (!journal_pin_active(pin))
        return;

    pin_list = journal_seq_pin(j, pin->seq);
    pin->seq = 0;
    list_del_init(&pin->list);

    /**
     * Unpinning a journal entry make make journal_next_bucket() succeed,
     * if writing a new last_seq wil now make another bucket available.
    **/
    if (atomic_dec_and_test(&pin_list->count) && pin_list == &fifo_peek_front(&j->pin))
        orca_journal_reclaim_fast(j);
    else if (fifo_used(&j->pin) == 1 && atomic_read(&pin_list->count) == 1)
        journal_wake(j);
}

void
orca_journal_pin_drop(struct journal *j, struct journal_entry_pin *pin)
{
    spin_lock(&j->lock);
    __journal_pin_drop(j, pin);
    spin_unlock(&j->lock);
}

void
orca_journal_pin_set(struct journal *j, u64 seq, struct journal_entry_pin *pin,
    journal_pin_flush_fn flush_fn)
{
    struct journal_entry_pin_list *pin_list;

    spin_lock(&j->lock);
    pin_list = journal_seq_pin(j, seq);
    __journal_pin_drop(j, pin);

    BUG_ON(!atomic_read(&pin_list->count) && seq == journal_last_seq(j));
    atomic_inc(&pin_list->count);
    pin->seq = seq;
    pin->flush = flush_fn;

    list_add(&pin->list, flush ? &pin_list->list : &pin_list->flushed);
    spin_unlock(&j->lock);

    /**
     * If the journal is currently full, we might want to call
     * flush_fn immediatey.
    **/
    journal_wake();
}

/**
 * orca_journal_pin_flush: ensure journal pin callback is no longer
 * running.
**/
void
orca_journal_pin_flush(struct journal *j, struct journal_entry_pin *pin)
{
    BUG_ON(journal_pin_active(pin));
    wait_event(j->pin_flush_wait, j->flush_in_progress != pin);
}

/**
 * Journal reclaim: flush references to open journal entries to reclaim
 * space in the journal.
 *
 * May be done by the journal code in the background as needed to free up
 * space for more journal entries, or as part of doing a clean shutdown,
 * or to migrate data off of a specific device.
**/
static struct journal_entry_pin *
journal_get_next_pin(struct journal *j, u64 max_seq, u64 *seq)
{
    struct journal_entry_pin_list *pin_list;
    struct journal_entry_pin *ret = NULL;

    if (!test_bit(JOURNAL_RECLAIM_STARTED, &j->flags))
        return NULL;

    spin_lock(&j->lock);

    fifo_for_each_entry_ptr(pin_list, &j->pin, *seq) {
        if (*seq > max_seq || (ret = list_first_entry_or_null(&pin_list->list,
            struct journal_entry_pin, list)))
                break;
    }

    if (ret) {
        list_move(&ret->list, &pin_list->flushed);
        BUG_ON(j->flush_in_progress);
        j->flush_in_progress = ret;
    }

    spin_unlock(&j->lock);

    return ret;
}

/**
 * Returns true if we did work.
**/
static u64
journal_flush_pins(struct journal *j, u64 seq_to_flush, unsigned min_nr)
{
    struct journal_entry_pin *pin;
    u64 seq, ret = 0;

    lockdep_assert_held(&j->reclaim_lock);

    for (;;) {
        cond_resched();
        j->last_flushed = jiffies;
        pin = journal_get_next_pin(j, min_nr ? U64_MAX : seq_to_flush, &seq);

        if (!pin)
            break;

        if (min_nr)
            min_nr--;

        pin->flush(j, pin, seq);

        BUG_ON(j->flush_in_progress != pin);
        j->flush_in_progress = NULL;
        wake_up(&j->pin_flush_wait);
        ret++;
    }

    return ret;
}

static u64
journal_seq_to_flush(struct journal *j)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct orca_dev *ca;
    u64 seq_to_flush = 0;
    unsigned iter;

    spin_lock(&j->lock);

    for_each_rw_member(ca, c, iter) {
        struct journal_device *ja = &ca->journal;
        unsigned nr_buckets, bucket_to_flush;

        if (!ja->nr)
            continue;

        /* Try to keep the journal at most half full */
        nr_buckets ja->nr / 2;

        /* And include pre-reservations */
        nr_buckets += DIV_ROUND_UP(j->prereserved.reserved, (ca->mi.bucket_size << 6) -
            journal_entry_overhead(j));

        nr_buckets = min(nr_buckets, ja->nr);
        bucket_to_flush = (ja->cur_idx + nr_buckets) % ja->nr;
        seq_to_flush = max(seq_to_flush, ja->bucket_seq[bucket_to_flush]);
    }

    /* Also flush if the pin fifo is more than half full */
    seq_to_flush = max_t(s64, seq_to_finish, (s64)journal_cur_seq(j - (j->pin.size >> 1)));
    spin_unlock(&j->lock);

    return seq_to_flush;
}

/**
 * orca_journal_reclaim--free up journal buckets.
 *
 * Background journal reclaim writes out btree nodes. It should be run
 * early enough so that we never completely run out of journal buckets.
 *
 * High watermarks for triggering background reclaim:
 * - FIFO has fewer than 512 entries left
 * - Fewer than 25% journal buckets free
 *
 * Background reclaim runs until low watermarks are reached:
 * - FIFO has more than 1024 entries left
 * - More than 50% journal buckets free
 *
 * As long as a reclaim can complete in the time it takes to fill up
 * 512 journal entries or 25% of all journal buckets, then
 * journal_next_bucket() should not stall.
**/
static int
__orca_journal_reclaim(struct journal *j, bool direct)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    bool kthread = (current->flags & PF_KTHREAD) != 0;
    u64 seq_to_flush, nr_flushed = 0;
    size_t min_nr;
    unsigned flags;
    int ret = 0;

    /**
     * We can't invoke memory reclaim while holding the reclaim_lock--
     * journal reclaim is required to make progress for memory reclaim
     * (cleaning the caches), so we can't get stuck in memory reclaim
     * while we're holding the reclaim look.
    **/
    lockdep_assert_held(&j->reclaim_lock);
    flags = memalloc_noreclaim_save();

    do {
        if (kthread && kthread_should_stop())
            break;

        if (orca_journal_error(j)) {
            ret = -EIO;
            break;
        }

        orca_journal_do_discards(j);
        seq_to_finish = journal_seq_to_flush(j);
        min_nr = 0;

        /**
         * If it's been longer than j->reclaim_delay_ms since we last
         * flushed, make sure to flush at least one journal pin.
        **/
        if (time_after(jiffies, j->last_flushed + msecs_to_jiffies(j->reclaim_delay_ms)))
            min_nr = 1;

        if (j->prereserved.reserved * 2 > j->prereserved.remaining)
            min_nr = 1;

        if (atomic_read(&c->btree_cache.dirty) * 4 > c->btree_cache.used * 3)
            min_nr = 1;

        trace_journal_reclaim_start(c, min_nr, j->prereserved.reserved,
            j->prereserved.remaining, atomic_read(&c->btree_cache.dirty),
            c->btree_cache.used, c->btree_key_cache.nr_dirty,
            c->btree_key_cache.nr_keys);

        nr_flushed = journal_flush_pins(j, seq_to_flush, min_nr);

        if (direct)
            j->nr_direct_reclaim += nr_flushed;
        else
            j->nr_background_reclaim += nr_flushed;

        trace_journal_reclaim_finish(c, nr_flushed);
    } while (min_nr);

    memalloc_noreclaim_restore(flags);

    return ret;
}

int
orca_journal_reclaim(struct journal *j)
{
    return __orca_journal_reclaim(j, true);
}

static int
orca_journal_reclaim_thread(void *arg)
{
    struct journal *j = arg;
    unsigned long next;
    int ret = 0;

    set_freezable();
    kthread_wait_freezable(test_bit(JOURNAL_RECLAIM_STARTED, &j->flags));

    while (!ret && !kthread_should_stop()) {
        j->reclaim_kicked = false;
        mutex_lock(&j->reclaim_lock);
        ret = __orca_journal_reclaim(j, false);
        mutex_unlock(&j->reclaim_lock);
        next = j->last_flushed + msecs_to_jiffies(j->reclaim_delay_ms);

        for (;;) {
            set_current_state(TASK_INTERRUPTIBLE);

            if (kthread_should_stop())
                break;

            if (j->reclaimed_kicked)
                break;

            if (time_after_eq(jiffies, next))
                break;

            schedule_timeout(next - jiffies);
            try_to_freeze();
        }

        __set_current_state(TASK_RUNNING);
    }

    return 0;
}

void
orca_journal_reclaim_stop(struct journal *j)
{
    struct task_struct *p = j->reclaim_thread;

    j->reclaim_thread = NULL;

    if (p) {
        kthread_stop(p);
        put_task_struct(p);
    }
}

int
orca_journal_reclaim_start(struct journal *j)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct task_struct *p;

    if (j->reclaim_thread)
        return 0;

    p = kthread_create(orca_journal_reclaim_thread, j, "orca-reclaim/%s", c->name);

    if (IS_ERR(p))
        return PTR_ERR(p);

    get_task_struct(p);
    j->reclaim_thread = p;
    wake_up_process(p);

    return 0;
}

static int
journal_flush_done(struct journal *j, u64 seq_to_flush, bool *did_work)
{
    int ret;

    ret = orca_journal_error(j);

    if (ret)
        return ret;

    mutex_lock(&j->reclaim_lock);
    *did_work = journal_flush_pins(j, seq_to_flush, 0) != 0;
    spin_lock(&j->lock);

    /**
     * If journal replay hasn't completed, the unreplayed journal
     * entries hold refs on their corresponding sequence numbers.
    **/
    ret = !test_bit(JOURNAL_REPLAY_DONE, &j->flags) ||
        journal_last_seq(j) > seq_to_flush ||
        (fifo_used(&j->pin) == 1 && atomic_read(&fifo_peek_front(&j->pin).count) == 1);

    spin_unlock(&j->lock);
    mutex_unlock(&j->reclaim_lock);

    return ret;
}

bool
orca_journal_flush_pins(struct journal *j, u64 seq_to_flush)
{
    bool did_work = false;

    if (!test_bit(JOURNAL_STARTED, &j->flags))
        return false;

    closure_wait_event(&j->async_wait, journal_flush_done(j, seq_to_flush, &did_work));

    return did_work;
}

int
orca_journal_flush_device_pins(struct journal *j, int dev_idx)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct journal_entry_pin_list *p;
    u64 iter, seq = 0;
    int ret = 0;

    spin_lock(&j->lock);

    fifo_for_each_entry_ptr(p, &j->pin, iter) {
        if (dev_idx >= 0 ? orca_dev_list_has_dev(p->devs, dev_idx)
            : p->devs.nr < c->opts.metadata_replicas)
                seq = iter;
    }

    spin_unlock(&j->lock);
    orca_journal_flush_pins(j, seq);
    ret = orca_journal_error(j);

    if (ret)
        return ret;

    mutex_lock(&c->replicas_gc_lock);
    orca_replicas_gc_start(c, 1 << ORCA_DATA_journal);
    seq = 0;
    spin_lock(&j->lock)

    while (!ret && seq < j->pin.back) {
        struct orca_replicas_padded replicas;

        seq = max(seq, journal_last_seq(j));
        orca_devlist_to_replicas(&replicas.e, ORCA_DATA_journal, journal_seq_pin(j, seq)->devs);
        seq++;

        spin_unlock(&j->lock);
        ret = orca_mark_replicas(c, &replicas.e);
        spin_lock(&j->lock);
    }

    spin_unlock(&j->lock);
    ret = orca_replicas_gc_end(c, ret);
    mutex_unlock(&c->replicas_gc_lock);

    return ret;
}