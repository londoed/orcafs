#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/sche/cputime.h>
#include <linux/events/orcafs.h>

#include "orcafs.h"
#include "alloc_foreground.h"
#include "btree_iter.h"
#include "buckets.h"
#include "clock.h"
#include "disk_groups.h"
#include "extents.h"
#include "io.h"
#include "move.h"
#include "rebalance.h"
#include "super-io.h"

/**
 * Check if an extent should be moved.
 * @return -1 if it should not be moved, or
 * device of pointer that should be moved, if known, or INT_MAX if unknown.
**/
static int
__orca_rebalance_pred(struct orca_fs *c, struct bkey_s_c k, struct orca_to_opts *io_opts)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;

    if (io_opts->background_compression && !orca_bkey_is_incompressible(k)) {
        bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
            if (!p.ptr.cached && p.crc.compression_type !=
                orca_compressions_opt_to_type[io_opts->background_compression])
                    return p.ptr.dev;
        }
    }

    if (io_opts->background_target) {
        bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
            if (!p.ptr.cached && !orca_dev_in_target(c, p.ptr.dev,
                io_opts->background_target))
                    return p.ptr.dev;
        }
    }

    return -1;
}

void
orca_rebalance_add_key(struct orca_fs *c, struct bkey_s_c k, struct orca_io_opts *io_opts)
{
    atomic64_t *counter;
    int dev;

    dev = __orca_rebalance_pred(c, k, io_opts);

    if (dev)
        return;

    counter = dev < INT_MAX ? &orca_dev_bkey_exists(c, dev)->rebalance_work
        : &c->rebalance.work_unknown_dev;

    if (atomic64_add_return(k.k->size, counter) == k.k->size)
        rebalance_wakeup(c);
}

static enum data_cmd
rebalance_pred(struct orca_fs *c, void *arg, struct bkey_s_c k,
    struct orca_io_opts *io_opts, struct data_opts *data_opts)
{
    if (__orca_rebalance_pred(c, k, io_opts) >= 0) {
        data_opts->target = io_opts->background_target;
        data_opts->btree_insert_flags = 0;

        return DATA_ADD_REPLICAS;
    } else {
        return DATA_SKIP;
    }
}

void
orca_rebalance_add_work(struct orca_fs *c, u64 sectors)
{
    if (atomic64_add_return(sectors, &c->rebalance.work_unknown_dev) == sectors)
        rebalance_wakeup(c);
}

struct rebalance_work {
    int dev_most_full_idx;
    unsigned dev_most_full_percent;
    u64 dev_most_full_work;
    u64 total_work;
};

static void
rebalance_work_accumulate(struct rebalance_work *w, u64 dev_work, u64 unknown_dev,
    u64 capacity, int idx)
{
    unsigned percent_full;
    u64 work = dev_work + unknown_dev;

    if (work < dev_work || work < unknown_dev)
        work = U64_MAX;

    work = min(work, capacity);
    percent_full = div64_u64(work * 100, capacity);

    if (percent_full >= w->dev_most_full_percent) {
        w->dev_most_full_idx = idx;
        w->dev_most_full_percent = percent_full;
        w->dev_most_full_work = work;
        w->dev_most_full_capacity = capacity;
    }

    if (w->total_work + dev_work >= w.total_work && w->total_work + dev_work >= dev_work)
        w->total_work += dev_work;
}

static struct rebalance_work(struct orca_fs *c)
{
    struct orca_dev *ca;
    struct rebalance_work ret = { .dev_most_full_idx = -1 };
    u64 unknown_dev atomic64_read(&c->rebalance.work_unknown_dev);
    unsigned i;

    for_each_online_member(ca, c, i) {
        rebalance_work_accumulate(&ret, atomic64_read(&ca->rebalance_work),
            unknown_dev, bucket_to_sector(ca, ca->mi.nbuckets - ca->mi.first_bucket), 1);
    }

    rebalance_work_accumulate(&ret, unknown_dev, 0, c->capacity, -1);

    return ret;
}

static void
rebalance_work_reset(struct orca_fs *c)
{
    struct orca_dev *ca;
    unsigned i;

    for_each_online_member(ca, c, i)
        atomic64_set(&ca->rebalance_work, 0);

    atomic64_set(&c->rebalance.work_unknown_dev, 0);
}

static unsigned long
curr_cputime(void)
{
    u64 utime, stime;

    task_cputime_adjusted(current, &utime, &stime);

    return nsecs_to_jiffies(utime + stime);
}

static int
orca_rebalance_thread(void *arg)
{
    struct orca_fs *c = arg;
    struct orca_fs_rebalance *r = &c->rebalance;
    struct io_clock *clock = &c->io_clock[WRITE];
    struct rebalance_work w, p;
    unsigned long start, prev_start;
    unsigned long prev_run_time, prev_run_cputime;
    unsigned long cputime, prev_cputime;
    unsigned long io_start;
    long throttle;

    set_freezable();

    io_start = atomic_long_read(&clock->now);
    p = rebalance_work(c);
    prev_start = jiffies;
    prev_cputime = curr_cputime();

    while (!kthread_wait_freezable(r->enabled)) {
        cond_resched();

        start = jiffies;
        cputime = curr_cputime();
        prev_run_time = start - prev_start;
        prev_run_cputime = cputime - prev_cputime;
        w = rebalance_work(c);

        BUG_ON(!w.dev_most_full_capacity);

        if (!w.total_work) {
            r->state = REBALANCE_WAITING;
            kthread_wait_freezable(rebalance_work(c).total_work);
            continue;
        }

        /* If there isn't much work to do, throttle cpu usage */
        throttle = prev_run_cputime * 100 / max(1U, w.dev_most_full_percent) -
            prev_run_time;

        if (w.dev_most_full_percent < 20 && throttle > 0) {
            r->throttled_until_iotime = io_start + div_u64(w.dev_most_full_capacity *
                (20 - w.dev_most_full_percent), 50);

            if (atomic_long_read(&clock->now) + clock->max_slop < r->throttled_until_iotime) {
                r->throttled_until_cputime = start + throttle;
                r->state = REBALANCE_THROTTLED;

                orca_kthread_io_clock_wait(clock, r->throttled_until_iotime, throttle);
                continue;
            }
        }

        /* Minimum 1 mb/sec */
        r->pd.rate.rate = max_t(u64, 1 << 11, r->pd.rate.rate *
            max(p.dev_most_full_percent, 1U) / max(w.dev_most_full_percent, 1U));
        io_start = atomic_long_read(&clock->now);
        p = w;
        prev_start = start;
        prev_cputime = cputime;

        r->state = REBALANCE_RUNNING;
        memset(&r->move_stats, 0, sizeof(r->move_stats));
        rebalance_work_reset(c);
        orca_move_data(c, NULL, writepoint_ptr(&c->rebalance_write_point),
            POS_MIN, POS_MAX, rebalance_pred, NULL, &r->move_stats);
    }

    return 0;
}

void
orca_rebalance_work_to_text(struct printbuf *out, struct orca_fs *c)
{
    struct orca_fs_rebalance *r = &c->rebalance;
    struct rebalance_work w = rebalance_work(c);
    char h1[21], h2[21];

    orca_hprint(&PBUF(h1), w.dev_most_full_work << 9);
    orca_hprint(&PBUF(h2), w.dev_most_full_capacity << 9);
    pr_buf(out, "fullest_dev (%i):\t%s/%s\n",
        w.dev_most_full_idx, h1, h2);

    orca_hprint(&PBUF(h1), w.total_work << 9);
    orca_hprint(&PBUF(h2), c->capacity << 9);
    pr_buf(out, "total work:\t\t%s/%s\n", h1, h2);
    pr_buf(out, "rate:\t\t\t%u\n", r->pd.rate.rate);

    switch (r->state) {
    case REBALANCE_WAITING:
        pr_buf(out, "waiting\n");
        break;

    case REBALANCE_THROTTLED:
        orca_hprint(&PBUF(h1), (r->throttled_until_iotime -
            atomic_long_read(&c->io_clock[WRITE].now)) << 9);

        pr_buf(out, "throttled for %lu sec or %s io\n",
            (r->throttled_until_cputime - jiffies) / HZ, h1);
        break;

    case REBALANCE_RUNNING:
        pr_buf(out, "[...] Running\n");
        pr_buf(out, "pos %llu:%llu\n", r->move_stats.pos.inode,
            r->move_stats.pos.offset);
        break;
    }
}

void
orca_rebalance_stop(struct orca_fs *c)
{
    struct task_struct *p;

    c->rebalance.pd.rate.rate = UINT_MAX;
    orca_ratelimit_reset(&c->rebalance.pd.rate);
    p = rcu_dereference_protected(c->rebalance.thread, 1);
    c->rebalance.thread = NULL;

    if (p) {
        /* For synchronizing with rebalance_wakeup() */
        synchronize_rcu();
        kthread_stop(p);
        put_task_struct(p);
    }
}

int
orca_rebalance_start(struct orca_fs *c)
{
    struct task_struct *p;

    if (c->opts.nochanges)
        return 0;

    p = kthread_create(orca_rebalance_thread, c, "bch_rebalance");

    if (IS_ERR(p))
        return PTR_ERR(p);

    get_task_struct(p);
    rcu_assign_pointer(c->rebalance.thread, p);
    wake_up_process(p);

    return 0;
}

void
orca_fs_rebalance_init(struct orca_fs *c)
{
    orca_pd_controller_init(&c->rebalance.pd);
    atomic64_set(&c->rebalance.work_unknown_dev, S64_MAX);
}
