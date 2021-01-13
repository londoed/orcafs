#ifdef CONFIG_ORCAFS_TESTS

#include <linux/kthread.h>
#include <linux/random.h>

#include "orcafs.h"
#include "btree_update.h"
#include "journal_reclaim.h"
#include "tests.h"

static void
delete_test_keys(struct orca_fs *c)
{
    int ret;

    ret = orca_btree_delete_range(c, BTREE_ID_EXTENTS, POS(0, 0), POS(0, U64_MAX),
        NULL);

    BUG_ON(ret);

    ret = orca_btree_delete_range(c, BTREE_ID_XATTRS, POS(0, 0), POS(0, U64_MAX),
        NULL);

    BUG_ON(ret);
}

/**
 * UNIT TESTS.
**/
static void
test_delete(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_i_cookie k;
    int ret;

    bkey_cookie_init(&k.k_i);
    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_XATTRS, k.k.p, BTREE_ITER_INTENT);
    ret = orca_btree_iter_traverse(iter);
    BUG_ON(ret);

    ret = __orca_trans_do(&trans, NULL, NULL, 0, orca_trans_update(&trans, iter,
        &k.k_i, 0));
    BUG_ON(ret);

    pr_info("deleting once");
    ret = orca_btree_delete_at(&trans, iter, 0);
    BUG_ON(ret);

    pr_info("deleting twice");
    ret = orca_btree_delete_at(&trans, iter, 0);
    BUG_ON(ret);

    orca_trans_exit(&trans);
}

static void
test_delete_written(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_i_cookie k;
    int ret;

    bkey_cookie_init(&k.k_i);
    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_XATTRS, k.k.p, BTREE_ITER_INTENT);
    ret = orca_btree_iter_traverse(iter);
    BUG_ON(ret);

    ret = __orca_trans_do(&trans, NULL, NULL, 0, orca_trans_update(&trans, iter,
        &k.k_i, 0));
    BUG_ON(ret);

    orca_journal_flush_all_pins(&c->journal);
    ret = orca_btree_delete_at(&trans, iter, 0);
    BUG_ON(ret);

    orca_trans_exit(&trans);
}

static void
test_iterate(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 i;
    int ret;

    orca_trans_init(&trans, c, 0, 0);
    delete_test_keys(c);
    pr_info("inserting test keys");

    for (i = 0; i < nr; i++) {
        struct bkey_i_cookie k;

        bkey_cookie_init(&k.k_i);
        k.k.p.offset = i;
        ret = orca_btree_insert(c, BTREE_ID_XATTRS, &k.k_i, NULL, NULL, 0);
        BUG_ON(ret);
    }

    pr_info("iterating forwards");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, 0, k, ret) {
        if (k.k->p.inode)
            break;

        BUG_ON(k.k->p.offset != i++);
    }

    BUG_ON(i != nr);
    pr_info("iterating backwards");

    while (!IS_ERR_OR_NULL((k = orca_btree_iter_prev(iter)).k))
        BUG_ON(k.k->p.offset != --i);

    BUG_ON(i);
    orca_trans_exit(&trans);
}

static void
test_iterate_extents(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 i;
    int ret;

    orca_trans_init(&trans, c, 0, 0);
    delete_test_keys(c);
    pr_info("inserting test extents");

    for (i = 0; i < nr; i += 8) {
        struct bkey_i_cookie k;

        bkey_cookie_init(&k.k_i);
        k.k.p.offset = i + 8;
        k.k.size = 8;

        ret = orca_btree_insert(c, BTREE_ID_EXTENTS, &k.k_i, NULL, NULL, 0);
        BUG_ON(ret);
    }

    pr_info("iterating forwards");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS_MIN, 0, k, ret) {
        BUG_ON(bkey_start_offset(k.k) != i);
        i = k.k->p.offset;
    }

    BUG_ON(i != nr);
    pr_info("iterating backwards");

    while (!IS_ERR_OR_NULL((k = orca_btree_iter_prev(iter)).k)) {
        BUG_ON(k.k->p.offset != i);
        i = bkey_start_offset(k.k);
    }

    BUG_ON(i);
    orca_trans_exit(&trans);
}

static void
test_iterate_slots(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 l;
    int ret;

    orca_trans_init(&trans, c, 0, 0);
    delete_test_keys(c);
    pr_info("inserting test keys");

    for (i = 0; i < nr; i++) {
        struct bkey_i_cookie k;

        bkey_cookie_init(&k.k_i);
        k.k.p.offset = i * 2;
        ret = orca_btree_insert(c, BTREE_ID_XATTRS, &k.k_i, NULL, NULL, 0);
        BUG_ON(ret);
    }

    pr_info("iterating forwards");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, 0, k, ret) {
        if (k.k->p.inode)
            break;

        BUG_ON(k.k->p.offset != i);
        i += 2;
    }

    orca_trans_iter_free(&trans, iter);
    BUG_ON(i != nr * 2);
    pr_info("iterating forwards by slots");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, BTREE_ITER_SLOTS,
        k, ret) {
            BUG_ON(k.k->p.offset != i);
            BUG_ON(bkey_deleted(k.k) != (i & 1));
            i++;

            if (i == nr *2)
                break;
    }

    orca_trans_exit(&trans);
}

static void
test_iterate_slots_extents(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 l;
    int ret;

    orca_trans_init(&trans, c, 0, 0);
    delete_test_keys(c);
    pr_info("inserting test keys");

    for (i = 0; i < nr; i += 16) {
        struct bkey_i_cookie k;

        bkey_cookie_init(&k.k_i);
        k.k.p.offset = i + 16;
        k.k.size = 8;

        ret = orca_btree_insert(c, BTREE_ID_EXTENTS, &k.k_i, NULL, NULL, 0);
        BUG_ON(ret);
    }

    pr_info("iterating forwards");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS_MIN, 0, k, ret) {
        BUG_ON(bkey_start_offset(k.k) != i + 8);
        BUG_ON(k.k->size != 8);
        i += 16;
    }

    orca_trans_iter_free(&trans, iter);
    BUG_ON(i != nr);
    pr_info("iterating forwards by slots");
    i = 0;

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS_MIN, BTREE_ITER_SLOTS, k, ret) {
        BUG_ON(bkey_deleted(k.k) != !(i % 16));
        BUG_ON(bkey_start_offset(k.k) != i);
        i = k.k->p.offset;

        if (i == nr)
            break;
    }

    orca_trans_exit(&trans);
}

/**
 * We really want to make sure we've got a btree with depth > 0 these
 * tests
**/
static void
test_peek_end(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_XATTRS, POS_MIN, 0);
    k = orca_btree_iter_peek(iter);
    BUG_ON(k.k);

    k = orca_btree_iter_peek(iter);
    BUG_ON(k.k);

    orca_trans_exit(&trans);
}

static void
test_peek_end_extents(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;

    orca_trans_init(&trans, c, 0, 0);
    iter = orca_trans_get_iter(&trans, BTREE_ID_EXTENTS, POS_MIN, 0);
    k = orca_btree_iter_peek(iter);
    BUG_ON(k.k);

    k = orca_btree_iter_peek(iter);
    BUG_ON(k.k);

    orca_trans_exit(&trans);
}

u64 test_version;

static void
insert_test_extent(struct orca_fs *c, u64 start, u64 end)
{
    struct bkey_i_cookie k;
    int ret;

    bkey_cookie_init(&k.k_i);
    k.k_i.k.p.offset = end;
    k.k_i.k.size = end - start;
    k.k_i.k.version.lo = test_version++;

    ret = orca_btree_insert(c, BTREE_ID_EXTENTS, &k.k_i, NULL, NULL, 0);
    BUG_ON(ret);
}

static void
__test_extent_overwrite(struct orca_fs *c, u64 e1_start, u64 e1_end,
    u64 e2_start, u64 e2_end)
{
    insert_test_extent(c, e1_start, e1_end);
    insert_test_extent(c, e2_start, e2_end);

    delete_test_keys(c);
}

static void
__test_extent_overwrite_front(struct orca_fs *c, u64 nr)
{
    __test_extent_overwrite(c, 0, 64, 0, 32);
    __test_extent_overwrite(c, 8, 64, 0, 32);
}

static void
__test_extent_overwrite_back(struct orca_fs *c, u64 nr)
{
    __test_extent_overwrite(c, 0, 64, 32, 64);
    __test_extent_overwrite(c, 0, 64, 32, 72);
}

static void
test_extent_overwrite_middle(struct orca_fs *c, u64 nr)
{
    __test_extent_overwrite(c, 0, 64, 32, 40);
}

static void
test_extent_overwrite_all(struct orca_fs *c, u64 nr)
{
    __test_extent_overwrite(c, 32, 64, 0, 64);
    __test_extent_overwrite(c, 32, 64, 0, 128);
    __test_extent_overwrite(c, 32, 64, 32, 64);
    __test_extent_overwrite(c, 32, 64, 32, 128);
}

static u64
test_rand(void)
{
    u64 v;
#if 0
    v = prandom_u32();
#else
    prandom_bytes(&v, sizeof(v));
#endif
    return v;
}

static void
rand_insert(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct bkey_i_cookie k;
    int ret;
    u64 i;

    orca_trans_init(&trans, c, 0, 0);

    for (i = 0; i < nr; i++) {
        bkey_cookie_init(&k.k_i);
        k.k.p.offset = test_rand();
        ret = __orca_trans_do(&trans, NULL, NULL, 0, __orca_btree_insert(&trans,
            BTREE_ID_XATTRS, &k.k_i));

        BUG_ON(ret);
    }

    orca_trans_exit(&trans);
}

static void
rand_lookup(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 i;

    orca_trans_init(&trans, c, 0, 0);

    for (i = 0; i < nr; i++) {
        iter = orca_trans_get_iter(&trans, BTREE_ID_XATTRS, POS(0, test_rand()), 0);
        k = orca_btree_iter_peek(iter);
        orca_trans_iter_free(&trans, iter);
    }

    orca_trans_exit(&trans);
}

static void
rand_mixed(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret;
    u64 i;

    orca_trans_init(&trans, c, 0, 0);

    for (i = 0; i < nr; i++) {
        iter = orca_trans_get_iter(&trans, BTREE_ID_XATTRS, POS(0, test_rand()), 0);
        k = orca_btree_iter_peek(iter);

        if (!(i & 3) && k.k) {
            struct bkey_i_cookie k;

            bkey_cookie_init(&k.k_i);
            k.k.p = iter->pos;

            ret = __orca_trans_do(&trans, NULL, NULL, 0, orca_trans_update(&trans,
                iter, &k.k_i, 0));

            BUG_ON(ret);
        }

        orca_trans_iter_free(&trans, iter);
    }

    orca_trans_exit(&trans);
}

static int
__do_delete(struct btree_trans *trans, struct bpos pos)
{
    struct btree_iter *iter;
    struct bkey_i delete;
    struct bkey_s_c k;
    int ret = 0;

    iter = orca_trans_get_iter(trans, BTREE_ID_XATTRS, pos, BTREE_ITER_INTENT);
    ret = PTR_ERR_OR_ZERO(iter);

    if (ret)
        goto err;

    k = orca_btree_iter_peek(iter);
    ret = bkey_err(k);

    if (ret)
        goto err;

    bkey_init(&delete.k);
    delete.k.p = k.k->p;

    orca_trans_update(trans, iter, &delete, 0);

err:
    orca_trans_iter_put(trans, iter);

    return ret;
}

static void
rand_delete(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    int ret;
    u64 i;

    orca_trans_init(&trans, c, 0, 0);

    for (i = 0; i < nr; i++) {
        struct bpos pos = POS(0, test_rand());

        ret = __orca_trans_do(&trans, NULL, NULL, 0, __do_delete(&trans, pos));

        BUG_ON(ret);
    }

    orca_trans_exit(&trans);
}

static void
seq_insert(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    struct bkey_i_cookie insert;
    int ret;
    u64 i = 0;

    bkey_cookie_init(&insert.k_i);
    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, BTREE_ITER_SLOTS |
        BTREE_ITER_INTENT, k, ret) {
            insert.k.p = iter->pos;
            ret = __orca_trans_do(&trans, NULL, NULL, 0, orca_trans_update(&trans,
                iter, &insert.k_i, 0));

            BUG_ON(ret);

            if (++i == nr)
                break;
    }

    orca_trans_exit(&trans);
}

static void
seq_lookup(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, 0, k, ret)
        ;

    orca_trans_exit(&trans);
}

static void
seq_overwrite(struct orca_fs *c, u64 nr)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    int ret;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_XATTRS, POS_MIN, BTREE_ITER_INTENT,
        k, ret) {
            struct bkey_i_cookie u;

            bkey_reassemble(&u.k_i, k);
            ret = __orca_trans_do(&trans, NULL, NULL, 0);

            BUG_ON(ret);
    }

    orca_trans_exit(&trans);
}

static void
seq_delete(struct orca_fs *c, u64 nr)
{
    int ret;

    ret = orca_btree_delete_range(c, BTREE_ID_XATTRS, POS(0, 0), POS(0, U64_MAX),
        NULL);

    BUG_ON(ret);
}

typedef void (*perf_test_fn)(struct orca_fs *, u64);

struct test_job {
    struct orca_fs *c;
    u64 nr;
    unsigned nr_threads;
    perf_test_fn fn;

    atomic_t ready;
    wait_queue_head_t ready_wait;
    atomic_t done;
    struct completion done_completion;
    u64 start;
    u64 finish;
};

static int
btree_perf_test_thread(void *data)
{
    struct test_job *j = data;

    if (atomic_dec_and_test(&j->ready)) {
        wake_up(&j->ready_wait);
        j->start = sched_clock();
    } else {
        wait_event(j->ready_wait, !atomic_read(&j->ready));
    }

    j->fn(j->c, j->nr / j->nr_threads);

    if (atomic_dec_and_test(&j->done)) {
        j->finish = sched_clock();
        complete(&j->done_completion);
    }

    return 0;
}

void
orca_btree_perf_test(struct orca_fs *c, const char *testname, u64 nr,
    unsigned nr_threads)
{
    struct test_job j = { .c = c, .nr = nr, .nr_threads = nr_threads };
    char name_buf[20], nr_buf[20], per_sec_buf[20];
    unsigned i;
    u64 time;

    atomic_set(&j.done, nr_threads);
    init_completion(&j.done_completion);

#define perf_test(_test)    \
    if (!strcmp(testname, #_test)) j.fn = _test

    perf_test(rand_insert);
    perf_test(rand_lookup);
    perf_test(rand_mixed);
    perf_test(rand_delete);
    perf_test(seq_insert);
    perf_test(seq_lookup);
    perf_test(seq_overwrite);
    perf_test(seq_delete);

    /* A unit test, not a perf test */
    perf_test(test_delete);
    perf_test(test_delete_written);
    perf_test(test_iterate);
    perf_test(test_iterate_extents);
    perf_test(test_iterate_slots);
    perf_test(test_iterate_slots_extents);
    perf_test(test_peek_end);
    perf_test(test_peek_and_extents);

    perf_test(test_extent_overwrite_front);
    perf_test(test_extent_overwrite_back);
    perf_test(test_extent_overwrite_middle);
    perf_test(test_extent_overwrite_all);

    if (!j.fn) {
        pr_err("unknown test %s", testname);
        return;
    }

    if (nr_thread == 1) {
        btree_perf_test_thread(&j)
    } else {
        for (i = 0; i < nr_threads; i++)
            kthread_run(btree_perf_test_thread, &j, "orcafs perf test[%u]", i);
    }

    while (wait_for_completion_interruptible(&j.done_completion))
        ;

    time = j.finish - j.start;

    scnprintf(name_buf, sizeof(name_buf), "%s:", testname);
    orca_hprint(&PBUF(nr_buf), nr);
    orca_hprint(&PBUF(per_sec_buf), nr * NSEC_PER_SEC / time);

    printk(KERN_INFO "%-12s %s with %u threads in %5llu sec, %5llu nsec per iter"
        ", , %5s per sec\n", name_buf, nr_buf, nr_threads, time / NSEC_PER_SEC,
        time * nr_threads / nr, per_sec_buf);
}

#endif
