#ifndef NO_ORCAFS_SYSFS

#include "orcafs.h"
#include "alloc_background.h"
#include "sysfs.h"
#include "btree_cache.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "btree_key_cache.h"
#include "btree_update.h"
#include "btree_update_interior.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "disk_groups.h"
#include "ec.h"
#include "inode.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "opts.h"
#include "rebalance.h"
#include "replicas.h"
#include "super-io.h"
#include "tests.h"

#include <linux/blkdev.h>
#include <linux/sort.h>
#include <linux/sched/clock.h>

#include "util.h"

#define SYSFS_OPS(type)							\
struct sysfs_ops type ## _sysfs_ops = {					\
	.show	= type ## _show,					\
	.store	= type ## _store					\
}

#define SHOW(fn)							\
static ssize_t fn ## _show(struct kobject *kobj, struct attribute *attr,\
			   char *buf)					\

#define STORE(fn)							\
static ssize_t fn ## _store(struct kobject *kobj, struct attribute *attr,\
			    const char *buf, size_t size)		\

#define __sysfs_attribute(_name, _mode)					\
	static struct attribute sysfs_##_name =				\
		{ .name = #_name, .mode = _mode }

#define write_attribute(n)	__sysfs_attribute(n, S_IWUSR)
#define read_attribute(n)	__sysfs_attribute(n, S_IRUGO)
#define rw_attribute(n)		__sysfs_attribute(n, S_IRUGO|S_IWUSR)

#define sysfs_printf(file, fmt, ...)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		return scnprintf(buf, PAGE_SIZE, fmt "\n", __VA_ARGS__);\
} while (0)

#define sysfs_print(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		return snprint(buf, PAGE_SIZE, var);			\
} while (0)

#define sysfs_hprint(file, val)						\
do {									\
	if (attr == &sysfs_ ## file) {					\
		bch2_hprint(&out, val);					\
		pr_buf(&out, "\n");					\
		return out.pos - buf;					\
	}								\
} while (0)

#define var_printf(_var, fmt)	sysfs_printf(_var, fmt, var(_var))
#define var_print(_var)		sysfs_print(_var, var(_var))
#define var_hprint(_var)	sysfs_hprint(_var, var(_var))

#define sysfs_strtoul(file, var)					\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe(buf, var) ?: (ssize_t) size;	\
} while (0)

#define sysfs_strtoul_clamp(file, var, min, max)			\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe_clamp(buf, var, min, max)		\
			?: (ssize_t) size;				\
} while (0)

#define strtoul_or_return(cp)						\
({									\
	unsigned long _v;						\
	int _r = kstrtoul(cp, 10, &_v);					\
	if (_r)								\
		return _r;						\
	_v;								\
})

#define strtoul_restrict_or_return(cp, min, max)			\
({									\
	unsigned long __v = 0;						\
	int _r = strtoul_safe_restrict(cp, __v, min, max);		\
	if (_r)								\
		return _r;						\
	__v;								\
})

#define strtoi_h_or_return(cp)						\
({									\
	u64 _v;								\
	int _r = strtoi_h(cp, &_v);					\
	if (_r)								\
		return _r;						\
	_v;								\
})

#define sysfs_hatoi(file, var)						\
do {									\
	if (attr == &sysfs_ ## file)					\
		return strtoi_h(buf, &var) ?: (ssize_t) size;		\
} while (0)

write_attribute(trigger_journal_flush);
write_attribute(trigger_btree_coalesce);
write_attribute(trigger_gc);
write_attribute(prune_cache);
rw_attribute(btree_gc_periodic);

read_attribute(uuid);
read_attribute(minor);
read_attribute(bucket_size);
read_attribute(block_size);
read_attribute(btree_node_size);
read_attribute(first_bucket);
read_attribute(nbuckets);
read_attribute(durability);
read_attribute(iodone);

read_attribute(io_latency_read);
read_attribute(io_latency_write);
read_attribute(io_latency_stats_read);
read_attribute(io_latency_stats_write);
read_attribute(congested);

read_attribute(bucket_quantiles_last_read);
read_attribute(bucket_quantiles_last_write);
read_attribute(bucket_quantiles_fragmentation);
read_attribute(bucket_quantiles_oldest_gen);

read_attribute(reserve_stats);
read_attribute(btree_cache_size);
read_attribute(compression_stats);
read_attribute(journal_debug);
read_attribute(journal_pins);
read_attribute(btree_updates);
read_attribute(dirty_btree_nodes);
read_attribute(btree_key_cache);
read_attribute(btree_transactions);
read_attribute(stripes_heap);

read_attribute(internal_uuid);

read_attribute(has_data);
read_attribute(alloc_debug);
write_attribute(wake_allocator);

read_attribute(read_realloc_races);
read_attribute(extent_migrate_done);
read_attribute(extent_migrate_raced);

rw_attribute(journal_write_delay_ms);
rw_attribute(journal_reclaim_delay_ms);

rw_attribute(discard);
rw_attribute(cache_replacement_policy);
rw_attribute(label);

rw_attribute(copy_gc_enabled);
sysfs_pd_controller_attribute(copy_gc);

rw_attribute(rebalance_enabled);
sysfs_pd_controller_attribute(rebalance);
read_attribute(rebalance_work);
rw_attribute(promote_whole_extents);

read_attribute(new_stripes);

rw_attribute(pd_controllers_update_seconds);

read_attribute(meta_replicas_have);
read_attribute(data_replicas_have);

read_attribute(io_timers_read);
read_attribute(io_timers_write);

#ifdef CONFIG_BCACHEFS_TESTS
write_attribute(perf_test);
#endif /* CONFIG_BCACHEFS_TESTS */

#define BCH_DEBUG_PARAM(name, description)				\
	rw_attribute(name);

	BCH_DEBUG_PARAMS()
#undef BCH_DEBUG_PARAM

#define x(_name)						\
	static struct attribute sysfs_time_stat_##_name =		\
		{ .name = #_name, .mode = S_IRUGO };
	BCH_TIME_STATS()
#undef x

static struct attribute sysfs_state_rw = {
    .name = "state",
    .mode = S_IRUGO,
};

static size_t
orca_btree_cache_size(struct orca_fs *c)
{
    size_t ret = 0;
    struct btree *b;

    mutex_lock(&c->btree_cache.lock);

    list_for_each_entry(b, &c->btree_cache.live, list)
        ret += btree_bytes(c);

    mutex_unlock(&c->btree_cache.lock);

    return ret;
}

static int
fs_alloc_debug_to_text(struct printbuf *out, struct orca_fs *c)
{
    struct orca_fs_usage *fs_usage = orca_fs_usage_read(c);

    if (!fs_usage)
        return -ENOMEM;

    orca_fs_usage_to_text(out, c, fs_usage);
    percpu_up_read(&c->mark_lock);
    kfree(fs_usage);

    return 0;
}

static int
orca_compression_stats_to_text(struct printbuf *out, struct orca_fs *c)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bkey_s_c k;
    u64 nr_uncompressed_extents = 0, uncompressed_sectors = 0;
    u64 nr_compressed_extents = 0, compressed_sectors_compressed = 0;
    u64 compressed_sectors_uncompressed;
    int ret;

    if (!test_bit(ORCA_FS_STARTED, &c->flags))
        return -EPERM;

    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, POS_MIN, 0, k, ret) {
        if (k.k->type == KEY_TYPE_extent) {
            struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
            const union orca_entent_entry *entry;
            struct extent_ptr_decoded p;

            extent_for_each_ptr_decode(e, p, entry) {
                if (!crc_is_compressed(p.crc)) {
                    nr_uncompressed_extents++;
                    uncompressed_sectors += e.k->size;
                } else {
                    nr_compressed_extents++;
                    compressed_sectors_compressed += p.crc.compressed_size;
                    compressed_sectors_uncompressed += p.crc.uncompressed_size;
                }

                /* Only looking at the first ptr */
                break;
            }
        }
    }

    ret = orca_trans_exit(&trans) ?: ret;

    if (ret)
        return ret;

    pr_buf(out,
    	"uncompressed data:\n"
    	"	nr extents:			%llu\n"
    	"	size (bytes):			%llu\n"
    	"compressed data:\n"
    	"	nr extents:			%llu\n"
        "	compressed size (bytes):	%llu\n"
    	"	uncompressed size (bytes):	%llu\n",
    	nr_uncompressed_extents,
    	uncompressed_sectors << 9,
    	nr_compressed_extents,
    	compressed_sectors_compressed << 9,
    	compressed_sectors_uncompressed << 9);

    return 0;
}
