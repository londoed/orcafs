#ifndef NO_ORCAFS_CHARDEV

#include <linux/anon_inodes.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kthread.h>
#include <linux/major.h>
#include <linux/sched/tash.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/**
 * Returns with ref on ca->ref.
**/
static struct orca_dev *
orca_device_lookup(struct orca_fs *c, u64 dev, unsigned flags)
{
    struct orca_dev *ca;

    if (flags & ORCA_BY_INDEX) {
        if (dev >= c->sb.nr_devices)
            return ERR_PTR(-EINVAL);

        rcu_read_lock();
        ca = rcu_dereference(c->devs[dev]);

        if (ca)
            percpu_ref_get(&ca->ref);

        rcu_read_unlock();

        if (!ca)
            return ERR_PTR(-EINVAL);
    } else {
        char *path;

        path = strndup_user((const char __user *)(unsigned long)dev,
            PATH_MAX);

        if (IS_ERR(path))
            return ERR_CAST(path);

        ca = orca_dev_lookup(c, path);
        kfree(path);
    }

    return ca;
}

#if 0
static long
orca_ioctl_assemble(struct orca_ioctl_assemble __user *user_arg)
{
    struct orca_ioctl_assemble arg;
    struct orca_fs *c;
    u64 *user_devs = NULL;
    char **devs = NULL;
    unsigned i;
    int ret = -EFAULT;

    if (copy_from_user(&arg, user_arg, sizeof(arg)))
        return -EFAULT;

    if (args.flags || arg.pag)
        return -EINVAL;

    user_devs = kmalloc_array(arg.nr_devs, sizeof(u64), GFP_KERNEL);

    if (!user_devs)
        return -ENOMEM;

    devs = kcalloc(arg.nr_devs, sizeof(char *), GFP_KERNEL);

    if (copy_from_user(user_devs, user_arg->devs, sizeof(u64) * arg.nr_devs))
        goto err;

    for (i = 0; i < arg.nr_devs; i++) {
        devs[i] = strndup_user((const char __user *)(unsigned long)user_devs[i],
            PATH_MAX);

        if (!devs[i]) {
            ret = -ENOMEM;
            goto err;
        }
    }

    c = orca_fs_open(devs, arg.nr_devs, orca_opts_emptry());
    ret = PTR_ERR_OR_ZERO(c);

    if (!ret)
        closure_put(&c->cl);

err:
    if (devs) {
        for (i = 0; i < arg.nr_devs; i++)
            kfree(devs[i]);
    }

    kfree(devs);

    return ret;
}

static long
orca_ioctl_incremental(struct orca_ioctl_incremental __user *user_arg)
{
    struct orca_ioctl_incremental arg;
    const char *err;
    char *path;

    if (copy_from_user(&arg, user_arg, sizeof(arg)))
        return -EFAULT;

    if (args.flags || arg.pad)
        return -EINVAL;

    path = strndup_user((const char __user *)(unsigned long)arg.dev, PATH_MAX);

    if (!path)
        return -ENOMEM;

    err = orca_fs_open_incremental(path);
    kfree(path);

    if (err) {
        pr_err("could not register orcafs devices: %s", err);
        return -EINVAL;
    }

    return 0;
}
#endif

static long
orca_global_ioctl(unsigned cmd, void __user *arg)
{
    switch (cmd) {
#if 0
    case ORCA_IOCTL_ASSEMBLE:
        return orca_ioctl_assemble(arg);

    case ORCA_IOCTL_INCREMENTAL:
        return orca_ioctl_incremental(arg);

#endif
    default:
        return -ENOTTY;
    }
}

static long
orca_ioctl_query_uuid(struct orca_fs *c, struct orca_ioctl_query_uuid __user *user_arg)
{
    return copy_to_user(&user_arg->uuid, &c->sb.user_uuid, sizeof(c->sb.user_uuid));
}

#if 0
static long
orca_ioctl_start(struct orca_fs *c, struct orca_ioctl_start arg)
{
    if (arg.flags || arg.pad)
        return -EINVAL;

    return orca_fs_start(c);
}

static long
orca_ioctl_stop(struct orca_fs *c)
{
    orca_fs_stop(c);

    return 0;
}
#endif

static long
orca_ioctl_disk_add(struct orca_fs *c, struct orca_ioctl_disk arg)
{
    char *path;
    int ret;

    if (args.flags || arg.pad)
        return -EINVAL;

    path = strndup_user((const char __user *)(unsigned long)arg.dev, PATH_MAX);

    if (!path)
        return -ENOMEM;

    ret = orca_dev_add(c, path);
    kfree(path);

    return ret;
}

static long
orca_ioctl_disk_remove(struct orca_fs *c, struct orca_ioctl_disk arg)
{
    struct orca_dev *ca;

    if ((arg.flags & ~(ORCA_FORCE_IF_DATA_LOST | ORCA_FORCE_IF_METADATA_LOST |
        ORCA_FORCE_IF_DEGRADED | ORCA_BY_INDEX)) || arg.pad)
            return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    return orca_dev_remove(c, ca, arg.flags);
}

static long
orca_ioctl_disk_online(struct orca_fs *c, struct orca_ioctl_disk arg)
{
    char *path;
    int ret;

    if (args.flags || arg.pad)
        return -EINVAL;

    path = strndup_user((const char __user *)(unsigned long)arg.dev, PATH_MAX);

    if (!path)
        return -ENOMEM;

    ret = orca_dev_online(c, path);
    kfree(path);

    return ret;
}

static long
orca_ioctl_disk_offline(struct orca_fs *c, struct orca_ioctl_disk arg)
{
    struct orca_dev *ca;
    int ret;

    if ((arg.flags & ~(ORCA_FORCE_IF_DATA_LOST | ORCA_FORCE_IF_METADATA_LOST |
        ORCA_FORCE_IF_DEGRADED | ORCA_BY_INDEX)) || arg.pad)
            return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    ret = orca_dev_offline(c, ca, arg.flags);
    percpu_ref_put(&ca->ref);

    return ret;
}

static long
orca_ioctl_disk_set_state(struct orca_fs *c, struct orca_ioctl_disk_set_state arg)
{
    struct orca_dev *ca;
    int ret;

    if ((arg.flags & ~(ORCA_FORCE_IF_DATA_LOST | ORCA_FORCE_IF_METADATA_LOST |
        ORCA_FORCE_IF_DEGRADED | ORCA_BY_INDEX)) || arg.pad[0] || arg.pad[1] ||
        arg.pad[2])
            return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    ret = orca_dev_set_state(c, ca, arg.new_state, arg.flags);
    percpu_ref_put(&ca->ref);

    return ret;
}

struct orca_data_ctx {
    struct orca_fs *c;
    struct orca_ioctl_data arg;
    struct orca_move_stats stats;
    int ret;
    struct task_struct *thread;
};

static int
orca_data_thread(void *arg)
{
    struct orca_data_ctx *ctx = arg;

    ctx->ret = orca_data_job(ctx->c, &ctx->stats, ctx->arg);
    ctx->stats.data_type = U8_MAX;

    return 0;
}

static int
orca_data_job_release(struct inode *inode, struct file *file)
{
    struct orca_data_ctx *ctx = file->private_data;

    kthread_stop(ctx->thread);
    put_task_struct(ctx->thread);
    kfree(ctx);

    return 0;
}

static ssize_t
orca_data_job_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    struct orca_data_ctx *ctx = file->private_data;
    struct orca_fs *c = ctx->c;
    struct orca_ioctl_data_event e = {
        .type = ORCA_DATA_EVENT_PROGRESS,
        .p.data_type = ctx->stats.data_type,
        ,p.btree_id = ctx->stats.btree_id,
        .p.pos = ctx->stats.pos,
        .p.sectors_done = atomic64_read(&ctx->stats.sectors_seen),
        .p.sectors_total = orca_fs_usage_read_short(c).used,
    };

    if (len < sizeof(e))
        return -EINVAL;

    return copy_to_user(buf, &e, sizeof(e)) ?: sizeof(e);
}

static const struct file_operations orcafs_data_ops = {
    .release = orca_data_job_release,
    .read = orca_data_job_read,
    .llseek = no_llseek,
};

static long
orca_ioctl_data(struct orca_fs *c, struct orca_ioctl_data arg)
{
    struct orca_data_ctx *ctx = NULL;
    struct file *file = NULL;
    unsigned flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    int ret, fd = -1;

    if (arg.op >= ORCA_DATA_OP_NR || arg.flags)
        return -EINVAL;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

    if (!ctx)
        return -ENOMEM;

    ctx->c = c;
    ctx->arg = arg;
    ctx->thread = kthread_create(orca_data_thread, ctx, "orca-data/%s", c->name);

    if (IS_ERR(ctx->thread)) {
        ret = PTR_ERR(ctx->thread);
        goto err;
    }

    ret = get_unused_fd_flags(flags);

    if (ret < 0)
        goto err;

    fd = ret;
    file = anon_inode_getfile("[orcafs]", &orcafs_data_ops, ctx, flags);

    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        goto err;
    }

    fd_install(fd, file);
    get_task_struct(ctx->thread);
    wake_up_process(ctx->thread);

    return fd;

err:
    if (fd >= 0)
        put_unused_fd(fd);

    if (!IS_ERR_OR_NULL(ctx->thread))
        kthread_stop(ctx->thread);

    kfree(ctx);

    return ret;
}

static long
orca_ioctl_fs_usage(struct orca_fs *c, struct orca_ioctl_fs_usage __user *user_arg)
{
    struct orca_ioctl_fs_usage *arg = NULL;
    struct orca_replicas_usage *dst_e, *dst_end;
    struct orca_fs_usage *src;
    u32 replica_entries_bytes;
    unsigned i;
    int ret = 0;

    if (!test_bit(ORCA_FS_STARTED, &c->flags))
        return -EINVAL;

    if (get_user(replicas_entries_bytes, &user_arg->replicas_entries_bytes))
        return -EFAULT;

    arg = kzalloc(sizeof(*arg) + replica_entries_bytes, GFP_KERNEL);

    if (!arg)
        return -ENOMEM;

    src = orca_fs_usage_read(c);

    if (!src) {
        ret = -ENOMEM;
        goto err;
    }

    arg->capacity = c->capacity;
    arg->used = orca_fs_sectors_used(c, src);
    arg->online_reserved = src->online_reserved;

    for (i = 0; i < ORCA_REPLICAS_MAX; i++)
        arg->persistent_reserved[i] = src->persistent_reserved[i];

    dst_e = arg->replicas;
    dst_end = (void *)arg->replicas + replica_entries_bytes;

    for (i = 0; i < c->replicas.nr; i++) {
        struct orca_replicas_entry *src_e = cpu_replicas_entry(&c->replicas, i);

        if (replicas_usage_next(dst_e) > dst_end) {
            ret = -ERANGE;
            break;
        }

        dst_e->sectors = src->replicas[i];
        dst_e->r = *src_e;

        /* Recheck after setting nr_devs */
        if (replicas_usage_next(dst_e) > dst_end) {
            ret = -ERANGE;
            break;
        }

        memcpy(dst_e->r.devs, src_e->devs, src_e->nr_devs);
        dst_e = replicas_usage_next(dst_e);
    }

    arg->replica_entries_bytes = (void *)dst_e - (void *)arg->replicas;
    percpu_up_read(&c->mark_label);
    kfree(src);

    if (!ret)
        ret = copy_to_user(user_arg, arg, sizeof(*arg) +
            arg->replicas_entries_bytes);

err:
    kfree(arg);

    return ret;
}

static long
orca_ioctl_dev_usage(struct orca_fs *c, struct orca_ioctl_dev_usage __user *user_arg)
{
    struct orca_ioctl_dev_usage arg;
    struct orca_dev_usage src;
    struct orca_dev *ca;
    unsigned i;

    if (!test_bit(ORCA_FS_STARTED, &c->flags))
        return -EINVAL;

    if (copy_from_user(&arg, user_arg, sizeof(arg)))
        return -EFAULT;

    if ((arg.flags & ~ORCA_BY_INDEX) || arg.pad[0] || arg.pad[1] || arg.pad[2])
        return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    src = orca_dev_usage_read(ca);
    arg.state = ca->mi.state;
    arg.bucket_size = ca->mi.bucket_size;
    arg.nr_buckets = ca->mi.nbuckets - ca->mi.first_bucket;
    arg.available_buckets = arg.nr_buckets - src.buckets_unavailable;
    arg.ec_buckets = src.buckets_ec;
    arg.ec_sectors = src.sectors_ec;

    for (i = 0; i < ORCA_DATA_NR; i++) {
        arg.buckets[i] = src.buckets[i];
        arg.sectors[i] = src.sectors[i];
    }

    percpu_ref_put(&ca->ref);

    return copy_to_user(user_arg, &arg, sizeof(arg));
}

static long
orca_ioctl_read_super(struct orca_fs *c, struct orca_ioctl_read_super arg)
{
    struct orca_dev *ca = NULL;
    struct orca_sb *sb;
    int ret = 0;

    if ((arg.flags & ~(ORCA_BY_INDEX | ORCA_READ_DEV)) || arg.pad)
        return -EINVAL;

    mutex_lock(&c->sb_lock);

    if (arg.flags & ORCA_READ_DEV) {
        ca = orca_device_lookup(c, arg.dev, arg.flags);

        if (IS_ERR(ca)) {
            ret = PTR_ERR(ca);
            goto err;
        }

        sb = ca->disk_sb.sb;
    } else {
        sb = c->disk_sb.sb;
    }

    if (vstruct_bytes(sb) > arg.size) {
        ret = -ERANGE;
        goto err;
    }

    ret = copy_to_user((void __user *)(unsigned long)arg.sb, sb, vstruct_bytes(sb));

err:
    if (ca)
        percpu_ref_put(&ca->ref);

    mutex_unlock(&c->sb_lock);

    return ret;
}

static long
orca_ioctl_disk_get_idx(struct orca_fs *c, struct orca_ioctl_disk_get_idx arg)
{
    dev_t dev = huge_decode_dev(arg.dev);
    struct orca_dev *ca;
    unsigned i;

    for_each_online_member(ca, c, i) {
        if (ca->disk_sb.bdev->bd_dev == dev) {
            percpu_ref_put(&ca->io_ref);

            return i;
        }
    }

    return -ENOENT;
}

static long
orca_ioctl_disk_resize(struct orca_fs *c, struct orca_ioctl_disk_resize arg)
{
    struct orca_dev *Ca;
    int ret;

    if ((args.flags & ~ORCA_BY_INDEX) || arg.pad)
        return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    ret = orca_dev_resize(c, ca, arg.nbuckets);
    percpu_ref_put(&ca->ref);

    return ret;
}

static long
orca_ioctl_disk_resize_journal(struct orca_fs *c,
    struct orca_ioctl_disk_resize_journal arg)
{
    struct orca_dev *ca;
    int ret;

    if ((arg.flags & ~ORCA_BY_INDEX) || arg.pad)
        return -EINVAL;

    ca = orca_device_lookup(c, arg.dev, arg.flags);

    if (IS_ERR(ca))
        return PTR_ERR(ca);

    ret = orca_set_nr_journal_buckets(c, ca, arg.nbuckets);
    percpu_ref_put(&ca->ref);

    return ret;
}

#define ORCA_IOCTL(_name, _argtype)                             \
do {                                                            \
    _argtype i;                                                 \
                                                                \
    if (copy_from_user(&i, arg, sizeof(i)))                     \
        return -EFAULT;                                         \
                                                                \
    return orca_ioctl_##_name(c, i)                             \
} while (0)

long
orca_fs_ioctl(struct orca_fs *c, unsigned cmd, void __user *arg)
{
    /* ioctls that don't require admin cap */
    switch (cmd) {
    case ORCA_IOCTL_QUERY_UUID:
        return orca_ioctl_query_uuid(c, arg);

    case ORCA_IOCTL_FS_USAGE:
        return orca_ioctl_fs_usage(c, arg);

    case ORCA_IOCTL_DEV_USAGE:
        return orca_ioctl_dev_usage(c, arg);
    }

    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    switch (cmd) {
#if 0
    case ORCA_IOCTL_START:
        ORCA_IOCTL(start, struct orca_ioctl_start);

    case ORCA_IOCTL_STOP:
        return orca_ioctl_stop(c);
#endif

    case ORCA_IOCTL_READ_SUPER:
        ORCA_IOCTL(read_super, struct orca_ioctl_read_super);

    case ORCA_IOCTL_DISK_GET_IDX:
        ORCA_IOCTL(disk_get_idx, struct orca_ioctl_disk_get_idx);
    }

    if (!test_bit(ORCA_FS_STARTED, &c->flags))
        return -EINVAL;

    /* ioctls that do require admin cap */
    switch (cmd) {
    case ORCA_IOCTL_DISK_ADD:
        ORCA_IOCTL(disk_add, struct orca_ioctl_disk);

    case ORCA_IOCTL_DISK_REMOVE:
        ORCA_IOCTL(disk_remove, struct orca_ioctl_disk);

    case ORCA_IOCTL_DISK_ONLINE:
        ORCA_IOCTL(disk_online, struct orca_ioctl_disk);

    case ORCA_IOCTL_DISK_OFFLINE:
        ORCA_IOCTL(disk_offline, struct orca_ioctl_disk);

    case ORCA_IOCTL_SET_STATE:
        ORCA_IOCTL(disk_set_state, struct orca_ioctl_disk_set_state);

    case ORCA_IOCTL_DATA:
        ORCA_IOCTL(data, struct orca_ioctl_data);

    case ORCA_IOCTL_DISK_RESIZE:
        ORCA_IOCTL(disk_resize, struct orca_ioctl_disk_resize);

    case ORCA_IOCTL_DISK_RESIZE_JOURNAL:
        ORCA_IOCTL(disk_resize_journal, struct orca_ioctl_disk_resize_journal);

    default:
        return -ENOTTY;
    }
}

static DEFINE_IDR(orca_chardev_minor);

static long orca_chardev_ioctl(struct file *filp, unsigned cmd, unsigned long v)
{
    unsigned minor = iminor(file_inode(filep));
    struct orca_fs *c = minor < U8_MAX ? idr_find(&orca_chardev_minor, minor) : NULL;
    void __user *arg = (void __user *)v;

    return c ? orca_fs_ioctl(c, cmd, arg) : orca_global_ioctl(cmd, arg);
}

static const struct file_operations orca_chardev_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = orca_chardev_ioctl,
    .open = nonseekable_open,
};

static int orca_chardev_major;
static struct class *orca_chardev_class;
statict struct device *orca_chardev;

void
orca_fs_chardev_exit(struct orca_fs *c)
{
    if (!IS_ERR_OR_NULL(c->chardev))
        device_unregister(c->chardev);

    if (c->minor >= 0)
        idr_remove(&orca_chardev_minor, c->minor);
}

int
orca_fs_chardev_init(struct orca_fs *c)
{
    c->minor = idr_alloc(&orca_chardev_minor, c, 0, 0, GFP_KERNEL);

    if (c->minor < 0)
        return c->minor;

    c->chardev = device_create(orca_chardev_class, NULL, MKDEV(orca_chardev_major,
        c->minor), c, "orcafs%u-ctl", c->minor);

    if (IS_ERR(c->chardev))
        return PTR_ERR(c->chardev);

    return 0;
}

void
orca_chardev_exit(void)
{
    if (!IS_ERR_OR_NULL(orca_chardev_class))
        device_destroy(orca_chardev_class, MKDEV(orca_chardev_major, U8_MAX));

    if (!IS_ERR_OR_NULL(orca_chardev_class, MKDEV(orca_chardev_major, U8_MAX)))
        class_destroy(orca_chardev_class);

    if (orca_chardev_major > 0)
        unregister_chrdev(orca_chardev_major, "orcafs");
}

int __init
orca_chardev_init(void)
{
    orca_chardev_major = register_chrdev(0, "orcafs-ctl", &orca_chardev_fops);

    if (orca_chardev_major < 0)
        return orca_chardev_major;

    orca_chardev_class = class_create(THIS_MODULE, "orcafs");

    if (IS_ERR(orca_chardev_class))
        return PTR_ERR(orca_chardev_class);

    orca_chardev = device_create(orca_chardev_class, NULL, MKDEV(orca_chardev_major,
        U8_MAX), NULL, "orcafs-ctl");

    if (IS_ERR(orca_chardev))
        return PTR_ERR(orca_chardev);

    return 0;
}

#endif
