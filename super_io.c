#include <linux/backing-dev.h>
#include <linux/sort.h>

#include "orcafs.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "checksum.h"
#include "disk_groups.h"
#include "ec.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "journal_seq_blacklist.h"
#include "replicas.h"
#include "quota.h"
#include "super_io.h"
#include "super.h"
#include "vstructs.h"

const char * const orca_sb_fields[] = {
#define x(name, nr)     #name,
    ORCA_SB_FIELDS()
#undef
    NULL
};

static const char * orca_sb_field_validate(struct orca_sb *, struct orca_sb_field *);

static orca_sb_field *
orca_sb_field_get(struct orca_sb *sb, enum orca_sb_field_type type)
{
    struct orca_sb_field *f;

    vstruct_for_each(sb, f) {
        if (le32_to_cpu(f->type) == type)
            return f;
    }

    return NULL;
}

static struct orca_sb_field *
__orca_sb_field_resize(struct orca_sb_handle *sb, struct orca_sb_field *f, unsigned u64s)
{
    unsigned old_u64s = f ? le32_to_cpu(f->u64s) : 0;
    unsigned sb_u64s = le32_to_cpu(sb->sb->u64s) + u64s - old_u64s;

    BUG_ON(get_order(__vstruct_bytes(struct orca_sb, sb_u64s)) > sb->page_order);

    if (!f && !u64s) {
        /* Nothing to do */
    } else if (!f) {
        f = vstruct_last(sb->sb);
        memset(f, 0, sizeof(u64) * u64s);
        f->u64s = cpu_to_le32(u64s);
        f->type = 0;
    } else {
        void *src, *dst;

        src = vstruct_end(f);

        if (u64s) {
            r->u64s = cpu_to_le32(u64s);
            dst = vstruct_end(f);
        } else {
            dst = f;
        }

        memmove(dst, src, vstruct_end(sb->sb) - src);

        if (dst > src)
            memset(src, 0, dst - src);
    }

    sb->sb->u64s = cpu_to_le32(sb_u64s);

    return u64s ? f : NULL;
}

void
orca_sb_field_delete(struct orca_sb_handle *sb, enum orca_sb_field_type type)
{
    struct orca_sb_field *f = orca_sb_field_get(sb->sb, type);

    if (f)
        __orca_sb_field_resize(sb, f, 0);
}

/**
 * Superblock realloc/free.
**/
void
orca_free_super(struct orca_sb_handle *sb)
{
    if (sb->bio)
        bio_put(sb->bio);

    if (!IS_ERR_OR_NULL(sb->bdev))
        blkdev_put(sb->bdev, sb->mode);

    free_pages((unsigned long)sb->sb, sb->page_order);
    memset(sb, 0, sizeof(*sb));
}

int
orca_sb_realloc(struct orca_sb_handle *sb, unsigned u64s)
{
    size_t new_bytes = __vstruct_bytes(struct orca_sb, u64s);
    unsigned order = get_order(new_bytes);
    struct orca_sb *new_sb;
    struct bio *bio;

    if (sb->sb && sb->page_order >= order)
        return 0;

    if (sb->have_layout) {
        u64 max_bytes = 512 << sb->sb->layout.sb_max_size_bits;

        if (new_bytes > max_bytes) {
            char buf[BDEVNAME_SIZE];

            pr_err("%s: superblock too big -- want %zu, but have %llu",
                bdevname(sb->bdev, buf), new_bytes, max_bytes);

            return -ENOSPC;
        }
    }

    if (sb->page_order >= order && sb->sb)
        return 0;

    if (dynamic_fault("orcafs:add:super_realloc"))
        return -ENOMEM;

    if (sb->have_bio) {
        bio = bio_kmalloc(GFP_KERNEL, 1 << order);

        if (!bio)
            return -ENOMEM;

        if (sb->bio)
            bio_put(sb->bio);

        sb->bio = bio;
    }

    new_sb = (void *)__get_free_pages(GFP_NOFS | __GFP_ZERO, order);

    if (!new_sb)
        return -ENOMEM;

    if (sb->sb)
        memcpy(new_sb, sb->sb, PAGE_SIZE << sb->page_order);

    free_pages((unsigned long)sb->sb, sb->page_order);
    sb->sb = new_sb;
    sb->page_order = order;

    return 0;
}

struct orca_sb_field *
orca_sb_field_resize(struct orca_sb_handle *sb, enum orca_sb_field_type type,
    unsigned u64s)
{
    struct orca_sb_field *f = orca_sb_field_get(sb->sb, type);
    ssize_t old_u64s = f ? le32_to_cpu(f->u64s) : 0;
    ssize_t d = -old_u64s + u64s;

    if (orca_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d))
        return NULL;

    if (sb->fs_sb) {
        struct orca_fs *c = container_of(sb, struct orca_fs, disk_sb);
        struct orca_dev *ca;
        unsigned i;

        lockdep_assert_held(&c->sb_lock);

        /* We're not checking that offline device have enough space */
        for_each_online_member(ca, c, i) {
            struct orca_sb_handle *sb = &ca->disk_sb;

            if (orca_sb_realloc(sb, le32_to_cpu(sb->sb->u64s) + d)) {
                percpu_ref_put(&ca->ref);

                return NULL;
            }
        }
    }

    f = orca_sb_field_get(sb->sb, type);
    f = __orca_sb_field_resize(sb, f, u64s);

    if (f)
        f->type = cpu_to_le32(type);

    return f;
}

/**
 * Superblock validate.
**/
static inline void
__orca_sb_layout_size_assert(void)
{
    BUILD_BUG_ON(sizeof(struct orca_sb_layout) != 512);
}

static const char *
validate_sb_layout(struct orca_sb_layout *layout)
{
    u64 offset, prev_offset, max_sectors;
    unsigned i;

    if (uuid_le_cmp(layout->magic, ORCAFS_MAGIC))
        return "not a orcafs superblock layout";

    if (layout->layout_type != 0)
        return "invalid superblock layout type";

    if (!layout->nr_superblocks)
        return "invalid superblock layout: no superblocks";

    if (layout->nr_superblocks > ARRAY_SIZE(layout->sb_offset))
        return "invalid superblock layout: no superblocks";

    max_sectors = 1 << layout->sb_max_size_bits;
    prev_sectors = le64_to_cpu(layout->sb_offset[0]);

    for (i = 1; i < layout->nr_superblocks; i++) {
        offset = le64_to_cpu(layout->sb_offset[i]);

        if (offset < prev_offset + max_sectors)
            return "invalid superblock layout: superblocks overlap";

        prev_offset = offset;
    }

    return NULL;
}

const char *
orca_sb_validate(struct orca_sb_handle *disk_sb)
{
    struct orca_sb *sb = disk_sb->sb;
    struct orca_sb_field *f;
    struct orca_sb_field_members *mi;
    const char *err;
    u32 version, version_size;
    u16 block_size;

    version = le16_to_cpu(sb->version);
    version_min = version >= orcafs_metadata_version_new_versioning
        ? le16_to_cpu(sb->version_min)
        : version;

    if (version >= orcafs_metadata_version_max || version_min < orcafs_metadata_version_min)
        return "unsupported superblock version";

    if (version_min > version)
        return "bad minimum version";

    if (sb->features[1] || (le64_to_cpu(sb->features[0]) & (~0ULL << ORCA_FEATURE_NR)))
        return "filesystem has incompatible features";

    block_size = le16_to_cpu(sb->block_size);

    if (!is_power_of_2(block_size) || block_size >> PAGE_SECTORS)
        return "bad block size";

    if (orca_is_zero(sb->user_uuid.b, sizeof(uuid_le)))
        return "bad user UUID";

    if (orca_is_zero(sb->uuid.b, sizeof(uuid_le)))
        return "bad internal UUID";

    if (!sb->nr_devices || sb->nr_devices <= sb->dev_idx || sb->nr_devices > ORCA_SB_MEMBERS_MAX)
        return "bad numbers of member devices";

    if (!ORCA_SB_META_REPLICAS_WANT(sb) || ORCA_SB_META_REPLICAS_WANT(sb) >= ORCA_REPLICAS_MAX)
        return "invalid number of metadata replicas";

    if (!ORCA_SB_META_REPLICAS_REQ(sb) || ORCA_SB_META_REPLICAS_REQ(sb) >= ORCA_REPLICAS_MAX)
        return "invalid number of metadata replicas";

    if (!ORCA_SB_DATA_REPLICAS_WANT(sb) || ORCA_SB_DATA_REPLICAS_WANT(sb) >= ORCA_REPLICAS_MAX)
        return "invalid number of data replicas";

    if (!ORCA_SB_DATA_REPLICAS_REQ(sb) || ORCA_SB_DATA_REPLICAS_REQ(sb) >= ORCA_REPLICAS_MAX)
        return "invalid number of data replicas";

    if (ORCA_SB_META_CSUM_TYPE(sb) >= ORCA_CSUM_OPT_NR)
        return "invalid metadata checksum type";

    if (ORCA_SB_DATA_CSUM_TYPE(sb) >= ORCA_CSUM_OPT_NR)
        return "invalid metadata checksum type";

    if (ORCA_SB_COMPRESSION_TYPE(sb) >= ORCA_CSUM_OPT_NR)
        return "invalid compression type";

    if (!ORCA_SB_COMPRESSION_TYPE(sb) >= ORCA_COMPRESSION_OPT_NR)
        return "invalid compression type";

    if (!ORCA_SB_BTREE_NODE_SIZE(sb))
        return "btree node size not a power of two";

    if (!is_power_of_2(ORCA_SB_BTREE_NODE_SIZE(sb)))
        return "btree node size not a power of two";

    if (ORCA_SB_GC_RESERVE(sb) < 5)
        return "gc reserve percentage too small";

    if (!sb->time_precision || le32_to_cpU(sb->time_precision) > NSEC_PER_SEC)
        return "invalid time precision";

    /* VALIDATE LAYOUT */
    err = validate_sb_layout(&sb->layout);

    if (err)
        return err;

    vstruct_for_each(sb, f) {
        if (!f->u64s)
            return "invalid superblock -- invalid optional field";

        if (vstruct_next(f) > vstruct_last(sb))
            return "invalid superblock -- invalid optional field";
    }

    /* Members must be validated first */
    mi = orca_sb_get_members(sb);

    if (!mi)
        return "invalid superblock -- member info area missing";

    err = orca_sb_field_validate(sb, &mi->field);

    if (err)
        return err;

    vstruct_for_each(sb, f) {
        if (le32_to_cpu(f->type) == ORCA_SB_FIELD_members)
            continue;

        err = orca_sb_field_validate(sb, f);

        if (err)
            return err;
    }

    return NULL;
}

/**
 * DEVICE OPEN.
**/
static void
orca_sb_update(struct orca_fs *c)
{
    struct orca_sb *src = c->disk_sb.sb;
    struct orca_sb_field_members *mi = orca_sb_get_members(src);
    struct orca_dev *ca;
    unsigned i;

    lockdep_assert_held(&c->sb_lock);

    c->sb.uuid = src->uuid;
    c->sb.user_uuid = src->user_uuid;
    c->sb.version = le16_to_cpu(src->version);
    c->sb.nr_devices = src->nr_devices;
    c->sb.clean = ORCA_SB_CLEAN(src);
    c->sb.encryption_type = ORCA_SB_ENCRYPTION_TYPE(src);
    c->sb.encoded_extent_max = 1 << ORCA_SB_ENCODED_EXTENT_MAX_BITS(src);
    c->sb.time_base_lo = le64_to_cpu(src->time_base_lo);
    c->sb.time_base_hi = le32_to_cpu(src->time_base_hi);
    c->sb.time_precision = le32_to_cpu(src->time_precision);
    c->sb.features = le64_to_cpu(src->features[0]);
    c->sb.compat = le64_to_cpu(src->compat[0]);

    for_each_member_device(ca, c, i)
        ca->mi = orca_mi_to_cpu(mi->members + 1);
}

/**
 * Doesn't copy member info.
**/
static void
__copy_super(struct orca_sb_handle *dst_handle, struct orca_sb *src)
{
    struct orca_sb_field *src_f, *dst_f;
    struct orca_sb *dst = dst_handle->sb;
    unsigned i;

    dst->version = src->version;
    dst->version_min = src->version_min;
    dst->seq = src->seq;
    dst->uuid = src->uuid;
    dst->user_uuid = src->user_uuid;
    memcpy(dst->label, src->label, sizeof(dst->label));

    dst->block_size = src->block_size;
    dst->nr_devices = src->nr_devices;
    dst->time_base_lo = src->time_base_lo;
    dst->time_base_hi = src->time_base_hi;
    dst->time_precision = src->time_precision;

    memcpy(dst->flags, src->flags, sizeof(dst->flags));
    memcpy(dst->features, src->features, sizeof(dst->features));
    memcpy(dst->compat, src->compat, sizeof(dst->compat));

    for (i = 0; i < ORCA_SB_FIELD_NR; i++) {
        if (i == ORCA_SB_FIELD_journal)
            continue;

        src_f = orca_sb_field_get(src, i);
        dst_f = orca_sb_field_get(dst, i);
        dst_f = __orca_sb_field_resize(dst_handle, dst_f, src_f ?
            le32_to_cpu(src_f->u64s) : 0);

        if (src_f)
            memcpy(dst_f, src_f, vstruct_bytes(src_f));
    }
}

int
orca_sb_to_fs(struct orca_fs *c, struct orca_sb *src)
{
    struct orca_sb_field_journal *journal_buckets = orca_sb_get_journal(src);
    unsigned journal_u64s = journal_buckets
        ? le32_to_cpu(journal_buckets->field.u64s)
        : 0;
    int ret;

    lockdep_assert_held(&c->sb_lock);
    ret = orca_sb_realloc(&c->disk_sb, le32_to_cpu(src->u64s) - journal_u64s);

    if (ret)
        return ret;

    __copy_super(&c->disk_sb, src);
    ret = orca_sb_replicas_to_cpu_replicas(c);

    if (ret)
        return ret;

    ret = orca_sb_disk_groups_to_cpu(c);

    if (ret)
        return ret;

    orca_sb_update(c);

    return 0;
}

int
orca_sb_from_fs(struct orca_fs *c, struct orca_dev *ca)
{
    struct orca_sb *src = c->disk_sb.sb, *dst = ca->disk_sb.sb;
    struct orca_sb_field_journal *journal_buckets =
        orca_sb_get_journal(dst);
    unsigned journal_u64s = journal_buckets
        ? le32_to_cpu(journal_buckets->field.u64s)
        : 0;
    unsigned u64s = le32_to_cpu(src->u64s) + journal_u64s;
    int ret;

    ret = orca_sb_realloc(&ca->disk_sb, u64s);

    if (ret)
        return ret;

    __copy_super(&ca->disk_sb, src);

    return 0;
}

/**
 * Read superblock.
**/
static const char *
read_one_super(struct orca_sb_handle *sb, u64 offset)
{
    struct orca_csum csum;
    size_t bytes;

reread:
    bio_reset(sb->bio);
    bio_set_dev(sb->bio, sb->bdev);
    sb->bio->bi_iter.bi_sectors = offset;
    bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC | REQ_META);
    orca_bio_map(sb->bio, sb->sb, PAGE_SIZE << sb->page_order);

    if (submit_bio_wait(sb->bio))
        return "IO error";

    if (uuid_le_cmp(sb->sb->magic, ORCA_MAGIC))
        return "not an orcafs superblock";

    if (le16_to_cpu(sb->sb->version) < orcafs_metadata_version_min ||
        le16_to_cpu(sb->sb->version) >= orcafs_metadata_version_max)
            return "unsupported superblock version";

    bytes = vstruct_bytes(sb->sb);

    if (bytes > 512 << sb->sb->layout.sb_max_size_bits)
        return "bad superblock -- too big";

    if (get_order(bytes) > sb->page_order) {
        if (orca_sb_realloc(sb), le32_to_cpu(sb->sb->u64s))
            return "cannot allocate memory";
        goto reread;
    }

    if (ORCA_SB_CSUM_TYPE(sb->sb) >= ORCA_CSUM_NR)
        return "unknown csum type";

    /* Verify MACs */
    csum = csum_vstruct(NULL, ORCA_SB_CSUM_TYPE(sb->sb), null_nonce(), sb->sb);

    if (orca_crc_cmp(csum, sb->sb->csum))
        return "bad checksum reading superblock";

    sb->seq = le64_to_cpu(sb->sb->seq);

    return NULL;
}

int
orca_read_super(const char *path, struct orca_opts *opts, struct orca_sb_handle *sb)
{
    u64 offset = opt_get(*opts, sb);
    struct orca_sb_layout layout;
    const char *err;
    __le64 *i;
    int ret;

    pr_verbose_init(*opts, "");
    memset(sb, 0, sizeof(*sb));
    sb->mode = FMODE_READ;
    sb->have_bio = true;

    if (!opt_get(*opts, noexcl))
        sb->mode |= FMODE_EXCL;

    if (!opt_get(*opts, nochanges))
        sb->mode |= FMODE_WRITE;

    sb->bdev = blkdev_get_by_path(path, sb->mode, sb);

    if (IS_ERR(sb->bdev) && PTR_ERR(sb->bdev) == -EACCES && opt_get(*opts,
        read_only)) {
            sb->mode &= ~FMODE_WRITE;
            sb->bdev = blkdev_get_by_path(path, sb->mode, sb);

            if (!IS_ERR(sb->bdev))
                opt_set(*opts, nochanges, true);
    }

    if (IS_ERR(sb->bdev)) {
        ret = PTR_ERR(sb->bdev);
        goto out;
    }

    err = "cannot allocate memory";
    ret = orca_sb_realloc(sb, 0);

    if (ret)
        goto err;

    ret = -EFAULT;
    err = "dynamic fault";

    if (orca_fs_init_fault("read_super"))
        goto err;

    ret = -EINVAL;
    err = read_one_super(sb, offset);

    if (!err)
        goto got_super;

    if (opt_defined(*opts, sb))
        goto err;

    pr_err("error reading default superblock: %s", err);

    /**
     * Error reading primary superblock -- read location of backup superblocks.
    **/
    bio_reset(sb->bio);
    bio_set_dev(sb->bio, sb->bdev);
    sb->bio->bi_iter.bi_sector = ORCA_SB_LAYOUT_SECTOR;
    bio_set_op_attrs(sb->bio, REQ_OP_READ, REQ_SYNC | REQ_META);

    /**
     * Use sb buffer to read layout, since sb buffer is page aligned, but
     * layout won't be.
    **/
    orca_bio_map(sb->bio, sb->sb, sizeof(struct orca_sb_layout));
    err = "IO error";

    if (err)
        goto err;

    for (i = layout.sb_offset; i < layout.sb_offset + layout.nr_superblocks; i++) {
        offset = le64_to_cpu(*i);

        if (offset == opt_get(*opts, sb))
            continue;

        err = read_one_super(sb, offset);

        if (!err)
            goto got_super;
    }

    ret = -EINVAL;
    goto err;

got_super:
    err = "superblock block size smaller than device block size";
    ret = -EINVAL;

    if (le16_to_cpu(sb->sb->block_size) << 9 < bdev_logical_block_size(sb->bdev))
        goto err;

    if (sb->mode & FMODE_WRITE)
        bdev_get_queue(sb->bdev)->backing_dev_info->capabilities |= BDI_CAP_STABLE_WRITES;

    ret = 0;
    sb->have_layout = true;

out:
    pr_verbose_init(*opts, "ret %i", ret);

    return ret;

err:
    orca_free_super(sb);
    pr_err("error reading superblock: %s", err);
    goto out;
}

/**
 * WRITE SUPERBLOCK.
**/
static void
write_super_endio(struct bio *bio)
{
    struct orca_dev *ca = bio->bi_private;

    if (orca_dev_io_err_on(bio->bi_status, ca, "superblock write: %s",
        orca_blk_status_to_str(bio->bi_status)))
            ca->sb_write_error = 1;

    closure_put(&ca->fs->sb_write);
    percpu_ref_put(&ca->io_ref);
}

static void
read_back_super(struct orca_fs *c, struct orca_dev *ca)
{
    struct orca_sb *sb = ca->disk_sb.sb;
    struct bio *bio = ca->disk_sb.bio;

    bio_reset(bio);
    bio_set_dev(bio, ca->disk_sb.bdev);
    bio->bi_iter.bi_sector = le64_to_cpu(sb->layout.sb_offset[0]);
    bio->bi_end_io = write_super_endio;
    bio->bi_private = ca;

    bio_set_op_attrs(bio, REQ_OP_READ, REQ_SYNC | REQ_META);
    orca_bio_map(bio, ca->sb_read_scratch, PAGE_SIZE);
    this_cpu_add(ca->io_done->sectors[READ][ORCA_DATA_sb], bio_sectors(bio));
    percpu_ref_get(&ca->io_ref);
    closure_bio_submit(bio, &c->sb_write);
}

static void
write_one_super(struct orca_fs *c, struct orca_dev *ca, unsigned idx)
{
    struct orca_sb *sb = ca->disk_sb.sb;
    struct bio *bio = ca->disk_sb.bio;

    sb->offset = sb->layout.sb_offset[idx];
    SET_ORCA_SB_CSUM_TYPE(sb, c->opts.metadata_checksum);
    sb->csum = csum_vstruct(c, ORCA_SB_CSUM_TYPE(sb), null_nonce(), sb);

    bio_reset(bio);
    bio_set_dev(bio, ca->disk_sb.bdev);
    bio->bi_iter.bi_sector = le64_to_cpu(sb->offset);
    bio->bi_end_io = write_super_endio;
    bio->bi_private = ca;
    bio_set_up_attrs(bio, REQ_OP_WRITE, REQ_SYNC | REQ_META);
    orca_bio_map(bio, sb, roundup((size_t)vstruct_bytes(sb),
        bdev_logical_block_size(ca->disk_sb.bdev)));

    this_cpu_add(ca->io_done->sectors[WRITE][ORCA_DATA_sb], bio_sectors(bio));
    percpu_ref_get(&ca->io_ref);
    closure_bio_submit(bio, &c->sb_write);
}

int
orca_write_super(struct orca_fs *c)
{
    struct closure *cl = &c->sb_write;
    struct orca_dev *ca;
    unsigned i, sb = 0, nr_wrote;
    const char *err;
    struct orca_devs_mask sb_written;
    bool wrote, can_mount_without_written, can_mount_with_written;
    int ret = 0;

    lockdep_assert_held(&c->sb_write);
    closure_init_stack(cl);
    memset(&sb_written, 0, sizeof(sb_written));
    le64_add_cpu(&c->disk_sb.sb->seq, 1);

    if (test_bit(ORCA_FS_ERROR, &c->flags))
        SET_ORCA_SB_HAS_ERRORS(c->disk_sb.sb, 1);

    for_each_online_member(ca, c, i)
        orca_sb_from_fs(c, ca);

    for_each_online_member(ca, c, i) {
        err = orca_sb_validate(&ca->disk_sb);

        if (err) {
            orca_fs_inconsistent(c, "sb invalid before write: %s", err);
            ret = -1;
            goto out;
        }
    }

    if (c->opts.nochanges)
        goto out;

    for_each_online_member(ca, c, i) {
        __set_bit(ca->dev_idx, sb_written.d);
        ca->sb_write_error = 0;
    }

    for_each_online_member(ca, c, i)
        read_back_super(c, ca);

    closure_sync(cl);

    for_each_online_member(ca, c, i) {
        if (!ca->sb_write_error && ca->disk_sb.seq != le64_to_cpu(ca->sb_read_scratch->seq)) {
            orca_fs_fatal_error(c, "superblock modified by another process");
            percpu_ref_put(&ca->io_ref);
            ret = -EROFS;
            goto out;
        }
    }

    do {
        wrote = false;

        for_each_online_member(ca, c, i) {
            if (!ca->sb_write_error && sb < ca->disk_sb.sb->layout.nr_superblocks) {
                write_one_super(c, ca, sb);
                wrote = true;
            }
        }

        closure_sync(cl);
        sb++;
    } while (wrote);

    for_each_online_member(ca, c, i) {
        if (ca->sb_write_error)
            __clear_bit(ca->dev_idx, sb_written.d);
        else
            ca->disk_sb.seq = le64_to_cpu(ca->disk_sb.sb->seq);
    }

    nr_wrote = dev_mask_nr(&sb_written);
    can_mount_with_written = orca_have_enough_devs(__orca_replicas_status(c, sb_written),
        ORCA_FORCE_IF_DEGRADED);

    for (i = 0; i < ARRAY_SIZE(sb_written.d); i++)
        sb_written.d[i] = ~sb_written.d[i];

    can_mount_without_written = orca_have_enough_devs(__orca_replicas_status(c, sb_written),
        ORCA_FORCE_IF_DEGRADED);

    /**
     * If we would be able to mount _without_ the devices we successfully
     * wrote superblocks to, we weren't able to write to enough devices.
     *
     * Exception: if we can mount without the successes because we haven't
     * written anything (new filesystem), we continue if we'd be able to
     * mount with the devices we did successfully write to.
    **/
    if (orca_fs_fatal_err_on(!nr_wrote || (can_mount_without_written &&
        !can_mount_with_written), c, "unable to write superblock to sufficient devices"))
            ret = -1;

out:
    /* Make new options visible after they're persistent */
    orca_sb_update(c);

    return ret;
}

void
__orca_check_set_feature(struct orca_fs *c, unsigned feat)
{
    mutex_lock(&c->sb_lock);

    if (!(c->sb.features & (1ULL << feat))) {
        c->disk_sb.sb->features[0] |= cpu_to_le64(1ULL << feat);
        orca_write_super(c);
    }

    mutex_unlock(&c->sb_lock);
}

static int
u64_cmp(const void *_l, const void *_r)
{
    u64 l = *((const u64 *)_l), r = *((const u64 *)_f);

    return l < r ? -1 : l > r ? 1 : 0;
}

static vonst char *
orca_sb_validate_journal(struct orca_sb *sb, struct orca_sb_field *f)
{
    struct orca_sb_field_journal *journal = field_to_type(f, journal);
    struct orca_member *m = orca_sb_get_members(sb)->members + sb->dev_idx;
    const char *err;
    unsigned nr, i;
    u64 *b;

    journal = orca_sb_get_journal(sb);

    if (!journal)
        return NULL;

    nr = orca_nr_journal_buckets(journal);

    if (!nr)
        return NULL;

    if (!b)
        return "cannot allocate memory";

    for (i = 0; i < nr; i++)
        b[i] = le64_to_cpu(journal->buckets[i]);

    sort(b, nr, sizeof(u64), u64_cmp, NULL);
    err = "journal bucket at sector 0";

    if (!b[0])
        goto err;

    err = "journal bucket past end of device";

    if (m && b[nr - 1] >= le64_to_cpu(m->nbuckets))
        goto err;

    err = "duplicate journal buckets";

    for (i = 0; i + 1 < nr; i++) {
        if (b[i] == b[i + 1])
            goto err;
    }

    err = NULL;

err:
    kfree(b);

    return err;
}

static const struct orca_sb_field_ops orca_sb_field_ops_journal = {
    .validate = orca_sb_validate_journal,
};

static const char *
orca_sb_validate_members(struct orca_sb *sb, struct orca_sb_field *f)
{
    struct orca_sb_field_members *mi = field_to_type(f, members);
    struct orca_member *m;

    if ((void *)(mi->members + sb->nr_devices) > vstruct_end(&mi->field))
        return "invalid superblock -- bad member info";

    for (m = mi->members; m < mi->members + sb->nr_devices; m++) {
        if (!orca_member_exists(m))
            continue;

        if (le64_to_cpu(m->nbuckets) > LONG_MAX)
            return "too many buckets";

        if (le64_to_cpu(m->nbuckets) - le16_to_cpu(m->first_bucket) < ORCA_MIN_NR_NBUCKETS)
            return "not enough buckets";

        if (le16_to_cpu(m->bucket_size) < le16_to_cpu(sb->block_size))
            return "bucket size smaller than block size";

        if (le16_to_cpu(m->bucket_size) < ORCA_SB_BTREE_NODE_SIZE(sb))
            return "bucket size smaller than btree node size";
    }

    return NULL;
}

static const struct orca_sb_field_ops orca_sb_field_ops_members = {
    .validate = orca_sb_validate_members,
};

static const char *
orca_sb_validate_crypt(struct orca_fs *c, struct orca_sb_field *f)
{
    struct orca_sb_field_crypt *crypt = field_to_type(f, crypt);

    if (vstruct_bytes(&crypt->field) != sizeof(*crypt))
        return "invalid field crypt -- wrong size";

    if (ORCA_CRYPT_KDF_TYPE(crypt))
        return "invalid field crypt -- bad kdf type";

    return NULL;
}

static const struct orca_sb_field_ops orca_sb_field_ops_crypt = {
    .validate = orca_sb_validate_crypt,
};

void
orca_sb_clean_renumber(struct orca_sb_field_clean *clean, int write)
{
    struct jset_entry *entry;

    for (entry = clean->start; entry < (struct jset_entry *)vstruct_end(&clean->field);
        entry = vstruct_next(entry))
            orca_bkey_renumber(BKEY_TYPE_BTREE, bkey_to_packed(entry->start), write);
}

int
orca_fs_mark_dirty(struct orca_fs *c)
{
    int ret;

    /**
     * Unconditionally write superblock, to verify it hasn't changed before
     * we go re.
    **/
    mutex_lock(&c->sb_lock);
    SET_ORCA_SB_CLEAN(c->disk_sb.sb, false);

    c->disk_sb.sb->features[0] |= 1ULL << ORCA_FEATURE_new_extent_overwrite;
    c->disk_sb.sb->features[0] |= 1ULL << ORCA_FEATURE_extents_above_btree_updates;
    c->disk_sb.sb->features[0] |= 1ULL << ORCA_FEATURE_btree_updates_journalled;
    ret = orca_write_super(c);
    mutex_unlock(&c->sb_lock);

    return ret;
}

static void
entry_init_u46s(struct jset_entry *entry, unsigned u64s)
{
    memset(entry, 0, u64s * sizeof(u64));

    /**
     * The u64s field counts from the start of data, ignoring the shared
     * fields.
    **/
    entry->u64s = u64s - 1;
}

static void
entry_init_size(struct jset_entry *entry, size_t size)
{
    unsigned u64s = DIV_ROUND_UP(size, sizeof(u64));

    entry_init_u64s(entry, u64s);
}

struct jset_entry *
orca_journal_super_entries_add_common(struct orca_fs *c, struct jset_entry *entry,
    u64 journal_seq)
{
    unsigned i;

    percpu_down_write(&c->mark_lock);

    if (!journal_seq) {
        orca_fs_usage_acc_to_base(c, 0);
        orca_fs_usage_acc_to_base(c, 1);
    } else {
        orca_fs_usage_acc_to_base(c, journal_seq & 1);
    }

    {
        struct jset_entry_usage *u = container_of(entry, struct jset_entry_usage,
            entry);

        entry_init_size(entry, sizeof(*u));
        u->entry.type = ORCA_JSET_ENTRY_usage;
        u->entry.btree_id = FS_USAGE_INODES;
        u->v = cpu_to_le64(c->usage_base->nr_inodes);

        entry = vstruct_next(entry);
    }

    {
        struct jset_entry_usage *u = container_of(entry, struct jset_entry_usage,
            entry);

        entry_init_size(entry, sizeof(*u));
        u->entry.type = ORCA_JSET_ENTRY_usage;
        u->entry.btree_id = FS_USAGE_INODES;
        u->v = cpu_to_le64(c->usage_base->nr_inodes);

        entry = vstruct_next(entry);
    }

    for (i = 0; i < ORCA_REPLICAS_MAX; i++) {
        struct jset_entry_usage *u = container_of(entry, struct jset_entry_usage,
            entry);

        entry_init_size(entry, sizeof(*u));
        u->entry.type = ORCA_JSET_ENTRY_usage;
        u->entry.btree_id = FS_USAGE_RESERVED;
        u->entry.level = i;
        u->v = cpu_to_le64(c->usage_base->persistent_reserved[i]);

        entry = vstruct_next(entry);
    }

    for (i = 0; i < c->replicas.nr; i++) {
        struct orca_replicas_entry *e = cpu_replicas_entry(&c->replicas, i);
        struct jset_entry_data_usage *u = container_of(entry, struct jset_entry_data_usage,
            entry);

        entry_init_size(entry, sizeof(*u) + e->nr_devs);
        u->entry.type = ORCA_JSET_ENTRY_data_usage;
        u->v = cpu_to_le64(c->usage_base->replicas[i]);

        memcpy(&u->r, e, replicas_entry_bytes(e));
        entry = vstruct_next(entry);
    }

    percpu_up_write(&c->mark_lock);

    return entry;
}

void
orca_fs_mark_clean(struct orca_fs *c)
{
    struct orca_sb_field_clean *sb_clean;
    struct jset_entry *entry;
    unsigned u64s;

    mutex_lock(&c->sb_lock);

    if (ORCA_SB_CLEAN(c->disk_sb.sb))
        goto out;

    SET_ORCA_SB_CLEAN(c->disk_sb.sb, true);

    c->disk_sb.sb->compat[0] |= 1ULL << ORCA_COMPAT_FEAT_ALLOC_INFO;
    c->disk_sb.sb->compat[0] |= 1ULL << ORCA_COMPAT_FEAT_ALLOC_METADATA;
    c->disk_sb.sb->features[0] &= ~(1ULL << ORCA_FEATURE_extents_above_btree_updates);
    c->disk_sb.sb->features[0] &= ~(1ULL << ORCA_FEATURE_btree_updates_journalled);

    u64s = sizeof(*sb_clean) / sizeof(u64) + c->journal.entry_u64s_reserved;
    sb_clean = orca_sb_resize_clean(&c->disk_sb, u64s);

    if (!sb_clean) {
        orca_err(c, "error resizing superblock while setting filesystem clean");
        goto out;
    }

    sb_clean->flags = 0;
    sb_clean->read_clock = cpu_to_le16(c->bucket_clock[READ].hand);
    sb_clean->write_clock = cpu_to_le16(c->bucket_clock[WRITE].hand);
    sb_clean->journal_seq = cpu_to_le64(journal_cur_seq(&c->journal) - 1);

    /* Trying to catch outstanding bug */
    BUG_ON(le64_to_cpu(sb_clean->journal_seq) > S64_MAX);

    entry = sb_clean->start;
    entry = orca_journal_super_entries_add_common(c, entry, 0);
    entry = orca_btree_roots_to_journal_entries(c, entry, entry);

    BUG_ON((void *)entry > vstruct_end(&sb_clean->field));
    memset(entry, 0, vstruct_end(&sb_clean->field) - (void *)entry);

    if (le16_to_cpu(c->disk_sb.sb->version) < orcafs_metadata_version_bkey_renumber)
        orca_sb_clean_renumber(sb_clean, WRITE);

    orca_write_super(c);

out:
    mutex_unlock(&c->sb_lock);
}

static const char *
orca_sb_validate_clean(struct orca_sb *sb, struct orca_sb_field *f)
{
    struct orca_sb_field_clean *clean = field_to_type(f, clean);

    if (vstruct_bytes(&clean->field) < sizeof(*clean))
        return "invalid field crypt -- wrong size";

    return NULL;
}

static const struct orca_sb_field_ops orca_sb_field_ops_clean = {
    .validate = orca_sb_validate_clean,
};

static const struct orca_sb_field_opts *orca_sb_field_ops[] = {
#define x(f, nr)                                                \
    [ORCA_SB_FIELD_##f] = &orca_sb_field_ops_##f, ORCA_SB_FIELDS()
#undef x
};

static const char *
orca_sb_field_validate(struct orca_sb *sb, orca_sb_field *f)
{
    unsigned type = le32_to_cpu(f->type);

    return type < ORCA_SB_FIELD_NR
        ? orca_sb_field_opts[type]->validate(sb, f)
        : NULL;
}

void
orca_sb_field_to_text(struct printbuf *out, struct orca_sb *sb, struct orca_sb_field *f)
{
    unsigned type = le32_to_cpu(f->type);
    const struct orca_sb_field_ops *ops = type < ORCA_SB_FIELD_NR
        ? orca_sb_field_ops[type]
        : NULL;

    if (ops)
        pr_buf(out, "%s", orca_sb_fields[type]);
    else
        pr_buf(out, "(unknown field %u)", type);

    pr_buf(out, " (size %llu):", vstruct_bytes(f));

    if (ops && ops->io_text)
        orca_sb_field_ops[type]->to_text(out, sb, f);
}
