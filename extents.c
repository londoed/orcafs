#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "bkey_methods.h"
#include "btree_gc.h"
#include "btree_io.h"
#include "btree_iter.h"
#include "buckets.h"
#include "checksum.h"
#include "debug.h"
#include "disk_groups.h"
#include "error.h"
#include "extents.h"
#include "inode.h"
#include "journal.h"
#include "replicas.h"
#include "super.h"
#include "super_io.h"
#include "util.h"

static unsigned orca_crc_field_size_max[] = {
    [ORCA_EXTENT_ENTRY_crc32] = CRC32_SIZE_MAX,
    [ORCA_EXTENT_ENTRY_crc64] = CRC64_SIZE_MAX,
    [ORCA_EXTENT_ENTRY_crc128] = CRC128_SIZE_MAX,
};

static void orca_extent_crc_pack(union orca_extent crc *,
    struct orca_extent_crc_unpacked, enum orca_extent_entry_type);

static struct orca_dev_io_failures *
dev_io_failures(struct orca_io_failures *f, unsigned dev)
{
    struct orca_dev_io_features *i;

    for (i = f->devs; i < f->devs + f->nr; i++) {
        if (i->dev == dev)
            return i;
    }

    return NULL;
}

void
orca_mark_to_failure(struct orca_io_failures *failed, struct extent_ptr_decoded *p)
{
    struct orca_dev_io_features *f = dev_io_failures(failed, p->ptr.dev);

    if (!f) {
        BUG_ON(failed->nr >= ARRAY_SIZE(failed->devs));
        f = &failed->devs[failed->nr++];

        f->dev = p->ptr.dev;
        f->idx = p->idx;
        f->nr_failed = 1;
        f->nr_retries = 0;
    } else if (p->idx != f->idx) {
        f->idx = p->idx;
        f->nr_failed = 1;
        f->nr_retries = 0;
    } else {
        f->nr_failed++;
    }
}

/**
 * Returns true if pi is better than p2.
**/
static inline bool
ptr_better(struct orca_fs *c, const struct extent_ptr_decoded p1,
    const struct extent_ptr_decoded p2)
{
    if (likely(!p1.idx && !p2.idx)) {
        struct orca_dev *dev1 = orca_dev_bkey_exists(c, p1.ptr.dev);
        struct orca_dev *dev2 = orca_dev_bkey_exists(c, p2.ptr.dev);

        u64 l1 = atomic64_read(&dev1->cur_latency[READ]);
        u64 l2 = atomic64_read(&dev2->cur_latency[READ]);

        /* Pick at random, biased in favor of the faster device */
        return orca_rand_range(l1 + l2) > l1;
    }

    if (orca_force_reconstruct_read)
        return p1.idx > p2.idx;

    return p1.idx < p2.idx;
}

/**
 * This picks a non-stale pointer, preferably from a device other than
 * @avoid. Avoid can be NULL, meaning pick any. If there are no non-stale
 * pointers to other devices, it will still pick a pointer from avoid.
**/
int
orca_bkey_pick_read_device(struct orca_fs *c, struct bkey_s_c k,
    struct orca_io_failures *failed, struct extent_ptr_decoded *pick)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    struct orca_dev_io_failures *f;
    struct orca_dev *ca;
    int ret = 0;

    if (k.k->type == KEY_TYPE_error)
        return -EIO;

    bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
        ca = orca_dev_bkey_exists(c, p.ptr.dev);

        /**
         * If there are any dirty pointers it's an error if we can't
         * read.
        **/
        if (!ret && !p.ptr.cached)
            ret = -EIO;

        if (p.ptr.cached && ptr_stale(ca, &p.ptr))
            continue;

        f = failed ? dev_io_failures(failed, p.ptr.dev) : NULL;

        if (f)
            p.idx = f->nr_failed < f->nr_retries ? f->idx : f->idx + 1;

        if (!p.idx && !orca_dev_is_readable(ca))
            p.idx++;

        if (orca_force_reconstruct_read && !p.idx && p.has_ec)
            p.idx++;

        if (p.idx >= (unsigned)p.has_ec + 1)
            continue;

        if (ret > 0 && !ptr_better(c, p, *pick))
            continue;

        *pick = p;
        ret = 1;
    }

    return ret;
}

const char *
orca_btree_ptr_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    if (bkey_val_u64s(k.k) > BKEY_BTREE_PTR_VAL_U64s_MAX)
        return "value too big";

    return orca_bkey_ptrs_invalid(c, k);
}

void
orca_btree_ptr_debugcheck(struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const struct orca_extent_ptr *ptr;
    const char *err;
    char buf[160];
    struct bucket_mark mark;
    struct orca_dev *ca;

    if (!test_bit(ORCA_FS_INITIAL_GC_DONE, &c->flags))
        return;

    if (!percpu_down_read_trylock(&c->mark_lock))
        return;

    bkey_for_each_ptr(ptrs, ptr) {
        ca = orca_dev_bkey_exists(c, ptr->dev);
        mark = ptr_bucket_mark(ca, ptr);
        err = "stale";

        if (mark.data_type != ORCA_DATA_btree || mark.dirty_sectors <
            c->opts.btree_node_size)
                goto err;
    }

out:
    percpu_up_read(&c->mark_lock);
    return;

err:
    orca_fs_inconsistent(c, "%s btree pointer %s: bucket %zi gen %i mark %08x",
        err, (orca_bkey_val_to_text(&PBUF(buf), c, k), buf), PTR_BUCKET_NR(ca, ptr),
        mark.gen, (unsigned)mark.v.counter);

    goto out;
}

void
orca_btree_ptr_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    orca_bkey_ptrs_to_text(out, c, k);
}

void
orca_btre_ptr_v2_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_s_c_btree_ptr_v2 bp = bkey_s_c_to_btree_ptr_v2(k);

    pr_buf(out, "seq %llx sectors %u written %u min_key", le64_to_cpu(bp.v->seq),
        le16_to_cpu(bp.v->sectors), le16_to_cpu(bp.v->sectors_written));

    orca_bpos_to_text(out, bp.v->min_key);
    pr_buf(out, " ");
    orca_bkey_ptrs_to_text(out, c, k);
}

void
orca_btree_ptr_v2_compat(enum btree_id btree_id, unsigned version,
    unsigned big_endian, int write, struct bkey_s k)
{
    struct bkey_s_btree_ptr_v2 bp = bkey_s_to_btree_ptr_v2(k);

    compat_bpos(0, btree_id, version, big_endian, write, &bp.v->min_key);

    if (version < orcafs_metadata_version_inode_btree_change &&
        btree_node_type_is_extents(btree_id) && bkey_cmp(bp.v->min_key, POS_MIN))
            bp.v->min_key = write ? bkey_predecessor(bp.v->min_key)
            : bkey_successor(bp.v->min_key);
}

const char *
orca_extent_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    return orca_bkey_ptrs_invalid(c, k);
}

void
orca_extent_debugcheck(struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_s_c_extent e = bkey_s_c_to_extent(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    char buf[160];

    if (!test_bit(JOURNAL_REPLAY_DONE, &c->journal.flags) ||
        !test_bit(ORCA_FS_INITIAL_GC_DONE, &c->flags))
            return;

    if (!percpu_down_read_trylock(&c->mark_lock))
        return;

    extent_for_each_ptr_decode(e, p, entry) {
        struct orca_dev *ca = orca_dev_bkey_exists(c, p.ptr.dev);
        struct bucket_mark mark = ptr_bucket_mark(ca, &p.ptr);
        unsigned stale = gen_after(mark.gen, p.ptr.gen);
        unsigned disk_sectors = ptr_disk_sectors(p);
        unsigned mark_sectors = p.ptr.cached ?
            mark.cached_sectors : mark.dirty_sectors;

        orca_fs_inconsistent_on(stale && !p.ptr.cached, c,
            "stale dirty pointer (ptr gen %u bucket %u)",
            p.ptr.gen, mark.gen);

        orca_fs_inconsistent_on(stale > 96, c, "key too stale: %i", stale);

        orca_fs_inconsistent_on(!stale && (mark.data_type != ORCA_DATA_user ||
            mark_sectors < disk_sectors), c, "extent pointer not marked: %s\n"
            "type %u sectors %u < %u", (orca_bkey_val_to_text(&PBUF(buf), c, e.s_c), buf),
            mark.data_type, mark_sectors, disk_sectors);
    }

    percpu_up_read(&c->mark_lock);
}

void
orca_extent_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    orca_bkey_ptrs_to_text(out, c, k);
}

enum merge_result
orca_extent_merge(struct orca_fs *c, struct bkey_s _l, struct bkey_s _r)
{
    struct bkey_s_extent l = bkey_s_to_extent(_l);
    struct bkey_s_extent r = bkey_s_to_extent(_r);
    union orca_extent_entry *en_l = l.v->start;
    union orca_extent_entry *en_r = r.v->start;
    struct orca_extent_crc_unpacked crc_l, crc_r;

    if (bkey_val_u64s(l.k) != bkey_val_u64s(r.k))
        return ORCA_MERGE_NOMERGE;

    crc_l = orca_extent_crc_unpack(l.k, NULL);

    extent_for_each_entry(l, el_l) {
        en_r = vstruct_idx[r.v, (u64 *)en_l - l.v->_data];

        if (extent_entry_type(en_l) != extent_entry_type(en_r))
            return ORCA_MERGE_NOMERGE;

        switch (extent_entry_type(en_l)) {
        case ORCA_EXTENT_ENTRY_ptr:
        {
            const struct orca_extent_ptr *lp = &en_l->ptr;
            const struct orca_extent_ptr *rp = &en_r->ptr;
            struct orca_dev *ca;

            if (lp->offset + crc_l.compressed_size != rp->offset ||
                lp->dev != rp->dev || lp->gen != rp->gen)
                    return ORCA_MERGE_NOMERGE;

            /* We don't allow extents to straddle buckets */
            ca = orca_dev_bkey_exists(c, lp->dev);

            if (PTR_BUCKET_NR(ca, lp) != PTR_BUCKET_NR(ca, rp))
                return ORCA_MERGE_NOMERGE;

            break;
        }

        case ORCA_EXTENT_ENTRY_stripe_ptr:
            if (en_l->stripe_ptr.block != en_r->stripe_ptr.block ||
                en_l->stripe_ptr.idx != en_r->stripe_ptr.idx)
                    return ORCA_MERGE_NOMERGE;

            break;

        case ORCA_EXTENT_ENTRY_crc32:
        case ORCA_EXTENT_ENTRY_crc64:
        case ORCA_EXTENT_ENTRY_crc128:
            crc_l = orca_extent_crc_unpack(l.k, entry_to_crc(en_l));
            crc_r = orca_extent_crc_unpack(r.k, entry_to_crc(en_r));

            if (crc_l.csum_type != crc_r.csum_type ||
                crc_l.compression_type != crc_r.compression_type||
                crc_l.nonce != crc_r.nonce)
                    return ORCA_MERGE_NOMERGE;

            if (crc_l.offset + crc_l.live_size != crc_l.compressed_size ||
                crc_r.offset)
                    return ORCA_MERGE_NOMERGE;

            if (!orca_checksum_mergeable(crc_l.csum_type))
                return ORCA_MERGE_NOMERGE;

            if (crc_l.csum_type && crc_l.uncompressed_size + crc_r.uncompressed_size >
                c->sb.encoded_extent_max)
                    return ORCA_MERGE_NOMERGE;

            if (crc_l.uncompressed_size + crc_r uncompressed_size >
                orca_crc_field_size_max[extent_entry_type(en_l)])
                    return ORCA_MERGE_NOMERGE;

            break;

        default:
            return ORCA_MERGE_NOMERGE;
        }
    }

    extent_for_each_entry(l, en_l) {
        struct orca_extent_crc_unpacked crc_l, crc_r;

        en_r = vstruct_idx(r.v, (u64 *)en_l - l.v->_data);

        if (!extent_entry_is_crc(en_l))
            continue;

        crc_l = orca_extent_crc_unpack(l.k, entry_to_crc(en_l));
        crc_r = orca_extent_crc_unpack(r.k, entry_to_crc(en_r));

        crc_l.csum = orca_checksum_merge(crc_l.csum_type, crc_l.csum,
            crc_r.csum, crc_r.uncompressed_size << 9);

        crc_l.uncompressed_size += crc_r.uncompressed_size;
        crc_l.compressed_size += crc_r.compressed_size;

        orca_extent_crc_pack(entry_to_crc(en_l), crc_l, extent_entry_type(en_l));
    }

    orca_key_resize(l.k, l.k->size + r.k->size);

    return ORCA_MERGE_MERGE;
}

const char *
orca_reservation_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_s_c_reservation r = bkey_s_c_to_reservation(k);

    if (bkey_val_bytes(k.k) != sizeof(struct orca_reservation))
        return "incorrect valud size";

    if (!r.v->nr_replicas || r.v->nr_replicas > ORCA_REPLICAS_MAX)
        return "invalid number of replicas";

    return NULL;
}

void
orca_reservation_to_text(struct printbuf *out, struct orca_fs *c,
    struct bkey_s_c k)
{
    struct bkey_s_c_reservation r = bkey_s_c_to_reservation(k);

    pr_buf(out, "generation %u replicas %u", le32_to_cpu(r.v->generation),
        r.v->nr_replicas);
}

enum merge_result
orca_reservation_merge(struct orca_fs *c, struct bkey_s _l, struct bkey_s _r)
{
    struct bkey_s_reservation l = bkey_s_to_reservation(_l);
    struct bkey_s_reservation r = bkey_s_to_reservation(_r);

    if (l.v->generation != r.v->generation || l.v->replicas != r.v->nr_replicas)
        return ORCA_MERGE_NOMERGE;

    if ((u64)l.k->size + r.k->size > KEY_SIZE_MAX) {
        orca_key_resize(l.k, KEY_SIZE_MAX);
        orca_cut_front_s(l.k->p, r.s);
            return ORCA_MERGE_PARTIAL;
    }

    orca_key_resize(l.k, l.k->size + r.k->size);

    return ORCA_MERGE_MERGE;
}

/**
 * Extent checksum entries.
 * Returns true if not equal.
**/
static inline bool
orca_crc_unpacked_cmp(struct orca_extent_crc_unpacked l, struct orca_extent_crc_unpacked r)
{
    return (l.csum_type != r.csum_type || l.compression_type != r.compression_type ||
        l.compressed_size != r.compressed_size || l.uncompressed_size != r.uncompressed_size ||
        l.offset != r.offset || l.live_size != r.live_size || l.nonce != r.nonce)
            orca_crc_cmp(l.csum, r.csum);
}

static inline bool
can_narrow_crc(struct orca_extent_crc_unpacked u, struct orca_extent_crc_unpacked n)
{
    return !crc_is_compressed(u) && u.csum_type && u.uncompressed_size > u.live_size &&
        orca_csum_type_is_encryption(u.csum_type) == orca_csum_type_is_encryption(n.csum_type);
}

bool
orca_can_narrow_extent_crcs(struct bkey_s_c k, struct orca_extent_crc_unpacked n)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    struct orca_extent_crc_unpacked crc;
    const union orca_extent_entry *i;

    if (!n.csum_type)
        return false;

    bkey_for_each_crc(k.k, ptrs, crc, i) {
        if (can_narrow_crc(crc, n))
            return true;
    }

    return false;
}

/**
 * We're writing another replica for this extent, so while we've got the data in
 * memory, we'll be computing a new checksum for the currently live data.
 *
 * If there are other replicas, we aren't moving, and they are checksummed, but
 * not compressed, we can modify them to point to only the data that is
 * currently live (so that readers won't have to bounce) while we've got the
 * checksum we need.
**/
bool
orca_bkey_narrow_crcs(struct bkey_i *k, struct orca_extent_crc_unpacked n)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(bkey_i_to_s(k));
    struct orca_extent_crc_unpacked u;
    struct extent_ptr_decoded p;
    union orca_extent_entry *l;
    bool ret = false;

    /* Find a checksum entry that covers only live data */
    if (!n.csum_type) {
        bkey_for_each_crc(&k->k, ptrs, u, i) {
            if (!crc_is_compressed(u) && u.csum_type && u.live_size == u.uncompressed_size) {
                n = u;
                goto found;
            }
        }

        return false;
    }

found:
    BUG_ON(crc_is_compressed(n));
    BUG_ON(n.offset);
    BUG_ON(n.live_size != k->k.size);

reset_narrow_pointers:
    ptrs = orca_bkey_ptrs(bkey_i_to_s(k));

    bkey_for_each_ptr_decode(&k->k, ptrs, p, i) {
        if (can_narrow_crc(p.crc, n)) {
            orca_bkey_drop_ptr(bkey_i_to_s(k), &i->ptr);
            p.ptr.offset += p.crc.offset;
            p.crc = n;
            orca_extent_ptr_decoded_append(k. &p);
            ret = true;
            goto restart_narrow_pointers;
        }
    }

    return ret;
}

static void
orca_extent_crc_pack(union orca_extent_crc *dst, struct orca_extent_crc_unpacked src,
    enum orca_extent_entry_type type)
{
#define set_common_fields(_dst, _src)                       \
    _dst.type = 1 << type,                                  \
    _dst.csum_type = _src.csum_type,                        \
    _dst.compression_type = _src.compression_type,          \
    _dst._compressed_size = _src.compressed_size - 1,       \
    _dst._uncompressed_size = _src.uncompressed_size - 1,   \
    _dst.offset = _src.offset

    switch (type) {
    case ORCA_EXTENT_ENTRY_crc32:
        set_common_fields(dst->crc32, src);
        dst->crc32.csum = *((__le32 *)&src.csum.lo);
        break;

    case ORCA_EXTENT_ENTRY_crc64:
        set_common_fields(dst->crc64, src);
        dst->crc64.nonce = src.nonce;
        dst->crc64.csum_lo = src.csum.lo;
        dst->crc64.csum_hi = *((__le16 *)src.csum.hi);
        break;

    case ORCA_EXTENT_ENTRY_crc128:
        set_common_fields(dst->crc128, src);
        dst->crc128.nonce = src.nonce;
        dst->crc128.csum = src.csum;
        break;

    default:
        BUG();
    }
#undef set_common_fields
}

void
orca_extent_crc_append(struct bkey_i *k, struct orca_extent_crc_unpacked new)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(bkey_i_to_s(k));
    union orca_extent_crc *crc = (void *)ptrs.end;
    enum orca_extent_entry_type type;

    if (orca_crc_bytes[new.csum_type] <= 4 && new.uncompressed_size <= CRC32_SIZE_MAX &&
        new.nonce <= CRC32_NONCE_MAX)
            type = ORCA_EXTENT_ENTRY_crc32;
    else if (orca_crc_bytes[new.csum_type] <= 10 && new.uncompressed_size <= CRC64_SIZE_MAX &&
        new.nonce <= CRC64_NONCE_MAX)
            type = ORCA_EXTENT_ENTRY_crc64;
    else if (orca_crc_bytes[new.csum_type] <= 16 && new.uncompressed_size <= CRC128_SIZE_MAX &&
        new.nonce <= CRC128_NONCE_MAX)
            type = ORCA_EXTENT_ENTRY_crc128;
    else
        BUG();

    orca_extent_crc_pack(crc, new, type);
    k->k.u64s += extent_entry_u64s(ptrs.end);

    EBUG_ON(bkey_val_u64s(&k->k) > ORCA_EXTENT_VAL_U64s_MAX);
}

/**
 * Generic code for keys with pointers.
**/
unsigned
orca_bkey_nr_ptrs(struct bkey_s_c k)
{
    return orca_bkey_devs(k).nr;
}

unsigned
orca_bkey_nr_ptrs_allocated(struct bkey_s_c k)
{
    return k.k->type == KEY_TYPE_reservation
        ? bkey_s_c_to_reservation(k).v->nr_replicas
        : orca_bkey_dirty_devs(k).nr;
}

unsigned
orca_bkey_nr_ptrs_fully_allocated(struct bkey_s_c k)
{
    unsigned ret = 0;

    if (k.k->type == KEY_TYPE_reservation) {
        ret = bkey_s_c_to_reservation(k).v->nr_replicas;
    } else {
        struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
        const union orca_extent_entry *entry;
        struct extent_ptr_decoded p;

        bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
            ret += !p.ptr.cached && !crc_is_compressed(p.crc);
    }

    return ret;
}

unsigned
orca_bkey_sectors_compressed(struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    unsigned ret = 0;

    bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
        if (!p.ptr.cached && crc_is_compressed(p.crc))
            ret += p.crc.compressed_size;
    }

    return ret;
}

bool
orca_bkey_is_incompressible(struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct orca_extent_crc_unpacked crc;

    bkey_for_each_crc(k.k, ptrs, crc, entry) {
        if (crc.compression_type == ORCA_COMPRESSION_TYPE_incompressible)
            return true;
    }

    return false;
}

bool
orca_check_range_allocated(struct orca_fs *c, struct bpos pos, u64 size,
    unsigned nr_replicas)
{
    struct btree_trans trans;
    struct btree_iter *iter;
    struct bpos end = pos;
    struct bkey_s_c k;
    bool ret = true;
    int err;

    end.offset += size;
    orca_trans_init(&trans, c, 0, 0);

    for_each_btree_key(&trans, iter, BTREE_ID_EXTENTS, pos, BTREE_ITER_SLOTS, k, err) {
        if (bkey_cmp(bkey_start_pos(k.k), end) >= 0)
            break;

        if (nr_replicas > orca_bkey_nr_ptrs_fully_allocated(k)) {
            ret = false;
            break;
        }
    }

    orca_trans_exit(&trans);

    return ret;
}

static unsigned
orca_extent_ptr_durability(struct orca_fs *c, struct extent_ptr_decoded p)
{
    unsigned durability = 0;
    struct orca_dev *ca;

    if (p.ptr.cached)
        return 0;

    ca = orca_dev_bkey_exists(c, p.ptr.dev);

    if (ca->mi.state != ORCA_MEMBER_STATE_FAILED)
        durability = max_t(unsigned, durability, ca->mi.durability);

    if (p.has_ec) {
        struct stripe *s = genradix_ptr(&c->stripes[0], p.ec.idx);

        if (WARN_ON(!s))
            goto out;

        durability += s->nr_redundant;
    }

out:
    return durability;
}

unsigned
orca_bkey_durability(struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    unsigned durability = 0;

    bkey_for_each_ptr_decode(k.k, ptrs, p, entry)
        durability += orca_extent_ptr_durability(c, p);

    return durability;
}

void
orca_bkey_mark_replicas_cached(struct orca_fs *c, struct bkey_s k, unsigned target,
    unsigned nr_desired_replicas)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(k);
    union orca_extent_entry *entry;
    struct extent_ptr_decoded p;
    int extra = orca_bkey_durability(c, k.s_c) - nr_desired_replicas;

    if (target && extra > 0) {
        bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
            int n = orca_extent_ptr_durability(c, p);

            if (n && n <= extra && !orca_dev_in_target(c, p.ptr.dev, target)) {
                entry->ptr.cached = true;
                extra -= n;
            }
        }
    }

    if (extra > 0) {
        bkey_for_each_ptr_decode(k.k, ptrs, p, entry) {
            int n = orca_extent_ptr_durability(c, p);

            if (n && n <= extra) {
                entry->ptr.cached = true;
                extra -= n;
            }
        }
    }
}

void
orca_bkey_append_ptr(struct bkey_i *k, struct orca_extent_ptr ptr)
{
    EBUG_ON(orca_bkey_has_device(bkey_i_to_s_c(k), ptr.dev));

    switch (k->k.type) {
    case KEY_TYPE_btree_ptr:
    case KEY_TYPE_btree_ptr_v2:
    case KEY_TYPE_extent:
        EBUG_ON(bkey_val_u64s(&k->k) >= BKEY_EXTENT_VAL_U64s_MAX);

        ptr.type = 1 << ORCA_EXTENT_ENTRY_ptr;
        memcpy((void *)&k->v + bkey_val_bytes(&k->k), &ptr, sizeof(ptr));
        k->u64s++;
        break;

    default:
        BUG();
    }
}

static inline void
__extent_entry_insert(struct bkey_i *k, union orca_extent_entry *dst,
    union orca_extent_entry *new)
{
    union orca_extent_entry *end = bkey_val_end(bkey_i_to_s(k));

    memmove_u64s_up_small((u64 *)dst + extent_entry_u64s(new),
        dst, (u64 *)end - (u64 *)dst);

    k->k.u64s += extent_entry_u64s(new);
    memcpy(dst, new, extent_entry_bytes(new));
}

void
orca_extent_ptr_decoded_append(struct bkey_i *k, struct extent_ptr_decoded *p)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(bkey_i_to_s(k));
    struct orca_entent_crc_unpacked crc = orca_extent_crc_unpack(&k->k, NULL);
    union orca_extent_entry *pos;

    if (!orca_crc_unpacked_cmp(crc, p->crc)) {
        pos = ptrs.start;
        goto found;
    }

    bkey_for_each_crc(&k->k, ptrs, crc, pos) {
        if (!orca_crc_unpacked_cmp(crc, p->crc)) {
            pos = extent_entry_next(pos);
            goto found;
        }
    }

    orca_extent_crc_append(k, p->crc);
    pos = bkey_val_end(bkey_i_to_s(k));

found:
    p->ptr.type = 1 << ORCA_EXTENT_ENTRY_ptr;
    __extent_entry_insert(k, pos, to_entry(&p->ptr));

    if (p->has_ec) {
        p->ec.type = 1 << ORCA_EXTENT_ENTRY_stripe_ptr;
        __extent_entry_insert(k, pos, to_entry(&p->ec));
    }
}

static union orca_extent_entry *
extent_entry_prev(struct bkey_ptrs ptrs, union orca_extent_entry *entry)
{
    union orca_extent_entry *i = ptrs.start;

    if (i == entry)
        return NULL;

    while (extent_entry_next(i) != entry)
        i = extent_entry_next(i);

    return i;
}

union orca_extent_entry *
orca_bkey_drop_ptr(struct bkey_s k, struct orca_extent_ptr *ptr)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(k);
    union orca_extent_entry *dst, *src, *prev;
    bool drop_crc = true;

    EBUG_ON(ptr < &ptrs.start->ptr || ptr >= &ptrs.end->ptr);
    EBUG_ON(ptr->type != 1 << ORCA_EXTENT_ENTRY_ptr);

    src = extent_entry_next(to_entry(ptr));

    if (src != ptrs.end && !extent_entry_is_crc(src))
        drop_crc = false;

    dst = to_entry(ptr);

    while ((prev = extent_entry_prev(ptrs, dst))) {
        if (extent_entry_is_ptr(prev))
            break;

        if (extent_entry_is_crc(prev)) {
            if (drop_crc)
                dst = prev;

            break;
        }

        dst = prev;
    }

    memmove_u64s_down(dst, src, (u64 *)ptrs.end - (u64 *)src);
    k.k->u64s -= (u64 *)src - (u64 *)dst;

    return dst;
}

void
orca_bkey_drop_device(struct bkey_s k, unsigned dev)
{
    struct orca_extent_ptr *ptr;

    orca_bkey_drop_ptrs(k, ptr, ptr->dev == dev);
}

const struct orca_extent_ptr *
orca_bkey_has_device(struct bkey_s_c k, unsigned dev)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const struct orca_extent_ptr *ptr;

    bkey_for_each_ptr(ptrs, ptr) {
        if (ptr->dev == dev)
            return ptr;
    }

    return NULL;
}

bool
orca_bkey_has_target(struct orca_fs *c, struct bkey_s_c k, unsigned target)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const struct orca_extent_ptr *ptr;

    bkey_for_each_ptr(ptrs, ptr) {
        if (orca_dev_in_target(c, ptr->dev, target) && (!ptr->cached ||
            !ptr_stale(orca_dev_bkey_exists(c, ptr->dev), ptr)))
                return true;
    }

    return false;
}

bool
orca_bkey_matches_ptr(struct orca_fs *c, struct bkey_s_c k, struct orca_extent_ptr m,
    u64 offset)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct extent_ptr_decoded p;

    bkey_for_each_ptr_seconds(k.k, ptrs, p, entry) {
        if (p.ptr.dev == m.dev && p.ptr.gen == m.gen && (s64)p.ptr.offset +
            p.crc.offset - bkey_start_offset(k.k) == (s64)m.offset - offset)
                return true;
    }

    return false;
}

/**
 * Clean up an extent, dropping stale pointers etc.
 *
 * Returns true if @k should be dropped entirely.
 *
 * For existing keys, only called when btree nodes are being rewritten,
 * not when they're merely being compacted/resorted in memory.
**/
bool
orca_extent_normalize(struct orca_fs *c, struct bkey_s k)
{
    struct orca_extent_ptr *ptr;

    orca_bkey_drop_ptrs(k, ptr, ptr->cached && ptr_stale(orca_dev_bkey_exists(c, ptr->dev), ptr));

    /* Will only happen if all pointers were cached */
    if (!orca_bkey_nr_ptrs(k.s_c))
        k.k->type = KEY_TYPE_discard;

    return bkey_whiteout(k.k);
}

void
orca_bkey_ptrs_to_text(struct printbuf *out, struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct orca_extent_crc_unpacked crc;
    const struct orca_extent_ptr *ptr;
    const struct orca_extent_stripe_ptr *ec;
    struct orca_dev *ca;
    bool first = true;

    bkey_extent_entry_for_each(ptrs, entry) {
        if (!first)
            pr_buf(out, " ");

        switch (__extent_entry_type(entry)) {
        case ORCA_EXTENT_ENTRY_ptr:
            ptr = entry_to_ptr(entry);
            ca = ptr->dev < c->sb.nr_devices && c->devs[ptr->dev]
                ? orca_dev_bkey_exists(c, ptr->dev)
                : NULL;

            pr_buf(out, "ptr: %u:%llu gen %u%s%s", ptr->dev, (u64)ptr->offset,
                ptr->gen, ptr->cached ? " cached" : "", ca && ptr_stale(ca, ptr)
                ? " stale" : "");
            break;

        case ORCA_EXTENT_ENTRY_crc32:
        case ORCA_EXTENT_ENTRY_crc64:
        case ORCA_EXTENT_ENTRY_crc128:
            crc = orca_extent_crc_unpack(k.k, entry_to_crc(entry));

            pr_buf(out, "crc: c_size %u size %u offset %u nonce %u csum %u compress %u",
                crc.compressed_size, crc.uncompressed_size, crc.offset, crc.nonce,
                crc.csum_type, crc.compression_type);
            break;

        case ORCA_EXTENT_ENTRY_stripe_ptr:
            ec = &entry->stripe_ptr;

            pr_buf(out, "ec: idx %llu block %u", (u64)ec->idx, ec->block);
            break;

        default:
            pr_buf(out, "(invalid extent entry %.1611x)", *((u64 *)entry));
            return;
        }

        first = false;
    }
}

static const char *
extent_ptr_invalid(const struct orca_fs *c, struct bkey_s_c k,
    const struct orca_extent_ptr *ptr, unsigned size_ondisk, bool metadata)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const struct orca_extent_ptr *ptr2;
    struct orca_dev *ca;

    if (!orca_dev_exists2(c, ptr->dev))
        return "pointer to invalid device";

    ca = orca_dev_bkey_exists(c, ptr->dev);

    if (!ca)
        return "pointer to invalid device";

    bkey_for_each_ptr(ptrs, ptr2) {
        if (ptr != ptr2 && ptr->dev == ptr2->dev)
            return "multiple pointers to same device";
    }

    if (ptr->offset + size_ondisk > bucket_to_sector(ca, ca->mi.nbuckets))
        return "offset past end of device";

    if (ptr->offset < bucket_to_sector(ca, ca->mi.first_bucket))
        return "offset before first bucket";

    if (bucket_remainder(ca, ptr->offset) + size_ondisk > ca->mi.bucket_size)
        return "spans multiple buckets";

    return NULL;
}

const char *
orca_bkey_ptrs_invalid(const struct orca_fs *c, struct bkey_s_c k)
{
    struct bkey_ptrs_c ptrs = orca_bkey_ptrs_c(k);
    const union orca_extent_entry *entry;
    struct orcaa_extent_crc_unpacked crc;
    unsigned size_ondisk = k.k->size;
    const char *reason;
    unsigned nonce = UINT_MAX;

    if (k.k->type == KEY_TYPE_btree_ptr)
        size_ondisk = c->opts.btree_node_size;

    if (k.k->type == KEY_TYPE_btree_ptr_v2)
        size_ondisk = le16_to_cpu(bkey_s_c_to_btree_ptr_v2(k).v->sectors);

    bkey_extent_entry_for_each(ptrs, entry) {
        if (__extent_entry_type(entry) >= ORCA_EXTENT_ENTRY_MAX)
            return "invalid extent entry type";

        if (k.k->type == KEY_TYPE_btree_ptr && !extent_entry_is_ptr(entry))
            return "has non ptr field";

        switch (extent_entry_type(entry)) {
        case ORCA_EXTENT_ENTRY_ptr:
            reason = extent_ptr_invalid(c, k, &entry->ptr, size_ondisk, false);

            if (reason)
                return reason;

            break;

        case ORCA_EXTENT_ENTRY_crc32:
        case ORCA_EXTENT_ENTRY_crc64:
        case ORCA_EXTENT_ENTRY_crc128:
            crc = orca_extent_crc_unpack(k.k, entry_to_crc(entry));

            if (crc.offset + crc.live_size > crc.uncompressed_size)
                return "checksum offset + key size > uncompressed size";

            size_ondisk(crc.compressed_size);

            if (!orca_checksum_type_valid(c, crc.csum_type))
                return "invalid checksum type";

            if (crc.compression_type >= ORCA_COMPRESSION_TYPE_NR)
                return "invalid compression type";

            if (orca_csum_type_is_encryption(crc.csum_type)) {
                if (nonce == UINT_MAX)
                    nonce = crc.offset + crc.nonce;
                else if (nonce != crc.offset + crc.nonce)
                    return "incorrect nonce";
            }

            break;

        case ORCA_EXTENT_ENTRY_stripe_ptr:
            break;
        }
    }

    return NULL;
}

void
orca_ptr_swab(struct bkey_s k)
{
    struct bkey_ptrs ptrs = orca_bkey_ptrs(k);
    union orca_extent_entry *entry;
    u64 *d;

    for (d = (u64 *)ptrs.start; entry < ptrs.end; entry = extent_entry_next(entry)) {
        switch (extent_entry_type(entry)) {
        case ORCA_EXTENT_ENTRY_ptr:
            break;

        case ORCA_EXTENT_crc32:
            entry->crc32.csum = swab32(entry->crc32.csum);
            break;

        case ORCA_EXTENT_crc64:
            entry->crc32.sum = swab32(entry->crc32.csum);
            break;

        case ORCA_EXTENT_ENTRY_crc64:
            entry->crc64.csum_hi = swab16(entry->crc64.csum_hi);
            entry->crc64.csum_lo = swab64(entry->crc64.csum_lo);
            break;

        case ORCA_EXTENT_ENTRY_crc128:
            entry->crc128.csum.hi =
                (__force __le16)swab64((__force u64)entry->crc128.csum.hi);
            entry->crc128.csum.lo = (__force __le64 entry->crc128.csum.lo);
            break;
        }

        case ORCA_EXTENT_ENTRY_stripe_ptr:
            break;
    }
}

/**
 * Generic extent code.
**/
int
orca_cut_front_s(struct bpos where, struct bkey_s k)
{
    unsigned new_val_u64s = bkey_val_u64s(k.k);
    int val_u64s_delta;
    u64 sub;

    if (bkey_cmp(where, bkey_start_pos(k.k)) <= 0)
        return 0;

    EBUG_ON(bkey_cmp(where, k.k->p) > 0);

    sub = where.offset - bkey_start_offset(k.k);
    k.k->size -= sub;

    if (!k.k->size) {
        k.k->type = KEY_TYPE_deleted;
        new_val_u64s = 0;
    }

    switch (k.k->type) {
    case KEY_TYPE_extent:
    case ORCA_TYPE_reflink_v:
        {
            struct bkey_ptrs ptrs = orca_bkey_ptrs(k);
            union orca_extent_entry *entry;
            bool seen_crc = false;

            bkey_extent_entry_for_each(ptrs, entry) {
                switch (extent_entry_type(entry)) {
                case ORCA_EXTENT_ENTRY_ptr:
                    if (!seen_crc)
                        entry->ptr.offset += sub;
                    break;

                case ORCA_EXTENT_ENTRY_crc32:
                    entry->crc32.offset += sub;
                    break;

                case ORCA_ENTEXT_ENTRY_crc64:
                    entry->crc64.offset += sub;
                    break;

                case ORCA_EXTENT_ENTRY_crc128:
                    entry->crc128.offset += sub;
                    break;

                case ORCA_EXTENT_ENTRY_stripe_ptr:
                    break;
                }

                if (extent_entry_is_crc(entry))
                    seen_crc = true;
            }
        }

        break;

    case KEY_TYPE_reflink_p:
        {
            struct bkey_s_reflink_p p = bkey_s_to_reflink_p(k);

            le64_add_cpu(&p.v->idx, sub);
            break;
        }

    case KEY_TYPE_inline_data:
    case KEY_TYPE_indirect_inline_data:
        {
            void *p = bkey_inline_data_p(k);
            unsigned bytes = bkey_inline_data_bytes(k.k);

            sub = min_t(u64, sub << 9, bytes);
            memmove(p, p + sub, bytes - sub);
            new_val_u64s -= sub >> 3;
            break;
        }
    }

    val_u64s_delta = bkey_val_u64s(k.k) - new_val_u64s;
    BUG_ON(val_u64s_delta < 0);

    set_bkey_val_u64s(k.k, new_val_u64s);
    memset(bkey_val_end(k), 0, val_u64s_delta * sizeof(u64));

    return -val_u64s_delta;
}

int
orca_cut_back_s(struct bpos where, struct bkey_s k)
{
    unsigned new_val_u64s = bkey_val_u64s(k.k);
    int val_u64s_delta;
    u64 len = 0;

    if (bkey_cmp(where, k.k->p) >= 0)
        return 0;

    EBUG_ON(bkey_cmp(where, bkey_start_pos(k.k)) < 0);

    len = where.offset - bkey_start_offset(k.k);
    k.k->p = where;
    k.k->size = len;

    if (!len) {
        k.k->type = KEY_TYPE_deleted;
        new_val_u64s = 0;
    }

    switch (k.k->type) {
    case KEY_TYPE_inline_data:
    case KEY_TYPE_indirect_inline_data:
        new_val_u64s = (bkey_inline_data_offset(k.k) +
            min(bkey_inline_data_bytes(k.k), k.k->size << 9)) >> 3;
        break;
    }

    val_u64s_delta = bkey_val_u64s(k.k) - new_val_u64s;
    BUG_ON(val_u64s_delta < 0);

    set_bkey_val_u64s(k.k, new_val_u64s);
    memset(bkey_val_end(k), 0, val_u64s_delta * sizeof(u64));

    return -val_u64s_delta;
}
