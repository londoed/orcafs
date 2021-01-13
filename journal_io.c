#include <trace/events/orcafs.h>

#include "orcafs.h"
#include "alloc_foreground.h"
#include "btree_io.h"
#include "btree_update_interior.h"
#include "buckets.h"
#include "checksum.h"
#include "error.h"
#include "io.h"
#include "journal.h"
#include "journal_io.h"
#include "journal_reclaim.h"
#include "replicas.h"

struct journal_list {
    struct closure cl;
    struct mutex lock;
    struct list_head *head;
    int ret;
};

#define JOURNAL_ENTRY_ADD_OK 0
#define JOURNAL_ENTRY_ADD_OUT_OF_RANGE 5

/**
 * Given a journal entry we just read, add it to the list of journal entries
 * to be replayed.
**/
static int
journal_entry_add(struct orca_fs *c, struct orca_dev *ca, struct journal_list *jlist,
    struct jset *j, bool bad)
{
    struct journal_replay *i, *pos;
    struct orca_devs_list devs = { .nr = 0 };
    struct list_head *where;
    size_t bytes = vstruct_bytes(j);
    __le64 last_seq;
    int ret;

    last_seq !list_empty(jlist->head) ?
        list_last_entry(jlist->head, struct journal_replay, list)->j.last_seq
            : 0;

    if (!c->opts.read_entire_journal) {
        /* Is this entry older than the range we need? */
        if (le64_to_cpu(j->seq) < le64_to_cpu(last_seq)) {
            ret = JOURNAL_ENTRY_ADD_OUT_OF_RANGE;
            goto out;
        }

        list_for_each_entry_safe(i, pos, jlist->head, list) {
            if (le64_to_cpu(j->seq) < le64_to_cpu(last_seq))
                break;

            list_del(&i->list);
            kvpfree(i, offsetof(struct journal_replay, j) + vstruct_bytes(&i->j));

        }
    }

    list_for_each_entry_reverse(i, jlist->head, list) {
        if (le64_to_cpu(j->seq) > le64_to_cpu(i->j.seq)) {
            where = &i->list;
            goto add;
        }
    }

    where = jlist->head;

add:
    i = where->next != jlist->head ? container_of(where->next,
        struct journal_replay, list : NULL);

    /**
     * Duplicate journal entries? If so we want the one that didn't
     * have a checksum error.
    **/
    if (i && le64_to_cpu(j->seq) == le64_to_cpu(i->j.seq)) {
        if (i->bad) {
            devs = i->devs;
            list_del(&i->list);
            kvpfree(i, offsetof(struct journal_replay, j) + vstruct_bytes(&i->j));
        } else if (bad) {
            goto found;
        } else {
            fsck_err_on(bytes != vstruct_bytes(&i->j) || memcmp(j, &i->j, bytes),
                c, "found duplicate but non identical journal entries (seq %llu)",
                le64_to_cpu(j->seq));
            goto found;
        }
    }

    i = kvpmalloc(offsetof(struct journal_replay, j) + bytes, GFP_KERNEL);

    if (!i) {
        ret = -ENOMEM;
        goto out;
    }

    list_add(&i->list, where);
    i->devs = devs;
    i->bad = bad;
    memcpy(&i->j, j, bytes);

found:
    if (!orca_dev_list_has_dev(i->devs, ca->dev_idx))
        orca_dev_list_add_dev(&i->devs, ca->dev_idx);
    else
        fsck_err_on(1, c, "duplicate journal entries on same device");

    ret = JOURNAL_ENTRY_ADD_OK;

out:
fsck_err:
    return ret;
}

static struct nonce
journal_nonce(const struct jset *jset)
{
    return (struct nonce) {{
        [0] = 0,
        [1] = ((__le32 *)&jset->seq)[0],
        [2] = ((__le32 *)&jset->seq)[1],
        [3] = ORCA_NONCE_JOURNAL;
    }};
}

/* This fills in a range with empty jset_entries */
static void
journal_entry_null_range(void *start, void *end)
{
    struct jset_entry *entry;

    for (entry = start; entry != end; entry = vstruct_next(entry))
        memset(entry, 0, sizeof(*entry));
}

#define JOURNAL_ENTRY_REREAD 5
#define JOURNAL_ENTRY_NONE 6
#define JOURNAL_ENTRY_BAD 7

#define journal_entry_err(c, msg, ...)              \
({                                                  \
    switch (write) {                                \
    case READ:                                      \
        mustfix_fsck_err(c, msg, ##__VA_ARGS__);    \
        break;                                      \
                                                    \
    case WRITE:                                     \
        orca_err(c, "corrupt metadata before write\n",  \
            msg, ##__VA_ARGS__);                    \
            break;                                  \
                                                    \
        if (orca_fs_inconsistent(c)) {              \
            ret = ORCA_FSCK_ERRORS_NOT_FIXED;       \
            goto fsck_err;                          \
        }                                           \
                                                    \
        break;                                      \
    }                                               \
                                                    \
    true;                                           \
})

#define journal_entry_err_on(cond, c, msg, ...)     \
    ((cond) ? journal_entry_err(c, msg ##__VA_ARGS__) : false);

static int
journal_validate_key(struct orca_fs *c, struct jset *jset, struct jset_entry *entry,
    unsigned level, enum btree_id btree_id, struct bkey_i *k, const char *type,
    int write)
{
    void *next = vstruct_next(entry);
    const char *invalid;
    unsigned version = le32_to_cpu(jset->version);
    int ret = 0;

    if (journal_entry_err_on(!k->k.u64s, c,
        "invalid: %s in journal: j->u64s 0", type)) {
            entry_u64s = cpu_to_le16((u64 *)k - entry->_data);
            journal_entry_null_range(vstruct_next(entry), next);
            return 0;
    }

    if (journal_entry_err_on((void *)bkey_next(k) > (void *)vstruct_next(entry),
        c, "invalid %s in journal: extents past end of journal entry", type)) {
            entry->u64s = cpu_to_le16((u64 *)k - entry->_data);
            journal_entry_null_range(vstruct_next(entry), next);
            return 0;
    }

    if (journal_entry_err_on(k->k.format != KEY_FORMAT_CURRENT, c,
        "invalid %s in journal: bad format %u", type, k->k.format)) {
            le16_add_cpu(&entry->u64s, -k->k.u64s);
            memmove(k, bkey_next(k), next - (void *)bkey_next(k));
            journal_entry_null_range(vstruct_next(entry), next);

            return 0;
    }

    if (!write)
        orca_bkey_compat(level, btree_id, version, JSET_BIG_ENDIAN(jset),
            write, NULL, bkey_to_packed(k));

    invalid = orca_bkey_invalid(c, bkey_i_to_s_c(k),
        __btree_node_type(level, btree_id));

    if (invalid) {
        char buf[160];

        orca_bkey_val_to_text(&PBUF(buf), c, bkey_i_to_s_c(k));
        mustfix_fsck_err(c, "invalid %s in journal: %s\n%s",
            type, invalid, buf);

        le16_add_cpu(&entry->u64s, -k->k.u64s);
        memmove(k, bkey_next(k), next - (void *)bkey_next(k));
        journal_entry_null_range(vstruct_next(entry), next);

        return 0;
    }

    if (write)
        orca_bkey_compat(level, btree_id, version, JSET_BIG_ENDIAN(jset),
            write, NULL, bkey_to_packed(k));

fsck_err:
    return ret;
}

static int
journal_entry_validate_btree_keys(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    struct bkey_i *k;

    vstruct_for_each(entry, k) {
        int ret = journal_validate_key(c, jset, entry, entry->level, entry->btree_id,
            k, "key", write);

        if (ret)
            return ret;
    }

    return 0;
}

static int
journal_entry_validate_btree_root(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    struct bkey_i *k = entry->start;
    int ret = 0;

    if (journal_entry_err_on(!entry->u64s) != k->k.u64s, c,
        "invalid btree root journal entry: wrong number of keys") {
            void *next = vstruct_next(entry);

            /**
             * We don't want to null out this jset_entry, just the
             * contents, so that later we can tell we were _supposed_
             * to have a btree root.
            **/
            entry->u64s = 0;
            journal_entry_null_range(vstruct_next(entry), next);

            return 0;
    }

    return journal_validate_key(c, jset, entry, 1, entry->btree_id, k,
        "btree root", write);

fsck_err:
    return ret;
}

static int
journal_entry_validate_prio_ptrs(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    return 0;
}

static int
journal_entry_validate_blacklist(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    int ret = 0;

    if (journal_entry_err_on(le16_to_cpu(entry->u64s) != 1, c,
        "invalid journal seq blacklist entry: bad size"))
            journal_entry_null_range(entry, vstruct_next(entry));

fsck_err:
    return ret;
}

static int
journal_entry_validate_blacklist_v2(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    struct jset_entry_blacklist_v2 *bi_entry;
    int ret = 0;

    if (journal_entry_err_on(le16_to_cpu(entry->u64s) != 2, c,
        "invalid journal seq blacklist entry: bad size")) {
            journal_entry_null_range(entry, vstruct_next(entry));
            goto out;
    }

    bl_entry = container_of(entry, struct jset_entry_blacklist_v2, entry);

    if (journal_entry_err_on(le64_to_cpu(bl_entry->start) >
        le64_to_cpu(bl_entry->end), c,
        "invalid journal seq blacklist entry: start > end"))
            journal_entry_null_range(entry, vstruct_next(entry));

out:
fsck_err:
    return ret;
}

static int
journal_entry_validate_usage(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    struct jset_entry_usage *u = container_of(entry, struct jset_entry_usage, entry);
    unsigned bytes = jset_u64s(le16_to_cpu(entry->u64s)) * sizeof(u64);
    int ret = 0;

    if (journal_entry_err_on(bytes < sizeof(*u) || bytes < sizeof(*u) + u->r.nr_devs,
        c, "invalid journal entry usage: bad size")) {
            journal_entry_null_range(entry, vstruct_next(entry));
            return ret;
    }

fsck_err:
    return ret;
}

struct jset_entry_ops {
    int (*validate)(struct orca_fs *, struct jset *, struct jset_entry *, int);
};

static const struct jset_entry_ops orca_jset_entry_ops[] = {
#define x(f, nr)                                                \
    [ORCA_JSET_ENTRY_##f] = (struct jset_entry_ops) {           \
        .validate = journal_entry_validate_##f,                 \
    },                                                          \
    ORCA_JSET_ENTRY_TYPES()
#undef x
};

static int
journal_entry_validate(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    return entry->type < ORCA_JSET_ENTRY_NR ?
        orca_jset_entry_ops[entry->type].validate(c, jset, entry, write) : 0;
}

static int
jset_validate_entries(struct orca_fs *c, struct jset *jset,
    struct jset_entry *entry, int write)
{
    struct jset_entry *entry;
    int ret = 0;

    vstruct_for_each(jset, entry) {
        if (journal_entry_err_on(vstruct_next(entry) > vstruct_last(jset), c,
            "journal entry extends past end of jset")) {
                jset->u64s = cpu_to_le32((u64 *)entry - jset->_data);
                break;
        }

        ret = journal_entry_validate(c, jset, entry, write);

        if (ret)
            break;
    }

fsck_err:
    return ret;
}

static int
jset_validate(struct orca_fs *c, struct orca_dev *ca, struct jset *jset,
    u64 sector, unsigned bucket_sectors_left, unsigned sectors_read, int write)
{
    size_t bytes = vstruct_bytes(jset);
    struct orca_csum = csum;
    unsigned version;
    int ret = 0;

    if (le64_to_cpu(jset->magic) != jset_magic(c))
        return JOURNAL_ENTRY_NONE;

    version = le32_to_cpu(jset->version);

    if (journal_entry_err_on((version != ORCA_JSET_VERSION_OLD &&
        version < orcafs_metadata_version_min) ||
        version >= orcafs_metadata_version_max), c,
        "%s sector %llu seq %llu: unknown journal entry version %u",
        ca->name, sector, le64_to_cpu(jset->seq), version)
            return JOURNAL_ENTRY_BAD;

    if (journal_entry_err_on(bytes > bucket_sectors_left << 9, c,
        "%s sector %llu seq %llu: journal entry too big (%zu bytes)",
        ca->name, sector, le64_to_cpu(jset->seq), bytes))
            return JOURNAL_ENTRY_BAD;

    if (bytes > sectors_read << 9)
        return JOURNAL_ENTRY_REREAD;

    if (fsck_err_on(!orca_checksum_type_valid(c, JSET_CSUM_TYPE(jset)), c,
        "%s sector %llu seq %llu: journal entry with unknown csum, type %llu",
        ca->name, sector, le64_to_cpu(jset->seq), JSET_CSUM_TYPE(jset)))
            return JOURNAL_ENTRY_BAD;

    csum = csum_vstruct(c, JSET_CSUM_TYPE(jset), journal_nonce(jset), jset);

    if (journal_entry_err_on(orca_crc_cmp(csum, jset->csum), c,
        "invalid journal entry: last_seq > seq")) {
            jset->last_seq = jset->seq;

            return JOURNAL_ENTRY_BAD;
    }

    return 0;

fsck_err:
    return ret;
}

struct journal_read_buf {
    void *data;
    size_t size;
};

static int
journal_read_buf_realloc(struct journal_read_buf *b, size_t new_size)
{
    void *n;

    /* The bios are sized for this many pages max */
    if (new_size > JOURNAL_ENTRY_SIZE_MAX)
        return -ENOMEM;

    new_size = roundup_pow_of_two(new_size);
    n = kvpmalloc(new_size, GFP_KERNEL);

    if (!n)
        return -ENOMEM;

    kvpfree(b->data, b->size);
    b->data = n;
    b->size = new_size;

    return 0;
}

static int
journal_read_bucket(struct orca_dev *ca, struct journal_read_buf *buf,
    struct journal_list *jlist, unsigned bucket)
{
    struct orca_fs *c = ca->fs;
    struct journal_device *ja = &ca->journal;
    struct jset *j = NULL;
    unsigned sectors, sectors_read = 0;
    u64 offset = bucket_to_sector(ca, ja->buckets[bucket]);
    u64 end = offset + ca->mi.bucket_size;
    bool saw_bad = false;
    int ret = 0;

    pr_debug("reading %u", bucket);

    while (offset < end) {
        if (!sectors_read) {
            struct bio *bio;

            sectors_read = min_t(unsigned, end - offset, buf->size >> 9);
            bio = bio_kmalloc(GFP_KERNEL, buf_pages(buf->data, sectors_read << 9));
            bio_set_dev(bio, ca->disk_sb.bdev);
            bio->bi_iter.bi_sector = offset;
            bio_set_op_attrs(bio, REQ_OP_READ, 0);
            orca_bio_map(bio, buf->data, sectors_read << 9);

            ret = submit_bio_wait(bio);
            bio_put(bio);

            if (orca_dev_to_err_on(ret, ca, "journal read from sector %llu",
                offset) || orca_meta_read_fault("journal"))
                    return -EIO;

            j = buf->data;
        }

        ret = jset_validate(c, ca, j, offset, end - offset, sectors_read, READ);

        switch (ret) {
        case ORCA_FSCK_OK:
            sectors = vstruct_sectors(j, c->block_bits);
            break;

        case JOURNAL_ENTRY_REREAD:
            if (vstruct_bytes(j) > buf->size) {
                ret = journal_read_buf_realloc(buf, vstruct_bytes(j));

                if (ret)
                    return ret;
            }

            goto reread;

        case JOURNAL_ENTRY_NONE:
            if (!saw_bad)
                return 0;

            sectors = c->opts.block_size;
            goto next_block;

        case JOURNAL_ENTRY_BAD:
            saw_bad = true;

            /**
             * On checksum error we don't really trust the size
             * field of the journal entry we read, so try reading
             * again at next block boundary.
            **/
            sectors = c->opts.block_size;
            break;

        default:
            return ret;
        }

        /**
         * This happens sometimes if we don't have discards on==
         * when we've partially overwritten a bucket with new
         * journal entries. We don't need the rest of the bucket.
        **/
        if (le64_to_cpu(j->seq) < ja->bucket_seq[bucket])
            return 0;

        ja->bucket_seq[bucket] = le64_to_cpu(j->seq);

        mutex_lock(&jlist->lock);
        ret = journal_entry_add(c, ca, jlist, j, ret != 0);
        mutex_unlock(&jlist->lock);

        switch (ret) {
        case JOURNAL_ENTRY_ADD_OK:
            break;

        case JOURNAL_ENTRY_ADD_OUT_OF_RANGE:
            break;

        default:
            return ret;
        }

next_block:
        pr_debug("next");
        offset += sectors;
        sectors_read -= sectors;
        j = ((void *)j) + (sectors << 9);
    }

    return 0;
}

static void
orca_journal_read_device(struct closure *cl)
{
    struct journal_device *ja = container_of(cl, struct journal_device, read);
    struct orca_dev *ca = container_of(ja, struct orca_dev, journal);
    struct journal_list *jlist = container_of(cl->parent, struct orca_dev, journal);
    struct journal_read_buf buf = { NULL, 0 };
    u64 min_seq = u64_MAX;
    unsigned i;
    int ret;

    if (!ja->nr)
        goto out;

    ret = journal_read_buf_realloc(&buf, PAGE_SIZE);

    if (ret)
        goto err;

    pr_debug("%u journal buckets", ja->nr);

    for (i = 0; i < ja->nr; i++) {
        ret = journal_read_bucket(ca, &buf, jlist, i);

        if (ret)
            goto err;
    }

    /* Find the journal bucket with the highest sequence number */
    for (i = 0; i < ja->nr; i++) {
        if (ja->bucket_seq[i] > ja->bucket_seq[ja->cur_idx])
            ja->cur_idx = i;

        min_seq = min(ja->bucket_seq[i], min_seq);
    }

    /**
     * If there's a duplicate journal entries in mutiple buckets (which
     * definitely isn't supposed to happen, but...)--make sure to start
     * cur_idx at the last of those buckets, so we don't deadlock
     * trying to allocate.
    **/

    while (j->bucket_seq[ja->cur_idx] > min_seq &&
        ja->bucket_seq[ja->cur_idx] >
        ja->bucket_seq[(ja->cur_idx + 1) %ja->nr])
            ja-cur_idx = (ja->cur_idx + 1) % ja->nr;

    ja->sectors_free = 0;

    /**
     * Set dirty_idx to indicate the entire journal is full and needs to
     * be reclaimed--journal reclaim will immediately reclaim whatever isn't
     * pinned when it first runs.
    **/
    ja->discard_idx - ja->dirty_idx_ondisk = ja->dirty_idx = (ja->cur_idx + 1) % ja->nr;

out:
    kvpfree(buf.data, buf.size);
    percpu_ref_put(&ca->io_ref);
    closure_return(cl);
    return;

err:
    mutex_lock(&jlist->lock);
    jlist->ret = ret;
    mutex_unlock(&jlist->lock);
    goto out;
}

int
orca_journal_read(struct orca_fs *c, struct list_head *list)
{
    struct journal_list jlist;
    struct journal_replay *i;
    struct orca_dev *ca;
    unsigned iter;
    size_t keys = 0, entries = 0;
    bool degraded = false;
    int ret = 0;

    closure_init_stack(&jlist.cl);
    mutex_init(&jlist.lock);
    jlist.head = list;
    jlist.ret = 0;

    for_each_member_device(ca, c, iter) {
        if (!test_bit(ORCA_FS_REBUILD_REPLICAS, &c->flags) &&
            !(orca_dev_has_data(c, ca) & (1 << ORCA_DATA_journal)))
                continue;

        if ((ca->mi.state == ORCA_MEMBER_STATE_RW ||
            ca->mi.state == ORCA_MEMBER_STATE_RO) &&
            percpu_ref_tryget(&ca->io_ref))
                closure_call(&ca->journal.read, orca_journal_read_device,
                    system_unbound_wq, &jlist.cl);
        else
            degraded = true;
    }

    closure_sync(&jlist.cl);

    if (jlist.ret)
        return jlist.ret;

    list_for_each_entry(i, list, list) {
        struct jset_entry *entry;
        struct bkey_i *k, *_n;
        struct orca_replicas_padded replicas;
        char buf[80];

        ret = jset_validate_entries(c, &i->j, READ);

        if (ret)
            goto fsck_err;

        /**
         * If we're mounting in degraded mode--if we didn't read all
         * the devices--this is wrong.
        **/
        orca_devlist_to_replicas(&replicas.e, ORCA_DATA_journal, i->devs);

        if (!degraded && (test_bit(ORCA_FS_REBUILD_REPLICAS, &c->flags) ||
            fsck_err_on(!orca_replicas_marked(c, &replicas.e), c,
            "superblock not marked as containing replicas %s",
            (orca_replicas_entry_to_text(&PBUF(buf), &replicas.e), buf))) {
                ret = orca_mark_replicas(c, &replicas.e);

                if (ret)
                    return ret;
        }

        for_each_jset_key(k, _n, entry, &i->j)
            keys++;

        entries++;
    }

    if (!list_empty(list)) {
        i = list_last_entry(list, struct journal_replay, list);

        orca_info(c, "journal read done, %zu keys in %zu entries, seq %llu",
            keys, entries, le64_to_cpu(i->j.seq));
    }

fsck_err:
    return ret;
}

static void
__journal_write_alloc(struct journal *j, struct journal_buf *w,
    struct dev_alloc_list *devs_sorted, unsigned sectors, unsigned *replicas,
    unsigned replicas_want)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct journal_device *ja;
    struct orca_dev *ca;
    unsigned i;

    if (*replicas >= replicas_want)
        return;

    for (i = 0; i < devs_sorted->nr; i++) {
        ca = rcu_dereference(c->devs[devs_sorted->devs[i]]);

        if (!ca)
            continue;

        ja = &ca->journal;

        /**
         * Check that we can use this device and aren't already
         * using it.
        **/
        if (!ca->mi.durability || ca->mi.state != ORCA_MEMBER_STATE_RW ||
            !ja->nr || orca_bkey_has_device(bkey_i_to_s_c(&w->key),
            ca->dev_idx) || sectors > ja->sectors_free)
                continue;

        orca_dev_stripe_increment(ca, &j->wp.stripe);

        orca_bkey_append_ptr(&w->key, (struct orca_extent_ptr) {
            .offset = bucket_to_sector(ca, ja->buckets[ja->cur_idx]) +
                ca->mi.bucket_size - ja->sectors_free,
            .dev = ca->dev_idx;
        });

        ja->sectors_free -= sectors;
        ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);
        *replicas += ca->mi.durability;

        if (*replicas >= replicas_want)
            break;
    }
}

/**
 * journal_next_bucket--move on to the next journal bucket if possible.
**/
static int
journal_write_alloc(struct journal *j, struct journal_buf *w, unsigned sectors)
{
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct journal_device *ja;
    struct orca_dev *ca;
    struct dev_alloc_list devs_sorted;
    unsigned i, replicas = 0, replicas_want = READ_ONCE(c->opts.metadata_replicas);

    rcu_read_lock();
    devs_sorted = orca_dev_alloc_list(c, &j->wp.stripe, &c->rw_devs[ORCA_DATA_journal]);
    __journal_write_alloc(j, w, &devs_sorted, sectors, &replicas, replicas_want);

    if (replicas >= replicas_want)
        goto done;

    for (i = 0; i < devs_sorted->nr; i++) {
        ca = rcu_dereference(c->devs[devs_sorted.devs[i]]);

        if (!ca)
            continue;

        ja = &ca->journal;

        if (sectors > ja->sectors_Free && sectors <= ca->mi.bucket_size &&
            orca_journal_dev_buckets_available(j, ja, journal_space_discarded)) {
                ja->curr_idx = (ja->cur_idx + 1) % ja->nr;
                ja->sectors_free = ca->mi.bucket_size;

                /**
                 * ja->bucket_seq[ja->cur_idx] must always have
                 * something sensible.
                **/
                ja->bucket_seq[ja->cur_idx] = le64_to_cpu(w->data->seq);
        }
    }

    __journal_write_alloc(j, w, &devs_sorted, sectors, &replicas, replicas_want);

done:
    rcu_read_unlock();

    return replicas >= c->opts.metadata_replicas_required ? 0 : -EROFS;
}

static void
journal_write_compat(struct jset *jset)
{
    struct jset_entry *i, *next, *prev = NULL;

    /**
     * Simple compaction, dropping empty jset_entries (from journal
     * reservations that weren't fully utilized) and merging jset_entries
     * that can be.
     *
     * If we wanted to be really fancy here, we could sort all the keys
     * in the jset and drop keys that were overwritten--probably not worth
     * it.
    **/
    vstruct_for_each_safe(jset, i, next) {
        unsigned u64s = le16_to_cpu(i->u64s);

        if (!u46s)
            continue;

            /* Can we merge with previous entry? */
            if (prev && i->btree_id == prev->btree_id && i->level == prev->level &&
                i->type == prev->type && i->type == ORCA_JSET_ENTRY_btree_keys &&
                le16_to_cpu(prev->u64s) + u64s <= U16_MAX) {
                    memmove_u64s_down(vstruct_next(prev), i->_data, u64s);
                    le16_add_cpu(&prev->u64s, u64s);
                    continue;
            }

            /* Couldn't merge, move i into new position (after prev) */
            prev = prev ? vstruct_next(prev) : jset->start;

            if (i != prev)
                memmove_u64s_down(prev, i, jset_u64s(u64s));
    }

    prev = prev ? vstruct_next(prev) : jset->start;
    jset->u64s = cpu_to_le32((u64 *)prev - jset->_data);
}

static void
journal_buf_realloc(struct journal *j, struct journal_buf *buf)
{
    /* We aren't holding j->lock */
    unsigned new_size = READ_ONCE(j->buf_size_want);
    void *new_buf;

    if (buf->buf_size >= new_size)
        return;

    new_buf = kvpmalloc(new_size, GFP_NOIO | __GFP_NOWARN);

    if (!new_buf)
        return;

    memcpy(new_buf, buf->data, buf->buf_size);
    kvpfree(buf->data, buf->buf_size);
    buf->data = new_buf;
    buf->buf_size = new_size;
}

static void
journal_write_done(struct closure *cl)
{
    struct journal *j = container_of(cl, struct journal, io);
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct journal_buf *w = journal_prev_buf(j);
    struct orca_devs_list devs = orca_bkey_devs(bkey_i_to_s_c(&w->key));
    struct orca_replicas_padded replicas;
    u64 seq = le64_to_cpu(w->data->seq);
    u64 last_seq = le64_to_cpu(w->data->last_seq);

    orca_time_stats_update(j->write_time, j->write_start_time);

    if (!devs.nr) {
        orca_err(c, "Unable to write journal to sufficient devices");
        goto err;
    }

    orca_devlist_to_replicas(&replicas.e, ORCA_DATA_journal, devs);

    if (orca_mark_replicas(c, &replicas.e))
        goto err;

    spin_lock(&j->lock);

    if (seq >= j->pin.front)
        journal_seq_pin(j, seq)->devs = devs;

    j->seq_ondisk = seq;
    j->last_seq_ondisk = last_seq;
    orca_journal_space_available(j);
    mod_delayed_work(c->journal_reclaim_wq, &j->reclaim_work, 0);

out:
    closure_debug_destroy(cl);
    BUG_ON(!j->reservations.prev_buf_unwritten);

    atomic64_sub(((union journal_res_state) {
        .prev_buf_unwritten = 1}).v, &j->reservations.counter);
    closure_wake_up(&w->wait);
    journal_wake(j);

    if (test_bit(JOURNAL_NEED_WRITE, &j->flags))
        mod_delayed_work(system_freezeable_wq, &j->write_work, 0);

    spin_unlock(&j->lock);
    return;

err:
    orca_fatal_error(c);
    spin_lock(&j->lock);
    goto out;
}

static void
journal_write_endio(struct bio *bio)
{
    struct orca_dev *ca = bio->bi_private;
    struct journal *j = &ca->fs->journal;

    if (orca_dev_io_err_on(bio->bi_status, ca, "journal write: %s",
        orca_blk_status_to_str(bio->bi_status)) ||
        orca_meta_write_fault("journal")) {
            struct journal_buf *w = journal_prev_buf(j);
            unsigned long flags;

            spin_lock_irqsave(&j->err_lock, flags);
            orca_bkey_drop_device(bkey_i_to_s(&w->key), ca->dev_idx);
            spin_unlock_irqrestore(&j->err_lock, flags);
    }

    closure_put(&j->io);
    percpu_ref_put(&ca->io_ref);
}

void
orca_journal_write(struct closure *cl)
{
    struct journal *j = container_of(cl, struct journal, io);
    struct orca_fs *c = container_of(j, struct orca_fs, journal);
    struct orca_dev *ca;
    struct journal_buf *w = journal_prev_buf(j);
    struct jset_entry *start, *end;
    struct jset *jset;
    struct bio *bio;
    struct orca_extent_ptr *ptr;
    bool validate_before_checksum = false;
    unsigned i, sectors, bytes, u64s;
    int ret;

    orca_journal_pin_put(j, le64_to_cpu(w->data->seq));
    journal_buf_realloc(j, w);
    jset = w->data;
    j->write_start_time = local_clock();

    /**
     * New btree roots are set by journaling them; when the journal entry
     * gets written, we have to propogate them to c->btree_roots.
     *
     * But, every journal entry we write has to contain all the btree roots
     * (at least for now). So, after we copy btree roots to c->btree_roots,
     * we have to get any missing btree roots and add them to this journal
     * entry.
    **/
    orca_journal_entries_to_btree_roots(c, jset);
    start = end = vstruct_last(jset);
    end = orca_btree_roots_to_journal_entries(c, jset->start, end);
    end = orca_journal_super_entries_add_common(c, end, le64_to_cpu(jset->seq));
    u64s = (u64 *)end - (u64 *)start;
    BUG_ON(u64s > j->entry_u64s_reserved);

    le32_add_cpu(&jset->u64s, u64s);
    BUG_ON(vstruct_sectors(jset, c->block_bits) > w->sectors);

    journal_write_compact(jset);
    jset->read_clock = cpu_to_le16(c->bucket_clock[READ].hand);
    jset->write_block = cpu_to_le16(c->bucket_clock[WRITE].hand);
    jset->magic = cpu_to_le64(jset_magic(c));
    jset->version = c->sb.version < orcafs_metadata_version_new_versioning ?
        cpu_to_le32(ORCA_JSET_VERSION_OLD) : cpu_to_le32(c->sb.version);

    SET_JSET_BIG_ENDIAN(jset, CPU_BIG_ENDIAN);
    SET_JSET_CSUM_TYPE(jset, orca_meta_checksum_type(c));

    if (orca_csum_type_is_encryption(JSET_CSUM_TYPE(jset)))
        validate_before_checksum = true;

    if (le32_to_cpu(jset->version) < orcafs_metadata_version_max)
        validate_before_checksum = true;

    if (validate_before_checksum && jset_validate_entries(c, jset, WRITE))
        goto err;

    orca_encrypt(c, JSET_CSUM_TYPE(jset), journal_nonce(jset),
        jset->encrypted_start, vstruct_end(jset) - (void *)jset->encrypted_start);
    jset->csum = csum_vstruct(c, JSET_CSUM_TYPE(jset), journal_nonce(jset), jset);

    if (!validate_before_checksum && jset_validate_entries(c, jset, WRITE))
        goto err;

    sectors = vstruct_sectors(jset, c->block_bits);
    BUG_ON(sectors > w->sectors);
    bytes = vstruct_bytes(jset);
    memset((void *)jset + bytes, 0, (sectors << 9) - bytes);

retry_alloc:
    spin_lock(&j->lock);
    ret = journal_write_alloc(j, w, sectors);

    if (ret && j->can_discard) {
        spin_unlock(&j->lock);
        orca_journal_do_discards(j);
        goto retry_alloc;
    }

    /**
     * Write is allocated, no longer need to account for it in
     * orca_journal_space_available().
    **/
    w->sectors = 0;

    /**
     * Journal entry has been compacted and allocated, recalculate space
     * available.
    **/
    orca_journal_space_available(j);
    spin_unlock(&j->lock);

    if (ret) {
        orca_err(c, "Unable to allocate journal write");
        orca_fatal_error(c);
        continue_at(cl, journal_write_done, system_highpri_wq);
        return;
    }

    if (c->opts.nochanges)
        goto no_io;

    extent_for_each_ptr(bkey_i_to_s_extent(&w->key), ptr) {
        ca = orca_dev_bkey_exists(c, ptr->dev);

        if (!percpu_ref_tryget(&c->io_ref)) {
            orca_err(c, "missing device for journal write\n");
            continue;
        }

        this_cpu_add(ca->io_done->sectors[WRITE][ORCA_DATA_journal], sectors);

        bio = ca->journal.bio;
        bio_reset(bio);
        bio_set_dev(bio, ca->disk_sb.bdev);

        bio->bi_iter.bi_sector = ptr->offset;
        bio->bi_end_io = journal_write_endio;
        bio->bi_private = ca;
        orca_bio_map(bio, jset, sectors << 9);

        trace_journal_write(bio);
        closure_bio_submit(bio, cl);
        ca->journal.bucket_seq[ca->journal.cur_idx] = le64_to_cpu(jset->seq);
    }

    for_each_rw_member(ca, c, i) {
        if (journal_flushes_device(ca) && !orca_bkey_has_device(bkey_i_to_s_c(&w->key), i)) {
            percpu_ref_get(&ca->io_ref);

            bio = ca->journal.bio;
            bio_reset(bio);
            bio_set_dev(bio, ca->disk_sb.bdev);
            bio->bi_opf = REQ_QP_FLUSH;
            bio->bi_end_io = journal_write_endio;
            bio->bi_private = ca;
            closure_bio_submit(bio, cl);
        }
    }

no_io:
    orca_bucket_seq_cleanup(c);
    continue_at(cl, journal_write_done, system_highpri_wq);
    return;

err:
    orca_inconsistent_error(c);
    continue_at(cl, journal_write_done, system_highpri_wq);
}
