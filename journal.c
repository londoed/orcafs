#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include "orcafs.h"
#include "journal.h"

static void
dump_transaction(struct orca_sb_info *sbi, orca_trans *trans)
{
    int i;
    orca_log_entry *le = trans->start_addr;

    for (i = 0; i < trans->num_entries; i++) {
        orca_dbg("ao %llx tid %x gid %x type %x sz %x\n", le->addr_offset,
            le->trans_id, le->gen_id, le->type, le->size);
        le++;
    }
}

static inline uint32_t
next_log_entry(uint32_t jsize, uint32_t le_off)
{
    le_off += LOGENTRY_SIZE;

    if (le_off >= jsize)
        le_off = 0;

    return le_off;
}

static inline uint32_t
prev_log_entry(uint32_t jsize, uint32_t le_off)
{
    if (le_off == 0)
        le_off = jsize;

    le_off -= LOGENTRY_SIZE;

    return le_off;
}

static inline uint16_t
next_gen_id(uint16_t gen_id)
{
    gen_id++;

    /* Check for wraparound */
    if (gen_id == 0)
        gen_id++;

    return gen_id;
}

static inline uint16_t
prev_gen_id(uint16_t gen_id)
{
    gen_id--;

    /* Check for wraparound */
    if (gen_id == 0)
        gen_id--;

    return gen_id;
}

/* Undo a valid log entry */
static inline void
orca_undo_log_entry(struct super_block *sb, orca_log_entry *le)
{
    char *data;

    if (le->size > 0) {
        data = orca_get_block(sb, le64_to_cpu(le->addr_offset));

        /* Undo changes by flushing the log entry to orcafs */
        orca_memunlock_range(sb, data, le->size);
        memcpy(data, le->data, le->size);
        orca_memlock_range(sb, data, le->size);
        orca_flush_buffer(data, le->size, false);
    }
}

/**
 * Can be called during journal recovery or transaction abort.
 * We need to undo in the reverse order.
**/
static void
orca_undo_transaction(struct super_block *sb, orca_trans *trans)
{
    orca_log_entry *le;
    int i;
    uint16_t gen_id = trans->gen_id;

    le = trans->start_addr + trans->num_used;
    le--;

    for (i = trans->num_used - 1; i >= 0; i--, le--) {
        if (gen_id == le16_to_cpu(le->gen_id))
            orca_undo_log_entry(sb, le);
    }
}

/**
 * Can be called by either during log cleaning or during journal recovery.
**/
static void
orca_flush_transaction(struct super_block *sb, orca_trans *trans)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_log_entry *le = trans->start_addr;
    int i;
    char *data;

    for (i = 0; i < trans->num_used; i++, le++) {
        data = orca_get_block(sb, le64_to_cpu(le->addr_offset));

        if (sbi->redo_log) {
            orca_memunlock_range(sb, data, le->size);
            memcpy(data, le->data, le->size);
            orca_memlock_range(sb, data, le->size);
        } else {
            orca_flush_buffer(data, le->size, false);
        }
    }
}

static inline void
invalidate_gen_id(orca_log_entry *le)
{
    le->gen_id = 0;
    orca_flush_buffer(le, LOGENTRY_SIZE, false);
}

/**
 * Can be called by either during log cleaning or during journal recovery.
**/
static void
orca_invalidate_log_entries(struct super_block *sb, orca_trans *trans)
{
    orca_log_entry *le = trans->start_addr;
    int i;

    orca_memunlock_range(sb, trans->start_addr, trans->num_entries *
        LOGENTRY_SIZE);

    for (i = 0; i < trans->num_entries; i++) {
        invalidate_gen_id(le);

        if (le->type == LE_START) {
            PERSISTENT_MARK();
            PERSISTENT_BARRIER();
        }

        le++;
    }

    orca_memlock_range(sb, trans->start_addr, trans->num_entries *
        LOGENTRY_SIZE);
}

/**
 * Can be called by either during log cleaning or during journal recovery.
**/
static void
orca_redo_transaction(struct super_block *sb, orca_trans *trans, bool recover)
{
    orca_log_entry *le = trans->start_addr;
    int i;
    uint16_t gen_id = trans->gen_id;
    char *data;

    for (i = 0; i < trans->num_entries; i++) {
        if (gen_id == le16_to_cpu(le->gen_id) && le->size > 0) {
            data = orca_get_block(sb, le64_to_cpu(le->addr_offset));

            /* Flush data if we are called during recovery */
            if (recover) {
                orca_memunlock_range(sb, data, le->size);
                memcpy(data, le->data, le->size);
                orca_memlock_range(sb, data, le->size);
            }

            orca_flush_buffer(data, le->size, false);
        }

        le++;
    }
}

/**
 * Recover the transaction ending at a valid log entry.
 * Called for Undo log and traverses the journal backward.
**/
static uint32_t
orca_recover_transaction(struct super_block *sb, uint32_t head, uint32_t tail,
    orca_log_entry *le)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_trans trans;
    bool cmt_or_abrt_found = false, start_found = false;
    uint16_t gen_id = le16_to_cpu(le->gen_id);

    memset(&trans, 0, sizeof(trans));
    trans.trans_id = le32_to_cpu(le->trans_id);
    trans.gen_id = gen_id;

    do {
        trans.num_entries++;
        trans.num_used++;

        if (gen_id == le16_to_cpu(le->gen_id)) {
            /* Handle committed/aborted transactions */
            if (le->type & LE_COMMIT | le->type & LE_ABORT)
                cmt_or_abrt_found = true;

            if (le->type & LE_START) {
                trans.start_addr = le;
                start_found = true;
                break;
            }
        }

        if (tail == 0 || tail == head)
            break;

        /* Previous log entry */
        le--;

        /* Handle uncommitted transactions */
        if ((gen_id == le16_to_cpu(le->gen_id)) && (le->type & LE_COMMIT ||
            le->type & LE_ABORT)) {
                BUG_ON(trans.trans_id == le32_to_cpu(le->trans_id));
                le++;
                break;
        }

        tail = prev_log_entry(sbi->jsize, tail);
    } while (1);

    if (start_found && !cmt_or_abrt_found)
        orca_undo_transaction(sb, &trans);

    if (gen_id == MAX_GEN_ID) {
        if (!start_found)
            trans.start_addr = le;

        /**
         * Make sure the changes made by orca_undo_transaction() are
         * persistent before invalidating the log entries.
        **/
        if (start_found && !cmt_or_abrt_found) {
            PERSISTENT_MARK();
            PERSISTENT_BARRIER();
        }

        orca_invalidate_log_entries(sb, &trans);
    }

    return tail;
}

/**
 * Process the transaction staring at a valid log entry.
 * Called by the log cleaner and journal recovery.
**/
static uint32_t
orca_process_transaction(struct super_block *sb, uint32_t head, uint32_t tail,
    orca_log_entry *le, bool recover)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_trans trans;
    uint16_t gen_id;
    uint32_t new_head = head;

    gen_id = le16_to_cpu(le->gen_id);

    if (!(le->type & LE_START)) {
        orca_dbg("Starting of trans %x but LE_START not set. gen_id %d\n",
            le32_to_cpu(le->trans_id), gen_id);
        return next_log_entry(sbi->jsize, new_head);
    }

    memset(&trans, 0, sizeof(trans));
    trans.trans_id = le32_to_cpu(le->trans_id);
    trans.start_addr = le;
    trans.gen_id = gen_id;

    do {
        trans.num_entries++;
        trans.num_used++;
        new_head = next_log_entry(sbi->jsize, new_head);

        /* Handle committed/aborted transactions */
        if ((gen_id == le16_to_cpu(le->gen_id)) && (le->type & LE_COMMIT ||
            le->type & LE_ABORT)) {
                head = new_head;

                if ((le->type & LE_COMMIT) && sbi->redo_log)
                    orca_redo_transaction(sb, &trans, recover);

                if (gen_id == MAX_GEN_ID) {
                    if ((le->type & LE_COMMIT) && sbi->redo_log) {
                        PERSISTENT_MARK();
                        PERSISTENT_BARRIER();
                    }

                    orca_invalidate_log_entries(sb, &trans);
                }

                break;
        }

        /* Next log entry */
        le++;

        /* Handle uncommitted transactions */
        if ((new_head == tail) || ((gen_id == le16_to_cpu(le->gen_id)) &&
            (le->type & LE_START))) {
                /* Found a new valid transaction w/o finding a commit */
                if (recover) {
                    /**
                     * If this function is called by recovery, move ahead
                     * even if we didn't find a commit record for this
                     * transaction.
                    **/
                    head = new_head;

                    if (gen_id == MAX_GEN_ID)
                        orca_invalidate_log_entries(sb, &trans);
                }

                orca_dbg("no cmt tid %d sa %p nle %d tail %x gen %d\n",
                    trans.trans_id, trans.start_addr, trans.num_entries,
                    trans.num_used, trans.gen_id);

                /* dump_transaction(sbi, &trans); */
                break;
        }
    } while (new_head != tail);

    return head;
}

static void
orca_clean_journal(struct super_block *sb, bool unmount)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);
    uint32_t head = le32_to_cpu(journal->head);
    uint32_t new_head, tail;
    uint16_t gen_id;
    volatile __le64 *ptr_tail_gen_id = (volatile __le64 *)&journal->tail;
    u64 tail_gen_id;
    orca_log_entry *le;

    /**
     * Atomically read both tail and gen_id of journal. Normally use of
     * volatile is prohibited in kernel code but since we use volatile
     * to write to journal's tail and gen_id atomically, we thought we
     * should use volatile to read them simultaneneously and avoid locking
     * them.
    **/
    tail_gen_id = le64_to_cpu(*ptr_tail_gen_id);
    tail = tail_gen_id & 0xFFFFFFFF;
    gen_id = (tail_gen_id >> 32) & 0xFFFF;

    /* Journal wraparound happened. So head points to prev gen id */
    if (tail < head)
        gen_id = prev_gen_id(gen_id);

    orca_dbg_trans("Starting journal cleaning %x-->%x\n", head, tail);

    while (head != tail) {
        le = (orca_log_entry *)(sbi->journal_base_addr + head);

        if (gen_id == le16_to_cpu(le->gen_id)) {
            /* Found a valid log entry, process the transaction */
            new_head = orca_process_transaction(sb, head, tail, le, false);

            /* No progress was made--return */
            if (new_head == head)
                break;

            head = new_head;
        } else {
            if (gen_id == MAX_GEN_ID) {
                orca_memunlock_range(sb, le, sizeof(*le));
                invalidate_gen_id(le);
                orca_memlock_range(sb, le, sizeof(*le));
            }

            head = next_log_entry(sbi->jsize, head);
        }

        /* Handles journal wraparound */
        if (head == 0)
            gen_id = next_gen_id(gen_id);
    }

    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
    orca_memunlock_range(sb, journal, sizeof(*journal));

    journal->head = cpu_to_le32(head);
    orca_memlock_range(sb, journal, sizeof(*journal));
    orca_flush_buffer(*journal->head, sizeof(journal->head), true);

    if (unmount) {
        PERSISTENT_MARK();

        if (journal->head != journal->tail)
            orca_dbg("ORCAFS: umount, but journal not empty %x:%x\n",
                le32_to_cpu(journal->head), le32_to_cpu(journal->tail));

        PERSISTENT_BARRIER();
    }

    orca_dbg_trans("Leaving journal cleaning %x-->%x\n", head, tail);
}

static void
log_cleaner_try_sleeping(struct orca_sb_info *sbi)
{
    DEFINE_WAIT(wait);
    prepare_to_wait(%sbi->log_cleaner_wait, &wait, TASK_INTERRUPTIBLE);
    schedule();
    finish_wait(&sbi->log_cleaner_wait, &wait);
}

static int
orca_log_cleaner(void *arg)
{
    struct super_block *sb = (struct super_block *)arg;
    struct orca_sb_infor *sbi = ORCA_SB(sb);

    orca_dbg_trans("Running log cleaner thread\n");

    for (;;) {
        log_cleaner_try_sleeping(sbi);

        if (kthread_should_stop())
            break;

        orca_clean_journal(sb, false);
    }

    orca_clean_journal(sb, true);
    orca_dbg_trans("Exiting log cleaner thread\n");

    return 0;
}

static int
orca_journal_cleaner_run(struct super_block *sb)
{
    int ret = 0;
    struct orca_sb_info *sbi = ORCA_SB(sb);

    init_waitqueue_head(&sbi->log_cleaner_wait);
    sbi->log_cleaner_thread = kthread_run(orca_log_cleaner, sb,
        "orca_log_cleaner_0x%llx", sbi->phys_addr);

    if (IS_ERR(sbi->log_cleaner_thread)) {
        /* Failure at boot is fatal */
        orca_err(sb, "Failed to start orca log cleaner thread\n");
        ret = -1;
    }

    return ret;
}

int
orca_journal_soft_init(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);

    sbi->next_trans_id = 0;
    sbi->journal_base_addr = orca_get_block(sb, le64_to_cpu(journal->base));
    sbi->jsize = le32_to_cpu(journal->size);
    mutex_init(&sbi->journal_mutex);
    sbi->redo_log = !!le16_to_cpu(journal->redo_logging);

    return orca_journal_cleaner_run(sb);
}

int
orca_journal_hard_init(struct super_block *sb, uint64_t base, uint32_t size)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);

    orca_memunlock_range(sb, journal, sizeof(*journal));
    journal->base = cpu_to_le64(base);
    journal->size = cpu_to_le32(size);
    journal->gen_id = cpu_to_le16(1);
    journal->head = journal->tail = 0;

    /* Let's undo logging for now */
    journal->redo_logging = 0;
    orca_memlock_range(sb, journal, sizeof(*journal));

    sbi->journal_base_addr = orca_get_block(sb, base);
    orca_memunlock_range(sb, sbi->journal_base_addr, size);
    memset_nt(sbi->journal_base_addr, 0, size);
    orca_memlock_range(sb, sbi->journal_base_addr, size);

    return orca_journal_soft_init(sb);
}

static void
wakeup_log_cleaner(struct orca_sb_info *sbi)
{
    if (!waitqueue_active(&sbi->log_cleaner_wait))
        return;

    orca_dbg_trans("Waking up the cleaner thread\n");
    wake_up_interruptible(&sbi->log_cleaner_wait);
}

int
orca_journal_uninit(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    if (sbi->log_cleaner_thread)
        kthread_stop(sbi->log_cleaner_thread);

    return 0;
}

inline orca_trans *
orca_current_transaction(void)
{
    return (orca_trans *)current->journal_info;
}

static int
orca_free_logentries(int max_log_entries)
{
    orca_dbg("orca_free_logentries: Not Implemented\n");
    return -ENOMEM;
}

orca_trans *
orca_new_transaction(struct super_block *sb, int max_log_entries)
{
    orca_journal *journal = orca_get_journal(sb);
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_trans *trans;
    uint32_t head, tail, req_size, avail_size;
    uint64_t base;

#if 0
    trans = orca_current_transaction();

    if (trans) {
        BUG_ON(trans->t_journal != journal);
        return trans;
    }
#endif

    /* If it is an undo log, need more log-entry for commit record */
    if (!sbi->redo_log)
        max_log_entries++;

    trans = orca_alloc_transaction();

    if (!trans)
        return ERR_PTR(-ENOMEM);

    memset(trans, 0, sizeof(*trans));
    trans->num_used = 0;
    trans->num_entries = max_log_entries;
    trans->t_journal = journal;
    req_size = max_log_entries << LESIZE_SHIFT;

    mutex_lock(&sbi->journal_mutex);
    tail = le32_to_cpu(journal->tail);
    head = le32_to_cpu(journal->head);
    trans->trans_id = sbi->next_trans_id++;

again:
    trans->gen_id = le16_to_cpu(journal->gen_id);
    avail_size = (tail >= head) ? (sbi->jsize - (tail - head)) : (head - tail);
    avail_size -= LOGENTRY_SIZE;

    if (avail_size < req_size) {
        uint32_t freed_size;

        /* Run the log cleaner function to free some log entries */
        freed_size = orca_free_logentries(max_log_entries);

        if ((avail_size + freed_size) < req_size)
            goto journal_full;
    }

    base = le64_to_cpu(journal->base) + tail;
    tail += req_size;

    /**
     * Journal wraparound because of this transaction allocation.
     * Start the transaction from the beginning of the journal so
     * that we don't have any wraparound within a transaction.
    **/
    orca_memunlock_range(sb, journal, sizeof(*journal));

    if (tail >= sbi->jsize) {
        u64 *ptr;
        tail = 0;
        ptr = (u64 *)&journal->tail;

        /* Writing 8-bytes atomically setting tail to 0 */
        set_64bit(ptr, (__force u64)cpu_to_le64((u64)next_gen_id(
            le16_to_cpu(journal->gen_id)) << 32));
        orca_memlock_range(sb, journal, sizeof(*journal));
        orca_dbg_trans("Journal wrapped. tail %x gid %d cur tid %d\n",
            le32_to_cpu(journal->tail), le16_to_cpu(journal->gen_id),
            sbi->next_trans_id - 1);
        goto again;
    } else {
        journal->tail = cpu_to_le32(tail);
        orca_memunlock_range(sb, journal, sizeof(*journal));
    }

    orca_flush_buffer(&journal->tail, sizeof(u64), false);
    mutex_unlock(&sbi->journal_mutex);
    avail_size -= req_size;

    /* Wake up the log cleaner if required */
    if ((sbi->jsize - avail_size) > (sbi->jsize >> 3))
        wakeup_log_cleaner(sbi);

    orca_dbg_trans("New transaction tid %d nle %d avl sz %x sa %llx\n",
        trans->trans_id, max_log_entries, avail_size, base);
    trans->start_addr = orca_get_block(sb, base);
    trans->parent = (orca_trans *)current->journal_info;
    current->journal_info = trans;

    return trans;

journal_full:
    mutex_unlock(&sbi->journal_mutex);
    orca_err(sb, "Journal full. base %llx sz %x head:tail %x:%x ncl %x\n",
        le64_to_cpu(journal->base), le32_to_cpu(journal->size),
        le32_to_cpu(journal->head), le32_to_cpu(journal->tail),
        max_log_entries);
    orca_free_transaction(trans);

    return ERR_PTR(-EAGAIN);
}

static inline void
orca_commit_logentry(struct super_block *sb, orca_trans *trans,
    orca_log_entry *le)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    if (sbi->redo_log) {
        /* Redo Log */
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();

        /* Atomically write the commit type */
        le->type |= LE_COMMIT;
        barrier();

        /* Atomically make the log entry valid */
        le->gen_id = cpu_to_le16(trans->gen_id);
        orca_flush_buffer(le, LOGENTRY_SIZE, false);
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();

        /* Update orcafs in place */
        orca_flush_transaction(sb, trans);
    } else {
        /**
         * Undo Log: Update orcafs in place--currently already done, so
         * only need to clflush.
        **/
        orca_flush_transaction(sb, trans);
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();

        /* Atomically write the commit type */
        le->type |= LE_COMMIT;
        barrier();

        /* Atomically make the log entry valid */
        le->gen_id = cpu_to_le16(trans->gen_id);
        orca_flush_buffer(le, LOGENTRY_SIZE, true);
    }
}

int
orca_add_logentry(struct super_block *sb, orca_trans *trans, void *addr,
    uint16_t size, u8 type)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_log_entry *le;
    int num_les = 0, i;
    uint64_t le_start = size ? orca_get_addr_off(sbi, addr) : 0;
    uint8_t le_size;

    if (trans == NULL:)
        return -EINVAL;

    le = trans->start_addr + trans->num_used;

    if (size == 0) {
        /* Atleast one log entry required for commit/abort log entry */
        if ((type & LE_COMMIT) || (type & LE_ABORT))
            num_les = 1;
    } else {
        num_les = (size + sizeof(le->data) - 1) / sizeof(le->data);
    }

    orca_dbg_trans("add le id %d size %x num_les %d tail %x le %p\n",
        trans->trans_id, size, trans->num_entries, trans->num_used, le);

    if ((trans->num_used + num_les) > trans->num_entries) {
        orca_err(sb, "Log entry full. tid %x ne %x tail %x size %x\n",
            trans->trans_id, trans->num_entries, trans->num_used, size);
        dump_transaction(sbi, trans);
        dump_stack();

        return -ENOMEM;
    }

    orca_memunlock_range(sb, le, sizeof(*le) * num_les);

    for (i = 0; i < num_les; i++) {
        le->addr_offset = cpu_to_le64(le_start);
        le->trans_id = cpu_to_le32(trans->trans_id);
        le_size = (i == (num_les - 1)) ? size : sizeof(le->data);
        le->size = le_size;
        size -= le_size;

        if (le_size)
            memcpy(le->data, addr, le_size);

        le->type = type;

        if (i == 0 && trans->num_used == 0)
            le->type |= LE_START;

        trans->num_used++;

        /* Handle special log entry */
        if (i == (num_les - 1) && (type & LE_COMMIT)) {
            orca_commit_logentry(sb, trans, le);
            orca_memlock_range(sb, le, sizeof(*le) * num_les);

            return 0;
        }

        /**
         * Put a compile time barrier so that compiler doesn't reorder
         * the writes to the log entry.
        **/
        barrier();

        /* Atomically make the log entry valid */
        le->gen_id = cpu_to_le16(trans->gen_id);
        orca_flush_buffer(le, LOGENTRY_SIZE, false);

        addr += le_size;
        le_start += le_size;
        le++;
    }

    orca_memlock_range(sb, le, sizeof(*le) * num_les);

    if (!sbi->redo_log) {
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    return 0;
}

int
orca_commit_transaction(struct super_block *sb, orca_trans *trans)
{
    if (trans == NULL)
        return 0;

    /* Add commit log entry */
    orca_add_logentry(sb, trans, NULL, 0, LE_COMMIT);
    orca_dbg_trans("Completing transaction for id %d\n", trans->trans_id);

    current->journal_info = trans->parent;
    orca_free_transaction(trans);

    return 0;
}

int
orca_abort_transaction(struct super_block *sb, orca_trans *trans)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    if (trans == NULL)
        return 0;

    orca_dbg_trans("Abort trans for tid %x sa %p %d tail %x gen %d\n",
        trans->trans_id, trans->start_addr, trans->num_entries,
        trans->num_used, trans->gen_id);
    dump_transaction(sbi, trans);

    if (!sbi->redo_log) {
        /* Undo Log */
        orca_undo_transaction(sb, trans);
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    /* Add an abort log entry */
    orca_add_logentry(sb, trans, NULL, 0, LE_ABORT);
    current->journal_info = trans->parent;
    orca_free_transaction(trans);

    return 0;
}

static void
invalidate_remaining_journal(struct super_block *sb, void *journal_vaddr,
    uint32_t jtail, uint32_t jsize)
{
    orca_log_entry *le = (orca_log_entry *)(journal_vaddr + jtail);
    void *start = le;

    orca_memunlock_range(sb, start, jsize - jtail);

    while (jtail < jsize) {
        invalidate_gen_id(le);
        le++;
        jtail += LOGENTRY_SIZE;
    }

    orca_memlock_range(sb, start, jsize - jtail);
}

/**
 * We need to increse the gen_id to invalidate all of the journal log
 * entries. This is because after the recovery, we may still have some
 * valid log entries beyond the tail (before power failure, they become
 * persistent before the journal tail could become persistent).
 * Should gen_id and head be updated atomically? Not necessarily? We can
 * update gen_id before journal head because gen_id and head are in the
 * same cacheline.
**/
static void
orca_forward_journal(struct super_block *sb, struct orca_sb_info *sbi,
    orca_journal *journal)
{
    uint16_t gen_id = le16_to_cpu(journal->gen_id);

    /* Handle gen_id wraparound */
    if (gen_id == MAX_GEN_ID)
        invalidate_remaining_journal(sb, sbi->journal_base_addr.
            le32_to_cpu(journal->tail), sbi->jsize);

    PERSISTENT_MARK();
    gen_id = next_gen_id(gen_id);

    /* Make all changes persistent before advancing gen_id and head */
    PERSISTENT_BARRIER();
    orca_memunlock_range(sb, journal, sizeof(*journal));
    journal->gen_id = cpu_to_le16(gen_id);
    barrier();

    journal->head = journal->tail;
    orca_memlock_range(sb, journal, sizeof(*journal));
    orca_flush_buffer(journal, sizeof(*journal), false);
}

static int
orca_recover_undo_journal(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);
    uint32_t tail = le32_to_cpu(journal->tail);
    uint32_t head = le32_to_cpu(journal->head);
    uint16_t gen_id = le16_to_cpu(journal->gen_id);
    orca_log_entry *le;

    while (head != tail) {
        /* Handle journal wraparound */
        if (tail == 0)
            gen_id = prev_gen_id(gen_id);

        tail = prev_log_entry(sbi->jsize, tail);
        le = (orca_log_entry *)(sbi->journal_base_addr + tail);

        if (gen_id == le16_to_cpu(le->gen_id)) {
            tail = orca_recover_transaction(sb, head, tail, le)
        } else {
            if (gen_id == MAX_GEN_ID) {
                orca_memunlock_range(sb, le, sizeof(*le));
                invalidate_gen_id(le);
                orca_memlock_range(sb, le, sizeof(*le));
            }
        }
    }

    orca_forward_journal(sb, sbi, journal);
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    return 0;
}

static int
orca_recover_redo_journal(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);
    uint32_t tail = le32_to_cpu(journal->tail);
    uint32_t head = le32_to_cpu(journal->head);
    uint16_t gen_id = le16_to_cpu(journal->gen_id);
    orca_log_entry *le;

    /* Journal wrapped around. So head points to previous gen_id */
    if (tail < head)
        gen_id = prev_gen_id(gen_id);

    while (head != tail) {
        le = (orca_log_entry *)(sbi->journal_base_addr + head);

        if (gen_id == le16_to_cpu(le->gen_id)) {
            head = orca_process_transaction(sb, head, tail, le, true);
        } else {
            if (gen_id == MAX_GEN_ID) {
                orca_memunlock_range(sb, le, sizeof(*le));
                invalidate_gen_id(le);
                orca_memlock_range(sb, le, sizeof(*le));
            }

            head = next_log_entry(sbi->jsize, head);
        }

        /* Handle journal wraparound */
        if (head == 0)
            gen_id = next_gen_id(gen_id);
    }

    orca_forward_journal(sb, sbi, journal);
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    return 0;
}

int
orca_recover_journal(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    orca_journal *journal = orca_get_journal(sb);
    uint32_t tail = le32_to_cpu(journal->tail);
    uint32_t head = le32_to_cpu(journal->head);
    uint16_t gen_id = le16_to_cpu(journal->gen_id);

    /* Is the journal empty? True if unmounted properly */
    if (head == tail)
        return 0;

    orca_dbg("ORCAFS: journal recovery. head:tail %x:%x gen_id %d\n",
        head, tail, gen_id);

    if (sbi->redo_log)
        orca_recover_redo_journal(sb);
    else
        orca_recover_undo_journal(sb);

    return 0;
}
