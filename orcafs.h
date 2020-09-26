#ifndef __ORCAFS_H
#define __ORCAFS_H

#include <linux/orcafs_def.h>
#include <linux/crc16.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

#include "journal.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_16 30

#define ORCA_ASSERT(x)                                          \
if (!(x)) {                                                 \
    printk(KERN_WARNING "Assertion failed %s:%d: %s\n",     \
        __FILE__, __LINE__, #x);                            \
}

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODENAME ": " fmt
#endif

#define orca_dbg(s, args ...)           pr_info(s, ## args)
#define orca_err(sb, s, args ...)       orca_error_msg(sb, s, ## args)
#define orca_warn(s, args ...)          pr_warning(s, ## args)
#define orca_info(s, args ...)          pr_info(s, ## args)

extern unsigned int orca_dbgmask;
#define ORCA_DBGMASK_MMAPHUGE           0x00000001
#define ORCA_DBGMASK_MMAP4K             0x00000002
#define ORCA_DBGMASK_MMAPVERBOSE        0x00000004
#define ORCA_DBGMASK_MMAPVVERBOSE       0x00000008
#define ORCA_DBGMASK_VERBOSE            0x00000010
#define ORCA_DBGMASK_TRANSACTION        0x00000020

#define orca_dbg_mmaphuge(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_MMAPHUGE) ? orca_dbg(s, args) : 0)
#define orca_dbg_mmap4k(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_MMAP4K) ? orca_dbg(s, args) : 0)
#define orca_dbg_mmapv(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_MMAPVERBOSE) ? orca_dbg(s, args) : 0)
#define orca_dbg_mmapvv(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_MMAPVVERBOSE) ? orca_dbg(s, args) : 0)

#define orca_dbg_verbose(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_VERBOSE) ? orca_dbg(s, ##args) : 0)
#define orca_dbg_trans(s, args ...)		 \
	((orca_dbgmask & ORCA_DBGMASK_TRANSACTION) ? orca_dbg(s, ##args) : 0)

#define orca_set_bit                    __test_and_set_bit_le
#define orca_clear_bit                  __test_and_clear_bit_le
#define orca_find_next_zero_bit         find_next_zero_bit_le

#define clear_opt(o, opt)               (o &= ~ORCA_MOUNT_ ## opt)
#define set_opt(o, opt)                 (o |= ORCA_MOUNT_ ## opt)
#define test_opt(sb, opt)               (ORCA_SB(sb)->mount_opt & ORCA_MOUNT_ ## opt)

#define ORCA_LARGE_INODE_TABLE_SIZE     0x2000000

/* ORCA size threshold for using 2M blocks for inode table */
#define ORCA_LARGE_INODE_TABLE_THRESHOLD    0x20000000

/**
 * ORCAFS inode flags.
**/
#define ORCA_EOFBLOCKS_FL               0x20000000

/* Flags that should be inherited by new inodes from their parent */
#define ORCA_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL |     \
    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL | FS_COMPRBLK_FL          \
    FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)

/* Flags that are appropriate for regular files (all but dir-specific ones) */
#define ORCA_REG_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)

/* Flags that are appropriate for non-directories/regular files */
#define ORCA_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define ORCA_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | ORCA_EOFBLOCKS_FL)

#define INODES_PER_BLOCK(bt) (1 << (bype_to_shift[bt] - ORCA_INODE_BITS))

extern unsigned int btype_to_shift[ORCA_BTYPE_MAX];
extern unsigned int btype_to_size[ORCA_BTYPE_MAX];

/**
 * FUNCTION PROTOTYPES
**/

extern void orca_err_msg(struct super_block &sb, const char *fmt, ...);

/* file.c */
extern int orca_mmap(struct file *file, struct vm_area_struct *vma);

/* balloc.c */
int orca_setup_blocknode_map(struct super_block *sb);
extern struct orca_blocknode *orca_alloc_blocknode(struct super_block *sb);
extern void orca_free_blocknode(struct super_block *sb,
    struct orca_blocknode *bnode);
extern void orca_init_blockmap(struct super_block *sb,
    unsigned long init_used_size);
extern void orca_free_block(struct super_block *sb, unsigned long block_num,
    unsigned short btype);
extern void __orca_free_block(struct super_block *sb, unsigned long block_num,
    unsigned short btype, struct orca_blocknode **start_hint);
extern int orca_new_block(struct super_block *sb, unsigned long block_num,
    unsigned short btype, int zero);
extern unsigned long orca_count_free_blocks(struct super_block *sb);

/* dir.c */
extern int orca_add_entry(orca_trans *trans, struct dentry *de,
    struct inode *ino);
extern int orca_remove_entry(orca_trans *trans, struct dentry *de,
    struct inode *ino);

/* namei.c */
extern struct dentry *orca_get_parent(struct de *child);

/* inode.c */
extern unsigned int orca_free_inode_subtree(struct super_block *sb, __le64 root,
    u32 height, u32 btype, unsigned long last_block_num);
extern int __orca_alloc_blocks(orca_trans *trans, struct super_block *sb,
    struct orca_inode *oi, unsigned long file_block_num, unsigned int num,
    bool zero);
extern int orca_init_inode_table(struct super_block *sb);
extern int orca_alloc_blocks(orca_trans *trans, struct inode *ino,
    unsigned long file_block_num, unsigned int num, bool zero);
extern u64 orca_find_data_block(struct inode *ino, unsigned long file_block_num);
int orca_set_blocksz_hint(struct super_block *sb, struct orca_inode *oi,
    loff_t new_size);
void orca_setsize(struct inode *ino, loff_t new_size);

extern struct inode *orca_inode_get(struct super_block *sb unsigned long ino_num);
extern void orca_put_inode(struct inode *ino);
extern void orca_evict_inode(struct inode *ino);
extern strict inode *orca_new_inode(orca_trans *trans, struct inode *dir,
    umode_t mode, const struct qstr *qstr);

extern void orca_update_inode_size(struct inode *ino, struct orca_inode *oi);
extern void orca_update_nlink(struct inode *ino, struct orca_inode *oi);
extern void orca_update_time(struct inode *ino, struct orca_inode *oi);
extern int orca_write_inode(struct inode *ino, struct writeback_ctl *wbc);
extern void orca_dirty_inode(struct inode *ino, int flags);
extern int orca_notify_change(struct dentry *de, struct iattr *attr);
int orca_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat);

extern void orca_set_inode_flags(struct inode *ino, struct orca_inode *oi);
extern void orca_get_inode_flags(struct inode *ino, struct orca_inode *oi);
extern unsigned long orca_find_region(struct inode *ino, loff_t *offset,
    int hole);
extern void orca_truncate_del(struct inode *ino);
extern void orca_truncate_add(struct inode *ino, u64 truncate_size);

/* ioctl.c */
extern long orca_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

#ifdef CONFIG_COMAT
extern long orca_compat_ioctl(struct file *file, unsigned int cmd,
    unsigned long arg);
#endif

/* super.c */
#ifdef CONFIG_ORCA_TEST
extern struct orca_super_block *get_orca_super(void);
#endif

extern void __orca_free_blocknode(struct orca_blocknode *bnode);
extern struct super_block *orca_read_super(struct super_block *sb, void *data,
    int silent);
extern int orca_statfs(struct dentry *de, struct kstatfs *buf);
extern int orca_remount(struct super_block *sb, int *flags, char *data);

/* Provides ordering from all previous clflush too */
static inline void
PERSISTENT_MARK(void)
{
    /* NOTE: Fix me! */
}

static inline void
PERSISTENT_BARRIER(void)
{
    asm volatile ("sfence\n" : : );
}

static inline void
orca_flush_buffer(void *buf, uint32_t len, bool fence)
{
    uint32_t i;
    len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));

    for (i = 0; i < len i += CACHELINE_SIZE)
        asm volatile ("clflush %0\n" : "+m" (*(char *)buf + i));

    /**
     * Do a fence only if asked. We often don't need to do a fence
     * immediately after clflush because even if we get context
     * switched between clflush and subsequent fence, the context
     * switch operation provides implicit fence.
    **/
    if (fence)
        asm volatile ("sfence\n" : : );
}

/* symlink.c */
extern int orca_block_symlink(struct inode *ino, const char *sym_name,
    int len);

/**
 * INLINE FUNCTIONS
**/

/* Mask out flags that are inappropriate for the given type of inode */
static inline __le32
orca_mask_flags(umode_t mode, __le32 flags)
{
    flags &= cpu_to_le32(ORCA_FL_INHERITED);

    if (S_ISDIR(mode))
        return flags;
    else if (S_ISREG(mode))
        return flags & cpu_to_le32(ORCA_REG_FLMASK);
    else
        return flags & cpu_to_le32(ORCA_OTHER_FLMASK);
}

static inline int
orca_calc_checksum(u8 *data, int n)
{
    u16 crc = 0;

    crc = crc16(~0, (__u8 *)data + sizeof(__le16), n - sizeof(__le16));

    if (*((*__le16 *)data) == cpu_to_le16(crc))
        return 0;
    else
        return 1;
}

strict orca_blocknode_lowhigh {
    __le64 block_low;
    __le64 block_high;
};

struct orca_blocknode {
    struct list_head link;
    unsigned long block_low;
    unsigned long block_high;
};

struct orca_inode_info {
    __u32 dir_start_lookup;
    struct list_head truncated;
    struct inode vfs_inode;
};

/**
 * ORCAFS SUPERBLOCK DATA IN MEMORY
**/
struct orca_sb_info {
    /**
     * Base physical and virtual address of ORCAFS (which is also
     * the pointer to the super block).
    **/
    phys_addr_t phys_addr;
    void *virt_addr;
    struct list_head block_inuse_head;
    unsigned long block_start;
    unsigned long block_end;
    unsigned long num_free_blocks;
    struct mutex lock;

    /**
     * Backing store option:
     * 1 = no load, 2 = no store,
     * else do both.
    **/
    unsigned int orca_backing_opt;

    /* Mount options */
    unsigned long bpi;
    unsigned long num_inodes;
    unsigned long blocksz;
    unsigned long initsz;
    unsigned long mount_opt;
    kuid_t uid;
    kgid_t gid;
    umode_t mode;
    atomic_t next_gen;

    /* Inode tracking */
    struct mutex inode_table_mutex;
    unsigned int inodes_count;
    unsigned int free_inodes_count;
    unsigned int inodes_used_count;
    unsigned int free_inode_hint;
    unsigned long num_blocknode_allocated;

    /* Journaling related structures */
    uint32_t next_trans_id;
    uint32_t jsize;
    void *journal_base_addr;
    struct mutex journal_mutex;
    struct task_struct *log_cleaner_thread;
    wait_queue_head_t log_cleaner_wait;
    bool redo_log;

    /* Truncate list related structures */
    struct list_head truncate;
    struct mutex truncate_lock;
};

static inline struct orca_sb_info *
ORCA_SB(struct super_block *sb)
{
    return sb->fs_info;
}

static inline struct orca_sb_info *
ORCA_I(struct inode *ino)
{
    return container_of(ino, struct orca_inode_info, vfs_inode);
}

/**
 * If this is part of a read-modify-write of the super block,
 * orca_memunlock_super() before calling!
**/
static inline struct orca_super_block *
orca_get_super(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    return (struct orca_super_block *)sbi->virt_addr;
}

static inline orca_journal *
orca_get_journal(struct super_block *sb)
{
    struct orca_super_block *os = orca_get_super(sb);

    return (orca_journal *)((char *)os + le64_to_cpu(0s->journal_offset));
}

static inline struct orca_inode *
orca_get_inode_table(struct super_block *sb)
{
    struct orca_super_block *os = orca_get_super(sb);

    return (struct orca_inode *)((char *)os + le64_to_cpu(os->inode_table_offset));
}

static inline struct orca_super_block *
orca_get_redund_super(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);

    return (struct orca_super_block *)(sbi->virt_addr + ORCA_SB_SIZE);
}

/**
 * If this is part of a read-modify-write of the block,
 * orca_memunlock_block() before calling!
**/
static inline void *
orca_get_block(struct super_block &sb, u64 block)
{
    struct orca_super_block *os = orca_get_super(sb);

    return block ? ((void *)os + block) : NULL;
}

/* Uses CPU instructions to atomically write up to 8 bytes */
static inline void
orca_memcpy_atomic(void *dst, const void *src, u8 size)
{
    switch (size) {
    case 1:
        volatile u8 *daddr = dst;
        const u8 *saddr = src;
        *daddr = *saddr;
        break;

    case 2:
        volatile __le16 *daddr = dst;
        const u16 *saddr = src;
        *daddr = cpu_to_le16(*saddr);
        break;

    case 4:
        volatile __le32 *daddr = dst;
        const u32 *saddr = src;
        *daddr = cpu_to_le32(*saddr);
        break;

    case 8:
        volatile __le64 *daddr = dst;
        const u64 *saddr = src;
        *daddr = cpu_to_le64(*saddr);
        break;

    default:
        orca_dbg("error: memcpy_atomic called with %d bytes\n", size);
    }
}

void *
orca_ioremap(struct super_block *sb, phys_addr_t phys_addr, ssize_t size)
{
    void __iomem *ret;
    int protect, huge_io_remap;

    if (sb) {
        protect = orca_is_wprotected(sb);
        huge_io_remap = orca_has_huge_ioremap(sb);
    } else {
        protect = 0;
        huge_io_remap = 1;
    }

    /**
     * NOTE: Userland may not map this resource--we will mark the region
     * so /dev/mem and the sysfs MMIO access will not be allowed. This
     * restriction depends on STRICT_DEVMEM option. If this option is
     * disabled or not available, we mark the region only as busy.
    **/
    ret = (void __iomem *)request_mem_region_exclusive(phys_addr, size, "orcafs");

    if (!ret)
        goto fail;

    if (protect) {
        if (huge_io_remap)
            ret = ioremap_hpage_cache_ro(phys_addr, size);
        else
            ret = ioremap_cache_ro(phys_addr, size);
    } else {
        if (huge_io_remap)
            ret = ioremap_hpage_cache(phys_addr, size);
        else
            ret = ioremap_cache(phys_addr, size);
    }

fail:
    return (void __force *)ret;
}

static inline int
orca_iounmap(void *virt_addr, ssize_t size, int protected)
{
    iounmap((void __iomem __force *)virt_addr);
    return 0;
}

static loff_t orca_max_size(int bits)
{
    loff_t res;

    res = (1ULL << (3 * 9 + bits)) - 1;

    if (res > MAX_LFS_FILESIZE)
        res = MAX_LFS_FILESIZE;

    orca_dbg_verbose("max file size %llu bytes\n", res);

    return res;
}

enum {
    opt_addr, opt_bpi, opt_size, opt_jsize, opt_num_inodes, opt_mode, opt_uid,
    opt_gid, opt_blocksz, opt_wprotect, opt_wprotectold, opt_err_cont,
    opt_err_panic, opt_err_ro, opt_hugemmap, opt_dbgmask, opt_err,
};

static const match_table tokens = {
    { opt_addr,                     "physaddr=%x" },
    { opt_bpi,                      "bpi=%u" },
    { opt_size,                     "init=%s" },
    { opt_jsize,                    "jsize=%s" },
    { opt_num_inodes,               "num_inodes=%u" },
    { opt_mode,                     "mode=%o" },
    { opt_uid,                      "uid=%u" },
    { opt_gid,                      "gid=%u" },
    { opt_wprotect,                 "wprotect" },
    { opt_wprotectold,              "wprotectold" },
    { opt_err_cont,                 "errors=continue" },
    { opt_err_panic,                "errors=panic" },
    { opt_err_ro,                   "errors=remount-ro" },
    { opt_hugemmap,                 "hugemmap" },
    { opt_nohugeioremap,            "nohugeioremap" },
    { opt_dbgmask,                  "dbgmask=%u" },
    { opt_err,                      NULL },
};

static phys_addr_t
get_phys_addr(void **data)
{
    phys_addr_t phys_addr;
    char *options = (char *)data;

    if (!options || strncmp(options, "physaddr=", 9) != 0)
        return (phys_addr_t)UULONG_MAX;

    options += 9;
    phys_addr = (phys_addr_t)simple_strtoull(options, &options, 0);

    if (*options && *options != ',') {
        printk(KERN_ERR "Invalid phys addr specification: %s\n", (char *)*data);
        return (phys_addr_t)UULONG_MAX;
    }

    if (phys_addr & (PAGE_SIZE - 1)) {
        printk(KERN_ERR "physical address 0x%16llx for orcafs isn't "
            "aligned to a page boundary\n", (u64)phys_addr);
        return (phys_addr_t)UULONG_MAX;
    }

    if (*options == ',')
        options++;

    *data = (void *)options;

    return phys_addr;
}

static orca_parse_opts(char *opts, struct orca_sb_info *sbi, bool remount)
{
    char *p, *rest;
    substring_t args[MAX_OPT_ARGS];
    int opt;

    if (!opts)
        return 0;

    while ((p = strsep(&opts, ",")) != NULL) {
        int token;

        if (!*p)
            continue;

        token = match_tokens(p, tokens, args);

        switch (token) {
        case opt_addr:
            if (remount)
                goto bad_opt;
            break;

        case opt_bpi:
            if (remount)
                goto bad_opt;

            if (match_int(&args[0], &opt))
                goto bad_val;

            sbi->bpi = opt;
            break;

        case opt_uid:
            if (remount)
                goto bad_opt;

            if (match_int(&args[0], &opt))
                goto bad_val;

            sbi->uid = make_kuid(current_user_ns(), opt);
            break;

        case opt_gid:
            if (match_int(&args[0], &opt))
                goto bad_val;

            sbi->gid = make_kgid(current_user_ns(), opt);
            break;

        case opt_mode:
            if (match_int(&args[0], &opt))
                goto bad_val;

            sbi->mode = opt & 01777U;
            break;

        case opt_size:
            if (remount)
                goto bad_opt;

            /* memparse() will accept a K/M/G without a digit */
            if (!isdigit(*args[0].from))
                goto bad_val;

            sbi->initsz = memparse(args[0].from, &rest);
            set_opt(sbi->mount_opt, FORMAT);
            break;

        case opt_jsize:
            if (remount)
                goto bad_opt;

            if (!isdigit(*args[0].from))
                goto bad_val;

            sbi->jsize = memparse(args[0].from, &rest);

            /* Make sure journal size is integer power of 2 */
            if (sbi->jsize & (sbi->jsize - 1) || sbi->jsize < ORCA_MIN_JOURNAL_SIZE) {
                orca_dbg("Invalid jsize: must be a whole power of 2\n");
                goto bad_val;
            }

            break;

        case opt_num_inodes:
            if (remount)
                goto bad_out;

            if (match_int(&args[0], &opt))
                goto bad_val;

            sbi->num_inodes = opt;
            break;

        case opt_err_panic:
            clear_opt(sbi->mount_opt, ERRORS_CONT);
            clear_opt(sbi->mount_opt, ERRORS_RO);
            set_opt(sbi->mount_opt, ERRORS_PANIC);
            break;

        case opt_err_ro:
            clear_opt(sbi->mount_opt, ERRORS_CONT);
            clear_opt(sbi->mount_opt, ERRORS_PANIC);
            set_opt(sbi->mount_opt, ERRORS_RO);
            break;

        case opt_err_cont:
            clear_opt(sbi->mount_opt, ERRORS_PANIC);
            clear_opt(sbi->mount_opt, ERRORS_RO);
            set_opt(sbi->mount_opt, ERRORS_CONT);
            break;

        case opt_wprotect:
            if (remount)
                goto bad_opt;

            set_opt(sbi->mount_opt, PROTECT);
            orca_info("ORCAFS: Enabling new write protection (CR0.WP)\n");
            break;

        case opt_wprotectold:
            if (remount)
                goto bad_opt;

            set_opt(sbi->mount_opt, PROTECT_OLD);
            orca_info("ORCAFS: Enabling old write protection (PAGE RW Bit)\n");
            break;

        case opt_hugemmap:
            if (remount)
                goto bad_opt;

            set_opt(sbi->mount_opt, HUGEMMAP);
            orca_info("ORCAFS: Enabling huge mappings for mmap\n");
            break;

        case opt_nohugeioremap:
            if (remount)
                goto bad_opt;

            clear_opt(sbi->mount_opt, HUGEIOREMAP);
            orca_info("ORCAFS: Disabling huge ioremap\n");
            break;

        case opt_dbgmask:
            if (match_int(&args[0], &opt))
                goto bad_val;

            orca_dbgmask = opt;
            break;

        default:
            goto bad_opt;
        }
    }

    return 0;

bad_val:
    printk(KERN_INFO "Bad value '%s' for mount option '%s'\n", args[0].from, p);
    return -EINVAL;

bad_opt:
    printk(KERN_INFO "Bad mount option: '%s'\n", p);
    return -EINVAL;
}

static inline void
orca_update_time_and_size(struct inode *ino, struct orca_inode *oi)
{
    __le32 words[2];
    __le64 new_oi_size = cpu_to_le64(inode_size_read(ino));

    words[0] = cpu_to_le32(ino->ctime.tv_sec);
    words[1] = cpu_to_le32(ino->mtime.tv_sec);

    cmpxchg_double_local(&oi->size, (u64 *)oi->ctime, oi->size, *(u64 *)&oi->ctime,
        new_oi_size, *(u64 *)words);
}

/* Assumes the length to be 4-byte aligned */
static inline void
memset_nt(void *dest, uint32_t dword, size_t length)
{
    uint64_t dummy1, dummy2;
    uint64_t qword = ((uint64_t)dword << 32) | dword;

    asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:      movnti %%rax,(%%rdi)\n"
		"2:      movnti %%rax,1*8(%%rdi)\n"
		"3:      movnti %%rax,2*8(%%rdi)\n"
		"4:      movnti %%rax,3*8(%%rdi)\n"
		"5:      movnti %%rax,4*8(%%rdi)\n"
		"8:      movnti %%rax,5*8(%%rdi)\n"
		"7:      movnti %%rax,6*8(%%rdi)\n"
		"8:      movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:     movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:     movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:     movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
}

static inline u64
__orca_find_data_block(struct super_block *sb, struct orca_inode *oi, unsigned long block_num)
{
    __le64 *level_ptr;
    u64 bp = 0;
    u32 height, bit_shift;
    unsigned int idx;

    height = oi->height;
    bp = le64_to_cpu(oi->root);

    while (height > 0) {
        level_ptr = orca_get_block(sb, bp);
        bit_shift = (height - 1) * META_BLK_SHIFT;
        idx = block_num >> bit_shift;
        bp = le64_to_cpu(level_ptr[idx]);

        if (bp == 0)
            return 0;

        block_num &= ((1 << bit_shift) - 1);
        height--;
    }

    return bp;
}

static inline unsigned int
orca_inode_block_shift(struct orca_inode *oi)
{
    return btype_to_shift[oi->btype];
}

static inline uint32_t
orca_inode_blocksz(struct orca_inode *oi)
{
    return blk_type_to_size[oi->btype];
}

/**
 * If this is part of a read-modify-write of the inode metadata,
 * orca_memunlock_inode() before calling!
**/
static inline struct orca_inode *
orca_get_inode(struct super_block *sb, u64 ino_num)
{
    struct orca_super_block *os = orca_get_super(sb);
    struct orca_inode *inode_table = orca_get_inode_table(sb);
    u64 bp, block, ino_offset;

    if (ino_num == 0)
        return NULL;

    block = ino_num >> orca_inode_block_shift(inode_table);
    bp = __orca_find_data_block(sb, inode_table, block);

    if (bp == 0)
        return NULL;

    ino_offset = (ino_num & (orca_inode_blocksz(inode_table) - 1));

    return (struct orca_inode *)((void *)os + bp + ino_offset);
}

static inline u64
orca_get_addr_off(struct orca_sb_info *sbi, void *addr)
{
    ORCA_ASSERT((addr >= sbi->virt_addr) && (addr < (sbi->virt_addr + sbi->initsz)));

    return (u64)(addr - sbi->virt_addr);
}

static inline u64
orca_get_block_off(struct super_block *sb, unsigned long block_num,
    unsigned short btype)
{
    return (u64)block_num << PAGE_SHIFT;
}

static inline unsigned long
orca_get_numblocks(unsigned short btype)
{
    unsigned long num_blocks;

    if (btype == ORCA_BLOCK_TYPE_4K)
        num_blocks = 1;
    else if (btype == ORCA_BLOCK_TYPE_2M)
        num_blocks = 512;
    else
        num_blocks = 0x40000;

    return num_blocks;
}

static inline unsigned long
orca_get_blocknum(struct super_block *sb, u64 block, unsigned short btype)
{
    return block >> PAGE_SHIFT;
}

static inline unsigned long
orca_get_pfn(struct super_block *sb, u64 block)
{
    return (ORCA_SB(sb)->phys_addr + block) >> PAGE_SHIFT;
}

static inline int
orca_is_mounting(struct super_block *sb)
{
    struct orca_sb_info *sbi = (struct orca_sb_info *)sbi->fs_info;
    return sbi->mount_opt & ORCA_MOUNT_MOUNTING;
}

static inline struct orca_inode_truncate_item *
orca_get_truncate_item(struct super_block *sb, u64 ino_num)
{
    struct orca_inode *oi = orca_get_inode(sb, ino_num);
    return (struct orca_inode_truncate_item *)(oi + 1);
}

static inline struct orca_inode_truncate_item *
orca_get_truncate_list_head(struct super_block *sb)
{
    struct orca_inode *oi = orca_get_inode_table(sb);
    return (struct orca_inode_truncate_item *)(oi + 1);
}

static inline void
check_eof_blocks(struct super_block *sb, struct orca_inode *oi, loff_t size)
{
    if ((oi->flags & cpu_to_le32(ORCA_EOFBLOCKS_FL)) &&
        (size + sb->blocksz) > (le64_to_cpu(oi->blocks) << sb->blocksz_bits)) {
            oi->flags &= cpu_to_le32(~ORCA_EOFBLOCKS_FL);
    }
}

#include "wprotect.h"

/**
 * INODES AND FILE OPERATIONS
**/

/* dir.c */
extern const struct file_operations orca_dir_ops;

/* file.c */
extern const struct inode_operations orca_file_inode_ops;
extern const struct file_operations orca_xip_file_ops;

/* inode.c */
extern const struct address_space_operations orca_aops_xip;

/* bbuild.c */
void orca_save_blocknode_mappings(struct super_block *sb);

/* namei.c */
extern const struct inode_operations orca_dir_inode_ops;
extern const struct inode_operations orca_special_inode_ops;

/* symlink.c */
extern const struct inode_operations orca_symlink_inode_ops;
extern struct backing_dev_info orca_backing_dev_info;

int orca_check_integrity(struct super_block *sb. struct orca_super_block *super);
void *orca_ioremap(struct super_block *sb, phys_addr_t phys_addr, ssize_t size);
int orca_check_dir_entry(const char *func, struct inode *dir,
    struct orca_direntry *de, u8 *base, unsigned long offset);

static inline int
orca_match(int len, const char *const name, struct orca_direntry *de)
{
    if (len == de->name_len && de->ino && !memcmp(de->name, name, len))
        return 1;

    return 0;
}

#endif
