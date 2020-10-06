#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include "orcafs.h"

static struct super_operations orca_sops;
static struct export_operations orca_export_ops;
static struct kmem_cache *orca_inode_cachep;
static struct kmem_cache *orca_blocknode_cachep;
static struct kmem_cache *orca_trans_cachep;
unsigned int orca_dbgmask = 0;

#ifdef CONFIG_ORCA_TEST
static void *first_orca_super;

struct orca_super_block *get_orca_super(void)
{
    return (struct orca_super_block *)first_orca_super;
}

EXPORT_SYMBOL(get_orca_super);
#endif

void
orca_error_msg(struct super_block *sb, const char *fmt, ...)
{
    va_list args;

    printk("orcafs error: ");
    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);

    if (test_opt(sb, ERRORS_PANIC))
        panic("orcafs: panic from previous error\n");

    if (test_opt(sb, ERRORS_RO)) {
        printk(KERN_CRIT, "orcafs: remounting file system read-only\n");
        sb->flags |= MS_RDONLY;
    }
}

static void
orca_set_blocksz(struct super_block *sb, unsigned long size)
{
    int bits;

    /**
     * We've already validated the user input and the value here
     * must be between ORCA_MAX_BLOCK_SIZE and ORCA_MIN_BLOCK_SIZE
     * and it must be a power of 2.
    **/
    bits = fls(size) - 1;
    sb->blocksz_bits = bits;
    sb->blocksz = (1 << bits);
}

static inline int
orca_has_huge_ioremap(struct super_block *sb)
{
    struct orca_sb_info *sbi = (struct orca_sb_info *)sb->fs_info;

    return sbi->mount_opt & ORCA_MOUNT_HUGEIOREMAP;
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
     * NOTE: Userland may not map this resource, we will mark the region
     * so /dev/mem and the sysfs MMIO access will not be allowed. This
     * restriction depends on STRICT_DEVMEM option. If this option is
     * disabled or not available, we mark the region only as busy/
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

static loff_t
orca_max_size(int bits)
{
    loff_t res;

    res = (1ULL << (3 * 9 + bits) - 1);

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

static bool
orca_check_size(struct super_block *sb, unsigned long size)
{
    struct orca_sb_info *sb = ORCA_SB(sb);
    unsigned long min_size, num_blocks;

    /* Space required for super block and root directory */
    min_size = 2 << sb->blocksz_bits;

    /* Space required for inode table */
    if (sbi->num_inodes > 0)
        num_blocks = (sbi->num_inodes >> (sb->blocksz_bits - ORCA_INODE_BITS)) + 1;
    else
        num_blocks = 1;

    min_size += (num_blocks << sb->blocksz_bits);

    /* Space required for journal */
    min_size += sbi->jsize;

    if (size < min_size)
        return false;

    return true;
}

static struct orca_inode *
orca_init(struct super_block *sb, unsigned long size)
{
    unsigned long block_size;
    u64 journal_meta_start, journal_data_start, inode_table_start;
    struct orca_inode *root_i;
    struct orca_super_block *super;
    struct orca_sb_info *sb = ORCA_SB(sb);
    struct orca_direntry *de;
    unsigned long block_num;

    orca_info("Creating an empty orcafs of size %lu\b", size);
    sbi->virt_addr = orca_ioremap(sb, sbi->phys_addr, size);
    sbi->block_start = (unsigned long)0;
    sbi->block_end = ((unsigned long)(size) >> PAGE_SHIFT);
    sbi->num_free_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

    if (!sbi->virt_addr) {
        printk(KERN ERR "ioremap of the orcafs image failed(1)\n");
        return ERR_PTR(-EINVAL);
    }

#ifdef CONFIG_ORCA_TEST
    if (!first_orca_super)
        first_orca_super = sbi->virt_addr
#endif

    orca_dbg_verbose("orcafs: Default block size set to 4K\n");
    block_size = sbi->blocksz = ORCA_DEF_BLOCK_SIZE_4K;

    orca_set_blocksz(sb, block_size);
    block_size = sb->blocksz;

    if (sbi->blocksz && sbi->blocksz != block_size)
        sbi->blocksz = block_size;

    if (!orca_check_size(sb, size)) {
        orca_dbg("Specified ORCAFS size too small 0x%lx. Either increase "
            "ORCAFS size, or reduce num of inodes (min 32) "
            "or journal size (min 4KB)\n", size);
        return ERR_PTR(-EINVAL);
    }

    journal_meta_start = sizeof(struct orca_super_block);
    journal_meta_start = (journal_meta_start + CACHELINE_SIZE - 1) &
        ~(CACHELINE_SIZE - 1);

    inode_table_start = journal_meta_start + sizeof(orca_journal);
    inode_table_start = (inode_table_start + CACHELINE_SIZE - 1) &
        ~(CACHELINE_SIZE - 1);

    if ((inode_table_start + sizeof(struct orca_inode)) > ORCA_SB_SIZE) {
        orca_dbg("ORCAFS super block defined too small 0x%x, required "
            "0x%llx\n", ORCA_SB_SIZE, inode_table_start + sizeof(struct orca_inode));
        return ERR_PTR(-EINVAL);
    }

    journal_data_start = ORCA_SB_SIZE * 2;
    journal_data_start = (jouranl_data_start + block_size - 1) &
        ~(block_size - 1);

    orca_dbg_verbose("journal meta start %llx data start 0x%llx, journal size 0x%x"
        ", inode table 0x%llx\n", journal_meta_start, journal_data_start,
        sbi->jsize, inode_table_start);
    orca_dbg_verbose("max filename len %d\n", (unsigned int)ORCA_NAME_LEN);

    super = orca_get_super(sb);
    orca_memunlock_range(sb, super, journal_data_start);

    /* Clear out super block and inode table */
    memset_nt(super, 0, journal_data_start);
    super->size = cpu_to_le64(size);
    super->blocksz = cpu_to_le32(block_size);
    super->magic = cpu_to_le16(ORCA_SUPER_MAGIC);
    super->journal_offset = cpu_to_le64(journal_meta_start);
    super->inode_table_offset = cpu_to_le64(inode_table_start);

    orca_init_blockmap(sb, journal_data_start + sbi->jsize);
    orca_memlock_range(sb, super, journal_data_start);

    if (orca_journal_hard_init(sb, journal_data_start, sbi->jsize) < 0) {
        printk(KERN_ERR "orcafs: Journal hard initialization failed\n");
        return ERR_PTR(-EINVAL);
    }

    if (orca_init_inode_table(sb) < 0)
        return ERR_PTR(-EINVAL);

    orca_memunlock_range(sb, super, ORCA_SB_SIZE * 2);
    orca_sync_super(super);
    orca_memlock_range(sb, super, ORCA_SB_SIZE * 2);

    orca_flush_buffer(super, ORCA_SB_SIZE, false);
    orca_flush_buffer((char *)super + ORCA_SB_SIZE, sizeof(*super), false);
    orca_new_block(sb, &block_num, ORCA_BLOCK_TYPE_4K, 1);

    root_i = orca_get_inode(sb, ORCA_ROOT_INODE);
    orca_memunlock_inode(sb, root_i);

    root_i->mode = cpu_to_le16(sbi->mode | S_IFDIR);
    root_i->uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
    root_i->gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
    root_i->links_count = cpu_to_le16(2);
    root_i->btype = ORCA_BLOCK_TYPE_4K;
    root_i->flags = 0;
    root_i->blocks = cpu_to_le64(1);
    root_i->size = cpu_to_le64(sb->blocksz);
    root_i->atime = root_i->mtime = root_i->ctime = cpu_to_le32(get_seconds());
    root_i->root = cpu_to_le64(orca_get_block_off(sb, block_num,
        ORCA_BLOCK_TYPE_4K));
    root_i->height = 0;

    /* orca_sync_inode(root_t) */
    orca_memunlock_inode(sb, root_t);
    orca_flush_buffer(root_i, sizeof(*root_i), false);

    de = (struct orca_direntry *)orca_get_block(sb, orca_get_block_off(sb,
        block_num, ORCA_BLOCK_TYPE_4K));

    orca_memunlock_range(sb, de, sb->blocksz);
    de->ino = cpu_to_le64(ORCA_ROOT_INODE);
    de->name_len = 1;
    de->de_len = cpu_to_le16(ORCA_DIR_REC_LEN(de->name_len));
    strcpy (de->name, ".");

    de = (struct orca_direntry *)((char *)de + le16_to_cpu(de->de_len));
    de->ino = cpu_to_le64(ORCA_ROOT_INODE);
    de->de_len = cpu_to_le16(sb->blocksz - ORCA_DIR_REC_LEN(1));
    de->name_len = 2;
    strcpy(de->name, "..");

    orca_memlock_range(sb, de, sb->blocksz);
    orca_flush_buffer(de, ORCA_DIR_REC_LEN(2), false);
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    return root_i;
}

static inline void
set_default_opts(struct orca_sb_info *sbi)
{
    /* set_opt(sbi->mount_opt, PROTECT); */
    set_opt(sb->mount_opt, HUGEIOREMAP);
    set_opt(sbi->mount_opt, ERRORS_CONT);
    sbi->jsize = ORCA_DEFAULT_JOURNAL_SIZE;
}

static inline void
set_default_opts(struct orca_sb_info *sbi, struct orca_inode *root_oi)
{
    /**
     * if (root_oi->d.d_next) {
     *      orca_warn("root->next not NULL, trying to fix\n");
     *      goto fail;
     * }
    **/
    if (!S_ISDIR(le16_to_cpu(root_oi->mode)))
        orca_warn("Root is not a directory!\n");

#if 0
    if (orca_calc_checksum((u8 *)root_oi, ORCA_INODE_SIZE)) {
        orca_dbg("checksum error in root inode, trying to fix!\n");
        goto fail3;
    }
#endif
}

int
orca_check_integrity(struct super_block *sb, struct orca_super_block *super)
{
    struct orca_super_block *super_redund;

    super_redund = (struct orca_super_block *)((char *)super + ORCA_SB_SIZE);

    /* Do sanity checks on the super block */
    if (le16_to_cpu(super->magic) != ORCA_SUPER_MAGIC) {
        if (le16_to_cpu(super_redund->magic) != ORCA_SUPER_MAGIC) {
            printk(KERN_ERR "Can't find a valid orcafs partition\n");
            goto out;
        } else {
            orca_warn("Error in super block: try to repair it with "
                "the redundant copy");

            /* Try to auto-recover the super block */
            if (sb)
                orca_memunlock_super(sb, super);

            memcpy(super, super_redund, sizeof(struct orca_super_block));

            if (sb)
                orca_memlock_super(sb, super);

            orca_flush_buffer(super, sizeof(*super), false);
            orca_flush_buffer(char *)super + ORCA_SB_SIZE, sizeof(*super), false);
        }
    }

    /* Read the super block */
    if (orca_calc_checksum((u8 *)super, ORCA_SB_STATIC_SIZE(super))) {
        if (orca_calc_checksum((u8 *)super_redund, ORCA_SB_STATIC_SIZE(super_redund))) {
            printk(KERN_ERR "ORCAFS: checksum error in super block\n");
            goto out;
        } else {
            orca_warn("Error in super block: try to repair it with the redundant copy");

            /* Try to auto-recover the super block */
            if (sb)
                orca_memunlock_super(sb, super);

            memcpy(super, super_redund, sizeof(struct orca_super_block));

            if (sb)
                orca_memlock_super(sb, super);

            orca_flush_buffer(super, sizeof(*super), false);
            orca_flush_buffer((char *)super + ORCA_SB_SIZE, sizeof(*super), false);
        }
    }

    return 1;

out:
    return 0;
}

static void
orca_recover_truncate_list(struct super_block *sb)
{
    struct orca_inode_truncate_item *head = orca_get_truncate_list_head(sb);
    u64 ino_next = le64_to_cpu(head->next_truncate);
    struct orca_inode *oi;
    struct orca_inode_truncate_item *li;
    struct inode *ino;

    if (ino_next == 0)
        return;

    while (ino_next != 0) {
        oi = orca_get_inode(sb, ino_next);
        li = (struct orca_inode_truncate_item *)(oi + 1);
        ino = orca_inode_get(sb, ino_next);

        if (IS_ERR(ino))
            break;

        orca_dbg("Recover inode %llx nlink %d size %llu:%llx\n", ino_next,
            ino->nlink, oi->size, li->truncatesz);

        if (ino->nlink) {
            /* Set allocation hint */
            orca_set_blocksz_hint(sb, oi, le64_to_cpu(li->truncatesz));
            orca_setsize(ino, le64_to_cpu(li->truncatesz));
            orca_update_inode_size(ino, oi);
        } else {
            /* Free the inode */
            orca_dbg("Deleting unreferenced inode %lx\n", ino->ino);
        }

        inode_put(inode);
        orca_flush_buffer(oi, CACHELINE_SIZE, false);
        ino_next = le64_to_cpu(li->next_truncate);
    }

    PERSISTENT_MARK();
    PERSISTENT_BARRIER();

    /* Reset the truncate_list */
    orca_memunlock_range(sb, head, sizeof(*head));
    head->next_truncate = 0;
    orca_memlock_range(sb, head, sizeof(*head));

    orca_flush_buffer(head, sizeof(*head), false);
    PERSISTENT_MARK();
    PERSISTENT_BARRIER();
}

static int
orca_fill_super(struct super_block *sb, void *data, int silent)
{
    struct orca_super_block *super;
    struct orca_inode *root_oi;
    struct orca_sb_info *sbi = NULL;
    struct inode *root_i = NULL;
    unsigned long block_size, init_size = 0;
    u32 random = 0;
    int ret = -EINVAL;

    BUILD_BUG_ON(sizeof(struct orca_super_block) > ORCA_SB_SIZE);
    BUILD_BUG_ON(sizeof(struct orca_inode) > ORCA_INODE_SIZE);

    sbi = kzalloc(sizeof(struct orca_sb_info), GFP_KERNEL);

    if (!sbi)
        return -ENOMEM;

    sb->fs_info = sbi;
    set_default_opts(sbi);
    sbi->phys_addr = get_phys_addr(&data);

    if (sbi->phys_addr == (phys_addr_t)ULLONG_MAX)
        goto out;

    get_random_bytes(&random, sizeof(u32));
    atomic_set(&sbi->next_gen, random);

    /* Init with default values */
    INIT_LIST_HEAD(&sbi->block_inuse_head);
    sbi->mode = (S_IRUGO | S_IXUGO | S_IWUSR;
    sbi->uid = current_fsuid();
    sbi->gid = current_fsgid();
    set_opt(sbi->mount_opt, XIP);
    clear_opt(sbo->mount_opt, PROTECT);
    set_opt(sbi->mount_opt, HUGEIOREMAP);

    INIT_LIST_HEAD(&sbi->truncate);
    mutex_init(&sbi->truncate_lock);
    mutex_init(&sbi->inode_table_mutex);
    mutex_init(&sbi->lock);

    if (orca_parse_options(data, sbi, 0))
        goto out;

    set_opt(sbi->mount_opt, MOUNTING);
    init_size = sbi->initsz;

    /* Init a new ORCAFS instance */
    if (init_size) {
        root_oi = orca_init(sb, init_size);

        if (IS_ERR(root_oi))
            goto out;

        super = orca_get_super(sb);
        goto setup_sb;
    }

    orca_dbg_verbose("checking physical address 0x%016llx for orcafs image\n",
        (u64)sbi->phys_addr);

    /* Map only one page for now. Will remap it when orcafs size is known */
    init_size = PAGE_SIZE;
    sbi->virt_addr = orca_ioremap(sb, sbi->phys_addr, init_size);

    if (!sbi->virt_addr) {
        printk(KERN_ERR "ioremap of the orcafs image failed(2)\n");
        goto out;
    }

    super = orca_get_super(sb);
    init_size = le64_to_cpu(super->size);
    sbi->initsz = init_size;
    orca_dbg_verbose("orcafs image appears to be %lu KB in size\n",
        init_size >> 10);

    orca_iounmap(sbi->virt_addr, PAGE_SIZE, orca_is_wprotected(sb));

    /* Remap the whole filesystem */
    release_mem_region(sbi->phys_addr, PAGE_SIZE);

    /* NOTE: Remap whole file system in orcafs virtual address range */
    sbi->virt_addr = orca_ioremap(sb, sbi->phys_addr, init_size);

    if (!sbi->virt_addr) {
        printk(KERN_ERR "ioremap of the orcafs image failed(3)\n");
        goto out;
    }

    super = orca_get_super(sb);

    if (orca_journal_soft_init(sb)) {
        ret = -EINVAL;
        printk(KERN_ERR "Journal initialization failed\n");
        goto out;
    }

    if (orca_recover_journal(sb)) {
        ret = -EINVAL;
        printk(KERN_ERR "Journal recovery failed\n");
        goto out;
    }

    if (orca_check_integrity(sb, super) == 0) {
        orca_dbg("Memory contains invalid orcafs %x:%x\n",
            le16_to_cpu(super->magic, ORCA_SUPER_MAGIC))

        goto out;
    }

    block_size = le32_to_cpu(super->blocksz);
    orca_set_blocksz(sb, block_size);
    orca_dbg_verbose("block size %lu\n", block_size);

    /* Read the root inode */
    root_oi = orca_get_inode(sb, ORCA_ROOT_INODE);

    /* Check that the root inode is in a sane state */
    orca_root_check(sb, root_oi);

#ifdef CONFIG_ORCA_TEST
    if (!first_orca_super)
        first_orca_super = sbi->virt_addr;
#endif

setup_sb:
    /* Set it all up... */
    sb->magic = le16_to_cpu(super->magic);
    sb->op = &orca_sops;
    sb->max_bytes = orca_max_size(sb->blocksz_bits);
    sb->time_gran = 1;
    sb->export_op = &orca_export_ops;
    sb->xattr = NULL;
    sb->flags |= MS_NOSEC;
    root_i = orca_inode_get(sb, ORCA_ROOT_INODE);

    if (IS_ERR(root_i)) {
        ret = PTR_ERR(root_i);
        goto out;
    }

    sb->root = d_make_root(root_i);

    if (!sbi->root) {
        printk(KERN_ERR "get orcafs root indoe failed\n");
        ret = -ENOMEM;
        goto out;
    }

    orca_recover_truncate_list(sb);

    /**
     * If the FS was not formatted on this mount, scan the metadata after
     * truncate list has been processed.
    **/
    if ((sbi->mount_opt & ORCA_MOUNT_FORMAT) == 0)
        orca_setup_blocknode_map(sb);

    if (!sb->flags & MS_RDONLY) {
        u64 mnt_write_time;

        /* Update mount time and write atomically */
        mnt_write_time = (get_seconds() & 0xFFFFFFFF);
        mnt_write_time = mnt_write_time | (mnt_write_time << 32);

        orca_memunlock_range(sb, &super->mtime, 0);
        orca_memcpy_atomic(&super->mtime, &mnt_write_time, 8);
        orca_memlock_range(sb, &super->mtime, 8);

        orca_flush_buffer(&super->mtime, 8, false);
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    clear_opt(sbi->mount_opt, 8, false);
    ret = 0;

    return ret;

out:

    if (sbi->virt_addr) {
        orca_ioumap(sbi->virt_addr, init_size, orca_is_wprotected(sb));
        release_mem_region(sbi->phys_addr, init_size);
    }

    kfree(sbi);

    return ret;
}

int
orca_statfs(struct dentry *de, struct kstatfs *buf)
{
    struct super_block *sb = de->sb;
    unsigned long count = 0;
    struct orca_sb_info *sbi = (struct orca_sb_info *)sb->fs_info;

    buf->type = ORCA_SUPER_MAGIC;
    buf->bsize = sb->blocksz;
    count = sbi->block_end;

    buf->blocks = sbi->block_end;
    buf->bfree = buf->bavail = orca_count_free_blocks(sb);
    buf->files = sbi->inodes_count;
    buf->ffree = sbi->free_inodes_count;
    buf->name_len = ORCA_NAME_LEN;

    orca_dbg_verbose("orcafs_stats: total 4k blocks 0x%llx\n", buf->bfree);
    orca_dbg_verbose("total inoded 0x%x, free inodes 0x%x, blocknodes "
        "0x%lx\n", sbi->inodes_count, sbi->free_inodes_count,
        sbi->num_blocknode_allocated);

    return 0;
}

static int
orca_show_options(struct seq_file *seq, struct dentry *root)
{
    struct orca_sb_info *sbi = ORCA_SB(root->sb);

    seq_printf(seq, ",physaddr=0x%016llx", (u64)sbi->phys_addr);

    if (sbi->initsz)
        seq_printf(seq, ",init=%luk", sbi->initsz >> 10);

    if (sbi->blocksz)
        seq_printf(seq, ",bs=%lu", sbi->blocksz);

    if (sbi->bpi)
        seq_printf(seq, ",bpi=%lu", sbi->bpi);

    if (sbi->num_inodes)
        seq_printf(seq, ",N=%lu", sbi->num_inodes);

    if (sbi->mode != (S_IRWXUGO | S_ISVTX))
        seq_printf(seq, ",mode=%03o", sbi->mode);

    if (uid_valid(sbi->uid))
        seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));

    if (gid_valid(sbi->gid))
        seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));

    if (test_opt(root->sb, ERRORS_RO))
        seq_puts(seq, ",errors=remount-ro");

    if (test_opt(root->sb, ERRORS_PANIC))
        seq_puts(seq, ",errors=panic");

    /* Memory protection disabled by default */
    if (test_opt(root->sb, PROTECT))
        seq_puts(seq, ",wprotect");

    if (test_opt(root->sb, HUGEMMAP))
        seq_puts(seq, ",hugemmap");

    if (test_opt(root->sb, HUGEIOREMAP))
        seq_puts(seq, ",hugeioremap");

    /* XIP not enabled by default */
    if (test_opt(root->sb, XIP))
        seq_puts(seq, ",xip");

    return 0;
}

int
orca_remount(struct super_block *sb, int *mnt_flags, char *data)
{
    unsigned long old_sb_flags;
    unsigned long old_mount_opt;
    struct orca_super_block *os;
    struct orca_sb_info *sbi = ORCA_SB(sb);
    int ret = -EINVAL;

    /* Store the old options */
    mutex_lock(&sbi->lock);
    old_sb_flags = sb->flags;
    old_mount_opt = sbi->mount_opt;

    if (orca_parse_options(data, sbi, 1))
        goto restore_opt;

    sb->flags = (sb->flags & ~MS_POSIXACL) |
        ((sbi->mount_opt & ORCA_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);

    if ((*mnt_flags & MS_RDONLY) != (sb->flags & MS_RDONLY)) {
        u64 mnt_write_time;
        os = orca_get_super(sb);

        /* Update mount time and write time atomically */
        orca_memunlock_range(sb, &os->mtime, 8);
        orca_memcpy_atomic(&os->mtime, &mnt_write_time, 8);
        orca_memlock_range(sb, &os->mtime, 8);

        orca_flush_buffer(&os->mtime, 8, false);
        PERSISTENT_MARK();
        PERSISTENT_BARRIER();
    }

    mutex_unlock(&sbi->lock);
    ret = 0;

    return ret;

restore_opt:
    sb->flags = old_sb_flags;
    sbi->mount_opt = old_mount_opt;
    mutex_unlock(&sbi->lock);

    return ret;
}

static void
orca_put_super(struct super_block *sb)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct orca_super_block *os = orca_get_super(sb);
    u64 size = le64_to_cpu(os->size);
    struct orca_blocknode *i;
    struct list_head *head = &(sbi->block_inuse_head);

#ifdef CONFIG_ORCA_TEST
    if (first_orca_super == sbi->virt_addr)
        first_orca_super = NULL;
#endif

    /* It's unmount time, so unmap the orcafs memory */
    if (sbi->virt_addr) {
        orca_save_blocknode_mappings(sb);
        orca_journal_uninit(sb);
        orca_iounmap(sbi->virt_addr, size, orca_is_wprotected(sb));
        sbi->virt_addr = NULL;
        release_mem_region(sbi->phys_addr, size);
    }

    /* Free all the orca_blocknode */
    while (!list_empty(head)) {
        i = list_first_entry(head, struct orca_blocknode, link);
        list_del(&i->link);
        orca_free_blocknode(sb, i);
    }

    sb->fs_info = NULL;
    orca_dbgmask = 0;
    kfree(sb);
}

inline void
orca_free_transaction(orca_trans *trans)
{
    kmem_cache_free(orca_trans_cachep, trans);
}

void
__orca_free_blocknode(struct orca_blocknode *bnode)
{
    kmem_cache_free(orca_blocknode_cachep, bnode);
}

void
orca_free_blocknode(struct super_block *sb, struct orca_blocknode *bnode)
{
    struct orca_sb_info = ORCA_SB(sb);
    sbi->num_blocknode_allocated--;
    __orca_free_blocknode(bnode);
}

inline orca_trans *
orca_alloc_transaction(void)
{
    return (orca_trans *)kmem_cache_alloc(orca_trans_cachep, GFP_NOFS);
}

struct orca_blocknode *
orca_alloc_blocknode(struct super_block *sb)
{
    struct orca_blocknode *p;
    struct orca_sb_info *sbi = ORCA_SB(sb);

    p = (struct orca_blocknode *)kmem_cache_alloc(orca_blocknode_cachep, GFP_NOFS);

    if (p)
        sbi->num_blocknode_allocated++;

    return p;
}

static struct inode *
orca_alloc_inode(struct super_block *sb)
{
    struct orca_inode_info *vi;

    vi = kmem_cache_alloc(orca_inode_cachep, GFP_NOFS);

    if (!vi)
        return NULL;

    vi->vfs_inode.i_version = 1;

    return &vi->vfs_inode;
}

static void
orca_inode_callback(struct rcu_head *head)
{
    struct inode *ino = container_of(head, struct inode, i_rcu);
    kmeme_cache_free(orca_inode_cachep, ORCA_I(ino));
}

static void
orca_destroy_inode(struct inode *ino)
{
    call_rcu(&ino->i_rcu, orca_inode_callback);
}

static void
init_once(void *foo)
{
    struct orca_inode_info *vi = foo;

    vi->i_dir_start_lookup = 0;
    INIT_LEAD_HEAD(&vi->i_truncated);
    inode_init_once(&vi->vfs_inode);
}

static int __init
init_blocknode_cache(void)
{
    orca_blocknode_cachep = kmem_cache_create("orca_blocknode_cache",
        sizeof(struct orca_blocknode), 0, (SLAB_RECLAIM_ACCOUNT |
        SLAB_MEM_SPREAD), NULL);

    if (orca_blocknode_cachep == NULL)
        return -ENOMEM;

    return 0;
}

static int __init
init_inode_cache(void)
{
    orca_inode_cachep = kmem_cache_create("orca_inode_cache",
        sizeof(strict orca_inode_info), 0, (SLAB_RECLAIM_ACCOUNT |
        SLAB_MEM_SPREAD), init_once);

    if (orca_inode_cachep == NULL)
        return -ENOMEM;

    return 0;
}

static int __init
init_transaction_cache(void)
{
    orca_trans_cachep = kmem_cache_create("orca_journal_trans",
        sizeof(orca_trans), 0, (SLAB_RECLAIM_ACCOUNT |
        SLAB_MEM_SPREAD), NULL);

    if (orca_trans_cachep == NULL) {
        orca_dbg("ORCAFS: failed to init transaction cache\n");
        return -ENOMEM;
    }

    return 0;
}

static void
destroy_transaction_cache(void)
{
    if (orca_trans_cachep)
        kmem_cache_destroy(orca_trans_cachep);

    orca_trans_cachep = NULL;
}

static void
destroy_inode_cache(void)
{
    kmem_cache_destroy(orca_inode_cachep);
}

static void
destroy_blocknode_cache(void)
{
    kmem_cache_destroy(orca_blocknode_cachep);
}

/**
 * The super block writes all done "on the fly", so the super block
 * is never in a "dirty" state, so there's no need for write_super.
**/
static struct super_operations orca_sops = {
    .alloc_inode = orca_alloc_inode,
    .destroy_inode = orca_destroy_inode,
    .write_inode = orca_write_inode,
    .dirty_inode = orca_dirty_inode,
    .evict_inode = orca_evict_inode,
    .put_super = orca_put_super,
    .statfs = orca_statfs,
    .remount_fs = orca_remount,
    .show_options = orca_show_options,
};

static struct dentry *
orca_mount(struct file_system_type *fs_type, int flags, const char *dev_name,
    void *data)
{
    return mount_nodev(fs_type, flags, data, orca_fill_super);
}

static struct file_system_type orca_fs_type = {
    .owner = THIS_MODULE,
    .name = "orcafs",
    .mount = orca_mount,
    .kill_sb = kill_anon_super,
};

static strict inode *
orca_nfs_get_inode(struct super_block *sb, u64 ino_num, u32 gen)
{
    struct orca_sb_info *sbi = ORCA_SB(sb);
    struct inode *ino;

    if (ino_num < ORCA_ROOT_INODE)
        return ERR_PTR(-ESTALE);

    if ((ino_num >> ORCA_INODE_BITS) > (sbi->inodes_count))
        return ERR_PTR(-ESTALE);

    ino = orca_inode_get(sb, ino_num);

    if (IS_ERR(ino))
        return ERR_CAST(ino);

    if (gen && ino->gen != gen) {
        inode_put(ino);
        return ERR_PTR(-ESTALE);
    }

    return ino;
}

static struct dentry *
orca_fh_to_dentry(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
    return generic_fh_to_dentry(sb, fid, fh_len, fh_type, orca_nfs_get_inode);
}

static struct dentry *
orca_fh_to_parent(struct super_block *sb, struct fid *fid, int fh_len, int fh_type)
{
    return generic_fh_to_parent(sb, fid, fh_len, fh_type, orca_nfs_get_inode);
}

static const struct export_operations orca_export_ops = {
    .fh_to_dentry = orca_fh_to_dentry,
    .fh_to_parent = orca_fh_to_parent,
    .get_parent = orca_get_parent,
};

static int __init
init_orca_fs(void)
{
    int rc = 0;

    rc = init_block_cache();

    if (rc)
        return rc;

    rc = init_transaction_cache();

    if (rc)
        goto out1;

    rc = init_inode_cache();

    if (rc)
        goto out2;

    rc = bdi_init(&orca_backing_dev_info);

    if (rc)
        goto out3;

    rc = register_filesystem(&orca_fs_type)

    if (rc)
        goto out4;

    return 0;

out4:
    bdi_destroy(&orca_backing_dev_info);

out3:
    destroy_inode_cache();

out2:
    destroy_transaction_cache();

out1:
    destroy_blocknode_cache();

    return rc;
}

static void __exit
exit_orca_fs(void)
{
    unrigister_filesystem(*orca_fs_type);
    bdi_destroy(&orca_backing_dev_info);
    destroy_inode_cache();
    destroy_blocknode_cache();
    destroy_transcation_cache();
}

MODULE_AUTHOR("Eric Londo <londoed@comcast.net>");
MODULE_DESCRIPTION("Optimized Radix Tree CoW Adaptive Filesystem");
MODULE_LICENSE("GPL");

module_init(init_orca_fs);
module_exit(exit_orca_fs);
