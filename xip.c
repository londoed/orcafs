#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include "orcafs.h"
#include "xip.h"

/**
 * Wrappers. Need to use the rcu read lock to avoid concurrent
 * truncate operation. No problem for write because we held
 * i_mutex.
**/
ssize_t orca_xip_file_read(struct file *filp, char __user *buf, size_t len,
    loff_t *ppos)
{
    ssize_t res;

    rcu_read_lock();
    res = xip_file_read(filp, buf, len, ppos);
    rcu_read_unlock();

    return res;
}

static inline void
orca_flush_edge_cachelines(loff_t pos, ssize_t len, void *start_addr)
{
    if (unlikely(pos & 0x7))
        orca_flush_buffer(start_addr, 1, false);

    if (unlikely(((pos + len) & 0x7) && ((pos & CACHELINE_SIZE - 1)) !=
        ((pos + len) & (CACHELINE_SIZE - 1))))
            orca_flush_buffer(start_addr + len, 1, false);
}

static ssize_t
__orca_xip_file_write(struct address_space *mapping, const char __user *buf,
    size_t count, loff_t pos, loff_t *ppos)
{
    struct inode *ino = mapping->host;
    struct super_block *sb = ino->i_sb;
    long status = 0;
    size_t bytes;
    ssize_t written = 0;
    struct orca_inode *oi;

    oi = orca_get_inode(sb, ino->i_ino);

    do {
        unsigned long index;
        unsigned long offset;
        size_t copied;
        void *xmem;
        unsigned long xpfn;

        offset = (pos & (sb->s_blocksize - 1)); /* Within page */
        index = pos >> sb->s_blocksize_bits;
        bytes = sb->s_blocksize - offset;

        if (bytes > count)
            bytes = count;

        status = orca_get_xip_mem(mapping, index, 1, &xmem, &xpfn);

        if (status)
            break;

        orca_xip_mem_protect(sb, xmem + offset, bytes, 1);
        copied = bytes - __copy_from_user_inatomic_nocache(xmem + offset,
            buf, bytes);
        orca_xip_mem_protect(sb, xmem + offset, bytes, 0);

        /**
         * If start or end destination address is not 8 byte aligned,
         * __copy_from_user_inatomic_nocache uses cacheable, instructions
         * (instead of movnti) to write. So, flush those cachelines.
        **/
        orca_flush_edge_cachelines(pos, copied, xmem + offset);

        if (likely(copied > 0)) {
            status = copied;

            if (status >= 0) {
                written += status;
                count -= status;
                pos += status;
                buf += status;
            }
        }

        if (unlikely(copied != bytes)) {
            if (status >= 0)
                status = -EFAULT;
        }

        if (status < 0)
            break;
    } while (count);

    *ppos = pos;

    /**
     * No need to use i_size_read() here, the i_size cannot change
     * under us because we hold i_mutex.
    **/
    if (pos > ino->i_size) {
        i_size_write(ino, pos);
        orca_update_isize(ino, oi);
    }

    return written ? written : status;
}

/**
 * Optimized path for file write that doesn't require a transaction. In
 * this path we don't need to allocate any new data blocks. So, the only
 * metadata modified in path is inode's i_size, i_ctime, and i_mtime fields.
**/
static ssize_t
orca_file_write_fast(struct super_block *sb, struct inode *ino,
    struct orca_inode *oi, const char __user *buf, size_t count, off_t pos,
    loff_t *ppos, u64 block)
{
    void *xmem = orca_get_block(sb, block);
    size_t copied, ret = 0, offset;

    offset = pos & (sb->s_blocksize - 1);
    orca_xip_mem_protect(sb, xmem + offset, count, 1);
    copied = count - __copy_from_user_inatomic_nocache(xmem + offset, buf,
        count);
    orca_xip_mem_protect(sb, xmem + offset, count, 0);
    orca_flush_edge_cachelines(pos, copied, xmem + offset);

    if (likely(copied > 0)) {
        pos += copied;
        ret = copied;
    }

    if (unlikely(copied != count && copied == 0))
        ret = -EFAULT;

    *ppos = pos;
    ino->i_ctime = ino->i_mtime = CURRENT_TIME_SEC;

    if (pos > ino->i_size) {
        /**
         * Make sure written data is persistent before updating
         * time and size.
        **/
        PERSISTENT_MARK();
        i_size_write(ino, pos);
        PERSISTENT_BARRIER();

        orca_memunlock_inode(sb, oi);
        orca_update_time_and_size(ino, oi);
        orca_memlock_inode(sb, oi);
    } else {
        u64 c_m_time;

        /**
         * Update c_time and m_time atomically. We don't need to make
         * the data persistent because the expectation is that the
         * close() or an explicit fsync will do that.
        **/
        c_m_time = (ino->c_time.tv_sec & 0xFFFFFFFF);
        c_m_time |= (c_m_time << 32);

        orca_memunlock_inode(sb, oi);
        orca_memcpy_atomic(&oi->i_ctime, &c_m_time, 8);
        orca_memlock_inode(sb, oi);
    }

    orca_flush_buffer(oi, 1, false);

    return ret;
}

/**
 * block_off is used in different ways depending on whether the edge
 * block is at the beginning or end of the write. IF it is at the
 * beginning, we zero from start-of-block to 'block_off'. If it is
 * the end block, we zero from 'block_off' to end-of-block.
**/
static inline void
orca_clear_edge_block(struct super_block *sb, struct orca_inode *oi, bool new_block,
    unsigned long block, size_t block_off, bool is_end_block)
{
    void *ptr;
    size_t count;
    unsigned long block_num;

    if (new_block) {
        block_num = block >> (orca_inode_block_shift(oi) - sb->s_blocksize_bits);
        ptr = orca_get_block(sb, __orca_find_data_block(sb, oi, block_num));

        if (ptr != NULL) {
            if (is_end_block) {
                ptr += block_off - (block_off % 8);
                count = orca_inode_block_size(oi) - block_off + (block_off % 8);
            } else {
                count = block_off + (8 - (block_off % 8));
            }

            orca_memunlock_range(sb, ptr, orca_inode_blocksz(oi));
            memset_nt(ptr, 0, count);
            orca_memlock_range(sb, ptr, orca_inode_blocksz(oi));
        }
    }
}

ssize_t
orca_xip_file_write(struct file *filp, const char __user *buf, size_t len,
    loff_t *ppos)
{
    struct address_space *mapping = filp->f_mapping;
    struct inode *ino = mapping->host;
    struct super_block *sb = ino->i_sb;
    orca_trans *trans;
    struct orca_inode *oi;
    ssize_t written = 0;
    loff_t pos;
    u64 block;
    bool new_sblock = false, new_eblock = false;
    size_t count, offset, eblock_offset, ret;
    unsigned long start_block, end_block, num_blocks, max_logentries;
    bool same_block;

    sb_start_write(ino->i_sb);
    mutex_lock(&ino->i_mutex);

    if (!access_ok(VERIFY_READ, buf, len)) {
        ret = -EFAULT;
        goto out;
    }

    pos = *ppos;
    count = len;

    /* We can write back this queue in page reclaim */
    current->backing_dev_info = mapping->backing_dev_info;
    ret = generic_write_checks(filp, &pos, &count, S_ISBLK(ino->i_mode));

    if (ret || count == 0)
        goto out_backing;

    oi = orca_get_inode(sb, ino->i_ino);
    offset = pos & (sb->s_blocksize - 1);
    num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;

    /* Offset in the actual block size block */
    offset = pos & (orca_inode_blocksz(oi) - 1);
    start_block = pos >> sb->s_blocksize_bits;
    end_block = start_block + num_blocks - 1;
    block = orca_find_data_block(ino, start_block);

    /* Referring to the inode's block size, not 4K */
    same_block = (((count + offset - 1) >> orca_inode_block_shift(oi)) == 0) ? 1 : 0;

    if (block && same_block) {
        ret = orca_file_write_fast(sb, ino, oi, buf, count, pos, ppos, block);
        goto out_backing;
    }

    max_logentries = num_blocks / MAX_PTRS_PER_LENTRY + 2;

    if (max_logentries > MAX_METABLOCKS_LENTRIES)
        max_logentries = MAX_METABLOCKS_LENTRIES;

    trans = orca_new_transaction(sb, MAX_INODE_LENTRIES + max_logentries);

    if (IS_ERR(trans)) {
        ret = PTR_ERR(trans);
        goto out_backing;
    }

    orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);
    ret = file_remove_suid(filp);

    if (ret) {
        orca_abort_transaction(sb, trans);
        goto out_backing;
    }

    ino->i_ctime = ino->i_mtime = CURRENT_TIME_SEC;
    orca_update_time(ino, oi);

    /**
     * We avoid zeroing the alloc'd range, which is going to be
     * overwritten by this system call anyway.
    **/
    if (offset != 0) {
        if (orca_find_data_block(ino, start_block) == 0)
            new_sblock = true;
    }

    eblock_offset = (pos + count) & (orca_inode_blocksz(oi) - 1);

    if ((eblock_offset != 0) && (orca_find_data_block(ino, end_block) == 0))
        new_eblock = true;

    /* Don't zero-out the allocated blocks */
    orca_alloc_blocks(trans, ino, start_block, num_blocks, false);

    /* Now, zero out the edge blocks, which will be partially written */
    orca_clear_edge_block(sb, oi, new_sblock, start_block, offset, false);
    orca_clear_edge_block(sb, oi, new_eblock, end_block, eblock_offset, true);

    write = __orca_xip_file_write(mapping, buf, count, pos, ppos);

    if (written < 0 || written != count)
        orca_dbg_version("write incomplete/failed: written %ld len %ld "
            "pos %llx start_block %lx num_blocks %lx\n", written, count,
            pos, start_block, num_blocks);

    orca_commit_transaction(sb, trans);
    ret = written;

out_backing:
    current->backing_dev_info = NULL;

out:
    mutex_unlock(&ino->i_mutex);
    sb_end_write(ino->i_sb);

    return ret;
}

/**
 * Out of Memory error return with xip file fault handlers doesn't
 * mean anything. It would just cause the OS to go on an uneccessary
 * killing spree!
**/
static int
__orca_xip_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct address_space *mapping = vma->vm_file->f_mapping;
    struct inode *ino = mapping->host;
    pgoff_t size;
    void *xip_mem;
    unsigned long xip_pfn;
    int err;

    size = (i_size_read(ino) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

    if (vmf->pgoff >= size) {
        orca_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx), "
            "vm_end(0x%lx), pgoff(ox%lx), VA(%lx)\n", __func__,
            __LINE__, vma->va_start, vma->vm_end, vmf->pgoff,
            (unsigned long)vmf->virtual_address);
        return VM_FAULT_SIGBUS;
    }

    err = orca_get_xip_mem(mapping, vmf->pgoff, 1, &xip_mem, &xip_pfn);

    if (unlikely(err)) {
        orca_dbg("[%s:%d] get_xip_mem failed(OOM). vm_start(0x%lx),"
            " vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
            __func__, __LINE__, vma->vm_start, vma->vm_end,
            vmf->pgoff, (unsigned long)vmf->virtual_address);
        return VM_FAULT_SIGBUS;
    }

	orca_dbg_mmapv("[%s:%d] vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx), "
		"BlockSz(0x%lx), VA(0x%lx)->PA(0x%lx)\n", __func__,
		__LINE__, vma->vm_start, vma->vm_end, vmf->pgoff,
		PAGE_SIZE, (unsigned long)vmf->virtual_address,
		(unsigned long)xip_pfn << PAGE_SHIFT);

    err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, xip_pfn);

    if (err == -ENOMEM)
        return VM_FAULT_SIGBUS;

    /**
     * err == -EBUSY is fine, we've raced against another thread
     * that faulted-in the same page.
    **/
    if (err != -EBUSY)
        BUG_ON(err);

    return VM_FAULT_NOPAGE;
}

static int
orca_xip_file_fault(struct vm_area_struct *vma, struct vm_fault, *vmf)
{
    int ret = 0;

    rcu_read_lock();
    ret = __orca_xip_file_fault(vma, vmf);
    rcu_read_unlock();

    return ret;
}

static int
orca_find_and_alloc_blocks(struct inode *ino, sector_t iblock, sector_t *data_block,
    int create)
{
    int err = -EIO;
    u64 block;
    orca_trans *trans;
    struct orca_inode *oi;

    block = orca_find_data_block(ino, iblock);

    if (!block) {
        struct super_block *sb = ino->i_sb;

        if (!create) {
            err = -ENODATA;
            goto err;
        }

        oi = orca_get_inode(sb, ino->i_ino);
        trans = orca_current_transaction();

        if (trans) {

            if (err) {
                orca_dbg_verbose("[%s:%d] Allocation failed!\n",
                    __func__, __LINE__);
                goto err;
            }
        } else {
            /* 1 lentry for inode, 1 lentry for inode's radix tree */
            trans = orca_new_transaction(sb, MAX_INODE_LENTRIES);

            if (IS_ERR(trans)) {
                err = PTR_ERR(trans);
                goto err;
            }

            rcu_read_unlock();
            mutex_lock(&ino->i_mutex);
            orca_add_logentry(sb, trans, oi, MAX_DATA_PER_LENTRY, LE_DATA);

            err = orca_alloc_blocks(trans, inode, iblock, 1, true);
            orca_commit_transaction(sb, trans);
            mutex_unlock(&ino->i_mutex);
            rcu_read_lock();

            if (err) {
                orca_dbg_version("[%s:%d] Allocation failed\n",
                    __func__, __LINE__);
                goto err;
            }
        }

        block = orca_find_data_block(ino, iblock);

        if (!block) {
            orca_dbg("[%s:%d] But allocation didn't fail!\n",
                __func__, __LINE__);
                err = -ENODATA;
                goto err;
        }
    }

    orca_dbg_mmapvv("iblock 0x%lx allocated block 0x%llx\n", iblock, block);
    *data_block = block;
    err = 0;

err:
    return err;
}

static inline int
__orca_get_block(struct inode *ino, pgoff_t pgoff, int create, sector_t *result)
{
    int rc = 0;

    rc = orca_find_and_alloc_blocks(ino, (sector_t)pgoff, result, create);

    return rc;
}

int
orca_get_xip_mem(struct address_space *mapping, pgoff_t pgoff, int create,
    void **kmem, unsigned long *pfn)
{
    int rc;
    sector_t block = 0;
    struct inode *ino = mapping->host;

    rc = __orca_get_block(ino, pgoff, create, &block);

    if (rc) {
        orca_dbg1("[%s:%d] rc(%d), sb->physaddr(0x%llx), block(0x%llx),"
            " pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__,
            __LINE__, rc, PMFS_SB(inode->i_sb)->phys_addr,
            block, pgoff, create, *pfn);
        return rc;
    }

    *kmem = orca_get_block(ino->i_sb, block);
    *pfn = orca_get_pfn(ino->i_sb, block);

    orca_dbg_mmapvv("[%s:%d] sb->physaddr(0x%llx), block(0x%lx),"
        " pgoff(0x%lx), flag(0x%x), PFN(0x%lx)\n", __func__, __LINE__,
        ORCA_SB(inode->i_sb)->phys_addr, block, pgoff, create, *pfn);

    return 0;
}

static unsigned long
orca_data_block_size(struct vm_area_struct *vma, unsigned long addr,
    unsigned long pgoff)
{
    struct file *file = vma->vm_file;
    struct inode *ino = file->f_mapping->host;
    struct orca_inode *oi;
    unsigned long map_virt;

    if (addr < vma->vm_start || addr >= vma->vm_end)
        return -EFAULT;

    oi = orca_get_inode(ino->i_sb, ino->i_ino);
    map_virt = addr & PUD_MASK;

    if (!cpu_has_gbpages || oi->i_blk_type != ORCA_BLOCK_TYPE_1G ||
        (vma->vm_start & ~PUD_MASK) || map_virt < vma->vm_start ||
        (map_virt + PUD_SIZE) > vma->vm_end)
            goto use_2M_mappings;

    orca_dbg_mmapv("[%s:%d] Using 1G Mappings : "
    	"vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
    	"VA(0x%lx), MAP_VA(%lx)\n", __func__, __LINE__,
    	vma->vm_start, vma->vm_end, pgoff, addr, map_virt);

    return PUD_SIZE;

use_2M_mappings:
    map_virt = addr & PMD_MASK;


    if (!cpu_has_pse || pi->i_blk_type != PMFS_BLOCK_TYPE_2M ||
    	(vma->vm_start & ~PMD_MASK) || map_virt < vma->vm_start ||
    	(map_virt + PMD_SIZE) > vma->vm_end)
    		goto use_4K_mappings;

    orca_dbg_mmapv("[%s:%d] Using 2M Mappings : "
    	"vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
    	"VA(0x%lx), MAP_VA(%lx)\n", __func__, __LINE__,
    	vma->vm_start, vma->vm_end, pgoff, addr, map_virt);

    return PMD_SIZE;

use_4K_mappings:
    orca_dbg_mmapvv("[%s:%d] 4K Mappings : "
        "vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
        "VA(0x%lx)\n", __func__, __LINE__,
        vma->vm_start, vma->vm_end, pgoff, addr);

    return PAGE_SIZE;
}

static inline pte_t *
orca_xip_hugetlb_pte_offset(struct mm_struct *mm, unsigned long addr,
    unsigned long *sz)
{
    return pte_offset_pagesz(mm, addr, sz);
}

static inline pte_t *
orca_pte_alloc(struct mm_struct *mm, unsigned long addr, unsigned long sz)
{
    return pte_alloc_pagesz(mm, addr, sz);
}

static pte_t
orca_make_huge_pte(struct vm_area_struct *vma, unsigned long pfn,
    unsigned long sz, int writeable)
{
    pte_t entry;

    if (writeable)
        entry = pte_mkwrite(pte_mkdirty(pfn_pte(pfn, vma->vm_page_prot)));
    else
        entry = pte_wrprotect(pfn_pte(pfn, vma->vm_page_prot));

    entry = pte_mkspecial(pte_mkyoung(entry));

    if (sz != PAGE_SIZE) {
        BUG_ON(sz != PMD_SIZE && sz != PUD_SIZE);
        entry = ote_mkhuge(entry);
    }

    return entry;
}

static int
__orca_xip_file_hpage_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int ret;
    pte_t *ptep, new_pte;
    unsigned long size, block_sz;
    struct mm_struct *mm = vma->vm_mm;
    struct inode *ino = vma->vm_file->f_mapping_host;
    unsigned long address = (unsigned long)vmf->virtual_address;

    static DEFINE_MUTEX(orca_instantiation_mutex);
    size = (i_size_read(ino) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

    if (vmf->pgoff >= size) {
        orca_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
            " vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
            __func__, __LINE__, vma->vm_start, vma->vm_end,
            vmf->pgoff, (unsigned long)vmf->virtual_address);
        return VM_FAULT_SIGBUS;
    }

    block_sz = orca_data_block_size(vma, address, vmf->pgoff);
    address &= ~(block_sz - 1);
    BUG_ON(block_sz == PAGE_SIZE);
    pmfs_dbg_mmapvv("[%s:%d] BlockSz : %lx",
		__func__, __LINE__, block_sz);

    ptep = orca_pte_alloc(mm, address, block_sz);

    if (!ptep) {
        pmfs_dbg("[%s:%d] orca_pte_alloc failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		return VM_FAULT_SIGBUS;
    }

    /**
     * Serialize hugepage allocation and instantiation so that we
     * don't get spurious allocation features if two CPUs race to
     * instantiate the same page in the page cache.
    **/
    mutex_lock(&orca_instantiation_mutex);

    if (pte_none(*ptep)) {
        void *xip_mem;
        unsigned long xip_pfn;

        if (orca_get_xip_mem(vma->vm_file->f_mapping, vmf->pgoff, 1,
            &xip_mem, &xip_pfn) != 0) {
                orca_dbg("[%s:%d] get_xip_mem failed(OOM). vm_start(0x"
        			"%lx), vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
        			__func__, __LINE__, vma->vm_start,
        			vma->vm_end, vmf->pgoff,
        			(unsigned long)vmf->virtual_address);
            ret = VM_FAULT_SIGBUS;
            goto out_mutex;
        }

        /* VA has already been aligned. Align xip_pfn to block_sz */
        xip_pfn <<= PAGE_SHIFT;
        xip_pfn &= ~(block_sz - 1)
        xip_pfn >>= PAGE_SHIFT;
        new_pte = orca_make_huge_pte(vma, xip_pfn, block_sz,
            ((vma->vm_flags & VM_WRITE) && vma->vm_flags & VM_SHARED));

        /* NOTE: Is the lock necessary here? */
        spin_lock(&mm->page_table_lock);
        set_pte_at(mm, address, ptep, new_pte);
        spin_unlock(&mm->page_table_lock);

        if (ptep_set_access_flags(vma, address, ptep, new_pte, vmf->flags & FAULT_FLAG_WRITE))
            update_mmu_cache(vma, address, ptep);
    }

    ret = VM_FAULT_NOPAGE;

out_mutex:
    mutex_unlock(&orca_instantiation_mutex);

    return ret;
}

static int
orca_xip_file_hpage_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    int ret = 0;

    rcu_read_lock();
    ret = __orca_xip_file_hpage_fault(vma, vmf);
    rcu_read_unlock();

    return ret;
}

static const struct vm_operations_struct orca_xip_vm_ops = {
    .fault = orca_xip_file_fault,
};

static const struct vm_operations_struct orca_xip_hpage_vm_ops = {
    .fault = orca_xip_file_hpage_fault,
};

static inline int
orca_has_huge_mmap(struct super_block *sb)
{
    struct orca_sb_info *sbi = (struct orca_sb_info *)sb->s_fs_info;

    return sbi->s_mount_opt & ORCA_MOUNT_HUGEMMAP;
}

int
orca_xip_file_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long block_sz;

    BUG_ON(!file->f_mapping->a_ops->get_xip_mem);
    file_accessed(file);

    vma->vm_flags |= VM_MIXEDMAP;
    block_sz = orca_data_block_size(vma, vma->vm_start, 0);

    if (orca_has_huge_mmap(file->f_mapping->host->i_sb) &&
        (vma->vm_flags & VM_SHARED) &&
        (block_sz == PUD_SIZE || block_sz == PMD_SIZE)) {
            vma->vm_flags |= VM_XIP_HUGETLB;
            vma->vm_ops = &orca_xip_hpage_vm_ops;
            orca_dbg_mmaphuge("[%s:%d] MMAP HUGEPAGE vm_start(0x%lx),"
        		" vm_end(0x%lx), vm_flags(0x%lx), "
        		"vm_page_prot(0x%lx)\n", __func__,
        		__LINE__, vma->vm_start, vma->vm_end, vma->vm_flags,
        		pgprot_val(vma->vm_page_prot));

    } else {
        vma->vm_ops = &orca_xip_vm_ops;
        orca_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
            " vm_end(0x%lx), vm_flags(0x%lx), "
            "vm_page_prot(0x%lx)\n", __func__,
            __LINE__, vma->vm_start, vma->vm_end,
            vma->vm_flags, pgprot_val(vma->vm_page_prot));
    }

    return 0;
}
