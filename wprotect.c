#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "orcafs.h"

static inline void
wprotect_disable(void)
{
    unsigned long cr0_val;

    cr0_val = read_cr0();
    cr0_val &= (~X86_CR0_WP);
    write_cr0(cr0_val);
}

static inline void
wprotect_enable(void)
{
    unsigned long cr0_val;

    cr0_val = read_cr0;
    cr0_val |= X86_CR0_WP;
    write_cr0(cr0_val);
}

/**
 * NOTE: Assumes that we are always called in the right order.
 * orca_writeable(vaddr, size, 1);
 * orca_writeable(vaddr, size, 0);
**/
int
orca_writeable(void *vaddr, unsigned long size, int rw)
{
    static unsigned long flags;

    if (rw) {
        local_irq_save(flags);
        wprotect_disable();
    } else {
        wprotect_enable();
        local_irq_restore(flags);
    }

    return 0;
}

int
orca_xip_mem_protect(struct super_block *sb, void *vaddr, unsigned long size, int rw)
{
    if (!orca_is_wprotected(sb))
        return 0;

    return orca_writeable(vaddr, size, rw);
}
