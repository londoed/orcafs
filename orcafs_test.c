#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/fs.h>
#include "orcafs.h"

int __init
test_orca_write(void)
{
    struct orca_super_block *osb;

    osb = get_orca_super();

    if (!osb) {
        printk(KERN_ERR "%s: ORCAFS super block not found (not mounted?)\n",
            __func__);
        return 1;
    }

    /**
     * Attempt an unprotected clear of checksum information in the
     * superblock, this should cause a kernel page protection fault.
    **/
    printk("%s: writing to kernel VA %p\n", __func__, osb);
    osb->s_sum = 0;

    return 0;
}

void
test_orca_write_cleanup(void)
{
}

/* MODULE INFO */
MODULE_LICENSE("GPL");
module_init(test_orca_write);
module_exit(test_orca_write_cleanup);
