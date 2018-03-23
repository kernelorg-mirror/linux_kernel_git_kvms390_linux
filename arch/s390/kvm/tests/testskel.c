#define KMSG_COMPONENT "testskel"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt


#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static int __init skel_init(void)
{
	pr_info("--------- TEST MODULE STARTED ------------\n");
	return 0;
}

static void __exit skel_exit(void)
{
	pr_info("--------- TEST MODULE STOPPED ------------\n");
}

module_init(skel_init);
module_exit(skel_exit);
