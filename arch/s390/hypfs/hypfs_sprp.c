/*
 *    Hypervisor filesystem for Linux on s390.
 *    Set Partition-Resource Parameter interface.
 *
 *    Copyright IBM Corp. 2013
 *    Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/sclp.h>
#include "hypfs.h"

#define DIAG304_SET_WEIGHTS	0
#define DIAG304_QUERY_PRP	1
#define DIAG304_SET_CAPPING	2

#define DIAG304_SUBCODE_MAX	2

static unsigned long hypfs_sprp_diag304(void *lpib, unsigned long cmd)
{
	register unsigned long _lpib asm("2") = (unsigned long) lpib;
	register unsigned long _rc asm("3");
	register unsigned long _cmd asm("4") = cmd;

	asm volatile("diag %1,%2,0x304\n"
		     : "=d" (_rc) : "d" (_lpib), "d" (_cmd) : "memory" );

	return _rc;
}

static void hypfs_sprp_free(const void *data)
{
	free_page((unsigned long) data);
}

static int hypfs_sprp_create(void **data, void **data_free_ptr, size_t *size)
{
	unsigned long rc;
	void *lpib;

	lpib = (void *) get_zeroed_page(GFP_KERNEL);
	if (!lpib)
		return -ENOMEM;
	rc = hypfs_sprp_diag304(lpib, DIAG304_QUERY_PRP);
	if (rc) {
		*data = *data_free_ptr = NULL;
		*size = 0;
		free_page((unsigned long) lpib);
		return -EIO;
	}
	*data = *data_free_ptr = lpib;
	*size = PAGE_SIZE;
	return 0;
}

static int __hypfs_sprp_ioctl(void __user *user_area)
{
	struct hypfs_diag304 diag304;
	unsigned long cmd;
	void __user *ulpib;
	void *lpib;
	int rc;

	if (copy_from_user(&diag304, user_area, sizeof(diag304)))
		return -EFAULT;
	if (diag304.reserved[0] || diag304.reserved[1] ||
	    diag304.reserved[2] || diag304.sub_code > DIAG304_SUBCODE_MAX)
		return -EINVAL;

	lpib = (void *) get_zeroed_page(GFP_KERNEL | GFP_DMA);
	if (!lpib)
		return -ENOMEM;

	ulpib = (void __user *)(unsigned long) diag304.lpib_ptr;
	if (diag304.sub_code == DIAG304_QUERY_PRP)
		if (copy_from_user(lpib, ulpib, PAGE_SIZE)) {
			rc = -EFAULT;
			goto out;
		}

	cmd = *(unsigned long *) &diag304.reserved;
	diag304.return_code = hypfs_sprp_diag304(lpib, cmd);

	if (diag304.sub_code == DIAG304_SET_WEIGHTS ||
	    diag304.sub_code == DIAG304_SET_CAPPING)
		if (copy_to_user(ulpib, lpib, PAGE_SIZE)) {
			rc = -EFAULT;
			goto out;
		}
out:
	free_page((unsigned long) lpib);
	return rc;
}

static long hypfs_sprp_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	void __user *argp;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (is_compat_task())
		argp = compat_ptr(arg);
	else
		argp = (void __user *) arg;
	switch (cmd) {
	case HYPFS_DIAG304:
		return __hypfs_sprp_ioctl(argp);
	default: /* unknown ioctl number */
		return -ENOTTY;
	}
	return 0;
}

static struct hypfs_dbfs_file hypfs_sprp_file = {
	.name		= "diag_304",
	.data_create	= hypfs_sprp_create,
	.data_free	= hypfs_sprp_free,
	.unlocked_ioctl = hypfs_sprp_ioctl,
};

int hypfs_sprp_init(void)
{
	if (!sclp_has_sprp())
		return 0;
	return hypfs_dbfs_create_file(&hypfs_sprp_file);
}

void hypfs_sprp_exit(void)
{
	if (!sclp_has_sprp())
		return;
	hypfs_dbfs_remove_file(&hypfs_sprp_file);
}
