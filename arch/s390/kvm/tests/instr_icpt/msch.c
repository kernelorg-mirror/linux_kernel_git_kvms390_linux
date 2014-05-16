#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <asm/io.h>
#include "instr_icpt.h"

#if 0
# define Dprintk printk
#else
# define Dprintk(...)
#endif

static int _msch(u64 schid, void *buf)
{
	register int r1 asm("1") = schid;
	int rc = -EINVAL;

	asm volatile(
		"	msch	0(%2)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+d" (rc)
		: "d" (r1), "a" (buf)
		: "cc", "memory");
	return rc;
}

int test_msch(void)
{
	int rc;
	u8 *buf;

	Dprintk(KERN_INFO "Testing MSCH...\n");

	buf = (u8 *) __get_free_page(GFP_KERNEL);
	if (!buf) {
		ztst_set_err_str("could not get memory!");
		return -ENOMEM;
	}
	memset(buf, 0, 64);

	Dprintk("MSCH: Testing unaligned addr...\n");
	rc = _msch(0x00010000, buf + 2);
	if (rc != -EINVAL) {
		ztst_set_err_str("Unaligned address not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("MSCH: Testing bad SCHIB...\n");
	memset(buf, 0xff, 64);
	rc = _msch(0x00010000, buf);
	if (rc != -EINVAL) {
		ztst_set_err_str("Bad SCHIB not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	rc = 0;
out_free:
	free_page((unsigned long)buf);
	return rc;
}
