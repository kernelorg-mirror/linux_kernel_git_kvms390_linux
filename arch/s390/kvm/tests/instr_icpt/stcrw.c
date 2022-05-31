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

static int _stcrw(void *buf)
{
	int rc = -EINVAL;

	asm volatile(
		"	stcrw	0(%1)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+d" (rc)
		: "a" (buf)
		: "cc", "memory");
	return rc;
}

int test_stcrw(void)
{
	int rc;
	u8 *buf;

	Dprintk(KERN_INFO "Testing STCRW...\n");

	buf = vmalloc(4096);
	if (!buf) {
		ztst_set_err_str("could not get memory!");
		return -ENOMEM;
	}

	Dprintk("STCRW: Testing unaligned addr...\n");
	rc = _stcrw(buf + 2);
	if (rc != -EINVAL) {
		ztst_set_err_str("Unaligned address not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("STCRW: Testing good call...\n");
	*(u64 *)buf = 0xAA55AA55AA55AA55ULL;
	rc = _stcrw(buf);
	if (rc != 0 && rc != 1) {
		Dprintk("stcrw returned %i\n", rc);
		ztst_set_err_str("Good call rejected");
		rc = -EINVAL;
		goto out_free;
	}
	if (*(u64 *)buf == 0xAA55AA55AA55AA55ULL) {
		ztst_set_err_str("Buffer has not been written");
		rc = -EINVAL;
		goto out_free;
	}

	rc = 0;
out_free:
	vfree(buf);
	return rc;
}
