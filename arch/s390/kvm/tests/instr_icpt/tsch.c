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

static int _tsch(u64 schid, void *buf)
{
	register int r1 asm("1") = schid;
	int rc = -EINVAL;

	asm volatile(
		"	tsch	0(%2)\n"
		"0:	ipm	%0\n"
		"	srl	%0,28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+d" (rc)
		: "d" (r1), "a" (buf)
		: "cc", "memory");
	return rc;
}

int test_tsch(void)
{
	int rc;
	u8 *buf;

	Dprintk(KERN_INFO "Testing TSCH...\n");

	buf = (u8 *) __get_free_page(GFP_KERNEL);
	if (!buf) {
		ztst_set_err_str("could not get memory!");
		return -ENOMEM;
	}
	memset(buf, 0, 96);

	Dprintk("TSCH: Testing unaligned addr...\n");
	rc = _tsch(0x00010000, buf + 1);
	if (rc != -EINVAL) {
		ztst_set_err_str("Unaligned address not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("TSCH: Testing bad SSID...\n");
	rc = _tsch(0x0001ffff, buf);
	Dprintk("\trc = %i\n", rc);
	if (rc != 3) {
		ztst_set_err_str("Bad SSID not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	/*
	Dprintk("TSCH: Testing bad SSID + bad address...\n");
	rc = _tsch(0x0001ffff, (void*)0xffffdeadc0de0000UL);
	Dprintk("\trc = %i\n", rc);
	*/

	rc = 0;
out_free:
	free_page((unsigned long)buf);
	return rc;
}
