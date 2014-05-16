
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

static int _stsi(void *sysinfo, u32 r0in, u32 r1in)
{
	register int r0 asm("0") = r0in;
	register int r1 asm("1") = r1in;
	int rc = -EINVAL;

	asm volatile(
		"	stsi	0(%3)\n"
		"0:	ipm	%1\n"
		"	srl	%1,28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+d" (r0), "+d" (rc)
		: "d" (r1), "a" (sysinfo)
		: "cc", "memory");
	return rc;
}

int test_stsi(void)
{
	int rc, i;
	u8 *buf;

	Dprintk(KERN_INFO "Testing STSI...\n");

	buf = (u8 *) __get_free_page(GFP_KERNEL);
	if (!buf) {
		ztst_set_err_str("could not get memory!");
		return -ENOMEM;
	}

	Dprintk("STSI: Testing good call...\n");
	rc = _stsi(buf, 0x10000001, 0x1);
	if (rc != 0) {
		Dprintk("stsi returned %i\n", rc);
		ztst_set_err_str("Good call rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("STSI: Testing illegal function code...\n");
	rc = _stsi(buf, 0xe0000001, 0x1);
	if (rc != 3) {
		ztst_set_err_str("Illegal function code not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("STSI: Testing illegal bits in r0...\n");
	for (i = 36; i <= 55; i++) {
		rc = _stsi(buf, 0x10000001 | (1 << (63-i)), 0x1);
		if (rc != -EINVAL) {
			ztst_set_err_str("Illegal bits not rejected");
			rc = -EINVAL;
			goto out_free;
		}
	}

	Dprintk("STSI: Testing illegal bits in r1...\n");
	for (i = 32; i <= 47; i++) {
		rc = _stsi(buf, 0x10000001, (1 << (63-i)) | 1);
		if (rc != -EINVAL) {
			ztst_set_err_str("Illegal bits not rejected");
			rc = -EINVAL;
			goto out_free;
		}
	}

	Dprintk("STSI: Testing bad buffer alignment...\n");
	rc = _stsi(buf + 0x800, 0x10000001, 0x1);
	if (rc != -EINVAL) {
		Dprintk("stsi returned %i\n", rc);
		ztst_set_err_str("Bad aligned buffer not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("STSI: Testing bad selector 1...\n");
	rc = _stsi(buf, 0x100000ff, 0x1);
	if (rc != 3) {
		ztst_set_err_str("Bad selector 1 not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	Dprintk("STSI: Testing bad selector 2...\n");
	rc = _stsi(buf, 0x10000001, 0x0000ffff);
	if (rc != 3) {
		ztst_set_err_str("Bad selector 2 not rejected");
		rc = -EINVAL;
		goto out_free;
	}

	rc = 0;
out_free:
	free_page((unsigned long)buf);
	return rc;
}
