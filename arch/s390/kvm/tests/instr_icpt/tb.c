
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/io.h>
#include "instr_icpt.h"

/* Inline function for TEST BLOCK */
static inline int tb(u64 addr)
{
	register unsigned long r0 asm ("r0") = 0L;
	int ret = -EACCES;

	asm volatile(
		"0: .insn rre,0xb22c0000,0,%2\n" /* tb 0,%2 */
		"   ipm   %0\n"
		"   srl   %0,28\n"
		"2:\n"
		EX_TABLE(0b, 2b)
		: "+d" (ret), "+r"(r0) : "r" (addr) : "memory", "cc");
	return ret;
}

int test_tb(void)
{
	unsigned long phys;
	u8 *addr;
	int cc, i;

	addr = vmalloc(4096);
	if (!addr || ((long)addr & 0xfff) != 0) {
		ztst_set_err_str("vmalloc failed!");
		return -ENOMEM;
	}

	memset(addr, 0xaa, 4096);
	/* Just to be sure ;-) ... */
	if (addr[0] != 0xaa || addr[4095] != 0xaa) {
		ztst_set_err_str("memset failed!");
		vfree(addr);
		return -EINVAL;
	}

	phys = vmalloc_to_pfn(addr) << PAGE_SHIFT;
	cc = tb(phys+123);
	if (cc) {
		ztst_set_err_str("TB finished with CC != 0");
		vfree(addr);
		return -EINVAL;
	}
	for (i = 0; i < 4096; i++) {
		if (addr[i] != 0) {
			ztst_set_err_str("page has not been cleared");
			vfree(addr);
			return -EINVAL;
		}
	}

	vfree(addr);

	// printk("\n...testing TB low-address protection ...\n");
	cc = tb(4096L);
	if (cc != -EACCES) {
		ztst_set_err_str("no low-address protection for TB\n");
		return -EACCES;
	}
	cc = tb(510L);
	if (cc != -EACCES) {
		ztst_set_err_str("no low-address protection for TB\n");
		return -EACCES;
	}

	return 0;
}
