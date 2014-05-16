
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <asm/io.h>
#include "instr_icpt.h"

static inline int _pfmf(unsigned long function, unsigned long addr)
{
	int ret = -EACCES;

	asm volatile("0:  .insn	rre,0xb9af0000,%1,%2\n"
		     "    la	%0,0\n"
		     "2:\n"
		     EX_TABLE(0b, 2b)
		     : "+d" (ret) : "d" (function), "a" (addr) : "memory");
	return ret;
}

int test_pfmf(void)
{
	unsigned long phys;
	u8 *addr;
	int i, ret;

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
	ret = _pfmf(0x10000, phys);
	if (ret != 0) {
		ztst_set_err_str("pfmf returned error\n");
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

	ret = _pfmf(0x10000, 0L);
	if (ret != -EACCES) {
		ztst_set_err_str("no low-address protection for pfmf\n");
		return -EACCES;
	}
	ret = _pfmf(0x10000, 4096L);
	if (ret != -EACCES) {
		ztst_set_err_str("no low-address protection for pfmf\n");
		return -EACCES;
	}

	return 0;
}
