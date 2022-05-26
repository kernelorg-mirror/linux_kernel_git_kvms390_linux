// SPDX-License-Identifier: GPL-2.0

#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include <asm/abs_lowcore.h>

unsigned long __bootdata_preserved(__abs_lowcore);

int abs_lowcore_map(int cpu, struct lowcore *lc)
{
	unsigned long addr = __abs_lowcore + (cpu * sizeof(struct lowcore));
	unsigned long phys = __pa(lc);
	int rc;
	int i;

	for (i = 0; i < LC_PAGES; i++) {
		rc = vmem_map_page(addr, phys, PAGE_KERNEL);
		if (rc)
			return rc;
		addr += PAGE_SIZE;
		phys += PAGE_SIZE;
	}
	return 0;
}

void abs_lowcore_unmap(int cpu)
{
	unsigned long addr = __abs_lowcore + (cpu * sizeof(struct lowcore));
	int i;

	for (i = 0; i < LC_PAGES; i++) {
		vmem_unmap_page(addr);
		addr += PAGE_SIZE;
	}
}
