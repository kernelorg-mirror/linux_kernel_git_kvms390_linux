/*
 * Copyright IBM Corp. 2008, 2009
 *
 * Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/memblock.h>
#include <asm/ipl.h>
#include <asm/sclp.h>
#include <asm/setup.h>

#define ADDR2G (1ULL << 31)

/* Left over from memory_chunk, but usable here */

#define CHUNK_READ_WRITE 0
#define CHUNK_READ_ONLY  1

static void find_memory_memblock(void)
{
	unsigned long long rnmax, rzm;
	unsigned long addr, size;
	int type;

	rzm = sclp_get_rzm();
	rnmax = sclp_get_rnmax();
	max_physmem_end = rzm * rnmax;

	/* SCLP did not deliver valid rzm value */
	if (!rzm)
		rzm = 1ULL << 17;

	/* 31 bit case */
	if (sizeof(long) == 4) {
		rzm = min_t(unsigned long, ADDR2G, rzm);
		max_physmem_end = max_physmem_end ?
			min_t(unsigned long, ADDR2G, max_physmem_end)
			: ADDR2G;
	}

	addr = 0;
	do {
		size = 0;
		type = tprot(addr);
		do {
			size += rzm;
			if (max_physmem_end && addr + size >= max_physmem_end)
				break;
		} while (type == tprot(addr + size));
		if (type == CHUNK_READ_WRITE || type == CHUNK_READ_ONLY) {
			if (max_physmem_end && (addr + size > max_physmem_end))
				size = max_physmem_end - addr;
			/*
			 * memblock does not support type marker (rw/ro)
			 * All memory goes to node 0. In case of NUMA it will
			 * be "moved" later.
			 */
			memblock_add_node(addr, size, 0);
		}
		addr += size;
	} while (addr < max_physmem_end);

	/*
	 * Force max_physmem_end to end of detected memory if it could not
	 * be determined by means of sclp - this is worth a kernel warning.
	 */
	if (!max_physmem_end) {
		pr_warn("SCLP could not determine max memory size\n");
		max_physmem_end = memblock_end_of_DRAM();
	}
}

/*
 * detect_memory_memblock() - Detect full memory layout
 *
 * This function detects *all* installed memory and adds it to
 * memblock. Former variant used a maxsize parameter to limit
 * the detection. Limiting memory usage is now done elsewhere.
 */
void __init detect_memory_memblock()
{
	unsigned long flags, flags_dat, cr0;

	/*
	 * Disable IRQs, DAT and low address protection so tprot does the
	 * right thing and we don't get scheduled away with low address
	 * protection disabled.
	 */
	local_irq_save(flags);
	flags_dat = __arch_local_irq_stnsm(0xfb);

	__ctl_store(cr0, 0, 0);
	__ctl_clear_bit(0, 28);

	find_memory_memblock();

	__ctl_load(cr0, 0, 0);

	__arch_local_irq_ssm(flags_dat);
	local_irq_restore(flags);
}
