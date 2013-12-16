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

static void find_memory_chunks(struct mem_chunk chunk[], unsigned long maxsize)
{
	unsigned long long rnmax, rzm, memsize;
	unsigned long addr = 0, size;
	int i = 0, type;

	rzm = sclp_get_rzm();
	rnmax = sclp_get_rnmax();
	memsize = rzm * rnmax;
	if (!rzm)
		rzm = 1ULL << 17;
	if (sizeof(long) == 4) {
		rzm = min_t(unsigned long, ADDR2G, rzm);
		memsize = memsize ? min_t(unsigned long, ADDR2G, memsize)
			: ADDR2G;
	}
	if (maxsize)
		memsize = memsize ? min_t(unsigned long, memsize, maxsize)
			: maxsize;
	do {
		size = 0;
		type = tprot(addr);
		do {
			size += rzm;
			if (memsize && addr + size >= memsize)
				break;
		} while (type == tprot(addr + size));
		if (type == CHUNK_READ_WRITE || type == CHUNK_READ_ONLY) {
			if (memsize && (addr + size > memsize))
				size = memsize - addr;
			chunk[i].addr = addr;
			chunk[i].size = size;
			chunk[i].type = type;
			i++;
		}
		addr += size;
	} while (addr < memsize && i < MEMORY_CHUNKS);
}

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


/**
 * detect_memory_layout - fill mem_chunk array with memory layout data
 * @chunk: mem_chunk array to be filled
 * @maxsize: maximum address where memory detection should stop
 *
 * Fills the passed in memory chunk array with the memory layout of the
 * machine. The array must have a size of at least MEMORY_CHUNKS and will
 * be fully initialized afterwards.
 * If the maxsize paramater has a value > 0 memory detection will stop at
 * that address. It is guaranteed that all chunks have an ending address
 * that is smaller than maxsize.
 * If maxsize is 0 all memory will be detected.
 */
void detect_memory_layout(struct mem_chunk chunk[], unsigned long maxsize)
{
	unsigned long flags, flags_dat, cr0;

	memset(chunk, 0, MEMORY_CHUNKS * sizeof(struct mem_chunk));
	/*
	 * Disable IRQs, DAT and low address protection so tprot does the
	 * right thing and we don't get scheduled away with low address
	 * protection disabled.
	 */
	local_irq_save(flags);
	flags_dat = __arch_local_irq_stnsm(0xfb);
	/*
	 * In case DAT was enabled, make sure chunk doesn't reside in vmalloc
	 * space. We have disabled DAT and any access to vmalloc area will
	 * cause an exception.
	 * If DAT was disabled we are called from early ipl code.
	 */
	if (test_bit(5, &flags_dat)) {
		if (WARN_ON_ONCE(is_vmalloc_or_module_addr(chunk)))
			goto out;
	}
	__ctl_store(cr0, 0, 0);
	__ctl_clear_bit(0, 28);
	find_memory_chunks(chunk, maxsize);
	__ctl_load(cr0, 0, 0);
out:
	__arch_local_irq_ssm(flags_dat);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(detect_memory_layout);

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

/*
 * Create memory hole with given address and size.
 */
void create_mem_hole(struct mem_chunk mem_chunk[], unsigned long addr,
		     unsigned long size)
{
	int i;

	for (i = 0; i < MEMORY_CHUNKS; i++) {
		struct mem_chunk *chunk = &mem_chunk[i];

		if (chunk->size == 0)
			continue;
		if (addr > chunk->addr + chunk->size)
			continue;
		if (addr + size <= chunk->addr)
			continue;
		/* Split */
		if ((addr > chunk->addr) &&
		    (addr + size < chunk->addr + chunk->size)) {
			struct mem_chunk *new = chunk + 1;

			memmove(new, chunk, (MEMORY_CHUNKS-i-1) * sizeof(*new));
			new->addr = addr + size;
			new->size = chunk->addr + chunk->size - new->addr;
			chunk->size = addr - chunk->addr;
			continue;
		} else if ((addr <= chunk->addr) &&
			   (addr + size >= chunk->addr + chunk->size)) {
			memmove(chunk, chunk + 1, (MEMORY_CHUNKS-i-1) * sizeof(*chunk));
			memset(&mem_chunk[MEMORY_CHUNKS-1], 0, sizeof(*chunk));
		} else if (addr + size < chunk->addr + chunk->size) {
			chunk->size =  chunk->addr + chunk->size - addr - size;
			chunk->addr = addr + size;
		} else if (addr > chunk->addr) {
			chunk->size = addr - chunk->addr;
		}
	}
}
