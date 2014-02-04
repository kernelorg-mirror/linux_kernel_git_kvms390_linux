/*
 * Copyright IBM Corp. 2008, 2009
 *
 * Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/ipl.h>
#include <asm/sclp.h>
#include <asm/setup.h>

#define ADDR2G (1UL << 31)

#define CHUNK_READ_WRITE 0
#define CHUNK_READ_ONLY  1

#define INIT_PHYSMEM_REGIONS 4

static struct memblock_region init_regions[INIT_PHYSMEM_REGIONS]
__initdata_memblock;

struct memblock_type s390_physmem __initdata_memblock = {
	.regions       = init_regions,
	.cnt	       = 1,	/* empty dummy entry */
	.max	       = INIT_PHYSMEM_REGIONS,
};

static inline void memblock_physmem_add(phys_addr_t start, phys_addr_t size)
{
	memblock_add_range(&memblock.memory, start, size, 0, 0);
	memblock_add_range(&s390_physmem, start, size, 0, 0);
}

void __init detect_memory_memblock(void)
{
	unsigned long long rnmax, rzm;
	unsigned long addr, size;
	int type;

	rzm = sclp_get_rzm();
	rnmax = sclp_get_rnmax();
	max_physmem_end = rzm * rnmax;
	if (!rzm)
		rzm = 1ULL << 17;
	if (IS_ENABLED(CONFIG_32BIT)) {
		rzm = min_t(unsigned long, ADDR2G, rzm);
		if (!max_physmem_end || max_physmem_end > ADDR2G)
			max_physmem_end = min(ADDR2G, max_physmem_end);
	}
	addr = 0;
	/* keep memblock lists close to the kernel */
	memblock_set_bottom_up(true);
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
			memblock_physmem_add(addr, size);
		}
		addr += size;
	} while (addr < max_physmem_end);
	memblock_set_bottom_up(false);
	if (!max_physmem_end)
		max_physmem_end = memblock_end_of_DRAM();
}

#if defined(CONFIG_DEBUG_FS) && !defined(CONFIG_ARCH_DISCARD_MEMBLOCK)

static int memblock_debug_show(struct seq_file *m, void *private)
{
	struct memblock_type *type = m->private;
	struct memblock_region *reg;
	int i;

	for (i = 0; i < type->cnt; i++) {
		reg = &type->regions[i];
		seq_printf(m, "%4d: ", i);
		if (sizeof(phys_addr_t) == 4)
			seq_printf(m, "0x%08lx..0x%08lx\n",
				   (unsigned long)reg->base,
				   (unsigned long)(reg->base + reg->size - 1));
		else
			seq_printf(m, "0x%016llx..0x%016llx\n",
				   (unsigned long long)reg->base,
				   (unsigned long long)(reg->base + reg->size - 1));

	}
	return 0;
}

static int memblock_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, memblock_debug_show, inode->i_private);
}

static const struct file_operations memblock_debug_fops = {
	.open = memblock_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init memblock_init_debugfs(void)
{
	struct dentry *root = memblock_get_debugfs_dir();
	if (!root)
		return -ENXIO;
	debugfs_create_file("physmem", S_IRUGO, root, &s390_physmem, &memblock_debug_fops);
	return 0;
}
__initcall(memblock_init_debugfs);

#endif
