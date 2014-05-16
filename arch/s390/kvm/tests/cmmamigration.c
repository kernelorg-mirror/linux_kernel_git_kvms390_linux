/*
 *    Copyright IBM Corp. 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (version 2 only)
 * as published by the Free Software Foundation.
 *
 *    Author(s): Claudio Imbrenda <imbrenda@linux.vnet.ibm.com>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <asm/sclp.h>

MODULE_LICENSE("GPL");

#define NUM_PAGES 128
static struct page *start_page;

static int do_essa(struct page *page, int state)
{
	int rc = -EOPNOTSUPP;

	switch (state) {
	case 0:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (0));
		break;
	case 1:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (1));
		break;
	case 2:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (2));
		break;
	case 3:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (3));
		break;
	case 4:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (4));
		break;
	default:
		pr_warn("%s:%d: unsupported case!!\n", __FILE__, __LINE__);
		break;
	}
	return rc;
}

/* Set CMMA values to deterministic values */
static void set_cmma_values(void)
{
	int i, rc;

	for (i = 0; i < NUM_PAGES; i++) {
		int curval = i % 4;
		struct page *curpage = start_page + i;

		rc = do_essa(curpage, curval + 1);
	}
}

/* Complain if the CMMA values are not compatible with what we set  */
static void check_cmma_values(void)
{
	int i, realval;
	int fail_count = 0;
	int map[4] = {1, 2, 8, 13};

	for (i = 0; i < NUM_PAGES; i++) {
		int origval = i % 4;
		struct page *curpage = start_page + i;

		realval = do_essa(curpage, 0);
		realval = (realval >> 2) & 0x03;

		if (!((1 << realval) & map[origval])) {
			pr_info("%s:%d: Change detected for page %d: Expected=0x%03X, Actual=0x%03X\n",
				__FILE__, __LINE__, i, origval, realval);
			fail_count++;
		}
	}

	if (fail_count == 0)
		pr_info("cmma migration: PASS\n");
	else
		pr_info("cmma migration: FAIL\n");
}

static int __init cmmamigration_init(void)
{
	register unsigned long tmp = 0;
	register int rc = -EOPNOTSUPP;

	pr_info("Starting cmma migration test\n");

	asm volatile(
		"       .insn rrf,0xb9ab0000,%1,%1,0,0\n"
		"0:     la      %0,0\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+&d" (rc), "+&d" (tmp));
	if (rc)
		return -ENXIO;

	start_page = alloc_pages(GFP_KERNEL, get_order(NUM_PAGES * PAGE_SIZE));
	if (!start_page) {
		pr_warn("%s:%d: Failed to allocate memory\n",
			__FILE__, __LINE__);
		return -ENOMEM;
	}
	pr_info("cmma migration test starting, address=%lx\n",
		page_to_phys(start_page));

	set_cmma_values();
	return 0;
}

static void __exit cmmamigration_exit(void)
{
	check_cmma_values();
	__free_pages(start_page, get_order(NUM_PAGES * PAGE_SIZE));
}

module_init(cmmamigration_init);
module_exit(cmmamigration_exit);
