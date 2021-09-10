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
#include <linux/ratelimit.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <asm/diag.h>
#include <asm/facility.h>
#include <asm/page.h>

#define MODULE_NAME "cmma_torture"

MODULE_LICENSE("GPL");

#define NUM_PAGES 10000

static struct page *pages[NUM_PAGES];
static struct task_struct *task_cmmatorture;
static unsigned long fail_count;
static unsigned int values = 0x012389AB;
static unsigned int testnodat = 2;
static int maxwarn = -1;
module_param(values, int, 0000);
module_param(testnodat, int, 0000);
module_param(maxwarn, int, 0000);
MODULE_PARM_DESC(values, "The CMMA values to set. The default 0x012389AB is 0-3 and 0-3 again with no-translate.");
MODULE_PARM_DESC(testnodat, "Whether to test the no-translate bit. 0 = no, 1 = yes. 2 (default) = auto.");
MODULE_PARM_DESC(maxwarn, "Limit how many state-changed warnings to print. -1 (default) = no limit.");

static unsigned int states[8] = {0, 1, 2, 3, 8, 9, 0xA, 0xB};

static const unsigned int check[16] = {
	BIT(0), BIT(1), BIT(3), BIT(0) | BIT(2) | BIT(3),
	0, 0, 0, 0,
	BIT(8), BIT(9), BIT(11), BIT(8) | BIT(10) | BIT(11),
	0, 0, 0, 0
};

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
	case 7:
		asm volatile(".insn rrf,0xb9ab0000,%0,%1,%2,0"
			: "=&d" (rc)
			: "a" (page_to_phys(page)),
			"i" (7));
		break;
	default:
		pr_warn("%s: unsupported state!! (%d)\n", MODULE_NAME, state);
		break;
	}
	return rc;
}

/* Set CMMA values to deterministic values */
static void set_cmma_values(int base)
{
	int i;

	for (i = 0; i < NUM_PAGES; i++) {
		int curval = states[(base + i) % 8];

		if (!testnodat) {
			do_essa(pages[i], (curval & 3) + 1);
		} else {
			switch (curval) {
			case 0:
				do_essa(pages[i], 1);
				break;
			case 1:
			case 2:
			case 3:
				do_essa(pages[i], 1);
				do_essa(pages[i], (curval & 3) + 1);
				break;
			case 8:
				do_essa(pages[i], 7);
				break;
			case 9:
			case 0xA:
			case 0xB:
				do_essa(pages[i], 7);
				do_essa(pages[i], (curval & 3) + 1);
				break;
			default:
				pr_warn("%s: unsupported value (%d)!!\n",
					MODULE_NAME, curval);
				break;
			}
		}
	}
}


/* Complain if the CMMA values are not compatible with what we set  */
static void check_cmma_values(int base)
{
	int i, realval;

	for (i = 0; i < NUM_PAGES; i++) {
		int origval = states[(base + i) % 8];

		realval = do_essa(pages[i], 0);
		realval = (realval >> 2) & 0x0B;

		if (!((1 << realval) & check[origval])) {
			if (maxwarn != 0)
				pr_info("%s: Iteration %d, Change detected for page %d: set=0x%03X, actual=0x%03X\n",
					MODULE_NAME, base, i, origval, realval);
			if (maxwarn > 0)
				maxwarn--;
			fail_count++;
		}
	}
}


static int do_torture(void *arg)
{
	int i = 0;

	set_user_nice(current, 19);

	do {
		schedule();
		set_cmma_values(i);
		check_cmma_values(i);
		i++;
	} while (!kthread_should_stop());


	pr_info("%s: done\n", MODULE_NAME);
	return 0;
}

static void print_pages(void)
{
	int i;
	unsigned long start, last, now, num;

	start = now = page_to_phys(pages[0]);
	for (i = 1; i < NUM_PAGES; i++) {
		last = now;
		now = page_to_phys(pages[i]);
		if ((now != last + PAGE_SIZE) && (now != last - PAGE_SIZE)) {
			num = (max(start, last) - min(start, last)) / PAGE_SIZE + 1;
			pr_info("%s: 0x%16.16lx-0x%16.16lx (%lu pages)\n",
				MODULE_NAME,
				min(start, last),
				max(start, last) + PAGE_SIZE - 1,
				num);
			start = now;
			continue;
		}
	}
	if (start != now) {
		num = (max(start, last) - min(start, last)) / PAGE_SIZE + 1;
		pr_info("%s: 0x%16.16lx-0x%16.16lx (%lu pages)\n",
			MODULE_NAME,
			min(start, last),
			max(start, last) + PAGE_SIZE - 1,
			num);
	}
}

static int __init cmmatorture_init(void)
{
	register unsigned long tmp = 0;
	register int rc = -EOPNOTSUPP;
	int i;

	fail_count = 0;
	pr_info("%s: Initializing CMMA torture test...\n", MODULE_NAME);

	asm volatile(
		"       .insn rrf,0xb9ab0000,%1,%1,0,0\n"
		"0:     la      %0,0\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: "+&d" (rc), "+&d" (tmp));
	if (rc) {
		pr_warn("%s: cmma not available\n", MODULE_NAME);
		return -ENXIO;
	}

	if (testnodat && !test_facility(147)) {
		if (testnodat == 2) {
			pr_info("%s: disabling no-dat\n", MODULE_NAME);
			testnodat = 0;
		} else {
			pr_warn("%s: no-dat not available\n", MODULE_NAME);
			return -ENXIO;
		}
	}

	for (i = 0; i < 8; i++)
		states[i] = (values >> (28 - i * 4)) & (testnodat ? 0xB : 3);

	pr_info("%s: Testing this pattern: %d, %d, %d, %d, %d, %d, %d, %d.\n",
		MODULE_NAME,
		states[0], states[1], states[2], states[3],
		states[4], states[5], states[6], states[7]);
	pr_info("%s: Allocating %d test pages)\n", MODULE_NAME, NUM_PAGES);
	for (i = 0; i < NUM_PAGES; i++) {
		pages[i] = alloc_pages(GFP_KERNEL, 0);
		if (!pages[i]) {
			pr_warn("%s: Failed to allocate memory\n", MODULE_NAME);
			while (i--)
				__free_pages(pages[i], 0);
			return -ENOMEM;
		}
	}

	pr_info("%s: Clearing all CMMA state\n", MODULE_NAME);
	for (i = 0; i < NUM_PAGES; i++)
		do_essa(pages[i], 1);

	print_pages();

	task_cmmatorture = kthread_create(do_torture, NULL, "cmma_do_torture");

	pr_info("%s: Starting test...\n", MODULE_NAME);
	wake_up_process(task_cmmatorture);
	return 0;
}

static void __exit cmmatorture_exit(void)
{
	int i;

	kthread_stop(task_cmmatorture);
	for (i = 0; i < NUM_PAGES; i++)
		__free_pages(pages[i], 0);
	if (fail_count == 0)
		pr_info("%s: test outcome: PASS\n", MODULE_NAME);
	else
		pr_info("%s: test outcome: FAIL\n", MODULE_NAME);
}

module_init(cmmatorture_init);
module_exit(cmmatorture_exit);
