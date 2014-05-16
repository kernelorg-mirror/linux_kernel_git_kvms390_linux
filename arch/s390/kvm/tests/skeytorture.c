#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <asm/diag.h>
#include <asm/page.h>


MODULE_LICENSE("GPL");

#define PAGES 50000
#define PFMF_SET_KEY 0x20000

struct page *pages1[PAGES];
struct page *pages2[PAGES];
struct page *pages3[PAGES];
struct page *pages4[PAGES];

static inline unsigned long pfmf(unsigned long function, unsigned long address)
{
	asm volatile(
		"       .insn   rre,0xb9af0000,%[function],%[address]"
		: [address] "+a" (address)
		: [function] "d" (function)
		: "memory");
	return address;
}

static void check_key(char *name, char key, int i, bool wacc)
{
	/*
	 * POP 3-17
	 *
	 * The record provided by the reference bit is substantially
	 * accurate. The reference bit may be set to one by
	 * fetching data or instructions that are neither designated
	 * nor used by the program, and, under certain
	 * conditions, a reference may be made without the reference
	 * bit being set to one. Under certain unusual
	 * circumstances, a reference bit may be set to zero by
	 * other than explicit program action.
	 *
	 * Till now only the case where the ref bit was set could be
	 * observed.
	 */
	if ((((key ^ i) & 0x4) && !(key & 0x4)) && !wacc)
		printk_ratelimited("%s: It: %d: Ref bit diff exp: %x actual: %x\n",
				   name, i, i & 0xfe, key);
	if ((!wacc && ((key ^ i) & 0x2)) || (wacc && !(key & 0x2)))
		printk_ratelimited("%s: It: %d: Change bit diff exp: %x actual: %x\n",
				   name, i, i & 0xfe, key);
	if ((key ^ i) & 0x8)
		printk_ratelimited("%s: It: %d: F bit diff exp: %x actual: %x\n",
				   name, i, i & 0xfe, key);
	if ((key ^ i) & 0xf0)
		printk_ratelimited("%s: It: %d: ACC bit diff exp: %x actual: %x\n",
				   name, i, i & 0xfe, key);
}

static int key_set_read_empty(void *arg)
{
	int i;

	set_user_nice(current, 19);
	for (i = 0; i < PAGES; i++) {
		pages1[i] = alloc_pages(GFP_ATOMIC, 0);
		if (pages1[i] == NULL) {
			pr_err("Error allocating...\n");
			return -ENOMEM;
		}
		/* Ensure an empty pte */
		if (MACHINE_IS_VM || MACHINE_IS_KVM)
			diag10_range(page_to_pfn(pages1[i]), 1);
	}

	do {
		schedule_timeout_uninterruptible(1);

		for  (i = 0; i < PAGES; i++) {
			if (i % 2)
				pfmf(PFMF_SET_KEY | (i & 0xfe),
				     page_to_phys(pages1[i]));
			else
				page_set_storage_key(page_to_phys(pages1[i]), i, 0);
		}

		for  (i = 0; i < PAGES; i++) {
			char key;

			key = page_get_storage_key(page_to_phys(pages1[i]));
			check_key("set_read_empty", key, i, false);
		}

	} while (!kthread_should_stop());

	for (i = 0; i < PAGES; i++)
		__free_pages(pages1[i], 0);

	pr_info("%s done\n", __func__);
	return 0;
}

static int key_set_read_touched(void *arg)
{
	int i;

	set_user_nice(current, 19);
	for (i = 0; i < PAGES; i++) {
		pages2[i] = alloc_pages(GFP_ATOMIC, 0);
		if (pages2[i] == NULL) {
			pr_err("Error allocating...\n");
			return -ENOMEM;
		}
	}

	do {
		schedule_timeout_uninterruptible(1);

		for  (i = 0; i < PAGES; i++) {
			/* Ensure to make all pages touched */
			clear_page((void *)page_to_phys(pages2[i]));

			if (i % 2)
				pfmf(0x20000 | (i & 0xfe), page_to_phys(pages2[i]));
			else
				page_set_storage_key(page_to_phys(pages2[i]), i, 0);
		}

		for  (i = 0; i < PAGES; i++) {
			char key;

			key = page_get_storage_key(page_to_phys(pages2[i]));
			check_key("set_read_touched", key, i, false);
		}

	} while (!kthread_should_stop());

	for (i = 0; i < PAGES; i++)
		__free_pages(pages2[i], 0);

	pr_info("%s done\n", __func__);
	return 0;
}



static int key_set_write_rrbe(void *arg)
{
	int i;

	set_user_nice(current, 19);

	for (i = 0; i < PAGES; i++) {
		pages3[i] = alloc_pages(GFP_ATOMIC, 0);
		if (pages3[i] == NULL) {
			pr_err("Error allocating...\n");
			return -ENOMEM;
		}
	}

	do {
		schedule_timeout_uninterruptible(1);

		for  (i = 0; i < PAGES; i++) {
			if (i % 2)
				pfmf(0x20000 | (i & 0xfe), page_to_phys(pages3[i]));
			else
				page_set_storage_key(page_to_phys(pages3[i]), i, 0);
		}

		/* Write all pages R=1 C=1*/
		for (i = 0; i < PAGES; i++) {
			char *writer = (char *) page_to_phys(pages3[i]);
			*writer = 1;
		}

		for  (i = 0; i < PAGES; i++)
			page_reset_referenced(page_to_phys(pages3[i]));

		for  (i = 0; i < PAGES; i++) {
			char key;

			key = page_get_storage_key(page_to_phys(pages3[i]));
			check_key("set_write_rrbe", key, i, true);
		}

	} while (!kthread_should_stop());

	for (i = 0; i < PAGES; i++)
		__free_pages(pages3[i], 0);

	pr_info("%s done\n", __func__);
	return 0;
}

static int key_set_read_ro(void *arg)
{
	int i;

	set_user_nice(current, 19);
	for (i = 0; i < PAGES; i++) {
		pages4[i] = alloc_pages(GFP_ATOMIC, 0);
		if (pages4[i] == NULL) {
			pr_err("Error allocating...\n");
			return -ENOMEM;
		}
		/* Ensure an empty pte */
		if (MACHINE_IS_VM || MACHINE_IS_KVM)
			diag10_range(page_to_pfn(pages4[i]), 1);
	}

	do {
		schedule_timeout_uninterruptible(1);

		for  (i = 0; i < PAGES; i++) {
			volatile long dummy;
			/* Only read all pages (shared zero page in host) */
			dummy = *(unsigned long *) page_to_phys(pages4[i]);

			if (i % 2)
				pfmf(PFMF_SET_KEY | (i & 0xfe),
				     page_to_phys(pages4[i]));
			else
				page_set_storage_key(page_to_phys(pages4[i]), i, 0);
		}

		for  (i = 0; i < PAGES; i++) {
			char key;

			key = page_get_storage_key(page_to_phys(pages4[i]));
			check_key("set_read_ro", key, i, false);
		}

	} while (!kthread_should_stop());

	for (i = 0; i < PAGES; i++)
		__free_pages(pages4[i], 0);

	pr_info("%s done\n", __func__);
	return 0;
}



struct task_struct *task_set_read_empty;
struct task_struct *task_set_read_touched;
struct task_struct *task_set_write_rrbe;
struct task_struct *task_set_read_ro;

static int __init skey_torture_init(void)
{
	if (!MACHINE_HAS_EDAT1)
		return -ENODEV;

	task_set_read_empty = kthread_create(key_set_read_empty,
					     NULL, "set_read_empty");
	task_set_read_touched = kthread_create(key_set_read_touched,
					       NULL, "set_read_touched");
	task_set_write_rrbe = kthread_create(key_set_write_rrbe,
					     NULL, "set_write_rrbe");
	task_set_read_ro = kthread_create(key_set_read_ro,
					     NULL, "set_read_ro");


	pr_info("Starting\n");
	wake_up_process(task_set_read_empty);
	wake_up_process(task_set_read_touched);
	wake_up_process(task_set_write_rrbe);
	wake_up_process(task_set_read_ro);
	return 0;
}

static void __exit skey_torture_exit(void)
{
	kthread_stop(task_set_read_empty);
	kthread_stop(task_set_read_touched);
	kthread_stop(task_set_write_rrbe);
	kthread_stop(task_set_read_ro);
}

module_init(skey_torture_init);
module_exit(skey_torture_exit);

