#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/page.h>

MODULE_LICENSE("GPL");

#define NUM_PAGES 128
static struct page *start_page;

/* Set keys to deterministic values */
static void set_keys(void)
{
	int i;

	for (i = 0; i < NUM_PAGES; i++) {
		int curkey = i * 2;
		struct page *curpage = start_page + i;

		page_set_storage_key(page_to_phys(curpage), curkey, 0);
	}
}

/* Complain if anthing modified the skeys we set! */
static void check_keys(void)
{
	char key;
	int i;
	int fail_count = 0;

	for (i = 0; i < NUM_PAGES; i++) {
		int curkey = i * 2;
		struct page *curpage = start_page + i;

		key = page_get_storage_key(page_to_phys(curpage));

		/* Ignore reference bit! */
		key &= ~0x04;
		curkey &= ~0x04;

		if (key != curkey) {
			printk("skeymigration Change detected: "
			       "Expected=%03X, Actual=%03X\n", curkey, key);
			fail_count++;
		}
	}

	if (fail_count == 0)
		printk("skeymigration: PASS\n");
	else
		printk("skeymigration: FAIL\n");
}

static int __init skeymigration_init(void)
{
	printk("Starting skeymigration test\n");
	start_page = alloc_pages(GFP_ATOMIC, get_order(NUM_PAGES * PAGE_SIZE));
	if (!start_page) {
		printk("skeymigration: Failed to allocate memory\n");
		return -ENOMEM;
	}

	set_keys();
	return 0;
}
static void __exit skeymigration_exit(void)
{
	check_keys();
	__free_pages(start_page, get_order(NUM_PAGES * PAGE_SIZE));
}

module_init(skeymigration_init);
module_exit(skeymigration_exit);
