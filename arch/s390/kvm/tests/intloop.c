
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <asm/lowcore.h>

MODULE_DESCRIPTION("zKVM interruption loop test module");
MODULE_LICENSE("GPL");

static char *test;
module_param(test, charp, 0);

static u64 prev_psw_mask;
static u64 prev_psw_addr;

static u64 counter = 0x10000;

static inline void spt(void *addr)
{
	asm volatile ("spt 0(%0) " : : "d" (addr));
}

static void extint_handler(void)
{
	struct lowcore *lc = NULL;

	lc->external_new_psw.mask &= ~PSW_MASK_EXT;
#if 1
	asm volatile(" lpswe 0x130 " : : : "memory");
#else
	asm volatile("" : : : "memory");
	lc->external_new_psw.addr = prev_psw_addr;
	asm volatile("" : : : "memory");
	asm volatile(" lpswe 0x1b0 " : : : "memory");
#endif
}

static void printpsw(void)
{
	u32 psw1, psw2;

	asm volatile("epsw %0,%1\n" : "=r"(psw1), "=r"(psw2));
	pr_info("PSW mask: 0x%08x:%08x\n", psw1, psw2);
}

static int test_extint(void)
{
	unsigned long cr0, new_cr0, flags, i;
	struct lowcore *lc = NULL;
	u64 new_psw_mask;

	pr_info("Crashing with external interruption loop...\n");

	flags = arch_local_irq_save();
	__ctl_store(cr0, 0, 0);
	pr_info("Old CR0 :  0x%016lx\n", cr0);
	__ctl_clear_bit(0, 28); /* disable lowcore protection */
	__ctl_store(new_cr0, 0, 0);
	pr_info("New CR0 :  0x%016lx\n", new_cr0);
	printpsw();

	prev_psw_mask = lc->external_new_psw.mask;
	prev_psw_addr = lc->external_new_psw.addr;
	pr_info("Old ext-int PSW:\t0x%016llx:%016llx\n",
		prev_psw_mask, prev_psw_addr);

	new_psw_mask = lc->external_new_psw.mask | PSW_MASK_EXT;
	pr_info("New ext-int PSW:\t0x%016llx:%016llx\n",
		new_psw_mask, (u64)extint_handler);

	lc->external_new_psw.addr = (u64)extint_handler;
	lc->external_new_psw.mask = new_psw_mask;
	mb();		/* Make sure that values have been written to lowcore */

	arch_local_irq_restore(flags);

	spt(&counter);

	for (i = 0; i < 1000000000; i++)
		asm volatile(" nop " : : : "memory");

	flags = arch_local_irq_save();

	pr_info("Tst ext-int PSW:\t0x%016lx:%016lx\n",
		lc->external_new_psw.mask, lc->external_new_psw.addr);

	if (lc->external_new_psw.mask == new_psw_mask
	    && lc->external_new_psw.addr == (u64)extint_handler)
		pr_info("Nothing happened :-(\n");
	else
		pr_info("Survived an ext int!! :-)\n");

	lc->external_new_psw.mask = prev_psw_mask;
	lc->external_new_psw.addr = prev_psw_addr;
	mb();		/* Make sure that values have been written to lowcore */

	__ctl_load(cr0, 0, 0);

	arch_local_irq_restore(flags);

	return 0;
}

static int test_pgmspec(void)
{
	unsigned long cr0, new_cr0, flags;
	struct lowcore *lc = NULL;

	pr_info("Crashing with PGM specification error...\n");

	printpsw();
	flags = arch_local_irq_save();
	__ctl_store(cr0, 0, 0);
	__ctl_clear_bit(0, 28); /* disable lowcore protection */

	pr_info("Old CR0 :  0x%016lx\n", cr0);
	__ctl_store(new_cr0, 0, 0);
	pr_info("New CR0 :  0x%016lx\n", new_cr0);
	printpsw();

	prev_psw_mask = lc->program_new_psw.mask;
	prev_psw_addr = lc->program_new_psw.addr;
	pr_info("Old pgm-int PSW:\t0x%016llx:%016llx\n",
		prev_psw_mask, prev_psw_addr);

	lc->program_new_psw.addr = (u64)0xdeadc0dedeadc0dfULL;
	pr_info("New ext-int PSW:\t0x%016lx:%016lx\n",
		lc->program_new_psw.mask, lc->program_new_psw.addr);

	arch_local_irq_restore(flags);

	*(int *)-4ULL = 0xdeadbeef;

	pr_info("If you see this message, something went wrong.\n");

	__ctl_load(cr0, 0, 0);

	return 0;
}

static int __init intloop_mod_init(void)
{
	pr_info("------- INTERRUPTION LOOP TEST MODULE STARTED ----------\n");

	if (test) {
		if (strcmp(test, "extint") == 0)
			return test_extint();
		if (strcmp(test, "pgmspec") == 0)
			return test_pgmspec();
	}

	pr_info("Use the 'test' parameter to specify how to crash:\n");
	pr_info(" test=\"extint\"  : Crash with external interruptions loop\n");
	pr_info(" test=\"pgmspec\" : Crash with specification program check loop\n");

	return -EINVAL;
}

static void __exit intloop_mod_exit(void)
{
	pr_info("------- INTERRUPTION LOOP TEST MODULE STOPPED ----------\n");
}

module_init(intloop_mod_init);
module_exit(intloop_mod_exit);
