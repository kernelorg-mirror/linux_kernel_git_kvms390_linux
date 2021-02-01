
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <asm/io.h>
#include <asm/ctl_reg.h>
#include <linux/timex.h>  /* Inline functions for clock register access. */
#include "instr_icpt.h"

#define CLKOFFSET 0x1000000

static inline int store_tod_clock_asm(__u64 *time)
{
	int cc;

	asm volatile(
		"   stck  %1\n"
		"   ipm	  %0\n"
		"   srl	  %0,28\n"
		: "=d" (cc), "=Q" (*time) : : "cc");
	return cc;
}

int test_sck(void)
{
	u64 start, end;
	//u64 cr0;

	ctl_set_bit(0, (63-34));
	//__ctl_store(cr0, 0, 0);
	//printk(" cr0 = 0x%016llx\n", cr0);
	mdelay(20);

	//printk("cpu%i: Doing SCK + ...\n", cpu);
	store_tod_clock_asm(&start);
	set_tod_clock(start + CLKOFFSET);

	ctl_clear_bit(0, (63-34));
	//__ctl_store(cr0, 0, 0);
	//printk("cr0 = 0x%016llx\n", cr0);

	ctl_set_bit(0, (63-34));
	mdelay(20);

	store_tod_clock_asm(&end);
	set_tod_clock(end - CLKOFFSET);

	ctl_clear_bit(0, (63-34));

	if (end - start < CLKOFFSET) {
		ztst_set_err_str("clock did not change");
		return 1;
	}

	return 0;
}
