
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>
#include "instr_icpt.h"

#if 0
# define dbgprintk printk
#else
# define dbgprintk(...)
#endif

static inline int _tprot(unsigned long addr)
{
	int cc;

	asm volatile(
		" tprot   0(%1),0\n"
		" ipm     %0\n"
		" srl     %0,28\n"
		: "=d" (cc) : "a" (addr) : "cc");
	return cc;
}

int test_tprot(void)
{
	int cc;

	dbgprintk("TPROT: testing code segment\n");
	cc = _tprot((unsigned long)test_tprot);
	if (cc != 1) {   /* Assume code is read-only */
		ztst_set_err_str("code is not marked as read-only");
		dbgprintk("cc = %i\n", cc);
		return -EOPNOTSUPP;
	}

	dbgprintk("TPROT: testing data segment\n");
	cc = _tprot((unsigned long)&cc);
	if (cc != 0) {
		ztst_set_err_str("stack data is not marked as read-write");
		dbgprintk("cc = %i\n", cc);
		return -EOPNOTSUPP;
	}

	dbgprintk("TPROT: testing lowcore\n");
	cc = _tprot(0);
	if (cc != 1) {   /* Assume low-address protection ==> read-only */
		ztst_set_err_str("lowcore is not marked as read-only");
		dbgprintk("cc = %i\n", cc);
		return -EOPNOTSUPP;
	}

	dbgprintk("TPROT: testing illegal address\n");
	cc = _tprot(0xffffdeaddeadc0deULL);
	if (cc != 3) {
		ztst_set_err_str("illegal address not marked as unavailable");
		dbgprintk("cc = %i\n", cc);
		return -EOPNOTSUPP;
	}

	return 0;
}
