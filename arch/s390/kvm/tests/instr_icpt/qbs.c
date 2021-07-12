#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <asm/io.h>
#include "instr_icpt.h"

#if 0
# define Dprintk printk
#else
# define Dprintk(...)
#endif

static inline int _sqbs(u64 token)
{
	unsigned long _token = token;
	int rc = -EINVAL;

	asm volatile(
		"	lgr	1,%[token]\n"
		"	.insn	rsy,0xeb000000008A,0,0,0(0)\n"
		"0:	ipm	%[rc]\n"
		"	srl	%[rc],28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: [rc] "+&d" (rc)
		: [token] "d" (_token)
		: "memory", "cc", "1");

	return rc;
}

static inline int _eqbs(u64 token)
{
	unsigned long _token = token;
	int rc = -EINVAL;

	asm volatile(
		"	lgr	1,%[token]\n"
		"	.insn	rrf,0xB99c0000,0,0,0,0\n"
		"0:	ipm	%[rc]\n"
		"	srl	%[rc],28\n"
		"1:\n"
		EX_TABLE(0b, 1b)
		: [rc] "+&d" (rc)
		: [token] "d" (_token)
		: "memory", "cc", "1");

	return rc;
}

int test_qbs(void)
{
	int rc;

	Dprintk("Testing SQBS...\n");
	rc = _sqbs(0xffffffdeadbeefULL);
	if (rc != -EINVAL) {
		Dprintk("sqbs returned %i\n", rc);
		ztst_set_err_str("SQBS not rejected");
		return -EINVAL;
	}

	Dprintk("Testing EQBS...\n");
	rc = _eqbs(0xffffffdeadbeefULL);
	if (rc != -EINVAL) {
		Dprintk("eqbs returned %i\n", rc);
		ztst_set_err_str("EQBS not rejected");
		return -EINVAL;
	}

	return 0;
}
