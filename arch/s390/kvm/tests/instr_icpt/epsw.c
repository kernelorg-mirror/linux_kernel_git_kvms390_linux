
#include "instr_icpt.h"

#define MAGIC1 0x1234567890abcdefUL
#define MAGIC2 0xcafebabefacebeefUL

int test_epsw(void)
{
	register unsigned long r0 asm ("r0");
	register unsigned long r7 asm ("r7");
	register unsigned long r8 asm ("r8");

	r7 = MAGIC1;
	r8 = MAGIC2;

	asm volatile("epsw %r0,%1\n" : "=r"(r7), "=r"(r8) : "r"(r7), "r"(r8));
	if (r7 == MAGIC1 || r8 == MAGIC2) {
		ztst_set_err_str("register value did not change");
		return 1;
	}
	if ((r7 & 0xffffffff00000000UL) != (MAGIC1 & 0xffffffff00000000UL) ||
	    (r8 & 0xffffffff00000000UL) != (MAGIC2 & 0xffffffff00000000UL)) {
		ztst_set_err_str("register upper bits changed");
		return 2;
	}

	r0 = MAGIC2;
	asm volatile("epsw %r0,%1\n" : "=r"(r7), "=r"(r0) : "r"(r7), "r"(r0));
	if (r0 != MAGIC2) {
		ztst_set_err_str("register r0 changed");
		return 3;
	}

	return 0;
}
