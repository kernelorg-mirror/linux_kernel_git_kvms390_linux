
#include "instr_icpt.h"

#define MAGIC1 0x1234567890abcdefUL
#define MAGIC2 0xcafebabefacebeefUL

int test_epsw(void)
{
	unsigned long r0;
	unsigned long r7;
	unsigned long r8;

	r7 = MAGIC1;
	r8 = MAGIC2;

	asm volatile(
		"	lgr	7,%[r7]\n"
		"	lgr	8,%[r8]\n"
		"	epsw	7,8\n"
		"	lgr	%[r7],7\n"
		"	lgr	%[r8],8\n"
		: [r7] "+&d" (r7), [r8] "+&d" (r8)
		:
		: "7", "8");
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
	asm volatile(
		"	lgr	0,%[r0]\n"
		"	lgr	7,%[r7]\n"
		"	epsw	7,0\n"
		"	lgr	%[r0],0\n"
		"	lgr	%[r7],7\n"
		: [r7] "+&d" (r7), [r0] "+&d" (r0)
		:
		: "0", "7");
	if (r0 != MAGIC2) {
		ztst_set_err_str("register r0 changed");
		return 3;
	}

	return 0;
}
