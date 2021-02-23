#define KMSG_COMPONENT "timing"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt


#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/sysinfo.h>

MODULE_LICENSE("GPL");

#define LOOPS 5000
#define RETRIES 10000


static void diag9c(unsigned long data)
{
	int i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("diag %0,0,0x9c" : : "d" (data));
}

static void diag44(unsigned long data)
{
	int i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("diag %0,0,0x44" : : "d" (data));
}

static void sigp_sense_running(unsigned long cpu)
{
	int i;

	for (i = 0; i < LOOPS; i++) {
		unsigned long status;

		asm volatile("sigp %0,%1,0x15\n"
			: "=d" (status) : "d" (cpu) :  "cc");
	}

}

static void do_nop(unsigned long dummy)
{
	int i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("nop\n" ::: "memory");
}

static void do_stnsm(unsigned long dummy)
{
	int i;
	unsigned long buf;

	for (i = 0; i < LOOPS; i++)
		asm volatile("stnsm %0,0xff\n" : "=Q" (buf) :: "memory");
}

static void do_stosm(unsigned long dummy)
{
	int i;
	unsigned long buf;

	for (i = 0; i < LOOPS; i++)
		asm volatile("stosm %0,0\n":"=Q" (buf):: "memory");
}

static void do_ssm(unsigned long dummy)
{
	int i;
	unsigned long buf;

	asm volatile("stosm %0,0\n":"=Q" (buf):: "memory");
	for (i = 0; i < LOOPS; i++)
		asm volatile("ssm %0\n":"=Q" (buf):: "memory");
}
static void lpp(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		asm volatile(".insn s,0xb2800000,%0\n" :: "Q" (i) : "memory");
}

static void lctl4(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("lctl 4,4,%0\n" :: "Q" (i) : "cc", "memory");
}

static void do_stpx(unsigned long dummy)
{
	unsigned long i;
	unsigned int prefix;

	for (i = 0; i < LOOPS; i++)
		asm volatile("stpx %0\n" :: "Q" (prefix) : "cc", "memory");
}

static void do_stfl(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("stfl 0\n" ::: "cc", "memory");
}

static void do_epsw(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		asm volatile("epsw 1,2\n"::: "1", "2", "cc", "memory");
}

static void illegal(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		asm volatile(".word 0\n"
			     "1:\n"
			     EX_TABLE(1b, 1b)
			     ::: "cc", "memory");
}

static char *buffer;

static int servc(int command, void *sccb)
{
	int cc = 4; /* Initialize for program check handling */

	asm volatile(
		"0:	.insn	rre,0xb2200000,%1,%2\n"  /* servc %1,%2 */
		"1:	ipm	%0\n"
		"	srl	%0,28\n"
		"2:\n"
		EX_TABLE(0b, 2b)
		EX_TABLE(1b, 2b)
		: "+&d" (cc) : "d" (command), "a" (__pa(sccb))
		: "cc", "memory");
	if (cc == 4)
		return -EINVAL;
	if (cc == 3)
		return -EIO;
	if (cc == 2)
		return -EBUSY;
	return 0;
}

static void run_servc(unsigned long dummy)
{
	unsigned long i;

	buffer[0] = 0;
	buffer[1] = 8;
	for (i = 0; i < LOOPS; i++)
		servc(0, buffer);
}

static void run_stsi(unsigned long dummy)
{
	unsigned long i;

	for (i = 0; i < LOOPS; i++)
		stsi(buffer, dummy, 2, 2);
}


static unsigned long kick(unsigned long cookie)
{
	register unsigned long __nr asm("1") = 3;
	register unsigned long __schid asm("2") = 0x10000;
	register unsigned long __index asm("3") = 0;
	register long __rc asm("2");
	register long __cookie asm("4") = cookie;

	asm volatile ("diag 2,4,0x500\n"
		      "1: nop\n"
		      EX_TABLE(1b, 1b)
		      : "=d" (__rc)
		      : "d" (__nr), "d" (__schid), "d" (__index), "d"(__cookie)
		      : "memory", "cc");
	return __rc;
}

static void run_kick(unsigned long dummy)
{
	unsigned long i, cookie = 0;

	for (i = 0; i < LOOPS; i++)
		cookie = kick(cookie);
}


static void test_run(void func(unsigned long data), const char *string,
		     unsigned long data)
{
	unsigned long long teststart, start, end, shortest, sum, longest;
	int i;

	shortest = -1ULL;
	longest = 0;
	sum = 0;
	teststart = get_tod_clock_fast();
	for (i = 1; i <= RETRIES; i++) {
		start =	get_tod_clock_fast();
		func(data);
		end = get_tod_clock_fast();
		shortest = min(shortest, end-start);
		longest = max(longest, end-start);
		sum += end - start;
		/* max 0.1sec */
		if (end > teststart + 100 * 1000 * 4096)
			break;
	}
	pr_warn("exit time (%s): min %lu avg: %lu max: %lu\n",
		string,
		tod_to_ns(shortest) / LOOPS,
		tod_to_ns(sum) / LOOPS / i,
		tod_to_ns(longest) / LOOPS);
}

static int __init timing_init(void)
{
	pr_info("--------- TIMING TEST MODULE STARTED ------------\n");

	buffer = (char *) get_zeroed_page(GFP_KERNEL);
	preempt_disable();
	pr_info("Running on CPU %d\n", smp_processor_id());
	test_run(diag9c, "diag9c (self)", smp_processor_id());
	test_run(diag9c, "diag9c (0)", 0);
	test_run(diag9c, "diag9c (1)", 1);
	test_run(diag9c, "diag9c (1000)", 1000);
	test_run(diag44, "diag44", 0);
	test_run(sigp_sense_running, "sigp sense running(0)", 0);
	test_run(sigp_sense_running, "sigp sense running(1)", 1);
	test_run(do_nop, "nop", 0);
	test_run(do_stnsm, "stnsm", 0);
	test_run(do_stosm, "stosm", 0);
	test_run(do_ssm, "ssm", 0);
	test_run(lpp, "lpp", 0);
	test_run(lctl4, "lctl4", 0);
	test_run(do_stpx, "stpx", 0);
	test_run(do_stfl, "stfl", 0);
	test_run(do_epsw, "epsw", 0);
	test_run(illegal, "illegal", 0);
	test_run(run_servc, "servc", 0);
	test_run(run_stsi, "stsi122", 1);
	test_run(run_stsi, "stsi222", 2);
	test_run(run_stsi, "stsi322", 3);
	test_run(run_kick, "diag500", 0);
	preempt_enable();
	free_page((unsigned long) buffer);
	pr_info("--------- TIMING TEST MODULE ENDED ------------\n");
	return -1;
}

static void __exit timing_exit(void)
{
	pr_info("--------- TIMING TEST MODULE STOPPED ------------\n");
}

module_init(timing_init);
module_exit(timing_exit);
