#ifndef __ASM_PREEMPT_H
#define __ASM_PREEMPT_H

#include <asm/current.h>
#include <linux/thread_info.h>

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES

#define PREEMPT_ENABLED	(0 + PREEMPT_NEED_RESCHED)

static inline void __preempt_count_asi(int val)
{
	asm volatile(
		"	asi	%0,%1\n"
		: "+Q" (S390_lowcore.preempt_count) : "i" (val) : "cc");
}

static inline int __preempt_count_laa(int val)
{
	asm volatile(
		"	laa	%0,%0,%1\n"
		: "+d" (val), "+Q" (S390_lowcore.preempt_count) : : "cc");
	return val;
}

static inline int __preempt_count_lao(int val)
{
	asm volatile(
		"	lao	%0,%0,%1\n"
		: "+d" (val), "+Q" (S390_lowcore.preempt_count) : : "cc");
	return val;
}

static inline int __preempt_count_lan(int val)
{
	asm volatile(
		"	lan	%0,%0,%1\n"
		: "+d" (val), "+Q" (S390_lowcore.preempt_count) : : "cc");
	return val;
}

static inline int __preempt_count_cmpxchg(int old, int new)
{
	return __sync_bool_compare_and_swap(&S390_lowcore.preempt_count,
					    old, new);
}

static inline int preempt_count(void)
{
	return READ_ONCE(S390_lowcore.preempt_count) & ~PREEMPT_NEED_RESCHED;
}

static inline void preempt_count_set(int pc)
{
	int old, new;

	do {
		old = READ_ONCE(S390_lowcore.preempt_count);
		new = (old & PREEMPT_NEED_RESCHED) |
			(pc & ~PREEMPT_NEED_RESCHED);
	} while (!__preempt_count_cmpxchg(old, new));
}

#define init_task_preempt_count(p)	do { } while (0)

#define init_idle_preempt_count(p, cpu)	do { \
	S390_lowcore.preempt_count = PREEMPT_ENABLED; \
} while (0)

static inline void set_preempt_need_resched(void)
{
	__preempt_count_lan(~PREEMPT_NEED_RESCHED);
}

static inline void clear_preempt_need_resched(void)
{
	__preempt_count_lao(PREEMPT_NEED_RESCHED);
}

static inline bool test_preempt_need_resched(void)
{
	return !(READ_ONCE(S390_lowcore.preempt_count) & PREEMPT_NEED_RESCHED);
}

static inline void __preempt_count_add(int val)
{
	if (__builtin_constant_p(val) && (val >= -128) && (val <= 127))
		__preempt_count_asi(val);
	else
		__preempt_count_laa(val);
}

static inline void __preempt_count_sub(int val)
{
	__preempt_count_add(-val);
}

static inline bool __preempt_count_dec_and_test(void)
{
	return __preempt_count_laa(-1) == 1;
}

static inline bool should_resched(int preempt_offset)
{
	return unlikely(READ_ONCE(S390_lowcore.preempt_count) ==
			preempt_offset);
}

#else /* CONFIG_HAVE_MARCH_Z196_FEATURES */

#define PREEMPT_ENABLED	(0)

static inline int preempt_count(void)
{
	return READ_ONCE(S390_lowcore.preempt_count);
}

static inline void preempt_count_set(int pc)
{
	S390_lowcore.preempt_count = pc;
}

#define init_task_preempt_count(p)	do { } while (0)

#define init_idle_preempt_count(p, cpu)	do { \
	S390_lowcore.preempt_count = PREEMPT_ENABLED; \
} while (0)

static inline void set_preempt_need_resched(void)
{
}

static inline void clear_preempt_need_resched(void)
{
}

static inline bool test_preempt_need_resched(void)
{
	return false;
}

static inline void __preempt_count_add(int val)
{
	S390_lowcore.preempt_count += val;
}

static inline void __preempt_count_sub(int val)
{
	S390_lowcore.preempt_count -= val;
}

static inline bool __preempt_count_dec_and_test(void)
{
	return !--S390_lowcore.preempt_count && tif_need_resched();
}

static inline bool should_resched(int preempt_offset)
{
	return unlikely(preempt_count() == preempt_offset &&
			tif_need_resched());
}

#endif /* CONFIG_HAVE_MARCH_Z196_FEATURES */

#ifdef CONFIG_PREEMPT
extern asmlinkage void preempt_schedule(void);
#define __preempt_schedule() preempt_schedule()
extern asmlinkage void preempt_schedule_notrace(void);
#define __preempt_schedule_notrace() preempt_schedule_notrace()
#endif /* CONFIG_PREEMPT */

#endif /* __ASM_PREEMPT_H */
