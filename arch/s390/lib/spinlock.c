/*
 *    Out of line spinlock code.
 *
 *    Copyright IBM Corp. 2004, 2006
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com)
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <asm/io.h>

int spin_retry = -1;

static int __init spin_retry_init(void)
{
	if (spin_retry < 0)
		spin_retry = MACHINE_HAS_CAD ? 10 : 1000;
	return 0;
}
early_initcall(spin_retry_init);

/**
 * spin_retry= parameter
 */
static int __init spin_retry_setup(char *str)
{
	spin_retry = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("spin_retry=", spin_retry_setup);

static inline void compare_and_delay(int *lock, int old)
{
	asm(".insn rsy,0xeb0000000022,%0,0,%1" : : "d" (old), "Q" (*lock));
}

static inline int cpu_is_preempted(int cpu)
{
	if (test_cpu_flag_of(CIF_ENABLED_WAIT, cpu))
		return 0;
	if (smp_vcpu_scheduled(cpu))
		return 0;
	return 1;
}

struct spin_wait {
	struct spin_wait *next;
	int lock_spin;
};

static DEFINE_PER_CPU_ALIGNED(struct spin_wait, spin_wait[4]);

#define _Q_LOCK_CPU_OFFSET	0
#define _Q_LOCK_STEAL_OFFSET	16
#define _Q_TAIL_IDX_OFFSET	17
#define _Q_TAIL_CPU_OFFSET	19

#define _Q_LOCK_CPU_MASK	0x0000ffff
#define _Q_LOCK_STEAL_MASK	0x00010000
#define _Q_TAIL_IDX_MASK	0x00060000
#define _Q_TAIL_CPU_MASK	0xfff80000

#define _Q_LOCK_MASK		(_Q_LOCK_CPU_MASK | _Q_LOCK_STEAL_MASK)
#define _Q_TAIL_MASK		(_Q_TAIL_IDX_MASK | _Q_TAIL_CPU_MASK)

void arch_spin_lock_wait(arch_spinlock_t *lp)
{
	struct spin_wait *node, *prev, *next;
	int lockval, ix, cpu, node_id, tail_id, old, new, owner, count;

	ix = S390_lowcore.spinlock_index++;
	barrier();
	lockval = SPINLOCK_LOCKVAL;	/* cpu + 1 */
	node = this_cpu_ptr(&spin_wait[ix]);
	node_id = (lockval << _Q_TAIL_CPU_OFFSET) | (ix << _Q_TAIL_IDX_OFFSET);
	memset(node, 0, sizeof(*node));

	/* Enqueue the node for this CPU in the spinlock wait queue */
	while (1) {
		old = READ_ONCE(lp->lock);
		if ((old & _Q_LOCK_MASK) == 0) {
			/*
			 * The lock is free but there may be waiters.
			 * With no waiters simply take the lock, if there
			 * are waiters try to steal the lock. The lock may
			 * only be stolen once before the next queued waiter
			 * will get the lock.
			 */
			new = (old ? (old | _Q_LOCK_STEAL_MASK) : 0) | lockval;
			if (__atomic_cmpxchg_bool(&lp->lock, old, new))
				/* Got the lock */
				goto out;
			/* lock passing in progress */
			continue;
		}
		/* Make the node of this CPU the new tail. */
		new = node_id | (old & _Q_LOCK_MASK);
		if (__atomic_cmpxchg_bool(&lp->lock, old, new))
			break;
	}
	/* Set the 'next' pointer of the tail node in the queue */
	tail_id = old & _Q_TAIL_MASK;
	if (tail_id != 0) {
		ix = (tail_id & _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;
		cpu = (tail_id & _Q_TAIL_CPU_MASK) >> _Q_TAIL_CPU_OFFSET;
		prev = per_cpu_ptr(&spin_wait[ix], cpu - 1);
		WRITE_ONCE(prev->next, node);
	}

	/* Pass the virtual CPU to the lock holder if it is not running */
	owner = old & _Q_LOCK_CPU_MASK;
	if (owner && cpu_is_preempted(owner - 1))
		smp_yield_cpu(owner - 1);

	/* Spin on the CPU local 'lock_spin' word */
	if (tail_id != 0) {
		count = spin_retry;
		while (1) {
			if (__smp_load_acquire(&node->lock_spin))
				break;
			if (MACHINE_HAS_CAD)
				compare_and_delay(&node->lock_spin, 0);
			if (count-- >= 0)
				continue;
			count = spin_retry;
		}
	}

	/* Spin on the lock value in the spinlock_t */
	count = spin_retry;
	while (1) {
		old = READ_ONCE(lp->lock);
		owner = old & _Q_LOCK_CPU_MASK;
		if (!owner) {
			tail_id = old & _Q_TAIL_MASK;
			new = ((tail_id != node_id) ? tail_id : 0) | lockval;
			if (__atomic_cmpxchg_bool(&lp->lock, old, new))
				/* Got the lock */
				break;
			continue;
		}
		if (MACHINE_HAS_CAD)
			compare_and_delay(&lp->lock, old);
		if (count-- >= 0)
			continue;
		if (!MACHINE_IS_LPAR || cpu_is_preempted(owner - 1))
			smp_yield_cpu(owner - 1);
		count = spin_retry;
	}

	/* Pass lock_spin job to next CPU in the queue */
	if (tail_id != node_id) {
		/* Wait until the next CPU has set up the 'next' pointer */
		while ((next = __smp_load_acquire(&node->next)) == 0);
		next->lock_spin = 1;
	}

 out:
	S390_lowcore.spinlock_index--;
}
EXPORT_SYMBOL(arch_spin_lock_wait);

int arch_spin_trylock_retry(arch_spinlock_t *lp)
{
	int cpu = SPINLOCK_LOCKVAL;
	int owner, count;

	for (count = spin_retry; count > 0; count--) {
		owner = ACCESS_ONCE(lp->lock);
		/* Try to get the lock if it is free. */
		if (!owner) {
			if (__atomic_cmpxchg_bool(&lp->lock, 0, cpu))
				return 1;
		} else if (MACHINE_HAS_CAD)
			compare_and_delay(&lp->lock, owner);
	}
	return 0;
}
EXPORT_SYMBOL(arch_spin_trylock_retry);

void _raw_read_lock_wait(arch_rwlock_t *rw)
{
	int count = spin_retry;
	int owner, old;

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES
	__RAW_LOCK(&rw->lock, -1, __RAW_OP_ADD);
#endif
	owner = 0;
	while (1) {
		if (count-- <= 0) {
			if (owner && cpu_is_preempted(owner - 1))
				smp_yield_cpu(owner - 1);
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		owner = ACCESS_ONCE(rw->owner);
		if (old < 0) {
			if (MACHINE_HAS_CAD)
				compare_and_delay(&rw->lock, old);
			continue;
		}
		if (__atomic_cmpxchg_bool(&rw->lock, old, old + 1))
			return;
	}
}
EXPORT_SYMBOL(_raw_read_lock_wait);

int _raw_read_trylock_retry(arch_rwlock_t *rw)
{
	int count = spin_retry;
	int old;

	while (count-- > 0) {
		old = ACCESS_ONCE(rw->lock);
		if (old < 0) {
			if (MACHINE_HAS_CAD)
				compare_and_delay(&rw->lock, old);
			continue;
		}
		if (__atomic_cmpxchg_bool(&rw->lock, old, old + 1))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(_raw_read_trylock_retry);

#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES

void _raw_write_lock_wait(arch_rwlock_t *rw, int prev)
{
	int count = spin_retry;
	int owner, old;

	owner = 0;
	while (1) {
		if (count-- <= 0) {
			if (owner && cpu_is_preempted(owner - 1))
				smp_yield_cpu(owner - 1);
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		owner = ACCESS_ONCE(rw->owner);
		smp_mb();
		if (old >= 0) {
			prev = __RAW_LOCK(&rw->lock, 0x80000000, __RAW_OP_OR);
			old = prev;
		}
		if ((old & 0x7fffffff) == 0 && prev >= 0)
			break;
		if (MACHINE_HAS_CAD)
			compare_and_delay(&rw->lock, old);
	}
}
EXPORT_SYMBOL(_raw_write_lock_wait);

#else /* CONFIG_HAVE_MARCH_Z196_FEATURES */

void _raw_write_lock_wait(arch_rwlock_t *rw)
{
	int count = spin_retry;
	int owner, old, prev;

	prev = 0x80000000;
	owner = 0;
	while (1) {
		if (count-- <= 0) {
			if (owner && cpu_is_preempted(owner - 1))
				smp_yield_cpu(owner - 1);
			count = spin_retry;
		}
		old = ACCESS_ONCE(rw->lock);
		owner = ACCESS_ONCE(rw->owner);
		if (old >= 0 &&
		    __atomic_cmpxchg_bool(&rw->lock, old, old | 0x80000000))
			prev = old;
		else
			smp_mb();
		if ((old & 0x7fffffff) == 0 && prev >= 0)
			break;
		if (MACHINE_HAS_CAD)
			compare_and_delay(&rw->lock, old);
	}
}
EXPORT_SYMBOL(_raw_write_lock_wait);

#endif /* CONFIG_HAVE_MARCH_Z196_FEATURES */

int _raw_write_trylock_retry(arch_rwlock_t *rw)
{
	int count = spin_retry;
	int old;

	while (count-- > 0) {
		old = ACCESS_ONCE(rw->lock);
		if (old) {
			if (MACHINE_HAS_CAD)
				compare_and_delay(&rw->lock, old);
			continue;
		}
		if (__atomic_cmpxchg_bool(&rw->lock, 0, 0x80000000))
			return 1;
	}
	return 0;
}
EXPORT_SYMBOL(_raw_write_trylock_retry);

void arch_lock_relax(int cpu)
{
	if (!cpu)
		return;
	if (MACHINE_IS_LPAR && !cpu_is_preempted((cpu - 1) & 0xffff))
		return;
	smp_yield_cpu((cpu - 1) & 0xffff);
}
EXPORT_SYMBOL(arch_lock_relax);
