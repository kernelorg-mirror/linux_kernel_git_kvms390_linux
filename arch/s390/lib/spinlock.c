/*
 *    Out of line spinlock code.
 *
 *    Copyright IBM Corp. 2004, 2006
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com)
 */

#include <linux/types.h>
#include <linux/export.h>
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
			if (READ_ONCE(node->lock_spin))
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
		while ((next = READ_ONCE(node->next)) == 0);
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

void arch_read_lock_wait(arch_rwlock_t *rw)
{
	if (unlikely(in_interrupt())) {
		while (READ_ONCE(rw->cnts) & 0x10000)
			barrier();
		return;
	}

	/* Remove this reader again to allow recursive read locking */
	__atomic_add_const(-1, &rw->cnts);
	/* Put the reader into the wait queue */
	arch_spin_lock(&rw->wait);
	/* Now add this reader to the count value again */
	__atomic_add_const(1, &rw->cnts);
	/* Loop until the writer is done */
	while (READ_ONCE(rw->cnts) & 0x10000)
		barrier();
	arch_spin_unlock(&rw->wait);
}
EXPORT_SYMBOL(arch_read_lock_wait);

void arch_write_lock_wait(arch_rwlock_t *rw)
{
	int old;

	/* Add this CPU to the write waiters */
	__atomic_add(0x20000, &rw->cnts);

	/* Put the writer into the wait queue */
	arch_spin_lock(&rw->wait);

	while (1) {
		old = READ_ONCE(rw->cnts);
		if ((old & 0x1ffff) == 0 &&
		    __atomic_cmpxchg_bool(&rw->cnts, old, old | 0x10000))
			/* Got the lock */
			break;
		barrier();
	}

	arch_spin_unlock(&rw->wait);
}
EXPORT_SYMBOL(arch_write_lock_wait);

void arch_lock_relax(int cpu)
{
	if (!cpu)
		return;
	if (MACHINE_IS_LPAR && !cpu_is_preempted((cpu - 1) & 0xffff))
		return;
	smp_yield_cpu((cpu - 1) & 0xffff);
}
EXPORT_SYMBOL(arch_lock_relax);
