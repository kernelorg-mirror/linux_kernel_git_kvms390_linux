/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_S390_ABS_LOWCORE_H
#define _ASM_S390_ABS_LOWCORE_H

#include <linux/smp.h>
#include <asm/lowcore.h>

#define ABS_LOWCORE_MAP_SIZE	(NR_CPUS * sizeof(struct lowcore))
#define ABS_LOWCORE_UNMAPPED	1
#define ABS_LOWCORE_LAP_ON	2
#define ABS_LOWCORE_IRQS_ON	4

extern unsigned long __abs_lowcore;

static inline bool abs_lowcore_mapped(void)
{
	unsigned long irq_flags = arch_local_save_flags();

	return irq_flags & PSW_MASK_DAT;
}

static inline struct lowcore *get_abs_lowcore(unsigned long *flags)
{
	unsigned long irq_flags;
	union ctlreg0 cr0;
	int cpu;

	*flags = 0;
	cpu = get_cpu();
	if (abs_lowcore_mapped()) {
		return ((struct lowcore *)__abs_lowcore) + cpu;
	} else {
		local_irq_save(irq_flags);
		if (!irqs_disabled_flags(irq_flags))
			*flags |= ABS_LOWCORE_IRQS_ON;
		__ctl_store(cr0.val, 0, 0);
		if (cr0.lap) {
			*flags |= ABS_LOWCORE_LAP_ON;
			__ctl_clear_bit(0, 28);
		}
		*flags |= ABS_LOWCORE_UNMAPPED;
		return NULL;
	}
}

static inline void put_abs_lowcore(struct lowcore *, unsigned long flags)
{
	if (abs_lowcore_mapped()) {
		if (flags)
			panic("Invalid mapped absolute lowcore release\n");
	} else {
		if (!(flags & ABS_LOWCORE_UNMAPPED))
			panic("Invalid unmapped absolute lowcore release\n");
		if (flags & ABS_LOWCORE_LAP_ON)
			__ctl_set_bit(0, 28);
		if (flags & ABS_LOWCORE_IRQS_ON)
			local_irq_enable();
	}
	put_cpu();
}

int abs_lowcore_map(int cpu, struct lowcore *lc);
void abs_lowcore_unmap(int cpu);

#endif /* _ASM_ABS_S390_LOWCORE_H */
