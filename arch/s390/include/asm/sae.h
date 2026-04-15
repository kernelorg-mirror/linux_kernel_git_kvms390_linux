/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_S390_SAE_H
#define __ASM_S390_SAE_H

#include <linux/linkage.h>
#include <linux/types.h>
#include <asm/sae-asm.h>

#ifndef __ASSEMBLER__

/* defined in arch/s390/kernel/entry.S */
asmlinkage void __sae64a(phys_addr_t sae_block_phys);

#include <linux/io.h>
#include <asm/kvm_host_arm64_types.h>

asm(".include \"asm/sae-asm.h\"\n");

#define _SAE_ASR_REG_SHIFT	5
#define SASR_FLAG_INITIALIZED  0x8
#define EASR_FLAG_SA           0x8

/**
 * __sae64a() - Start Arm Execution
 */
static inline void sae64a(struct kvm_sae_block *sae_block)
{
	__sae64a(virt_to_phys(sae_block));
}

/**
 * sasr() - Set Arm System Register
 * @arm_reg: ARM system register identifier; compile-time constant
 * @val: Value to set
 * @save_area: Pointer to SAE save area
 * @flags: Operation flags; compile-time constant
 *
 * Sets an ARM system register value.
 */
static __always_inline void sasr(unsigned int arm_reg, u64 val,
				 struct kvm_sae_save_area *save_area,
				 u64 flags)
{
	struct kvm_sae_save_area *sdo = (void *)save_area->sdo;
	u16 reg = arm_reg >> _SAE_ASR_REG_SHIFT;

	asm volatile (
		"	SASR	%[r1],%[r3],%[i2],%[m4]\n"
		: "+m" (*save_area), "+m" (*sdo)
		: [r1] "d" (val),
		  [r3] "a" (save_area), [i2] "K" (reg), [m4] "I" (flags)
	);
}

/**
 * easr() - Extract Arm System Register
 * @arm_reg: ARM system register identifier; compile-time constant
 * @save_area: Pointer to SAE save area
 * @flags: Operation flags; compile-time constant
 *
 * Reads an ARM system register value.
 *
 * Return: Register value
 */
static __always_inline u64 easr(unsigned int arm_reg,
				const struct kvm_sae_save_area *save_area,
				u64 flags)
{
	struct kvm_sae_save_area *sdo = (void *)save_area->sdo;
	u16 reg = arm_reg >> _SAE_ASR_REG_SHIFT;
	u64 val;

	asm volatile(
		"	EASR	%[r1],%[r3],%[i2],%[m4]\n"
		: [r1] "=d"(val)
		: "m"(*save_area),
		  "m"(*sdo), [r3] "a"(save_area), [i2] "K"(reg), [m4] "I"(flags)
	);
	return val;
}

/**
 * stiasrm() - STore and Invalidate Arm System Register Multiple
 * @save_area: Pointer to SAE save area
 *
 * Store the guest system register to the save area.
 * The values in the guest are not valid anymore..
 */
static __always_inline void stiasrm(struct kvm_sae_save_area *save_area)
{
	asm volatile(
		"	.insn	rre,0xb9a70000,%[r1],0\n"
		: "+m"(*save_area)
		: [r1] "a"(save_area)
	);
}

/**
 * lasrm() - Load Arm System Register Multiple
 *
 * @save_area: Pointer to SAE save area
 *
 * Load the system registers from save_area into the guest.
 */
static __always_inline void lasrm(struct kvm_sae_save_area *save_area)
{
	asm volatile(
		"	.insn	rre,0xb9a60000,%[r1],0\n"
		:
		: "m"(*save_area), [r1] "a"(save_area)
	);
}

#endif /* !__ASSEMBLER__ */
#endif /* __ASM_S390_SAE_H */
