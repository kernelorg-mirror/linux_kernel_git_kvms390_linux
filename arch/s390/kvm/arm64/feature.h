/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ARCH_S390_KVM_FEATURE_H
#define ARCH_S390_KVM_FEATURE_H

#include <linux/types.h>
#include <linux/bitfield.h>

#include <asm/sae.h>

#include "qaaf.h"

int __init kvm_arm_host_sanitize_features(struct qaaf_qmc_block *qaaf_qmc);

/**
 * read_sanitised_ftr_reg() - Get the value of a sys register
 *
 * @id - ARM sysreg id
 *
 * Get the value of a sys register describing the host configuration.
 * The returned value indicates support by the machine (HW/FW)
 * after some sanitisation.
 * See `enum qaaf_regs` for supported registers.
 *
 * Example:
 *	read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1)
 *
 * Return: Sanitised HW value of the specified register
 */
static inline u64 read_sanitised_ftr_reg(u32 id)
{
	return kvm_qaaf_read_ftr_reg(id);
}

/**
 * kvm_sae_supported_sd_formats() - Retrieve supported SAE SD formats
 *
 * Return: Bitmap of supported SAE state description formats.
 */
static inline u32 kvm_sae_supported_sd_formats(void)
{
	extern struct qaaf_qmc_block __qaaf_qmp;

	return __qaaf_qmp.ssdf;
}

/**
 * kvm_sae_supported_sa_formats() - Retrieve supported SAE SA formats
 *
 * Return: Bitmap of supported SAE save area formats.
 */
static inline u32 kvm_sae_supported_sa_formats(void)
{
	extern struct qaaf_qmc_block __qaaf_qmp;

	return __qaaf_qmp.ssaf;
}

/**
 * kvm_sae_max_vcpus() - Retrieve maximum supported vcpus
 *
 * Return: Max number of vCPUs supported by the SAE instruction/the machine
 *	as indicated by QAAF, not necessarily that supported by the host software.
 */
static inline u16 kvm_sae_max_vcpus(void)
{
	extern struct qaaf_qmc_block __qaaf_qmp;

	/* QAAF QMP reports the max id not the max num */
	return __qaaf_qmp.maxncpu + 1;
}

/**
 * kvm_sae_irptc() - Retrieve supported SAE IRPTCs
 *
 * Return: Bitmap of supported SAE IRPTCs.
 */
static inline u64 kvm_sae_irptc(void)
{
	extern struct qaaf_qmc_block __qaaf_qmp;

	return __qaaf_qmp.regs[QAAF_IRPTC];
}

#define kvm_vcpu_has_pmu(_v) false

#endif /* ARCH_S390_KVM_FEATURE_H */
