// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <asm/aef.h>
#include "qaaf.h"
#include "feature.h"

void __init kvm_init_qaaf(void)
{
	kvm_arm_host_sanitize_features(aef_qmc());
}

#define _qaaf_reg_case(id) case SYS_##id: return aef_qmc()->regs[QAAF_REG_##id]
u64 kvm_qaaf_read_ftr_reg(u32 id)
{
	switch (id) {
	_qaaf_reg_case(MIDR_EL1);
	_qaaf_reg_case(MPIDR_EL1);
	_qaaf_reg_case(REVIDR_EL1);
	_qaaf_reg_case(ID_PFR0_EL1);
	_qaaf_reg_case(ID_PFR1_EL1);
	_qaaf_reg_case(ID_DFR0_EL1);
	_qaaf_reg_case(ID_AFR0_EL1);
	_qaaf_reg_case(ID_MMFR0_EL1);
	_qaaf_reg_case(ID_MMFR1_EL1);
	_qaaf_reg_case(ID_MMFR2_EL1);
	_qaaf_reg_case(ID_MMFR3_EL1);
	_qaaf_reg_case(ID_ISAR0_EL1);
	_qaaf_reg_case(ID_ISAR1_EL1);
	_qaaf_reg_case(ID_ISAR2_EL1);
	_qaaf_reg_case(ID_ISAR3_EL1);
	_qaaf_reg_case(ID_ISAR4_EL1);
	_qaaf_reg_case(ID_ISAR5_EL1);
	_qaaf_reg_case(ID_MMFR4_EL1);
	_qaaf_reg_case(ID_ISAR6_EL1);
	_qaaf_reg_case(MVFR0_EL1);
	_qaaf_reg_case(MVFR1_EL1);
	_qaaf_reg_case(MVFR2_EL1);
	_qaaf_reg_case(ID_PFR2_EL1);
	_qaaf_reg_case(ID_DFR1_EL1);
	_qaaf_reg_case(ID_MMFR5_EL1);
	_qaaf_reg_case(ID_AA64PFR0_EL1);
	_qaaf_reg_case(ID_AA64PFR1_EL1);
	_qaaf_reg_case(ID_AA64PFR2_EL1);
	_qaaf_reg_case(ID_AA64ZFR0_EL1);
	_qaaf_reg_case(ID_AA64SMFR0_EL1);
	_qaaf_reg_case(ID_AA64FPFR0_EL1);
	_qaaf_reg_case(ID_AA64DFR0_EL1);
	_qaaf_reg_case(ID_AA64DFR1_EL1);
	_qaaf_reg_case(ID_AA64DFR2_EL1);
	_qaaf_reg_case(ID_AA64AFR0_EL1);
	_qaaf_reg_case(ID_AA64AFR1_EL1);
	_qaaf_reg_case(ID_AA64ISAR0_EL1);
	_qaaf_reg_case(ID_AA64ISAR1_EL1);
	_qaaf_reg_case(ID_AA64ISAR2_EL1);
	_qaaf_reg_case(ID_AA64ISAR3_EL1);
	_qaaf_reg_case(ID_AA64MMFR0_EL1);
	_qaaf_reg_case(ID_AA64MMFR1_EL1);
	_qaaf_reg_case(ID_AA64MMFR2_EL1);
	_qaaf_reg_case(ID_AA64MMFR3_EL1);
	_qaaf_reg_case(ID_AA64MMFR4_EL1);
	_qaaf_reg_case(CNTFRQ_EL0);
	_qaaf_reg_case(CTR_EL0);
	_qaaf_reg_case(AIDR_EL1);
	_qaaf_reg_case(ICH_VTR_EL2);
	_qaaf_reg_case(PMMIR_EL1);
	_qaaf_reg_case(PMCR_EL0);
	_qaaf_reg_case(PMCEID0_EL0);
	_qaaf_reg_case(PMCEID1_EL0);
	default:
		WARN(true, "Unknown feature register 0x%x\n", id);
		return 0xbad1234bad;
	}
}
