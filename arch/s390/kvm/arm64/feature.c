// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <linux/printk.h>
#include <linux/bitfield.h>
#include <asm/sae.h>
#include <asm/kvm_host_types.h>

#include <arm64/sysreg.h>

#include "feature.h"

#define MASK_RESERVED(_qaafp, _id)				\
	({							\
		u64 *_reg = &((_qaafp)->regs[QAAF_REG_##_id]);	\
		*_reg = (*_reg & ~_id##_RES0) | _id##_RES1;	\
	})

#define QAAF_FIELD_MODIFY(_idp, _id_field, _val) \
	FIELD_MODIFY(_id_field##_MASK, _idp, _id_field##_##_val)

#define MODIFY(_qaafp, _id, _field, _val) \
	QAAF_FIELD_MODIFY(&((_qaafp)->regs[QAAF_REG_##_id]), _id##_##_field, _val)

int __init kvm_arm_host_sanitize_features(struct qaaf_qmc_block *qaaf_qmc)
{
	MASK_RESERVED(qaaf_qmc, ID_AA64ISAR0_EL1);

	MODIFY(qaaf_qmc, ID_AA64ISAR1_EL1, LS64, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64ISAR1_EL1);

	MODIFY(qaaf_qmc, ID_AA64ISAR2_EL1, SYSINSTR_128, NI);
	MODIFY(qaaf_qmc, ID_AA64ISAR2_EL1, SYSREG_128, NI);
	MODIFY(qaaf_qmc, ID_AA64ISAR2_EL1, PAC_frac, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64ISAR2_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64ISAR3_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64MMFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64MMFR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64MMFR2_EL1);

	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, Spec_FPACC, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, ADERR, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, SDERR, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, ANERR, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, SNERR, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR3_EL1, MEC, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64MMFR3_EL1);

	MODIFY(qaaf_qmc, ID_AA64MMFR4_EL1, SRMASK, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR4_EL1, E3DSE, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR4_EL1, RMEGDI, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR4_EL1, FGWTE3, NI);
	MODIFY(qaaf_qmc, ID_AA64MMFR4_EL1, ASID2, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64MMFR4_EL1);

	MODIFY(qaaf_qmc, ID_AA64PFR0_EL1, SEL2, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64PFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64PFR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64PFR2_EL1);

	MODIFY(qaaf_qmc, ID_AA64DFR0_EL1, PMUVer, NI);
	MASK_RESERVED(qaaf_qmc, ID_AA64DFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64DFR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64DFR2_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64AFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_AA64AFR1_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64ZFR0_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64SMFR0_EL1);

	MASK_RESERVED(qaaf_qmc, ID_AA64FPFR0_EL1);

	MASK_RESERVED(qaaf_qmc, ID_PFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_PFR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_PFR2_EL1);

	MASK_RESERVED(qaaf_qmc, ID_DFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_DFR1_EL1);

	MASK_RESERVED(qaaf_qmc, ID_MMFR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_MMFR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_MMFR2_EL1);
	MASK_RESERVED(qaaf_qmc, ID_MMFR3_EL1);
	MASK_RESERVED(qaaf_qmc, ID_MMFR4_EL1);
	MASK_RESERVED(qaaf_qmc, ID_MMFR5_EL1);

	MASK_RESERVED(qaaf_qmc, ID_ISAR0_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR1_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR2_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR3_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR4_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR5_EL1);
	MASK_RESERVED(qaaf_qmc, ID_ISAR6_EL1);

	MASK_RESERVED(qaaf_qmc, MVFR0_EL1);
	MASK_RESERVED(qaaf_qmc, MVFR1_EL1);
	MASK_RESERVED(qaaf_qmc, MVFR2_EL1);

	MASK_RESERVED(qaaf_qmc, CTR_EL0);

	MASK_RESERVED(qaaf_qmc, ICH_VTR_EL2);

	return 0;
}

/**
 * cpus_have_final_cap - Check if an ARM64 CPU capability is supported
 * @num: Capability number to check
 *
 * Maps ARM64 CPU capabilities to their corresponding ID register fields
 * and checks if the feature is supported by the s390 hardware via QAAF.
 *
 * Return: true if capability is supported, false otherwise
 */
bool cpus_have_final_cap(unsigned int num)
{
	u64 reg_val;

	switch (num) {
	case ARM64_HAS_STAGE2_FWB:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
		return SYS_FIELD_GET(ID_AA64MMFR2_EL1, FWB, reg_val) >=
		       ID_AA64MMFR2_EL1_FWB_IMP;

	case ARM64_HAS_WFXT:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64ISAR2_EL1);
		return SYS_FIELD_GET(ID_AA64ISAR2_EL1, WFxT, reg_val) >=
		       ID_AA64ISAR2_EL1_WFxT_IMP;

	case ARM64_HAS_RASV1P1_EXTN:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64PFR1_EL1);
		return SYS_FIELD_GET(ID_AA64PFR1_EL1, RAS_frac, reg_val) ==
		       ID_AA64PFR1_EL1_RAS_frac_RASv1p1;

	case ARM64_HAS_HCR_NV1:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
		return SYS_FIELD_GET(ID_AA64MMFR2_EL1, NV, reg_val) >=
		       ID_AA64MMFR2_EL1_NV_IMP;

	case ARM64_HAS_RAS_EXTN:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);
		return SYS_FIELD_GET(ID_AA64PFR0_EL1, RAS, reg_val) >=
		       ID_AA64PFR0_EL1_RAS_IMP;

	case ARM64_HAS_EVT:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64MMFR2_EL1);
		return SYS_FIELD_GET(ID_AA64MMFR2_EL1, EVT, reg_val) >=
		       ID_AA64MMFR2_EL1_EVT_IMP;

	case ARM64_HAS_ECV_CNTPOFF:
		reg_val = read_sanitised_ftr_reg(SYS_ID_AA64MMFR1_EL1);
		return SYS_FIELD_GET(ID_AA64MMFR1_EL1, PAN, reg_val) >=
		       ID_AA64MMFR1_EL1_PAN_IMP;

	case ARM64_MISMATCHED_CACHE_TYPE:
		return false;
	default:
		return false;
	}
}

bool system_supports_sve(void)
{
	return cpu_has_vx() &&
	       SYS_FIELD_GET(ID_AA64PFR0_EL1, SVE,
			     read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1)) ==
		       ID_AA64PFR0_EL1_SVE_IMP;
}

bool system_has_full_ptr_auth(void)
{
	u64 isar1 = read_sanitised_ftr_reg(SYS_ID_AA64ISAR1_EL1);
	u64 isar2 = read_sanitised_ftr_reg(SYS_ID_AA64ISAR2_EL1);
	bool address_auth;
	bool generic_auth;

	address_auth = SYS_FIELD_GET(ID_AA64ISAR1_EL1, APA, isar1) >= ID_AA64ISAR1_EL1_APA_PAuth ||
		       SYS_FIELD_GET(ID_AA64ISAR1_EL1, API, isar1) >= ID_AA64ISAR1_EL1_API_PAuth ||
		       SYS_FIELD_GET(ID_AA64ISAR2_EL1, APA3, isar2) >= ID_AA64ISAR2_EL1_APA3_PAuth;

	generic_auth = SYS_FIELD_GET(ID_AA64ISAR1_EL1, GPA, isar1) >= ID_AA64ISAR1_EL1_GPA_IMP ||
		       SYS_FIELD_GET(ID_AA64ISAR1_EL1, GPI, isar1) >= ID_AA64ISAR1_EL1_GPI_IMP ||
		       SYS_FIELD_GET(ID_AA64ISAR2_EL1, GPA3, isar2) >= ID_AA64ISAR2_EL1_GPA3_IMP;

	return address_auth && generic_auth;
}
