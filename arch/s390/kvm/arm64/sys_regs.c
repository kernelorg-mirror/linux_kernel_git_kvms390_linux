// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <linux/printk.h>
#include <linux/cpumask.h>

#include <arm64/kvm_emulate.h>
#include <arm64/sys_regs.h>
#include <arm64/sysreg.h>
#include <arm64/cputype.h>
#include <arm64/cache.h>
#include <arm64/kvm_nested.h>
#include <arm64/spectre.h>
#include <arm64/kvm_hyp.h>

#include "feature.h"

#include "trace.h"

static int arm64_check_features(struct kvm_vcpu *vcpu,
				const struct sys_reg_desc *rd, u64 val);
static const struct sys_reg_desc sys_reg_descs[];
static const size_t num_sys_reg_descs;
static u64 __ro_after_init boot_cpu_midr_val;
static u64 __ro_after_init boot_cpu_revidr_val;
static u64 __ro_after_init boot_cpu_aidr_val;

#define __INCL_GEN_ARM_FILE
#include "generated/sys_regs.inc"
#undef __INCL_GEN_ARM_FILE

#define SR_INVALID 0x8badf00d8badf00d

enum sr_loc_attr {
	SR_LOC_SAVE_AREA,	/* Register on SA, loaded (on cpu) */
	SR_LOC_SPECIAL,		/* Register in state description or Special care register*/
	SR_LOC_INVALID,		/* Register is unknown */
};

struct sr_loc {
	enum sr_loc_attr loc;
};

#define SREG_RANGE(NAME) __##NAME##_BEGIN__ + 1 ... __##NAME##_END__ - 1
static __always_inline void locate_register(const struct kvm_vcpu *vcpu,
					    enum vcpu_sysreg reg,
					    struct sr_loc *loc)
{
	switch (reg) {
	case SREG_RANGE(STATE_DESC):
	case SREG_RANGE(SPECIAL):
		loc->loc = SR_LOC_SPECIAL;
		break;
	case SREG_RANGE(SAVE_AREA):
		loc->loc = SR_LOC_SAVE_AREA;
		break;
	default:
		WARN(true, "%s wants to read invalid register %x", __func__, reg);
		loc->loc = SR_LOC_INVALID;
	}
}

static __always_inline u64 read_special_sr(const struct kvm_vcpu *vcpu,
					   enum vcpu_sysreg reg)
{
	switch (reg) {
	case CLIDR_EL1:		return vcpu->arch.sys_reg_clidr_el1;
	case CSSELR_EL1:	return vcpu->arch.sys_reg_csselr_el1;
	case MPIDR_EL1:		return vcpu->arch.mpidr;
	case ELR_EL1:		return vcpu->arch.ctxt.elr_el1;
	case SPSR_EL1:		return vcpu->arch.ctxt.spsr_el1;
	case CNTP_CTL_EL0:	return vcpu->arch.sae_block.cntp_ctl;
	case CNTV_CTL_EL0:	return vcpu->arch.sae_block.cntv_ctl;
	case CONTEXTIDR_EL1:	return vcpu->arch.sae_block.contextidr_el1;
	case SP_EL1:		return vcpu->arch.sae_block.sp_el1;
	default:
		WARN(true, "%s wants to read non-special register %x", __func__, reg);
		return SR_INVALID;
	}
}

static __always_inline u64 read_sr_from_vcpu(const struct kvm_vcpu *vcpu,
					     enum vcpu_sysreg reg)
{
	switch (reg) {
	case ACTLR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_ACTLR_EL1);
	case AFSR0_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_AFSR0_EL1);
	case AFSR1_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_AFSR1_EL1);
	case CNTFRQ_EL0:	return _vcpu_read_sys_reg(vcpu, SYS_CNTFRQ_EL0);
	case CNTP_CVAL_EL0:	return _vcpu_read_sys_reg(vcpu, SYS_CNTP_CVAL_EL0);
	case CNTV_CVAL_EL0:	return _vcpu_read_sys_reg(vcpu, SYS_CNTV_CVAL_EL0);
	case DISR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_DISR_EL1);
	case MIDR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_MIDR_EL1);
	case OSLSR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_OSLSR_EL1);
	case PAR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_PAR_EL1);
	case SCTLR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_SCTLR_EL1);
	case CPACR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_CPACR_EL1);
	case VBAR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_VBAR_EL1);
	case ESR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_ESR_EL1);
	case TCR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_TCR_EL1);
	case MAIR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_MAIR_EL1);
	case TTBR0_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_TTBR0_EL1);
	case TTBR1_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_TTBR1_EL1);
	case FAR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_FAR_EL1);
	case TPIDR_EL0:		return _vcpu_read_sys_reg(vcpu, SYS_TPIDR_EL0);
	case TPIDR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_TPIDR_EL1);
	case TPIDRRO_EL0:	return _vcpu_read_sys_reg(vcpu, SYS_TPIDRRO_EL0);
	case CNTKCTL_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_CNTKCTL_EL1);
	case ZCR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_ZCR_EL1);
	case SCXTNUM_EL0:	return _vcpu_read_sys_reg(vcpu, SYS_SCXTNUM_EL0);
	case SCXTNUM_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_SCXTNUM_EL1);
	case APIBKEYLO_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APIBKEYLO_EL1);
	case APIBKEYHI_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APIBKEYHI_EL1);
	case APIAKEYLO_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APIAKEYLO_EL1);
	case APIAKEYHI_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APIAKEYHI_EL1);
	case APGAKEYLO_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APGAKEYLO_EL1);
	case APGAKEYHI_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APGAKEYHI_EL1);
	case APDBKEYLO_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APDBKEYLO_EL1);
	case APDBKEYHI_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APDBKEYHI_EL1);
	case APDAKEYLO_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APDAKEYLO_EL1);
	case APDAKEYHI_EL1:	return _vcpu_read_sys_reg(vcpu, SYS_APDAKEYHI_EL1);
	case MDSCR_EL1:		return _vcpu_read_sys_reg(vcpu, SYS_MDSCR_EL1);
	default:
		WARN(true, "%s: failed to resolve %x", __func__,  reg);
		return SR_INVALID;
	}
}

u64 vcpu_read_sys_reg(const struct kvm_vcpu *vcpu, enum vcpu_sysreg reg)
{
	struct sr_loc loc = {};

	locate_register(vcpu, reg, &loc);

	if (unlikely(loc.loc == SR_LOC_INVALID)) {
		WARN(true, "%s: failed to locate %u", __func__,  reg);
		return SR_INVALID;
	}

	if (loc.loc == SR_LOC_SPECIAL)
		return read_special_sr(vcpu, reg);

	return read_sr_from_vcpu(vcpu, reg);
}

static __always_inline void write_special_sr(struct kvm_vcpu *vcpu, u64 val,
					     enum vcpu_sysreg reg)
{
	switch (reg) {
	case CLIDR_EL1:		vcpu->arch.sys_reg_clidr_el1 = val;		break;
	case CSSELR_EL1:	vcpu->arch.sys_reg_csselr_el1 = val;		break;
	case MPIDR_EL1:		vcpu->arch.mpidr = val;				break;
	case CNTP_CTL_EL0:	vcpu->arch.sae_block.cntp_ctl = val;		break;
	case CNTV_CTL_EL0:	vcpu->arch.sae_block.cntv_ctl = val;		break;
	case CONTEXTIDR_EL1:	vcpu->arch.sae_block.contextidr_el1 = val;	break;
	case SP_EL1:		vcpu->arch.sae_block.sp_el1 = val;		break;
	case ELR_EL1:		vcpu->arch.ctxt.elr_el1 = val		;	break;
	case SPSR_EL1:		vcpu->arch.ctxt.spsr_el1 = val;			break;
	default:
		WARN(true, "%s wants to write non-special register %x", __func__, reg);
	}
}

static __always_inline void write_sr_to_vcpu(struct kvm_vcpu *vcpu, u64 val,
					     enum vcpu_sysreg reg)
{
	switch (reg) {
	case ACTLR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_ACTLR_EL1);		break;
	case AFSR0_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_AFSR0_EL1);		break;
	case AFSR1_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_AFSR1_EL1);		break;
	case CNTFRQ_EL0:	_vcpu_write_sys_reg(vcpu, val, SYS_CNTFRQ_EL0);		break;
	case CNTP_CVAL_EL0:	_vcpu_write_sys_reg(vcpu, val, SYS_CNTP_CVAL_EL0);	break;
	case CNTV_CVAL_EL0:	_vcpu_write_sys_reg(vcpu, val, SYS_CNTV_CVAL_EL0);	break;
	case DISR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_DISR_EL1);		break;
	case MIDR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_MIDR_EL1);		break;
	case PAR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_PAR_EL1);		break;
	case OSLAR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_OSLAR_EL1);		break;
	case SCTLR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_SCTLR_EL1);		break;
	case CPACR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_CPACR_EL1);		break;
	case VBAR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_VBAR_EL1);		break;
	case ESR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_ESR_EL1);		break;
	case TCR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_TCR_EL1);		break;
	case MAIR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_MAIR_EL1);		break;
	case TTBR0_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_TTBR0_EL1);		break;
	case TTBR1_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_TTBR1_EL1);		break;
	case FAR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_FAR_EL1);		break;
	case TPIDR_EL0:		_vcpu_write_sys_reg(vcpu, val, SYS_TPIDR_EL0);		break;
	case TPIDR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_TPIDR_EL1);		break;
	case TPIDRRO_EL0:	_vcpu_write_sys_reg(vcpu, val, SYS_TPIDRRO_EL0);	break;
	case CNTKCTL_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_CNTKCTL_EL1);	break;
	case ZCR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_ZCR_EL1);		break;
	case SCXTNUM_EL0:	_vcpu_write_sys_reg(vcpu, val, SYS_SCXTNUM_EL0);	break;
	case SCXTNUM_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_SCXTNUM_EL1);	break;
	case APIBKEYLO_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APIBKEYLO_EL1);	break;
	case APIBKEYHI_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APIBKEYHI_EL1);	break;
	case APIAKEYLO_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APIAKEYLO_EL1);	break;
	case APIAKEYHI_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APIAKEYHI_EL1);	break;
	case APGAKEYLO_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APGAKEYLO_EL1);	break;
	case APGAKEYHI_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APGAKEYHI_EL1);	break;
	case APDBKEYLO_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APDBKEYLO_EL1);	break;
	case APDBKEYHI_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APDBKEYHI_EL1);	break;
	case APDAKEYLO_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APDAKEYLO_EL1);	break;
	case APDAKEYHI_EL1:	_vcpu_write_sys_reg(vcpu, val, SYS_APDAKEYHI_EL1);	break;
	case MDSCR_EL1:		_vcpu_write_sys_reg(vcpu, val, SYS_MDSCR_EL1);		break;
	default:
		WARN(true, "%s: failed to resolve %x", __func__,  reg);
	}
}

void vcpu_write_sys_reg(struct kvm_vcpu *vcpu, u64 val, enum vcpu_sysreg reg)
{
	struct sr_loc loc = {};

	locate_register(vcpu, reg, &loc);

	if (unlikely(loc.loc == SR_LOC_INVALID)) {
		WARN(true, "%s: failed to locate %u", __func__,  reg);
		return;
	}

	if (loc.loc == SR_LOC_SPECIAL) {
		write_special_sr(vcpu, val, reg);
		return;
	}

	write_sr_to_vcpu(vcpu, val, reg);
}

u64 vcpu_read_host_sys_reg(const struct kvm_vcpu *vcpu, int reg)
{
	switch (reg) {
	case SYS_ICH_LR0_EL2:	return vcpu->arch.sae_block.ic_regs.ich_lrn_el2[0];
	case SYS_ICH_LR1_EL2:	return vcpu->arch.sae_block.ic_regs.ich_lrn_el2[1];
	case SYS_ICH_LR2_EL2:	return vcpu->arch.sae_block.ic_regs.ich_lrn_el2[2];
	case SYS_ICH_LR3_EL2:	return vcpu->arch.sae_block.ic_regs.ich_lrn_el2[3];
	case SYS_ICH_HCR_EL2:	return vcpu->arch.sae_block.ic_regs.ich_hcr_el2;
	case SYS_ICH_AP0R0_EL2:	return vcpu->arch.sae_block.ic_regs.ich_ap0r0_el2;
	case SYS_ICH_AP1R0_EL2:	return vcpu->arch.sae_block.ic_regs.ich_ap1r0_el2;
	case SYS_ICH_VMCR_EL2:	return vcpu->arch.sae_block.ic_regs.ich_vmcr_el2;
	case SYS_VSESR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_VSESR_EL2);
	case SYS_HCR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HCR_EL2);
	case SYS_CPTR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_CPTR_EL2);
	case SYS_MDCR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_MDCR_EL2);
	case SYS_HCRX_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HCRX_EL2);
	case SYS_HFGRTR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HFGRTR_EL2);
	case SYS_HFGWTR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HFGWTR_EL2);
	case SYS_HDFGWTR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HDFGWTR_EL2);
	case SYS_HDFGRTR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HDFGRTR_EL2);
	case SYS_HFGITR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_HFGITR_EL2);
	case SYS_CNTHCTL_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_CNTHCTL_EL2);
	case SYS_ICC_SRE_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_ICC_SRE_EL2);
	case SYS_VMPIDR_EL2:	return _vcpu_read_sys_reg(vcpu, SYS_VMPIDR_EL2);
	default:
		WARN(true, "%s wants to read non-host register %x", __func__, reg);
		return SR_INVALID;
	}
}

void vcpu_write_host_sys_reg(struct kvm_vcpu *vcpu, u64 val, int reg)
{
	switch (reg) {
	case SYS_ICH_LR0_EL2:	vcpu->arch.sae_block.ic_regs.ich_lrn_el2[0] = val;	break;
	case SYS_ICH_LR1_EL2:	vcpu->arch.sae_block.ic_regs.ich_lrn_el2[1] = val;	break;
	case SYS_ICH_LR2_EL2:	vcpu->arch.sae_block.ic_regs.ich_lrn_el2[2] = val;	break;
	case SYS_ICH_LR3_EL2:	vcpu->arch.sae_block.ic_regs.ich_lrn_el2[3] = val;	break;
	case SYS_ICH_HCR_EL2:	vcpu->arch.sae_block.ic_regs.ich_hcr_el2 = val;		break;
	case SYS_ICH_AP0R0_EL2:	vcpu->arch.sae_block.ic_regs.ich_ap0r0_el2 = val;	break;
	case SYS_ICH_AP1R0_EL2:	vcpu->arch.sae_block.ic_regs.ich_ap1r0_el2 = val;	break;
	case SYS_ICH_VMCR_EL2:	vcpu->arch.sae_block.ic_regs.ich_vmcr_el2 = val;	break;
	case SYS_VSESR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_VSESR_EL2);		break;
	case SYS_HCR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HCR_EL2);		break;
	case SYS_CPTR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_CPTR_EL2);		break;
	case SYS_MDCR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_MDCR_EL2);		break;
	case SYS_HCRX_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HCRX_EL2);		break;
	case SYS_HFGRTR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HFGRTR_EL2);		break;
	case SYS_HFGWTR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HFGWTR_EL2);		break;
	case SYS_HDFGWTR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HDFGWTR_EL2);	break;
	case SYS_HDFGRTR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HDFGRTR_EL2);	break;
	case SYS_HFGITR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_HFGITR_EL2);		break;
	case SYS_CNTHCTL_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_CNTHCTL_EL2);	break;
	case SYS_ICC_SRE_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_ICC_SRE_EL2);	break;
	case SYS_VMPIDR_EL2:	_vcpu_write_sys_reg(vcpu, val, SYS_VMPIDR_EL2);		break;
	default:
		WARN(true, "%s wants to write non-host register %x", __func__, reg);
	}
}

static int arm64_check_features(struct kvm_vcpu *vcpu,
				const struct sys_reg_desc *rd, u64 val)
{
	u32 id = reg_to_encoding(rd);
	u64 host_val;
	u64 old_val;

	/*
	 * This is a very minimal implementation to sanitise only the craziest
	 * shenanigans we could get from userspace. The final goal is to share
	 * the sanitisation with arm as well but this needs access to arm
	 * (core) kernel code for which there is no suitable solution yet. TODO
	 */

	/*
	 * If the register is RAZ we know the only safe value is 0.
	 */
	if (sysreg_visible_as_raz(vcpu, rd))
		return val ? -E2BIG : 0;

	host_val = read_sanitised_ftr_reg(id);

	switch (id) {
	case SYS_ID_AA64MMFR0_EL1:
		/* Forbid PRANGE values larger than the host supports*/
		if (SYS_FIELD_GET(ID_AA64MMFR0_EL1, PARANGE, val) >
		    SYS_FIELD_GET(ID_AA64MMFR0_EL1, PARANGE, host_val))
			return -E2BIG;
		break;
	case SYS_CTR_EL0:
		/* forbid upgrading from VIPT to PIPT */
		old_val = read_id_reg(vcpu, rd);
		if (SYS_FIELD_GET(CTR_EL0, L1Ip, old_val) == CTR_EL0_L1Ip_VIPT &&
		    SYS_FIELD_GET(CTR_EL0, L1Ip, val) == CTR_EL0_L1Ip_PIPT)
			return -E2BIG;
		break;
	}
	return 0;
}

static void init_imp_id_regs(void)
{
	boot_cpu_midr_val = read_sanitised_ftr_reg(SYS_MIDR_EL1);
	boot_cpu_revidr_val = read_sanitised_ftr_reg(SYS_REVIDR_EL1);
	boot_cpu_aidr_val = read_sanitised_ftr_reg(SYS_AIDR_EL1);
}

static bool access_imp_id_reg(struct kvm_vcpu *vcpu, struct sys_reg_params *p,
			      const struct sys_reg_desc *r)
{
	if (p->is_write)
		return write_to_read_only(vcpu, p, r);

	/*
	 * Return the VM-scoped implementation ID register values if userspace
	 * has made them writable.
	 */
	if (test_bit(KVM_ARCH_FLAG_WRITABLE_IMP_ID_REGS, &vcpu->kvm->arch.flags))
		return access_id_reg(vcpu, p, r);

	switch (reg_to_encoding(r)) {
	case SYS_REVIDR_EL1:
		p->regval = boot_cpu_revidr_val; //no old api to conform to?
		break;
	case SYS_AIDR_EL1:
		p->regval = boot_cpu_aidr_val;
		break;
	default:
		WARN_ON_ONCE(1);
	}

	return true;
}

static int get_mpidr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd, u64 *val)
{
	*val = vcpu->arch.mpidr;
	return 0;
}

static int set_mpidr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd, u64 val)
{
	vcpu->arch.mpidr = val;
	return 0;
}

static u64 reset_midr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r)
{
	_vcpu_write_sys_reg(vcpu, boot_cpu_midr_val, SYS_MIDR_EL1);
	return boot_cpu_midr_val;
}

static int set_oslsr_el1(struct kvm_vcpu *vcpu, const struct sys_reg_desc *rd,
			 u64 val)
{
	u64 oslk;

	/*
	 * The only modifiable bit is the OSLK bit. Refuse the write if
	 * userspace attempts to change any other bit in the register.
	 */
	if ((val ^ rd->val) & ~OSLSR_EL1_OSLK)
		return -EINVAL;

	/*
	 * Redirect the write to the proper control register.
	 * OSLSR is read-only
	 */
	oslk = SYS_FIELD_GET(OSLSR_EL1, OSLK, val);
	__vcpu_assign_sys_reg(vcpu, OSLAR_EL1, SYS_FIELD_PREP(OSLAR_EL1, OSLK, oslk));
	return 0;
}

static u64 reset_oslsr_el1(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r)
{
	u64 oslsr = r->val;

	set_oslsr_el1(vcpu, r, oslsr);
	return oslsr;
}

static int arch_timer_set_user(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 val)
{
	switch (reg_to_encoding(rd)) {
	case SYS_CNTVCT_EL0:
		vcpu->arch.sae_block.gpto = ptff_qagto(val);
		return 0;
	case SYS_CNTPCT_EL0:
		return 0;
	}

	__vcpu_assign_sys_reg(vcpu, rd->reg, val);
	return 0;
}

static int arch_timer_get_user(struct kvm_vcpu *vcpu,
			       const struct sys_reg_desc *rd,
			       u64 *val)
{
	switch (reg_to_encoding(rd)) {
	case SYS_CNTVCT_EL0:
		*val = ptff_qagpt(vcpu->arch.sae_block.gpto);
		break;
	case SYS_CNTPCT_EL0:
		*val = ptff_qagpt(vcpu->arch.sae_block.gpto);
		break;
	default:
		*val = __vcpu_sys_reg(vcpu, rd->reg);
	}

	return 0;
}

#define TIMER_REG(name) { \
	SYS_DESC(SYS_##name),			\
	.reset = reset_val,			\
	.reg = name,				\
	.get_user = arch_timer_get_user,	\
	.set_user = arch_timer_set_user,	\
}

/*
 * Architected system registers.
 * Important: Must be sorted ascending by Op0, Op1, CRn, CRm, Op2
 */
static const struct sys_reg_desc sys_reg_descs[] = {
	/* Op0 = 2 */
	{ SYS_DESC(SYS_OSLAR_EL1), trap_oslar_el1 },
	{ SYS_DESC(SYS_OSLSR_EL1), trap_oslsr_el1, reset_oslsr_el1, OSLSR_EL1,
	  OSLSR_EL1_OSLM_IMPLEMENTED, NULL, set_oslsr_el1 },

	/* Op0 = 3 */
	/* Op1 = 0 */
	/* CRn = 0 */
	/* CRm = 0 */

	{ SYS_DESC(SYS_MIDR_EL1), NULL, reset_midr, 0, GENMASK_ULL(31, 0),
	  get_id_reg, set_imp_id_reg },
	{ SYS_DESC(SYS_MPIDR_EL1), NULL, reset_mpidr, MPIDR_EL1, 0, get_mpidr,
	  set_mpidr },
	IMPLEMENTATION_ID(REVIDR_EL1, GENMASK_ULL(63, 0)),

	/*
	 * ID regs: all ID_SANITISED() entries here must have corresponding
	 * entries in arm64_ftr_regs[].
	 */

	/* AArch64 mappings of the AArch32 ID registers */
	/* CRm=1 */
	ID_HIDDEN(ID_PFR0_EL1),
	ID_HIDDEN(ID_PFR1_EL1),
	ID_HIDDEN(ID_DFR0_EL1),
	ID_HIDDEN(ID_AFR0_EL1),
	ID_HIDDEN(ID_MMFR0_EL1),
	ID_HIDDEN(ID_MMFR1_EL1),
	ID_HIDDEN(ID_MMFR2_EL1),
	ID_HIDDEN(ID_MMFR3_EL1),

	/* CRm=2 */
	ID_HIDDEN(ID_ISAR0_EL1),
	ID_HIDDEN(ID_ISAR1_EL1),
	ID_HIDDEN(ID_ISAR2_EL1),
	ID_HIDDEN(ID_ISAR3_EL1),
	ID_HIDDEN(ID_ISAR4_EL1),
	ID_HIDDEN(ID_ISAR5_EL1),
	ID_HIDDEN(ID_MMFR4_EL1),
	ID_HIDDEN(ID_ISAR6_EL1),

	/* CRm=3 */
	ID_HIDDEN(MVFR0_EL1),
	ID_HIDDEN(MVFR1_EL1),
	ID_HIDDEN(MVFR2_EL1),
	ID_UNALLOCATED(3, 3),
	ID_HIDDEN(ID_PFR2_EL1),
	ID_HIDDEN(ID_DFR1_EL1),
	ID_HIDDEN(ID_MMFR5_EL1),
	ID_UNALLOCATED(3, 7),

	/* AArch64 ID registers */
	/* CRm=4 */
	ID_FILTERED(ID_AA64PFR0_EL1, id_aa64pfr0_el1,
		    ~(ID_AA64PFR0_EL1_AMU | ID_AA64PFR0_EL1_MPAM |
		      ID_AA64PFR0_EL1_SVE | ID_AA64PFR0_EL1_RAS |
		      ID_AA64PFR0_EL1_GIC | ID_AA64PFR0_EL1_AdvSIMD |
		      ID_AA64PFR0_EL1_FP)),
	ID_FILTERED(ID_AA64PFR1_EL1, id_aa64pfr1_el1,
		    ~(ID_AA64PFR1_EL1_PFAR | ID_AA64PFR1_EL1_DF2 |
		      ID_AA64PFR1_EL1_MTEX | ID_AA64PFR1_EL1_THE |
		      ID_AA64PFR1_EL1_GCS | ID_AA64PFR1_EL1_MTE_frac |
		      ID_AA64PFR1_EL1_NMI | ID_AA64PFR1_EL1_RNDR_trap |
		      ID_AA64PFR1_EL1_SME | ID_AA64PFR1_EL1_RES0 |
		      ID_AA64PFR1_EL1_MPAM_frac | ID_AA64PFR1_EL1_RAS_frac |
		      ID_AA64PFR1_EL1_MTE)),
	ID_FILTERED(ID_AA64PFR2_EL1, id_aa64pfr2_el1,
		    (ID_AA64PFR2_EL1_FPMR		|
		     ID_AA64PFR2_EL1_MTEFAR		|
		     ID_AA64PFR2_EL1_MTESTOREONLY	|
		     ID_AA64PFR2_EL1_GCIE)),
	ID_UNALLOCATED(4, 3),
	ID_WRITABLE(ID_AA64ZFR0_EL1, ~ID_AA64ZFR0_EL1_RES0),
	ID_HIDDEN(ID_AA64SMFR0_EL1),
	ID_UNALLOCATED(4, 6),
	ID_WRITABLE(ID_AA64FPFR0_EL1, ~ID_AA64FPFR0_EL1_RES0),

	/* CRm=5 */
	/*
	 * Prior to FEAT_Debugv8.9, the architecture defines context-aware
	 * breakpoints (CTX_CMPs) as the highest numbered breakpoints (BRPs).
	 * KVM does not trap + emulate the breakpoint registers, and as such
	 * cannot support a layout that misaligns with the underlying hardware.
	 * While it may be possible to describe a subset that aligns with
	 * hardware, just prevent changes to BRPs and CTX_CMPs altogether for
	 * simplicity.
	 *
	 * See DDI0487K.a, section D2.8.3 Breakpoint types and linking
	 * of breakpoints for more details.
	 */
	ID_FILTERED(ID_AA64DFR0_EL1, id_aa64dfr0_el1,
		    ID_AA64DFR0_EL1_DoubleLock_MASK |
			    ID_AA64DFR0_EL1_WRPs_MASK |
			    ID_AA64DFR0_EL1_PMUVer_MASK |
			    ID_AA64DFR0_EL1_DebugVer_MASK),
	ID_SANITISED(ID_AA64DFR1_EL1),
	ID_UNALLOCATED(5, 2),
	ID_UNALLOCATED(5, 3),
	ID_HIDDEN(ID_AA64AFR0_EL1),
	ID_HIDDEN(ID_AA64AFR1_EL1),
	ID_UNALLOCATED(5, 6),
	ID_UNALLOCATED(5, 7),

	/* CRm=6 */
	ID_WRITABLE(ID_AA64ISAR0_EL1, ~ID_AA64ISAR0_EL1_RES0),
	ID_WRITABLE(ID_AA64ISAR1_EL1,
		    ~(ID_AA64ISAR1_EL1_GPI | ID_AA64ISAR1_EL1_GPA |
		      ID_AA64ISAR1_EL1_API | ID_AA64ISAR1_EL1_APA)),
	ID_WRITABLE(ID_AA64ISAR2_EL1,
		    ~(ID_AA64ISAR2_EL1_RES0 | ID_AA64ISAR2_EL1_APA3 |
		      ID_AA64ISAR2_EL1_GPA3)),
	ID_WRITABLE(ID_AA64ISAR3_EL1,
		    (ID_AA64ISAR3_EL1_FPRCVT | ID_AA64ISAR3_EL1_FAMINMAX)),
	ID_UNALLOCATED(6, 4),
	ID_UNALLOCATED(6, 5),
	ID_UNALLOCATED(6, 6),
	ID_UNALLOCATED(6, 7),

	/* CRm=7 */
	ID_FILTERED(ID_AA64MMFR0_EL1, id_aa64mmfr0_el1,
		    ~(ID_AA64MMFR0_EL1_RES0 | ID_AA64MMFR0_EL1_ASIDBITS)),
	ID_WRITABLE(ID_AA64MMFR1_EL1,
		    ~(ID_AA64MMFR1_EL1_RES0 | ID_AA64MMFR1_EL1_HCX |
		      ID_AA64MMFR1_EL1_TWED | ID_AA64MMFR1_EL1_XNX |
		      ID_AA64MMFR1_EL1_VH | ID_AA64MMFR1_EL1_VMIDBits)),
	ID_FILTERED(ID_AA64MMFR2_EL1, id_aa64mmfr2_el1,
		    ~(ID_AA64MMFR2_EL1_RES0 | ID_AA64MMFR2_EL1_EVT |
		      ID_AA64MMFR2_EL1_FWB | ID_AA64MMFR2_EL1_IDS |
		      ID_AA64MMFR2_EL1_NV | ID_AA64MMFR2_EL1_CCIDX)),
	ID_WRITABLE(ID_AA64MMFR3_EL1,
		    (ID_AA64MMFR3_EL1_TCRX | ID_AA64MMFR3_EL1_S1PIE |
		     ID_AA64MMFR3_EL1_S1POE)),
	ID_WRITABLE(ID_AA64MMFR4_EL1, ID_AA64MMFR4_EL1_NV_frac),
	ID_UNALLOCATED(7, 5),
	ID_UNALLOCATED(7, 6),
	ID_UNALLOCATED(7, 7),

	/* CRn = 1 */
	{ SYS_DESC(SYS_SCTLR_EL1), NULL, reset_val, SCTLR_EL1, 0x00C50078 },
	{ SYS_DESC(SYS_CPACR_EL1), NULL, reset_val, CPACR_EL1, 0 },

	/* CRn = 2 */
	{ SYS_DESC(SYS_TTBR0_EL1), access_rw, reset_val, TTBR0_EL1, 0 },
	{ SYS_DESC(SYS_TTBR1_EL1), access_rw, reset_val, TTBR1_EL1, 0 },
	{ SYS_DESC(SYS_TCR_EL1), access_rw, reset_val, TCR_EL1, 0 },

	{ SYS_DESC(SYS_PMMIR_EL1), trap_raz_wi },
	/* CRn = 10 */
	{ SYS_DESC(SYS_MAIR_EL1), NULL, reset_unknown, MAIR_EL1 },
	{ SYS_DESC(SYS_LORSA_EL1), trap_loregion },
	{ SYS_DESC(SYS_LOREA_EL1), trap_loregion },
	{ SYS_DESC(SYS_LORN_EL1), trap_loregion },
	{ SYS_DESC(SYS_LORC_EL1), trap_loregion },
	{ SYS_DESC(SYS_LORID_EL1), trap_loregion },

	/* CRn = 12 */
	{ SYS_DESC(SYS_VBAR_EL1), access_rw, reset_val, VBAR_EL1, 0 },

	/* CRn = 13 */
	{ SYS_DESC(SYS_TPIDR_EL1), NULL, reset_unknown, TPIDR_EL1 },

	/* Op1 = 1 */
	/* CRn = 0 */
	/* CRm = 0 */
	{ SYS_DESC(SYS_CCSIDR_EL1), access_ccsidr },
	{ SYS_DESC(SYS_CLIDR_EL1), access_clidr, reset_clidr, CLIDR_EL1,
	  ~CLIDR_EL1_RES0, .set_user = set_clidr },
	IMPLEMENTATION_ID(AIDR_EL1, GENMASK_ULL(63, 0)),
	{ SYS_DESC(SYS_CSSELR_EL1), access_csselr, reset_unknown, CSSELR_EL1 },
	ID_FILTERED(CTR_EL0, ctr_el0,
		    CTR_EL0_DIC_MASK | CTR_EL0_IDC_MASK |
			    CTR_EL0_DminLine_MASK | CTR_EL0_L1Ip_MASK |
			    CTR_EL0_IminLine_MASK),

	{ SYS_DESC(SYS_CNTFRQ_EL0), NULL, reset_val, CNTFRQ_EL0, 0x3B9ACA00 },
	{ SYS_DESC(SYS_CNTPCT_EL0), .get_user = arch_timer_get_user,
	  .set_user = arch_timer_set_user },
	{ SYS_DESC(SYS_CNTVCT_EL0), .get_user = arch_timer_get_user,
	  .set_user = arch_timer_set_user },
	TIMER_REG(CNTP_CTL_EL0),
	TIMER_REG(CNTP_CVAL_EL0),
	TIMER_REG(CNTV_CTL_EL0),
	TIMER_REG(CNTV_CVAL_EL0),
};

static const size_t  num_sys_reg_descs = ARRAY_SIZE(sys_reg_descs);

/**
 * kvm_reset_sys_regs - sets system registers to reset value
 * @vcpu: The VCPU pointer
 *
 * This function finds the right table above and sets the registers on the
 * virtual CPU struct to their architecturally defined reset values.
 */
void kvm_reset_sys_regs(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned long i;

	for (i = 0; i < num_sys_reg_descs; i++) {
		const struct sys_reg_desc *r = &sys_reg_descs[i];

		if (!r->reset)
			continue;

		if (is_vm_ftr_id_reg(reg_to_encoding(r))) {
			reset_vm_ftr_id_reg(vcpu, r);
			/*
			 * ID registers are stored per VCPU as well and need a
			 * meaningful reset value. Reset the VCPU regas well.
			 */
			if (!kvm_vcpu_initialized(vcpu))
				r->reset(vcpu, r);
		} else if (is_vcpu_ftr_id_reg(reg_to_encoding(r))) {
			reset_vcpu_ftr_id_reg(vcpu, r);
		} else {
			r->reset(vcpu, r);
		}
	}

	set_bit(KVM_ARCH_FLAG_ID_REGS_INITIALIZED, &kvm->arch.flags);

	if (kvm_vcpu_has_pmu(vcpu))
		kvm_make_request(KVM_REQ_RELOAD_PMU, vcpu);
}

/*
 * kvm_handle_sys_reg -- handles a system instruction or mrs/msr instruction
 *			 trap on a guest execution
 * @vcpu: The VCPU pointer
 */
int kvm_handle_sys_reg(struct kvm_vcpu *vcpu)
{
	const struct sys_reg_desc *desc = NULL;
	struct sys_reg_params params;
	unsigned long esr = kvm_vcpu_get_esr(vcpu);
	int Rt = kvm_vcpu_sys_get_rt(vcpu);

	trace_kvm_handle_sys_reg(esr);

	params = esr_sys64_to_params(esr);
	params.regval = vcpu_get_reg(vcpu, Rt);

	/* System registers have Op0=={2,3}, as per DDI487 J.a C5.1.2 */
	if (params.Op0 == 2 || params.Op0 == 3)
		desc = find_reg(&params, sys_reg_descs, num_sys_reg_descs);
	else
		WARN(true, "system instruction handling not supported");

	if (!desc) {
		if (!(params.Op0 == 3 && (params.CRn & 0b1011) == 0b1011))
			print_sys_reg_msg(&params,
					  "Unsupported guest access at: %lx\n",
					  *vcpu_pc(vcpu));
		kvm_inject_undefined(vcpu);
		return 1;
	} else {
		perform_access(vcpu, &params, desc);
	}

	/* Read from system register? */
	if (!params.is_write &&
	    (params.Op0 == 2 || params.Op0 == 3))
		vcpu_set_reg(vcpu, Rt, params.regval);

	return 1;
}

int __init kvm_sys_reg_table_init(void)
{
	init_imp_id_regs();

	bool valid =
		check_sysreg_table(sys_reg_descs, num_sys_reg_descs, false);

	if (!valid)
		return -EINVAL;

	return 0;
}

/*
 * Perform last adjustments to the ID registers that are implied by the
 * configuration outside of the ID regs themselves, as well as any
 * initialisation that directly depend on these ID registers (such as
 * RES0/RES1 behaviours). This is not the place to configure traps though.
 *
 * Because this can be called once per CPU, changes must be idempotent.
 */
int kvm_finalize_sys_regs(struct kvm_vcpu *vcpu)
{
	return 0;
}

