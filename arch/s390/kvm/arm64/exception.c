// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <arm64/kvm_emulate.h>
#include <arm64/sysreg-defs.h>

#include <arm64/ptrace.h>

/*
 * This performs the exception entry at a given EL (@target_mode), stashing PC
 * and PSTATE into ELR and SPSR respectively, and compute the new PC/PSTATE.
 * The EL passed to this function *must* be a non-secure, privileged mode with
 * bit 0 being set (PSTATE.SP == 1).
 *
 * When an exception is taken, most PSTATE fields are left unchanged in the
 * handler. However, some are explicitly overridden (e.g. M[4:0]). Luckily all
 * of the inherited bits have the same position in the AArch64/AArch32 SPSR_ELx
 * layouts, so we don't need to shuffle these for exceptions from AArch32 EL0.
 *
 * For the SPSR_ELx layout for AArch64, see ARM DDI 0487E.a page C5-429.
 * For the SPSR_ELx layout for AArch32, see ARM DDI 0487E.a page C5-426.
 *
 * Here we manipulate the fields in order of the AArch64 SPSR_ELx layout, from
 * MSB to LSB.
 */
static void enter_exception64(struct kvm_vcpu *vcpu, unsigned long target_mode,
			      enum exception_type type)
{
	unsigned long sctlr, vbar, old_pstate, new, mode;
	u64 exc_offset;

	old_pstate = *vcpu_cpsr(vcpu);
	mode = old_pstate & (PSR_MODE_MASK | PSR_MODE32_BIT);

	if      (mode == target_mode)
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
	else if ((mode | PSR_MODE_THREAD_BIT) == target_mode)
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
	else if (!(mode & PSR_MODE32_BIT))
		exc_offset = LOWER_EL_AArch64_VECTOR;
	else
		exc_offset = LOWER_EL_AArch32_VECTOR;

	switch (target_mode) {
	case PSR_MODE_EL1h:
		vbar = vcpu_read_sys_reg(vcpu, VBAR_EL1);
		sctlr = vcpu_read_sys_reg(vcpu, SCTLR_EL1);
		vcpu_write_sys_reg(vcpu, *vcpu_pc(vcpu), ELR_EL1);
		vcpu_write_sys_reg(vcpu, old_pstate, SPSR_EL1);
		break;
	default:
		panic("Unknown PSR Mode: 0x%lx.", target_mode);
	}

	*vcpu_pc(vcpu) = vbar + exc_offset + type;

	new = 0;

	new |= (old_pstate & PSR_N_BIT);
	new |= (old_pstate & PSR_Z_BIT);
	new |= (old_pstate & PSR_C_BIT);
	new |= (old_pstate & PSR_V_BIT);
	new |= (old_pstate & PSR_DIT_BIT);
	new |= (old_pstate & PSR_PAN_BIT);

	if (!(sctlr & SCTLR_EL1_SPAN))
		new |= PSR_PAN_BIT;

	if (sctlr & SCTLR_ELx_DSSBS)
		new |= PSR_SSBS_BIT;

	new |= PSR_D_BIT;
	new |= PSR_A_BIT;
	new |= PSR_I_BIT;
	new |= PSR_F_BIT;

	new |= target_mode;

	*vcpu_cpsr(vcpu) = new;
}

static void kvm_inject_exception(struct kvm_vcpu *vcpu)
{
	switch (vcpu_get_flag(vcpu, EXCEPT_MASK)) {
	case unpack_vcpu_flag(EXCEPT_AA64_EL1_SYNC):
		enter_exception64(vcpu, PSR_MODE_EL1h, except_type_sync);
		break;
	}
}

/*
 * Adjust the guest PC (and potentially exception state) depending on
 * flags provided by the emulation code.
 */
void kvm_adjust_pc(struct kvm_vcpu *vcpu)
{
	if (vcpu_get_flag(vcpu, PENDING_EXCEPTION)) {
		kvm_inject_exception(vcpu);
		vcpu_clear_flag(vcpu, PENDING_EXCEPTION);
		vcpu_clear_flag(vcpu, EXCEPT_MASK);
	} else if (vcpu_get_flag(vcpu, INCREMENT_PC)) {
		kvm_skip_instr(vcpu);
		vcpu_clear_flag(vcpu, INCREMENT_PC);
	}
}
