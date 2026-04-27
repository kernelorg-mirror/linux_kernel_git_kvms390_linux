// SPDX-License-Identifier: GPL-2.0

#include <arm64/kvm_emulate.h>

static void pend_sync_exception(struct kvm_vcpu *vcpu)
{
	kvm_pend_exception(vcpu, EXCEPT_AA64_EL1_SYNC);
}

static void inject_abt64(struct kvm_vcpu *vcpu, bool is_iabt, unsigned long addr)
{
	unsigned long cpsr = *vcpu_cpsr(vcpu);
	bool is_aarch32 = vcpu_mode_is_32bit(vcpu);
	u64 esr = 0;

	if (kvm_vcpu_abt_iss1tw(vcpu))
		esr |= ESR_ELx_FSC_SEA_TTW(kvm_vcpu_abt_gltl(vcpu));
	else
		esr |= ESR_ELx_FSC_EXTABT;

	pend_sync_exception(vcpu);

	if (kvm_vcpu_trap_il_is32bit(vcpu))
		esr |= ESR_ELx_IL;

	if (is_aarch32 || (cpsr & PSR_MODE_MASK) == PSR_MODE_EL0t)
		esr |= (ESR_ELx_EC_IABT_LOW << ESR_ELx_EC_SHIFT);
	else
		esr |= (ESR_ELx_EC_IABT_CUR << ESR_ELx_EC_SHIFT);

	if (!is_iabt)
		esr |= ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT;

	vcpu_write_sys_reg(vcpu, addr, FAR_EL1);
	vcpu_write_sys_reg(vcpu, esr, ESR_EL1);
}

/**
 * kvm_inject_undefined - inject an undefined instruction into the guest
 * @vcpu: The vCPU in which to inject the exception
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_undefined(struct kvm_vcpu *vcpu)
{
	u64 esr = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);

	/*
	 * Build an unknown exception, depending on the instruction
	 * set.
	 */
	if (kvm_vcpu_trap_il_is32bit(vcpu))
		esr |= ESR_ELx_IL;

	kvm_inject_sync(vcpu, esr);
}

static void __kvm_inject_sea(struct kvm_vcpu *vcpu, bool iabt, u64 addr)
{
	inject_abt64(vcpu, iabt, addr);
}

int kvm_inject_sea(struct kvm_vcpu *vcpu, bool iabt, u64 addr)
{
	lockdep_assert_held(&vcpu->mutex);

	__kvm_inject_sea(vcpu, iabt, addr);
	return 1;
}

void kvm_inject_size_fault(struct kvm_vcpu *vcpu)
{
	unsigned long addr, esr;

	addr  = kvm_vcpu_get_fault_ipa(vcpu);
	addr |= FAR_TO_FIPA_OFFSET(kvm_vcpu_get_hfar(vcpu));

	__kvm_inject_sea(vcpu, kvm_vcpu_trap_is_iabt(vcpu), addr);

	esr = vcpu_read_sys_reg(vcpu, ESR_EL1);
	esr &= ~GENMASK_ULL(5, 0);
	vcpu_write_sys_reg(vcpu, esr, ESR_EL1);
}

void kvm_inject_sync(struct kvm_vcpu *vcpu, u64 esr)
{
	pend_sync_exception(vcpu);
	vcpu_write_sys_reg(vcpu, esr, ESR_EL1);
}
