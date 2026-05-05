/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ASM_KVM_NESTED_H
#define ASM_KVM_NESTED_H

static inline bool vcpu_has_nv(const struct kvm_vcpu *vcpu)
{
	return false;
}

static inline u64 limit_nv_id_reg(struct kvm *kvm, u32 id, u64 val)
{
	return val;
}

#endif /* ASM_KVM_NESTED_H */
