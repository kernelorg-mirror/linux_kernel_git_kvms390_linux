// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>
#include <linux/kvm.h>

#include <arm64/kvm_emulate.h>
#include <arm64/kvm_nested.h>
#include <arm64/sys_regs.h>
#include <arm64/sve_context.h>

#include "feature.h"

#define SVE_VQ_MIN	__SVE_VQ_MIN
#define SVE_NUM_ZREGS	KVM_ARM64_SVE_NUM_ZREGS
#define SVE_NUM_PREGS	KVM_ARM64_SVE_NUM_PREGS

#define vcpu_sve_slices(_vcpu) 1

#define __INCL_GEN_ARM_FILE
#include "generated/guest.inc"
#undef __INCL_GEN_ARM_FILE

const struct kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS()
};

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vm_stats_desc),
};

const struct kvm_stats_desc kvm_vcpu_stats_desc[] = {
	KVM_GENERIC_VCPU_STATS(),
	/* ARM64 stats */
	STATS_DESC_COUNTER(VCPU, hvc_exit_stat),
	STATS_DESC_COUNTER(VCPU, wfe_exit_stat),
	STATS_DESC_COUNTER(VCPU, wfi_exit_stat),
	STATS_DESC_COUNTER(VCPU, mmio_exit_user),
	STATS_DESC_COUNTER(VCPU, mmio_exit_kernel),
	STATS_DESC_COUNTER(VCPU, signal_exits),
	STATS_DESC_COUNTER(VCPU, exits),
	/* GMAP stats */
	STATS_DESC_COUNTER(VCPU, pfault_sync),
};

const struct kvm_stats_header kvm_vcpu_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vcpu_stats_desc),
	.id_offset = sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
		       sizeof(kvm_vcpu_stats_desc),
};

static int sve_zreg_index(__u64 id, unsigned int *regnum)
{
	/* Currently only one slice is supported on arm, and our zreg is only 128 bit */
	const u64 zreg_id_max = KVM_REG_ARM64_SVE_ZREG(KVM_ARM64_SVE_NUM_ZREGS - 1,
						       KVM_ARM64_SVE_MAX_SLICES - 1);
	const u64 zreg_id_min = KVM_REG_ARM64_SVE_ZREG(0, 0);

	if (id < zreg_id_min || id > zreg_id_max)
		return -EINVAL;
	if ((id & SVE_REG_SLICE_MASK) > 0)
		return -ENOENT;

	*regnum = (id & SVE_REG_ID_MASK) >> SVE_REG_ID_SHIFT;

	return 0;
}

static int sve_preg_index(u64 id, unsigned int *regnum)
{
	const u64 preg_id_max = KVM_REG_ARM64_SVE_FFR(KVM_ARM64_SVE_MAX_SLICES - 1);
	const u64 preg_id_min = KVM_REG_ARM64_SVE_PREG(0, 0);

	if (id < preg_id_min || id > preg_id_max)
		return -EINVAL;
	if ((id & SVE_REG_SLICE_MASK) > 0)
		return -ENOENT;

	*regnum = (id & SVE_REG_ID_MASK) >> SVE_REG_ID_SHIFT;

	return 0;
}

static int sve_ffr_index(u64 id, unsigned int *regnum)
{
	if (id != KVM_REG_ARM64_SVE_FFR(0))
		return -EINVAL;
	if ((id & SVE_REG_SLICE_MASK) > 0)
		return -ENOENT;

	*regnum = (id & SVE_REG_ID_MASK) >> SVE_REG_ID_SHIFT;

	return 0;
}

static inline int get_sve_ffr_reg(struct kvm_vcpu *vcpu, unsigned int regnum,
				  u16 __user *uptr)
{
	/* ffr is pregmax + 1 */
	if (regnum != KVM_ARM64_SVE_NUM_PREGS)
		return -EINVAL;

	if (put_user(vcpu->arch.sae_block.sve_ffr, uptr))
		return -EFAULT;
	return 0;
}

static inline int get_sve_preg(struct kvm_vcpu *vcpu, unsigned int regnum,
			       u16 __user *uptr)
{
	if (regnum < 0 || regnum >= KVM_ARM64_SVE_NUM_PREGS)
		return -EINVAL;

	if (put_user(vcpu->arch.sae_block.sve_pregs[regnum], uptr))
		return -EFAULT;
	return 0;
}

static inline int get_sve_zreg(struct kvm_vcpu *vcpu, unsigned int regnum,
			       __vector128 __user *uptr)
{
	if (regnum < 0 || regnum >= KVM_ARM64_SVE_NUM_ZREGS)
		return -EINVAL;

	/* vreg and svreg overlap and zreg is also just 128 bit so we reuse the vreg space */
	if (copy_to_user(uptr, &vcpu->arch.ctxt.vregs[regnum],
			 sizeof(vcpu->arch.ctxt.vregs[regnum])))
		return -EFAULT;
	return 0;
}

static inline int set_sve_ffr_reg(struct kvm_vcpu *vcpu, unsigned int regnum,
				  const u16 __user *uptr)
{
	/* ffr is pregmax + 1*/
	if (regnum != KVM_ARM64_SVE_NUM_PREGS)
		return -EINVAL;

	if (get_user(vcpu->arch.sae_block.sve_ffr, uptr))
		return -EFAULT;
	return 0;
}

static inline int set_sve_preg(struct kvm_vcpu *vcpu, unsigned int regnum,
			       const u16 __user *uptr)
{
	if (regnum < 0 || regnum >= KVM_ARM64_SVE_NUM_PREGS)
		return -EINVAL;

	if (get_user(vcpu->arch.sae_block.sve_pregs[regnum], uptr))
		return -EFAULT;
	return 0;
}

static inline int set_sve_zreg(struct kvm_vcpu *vcpu, unsigned int regnum,
			       const __vector128 __user *uptr)
{
	if (regnum < 0 || regnum >= KVM_ARM64_SVE_NUM_ZREGS)
		return -EINVAL;

	/*vreg and svreg overlap and zreg is also just 128 bit so we reuse the vreg space*/
	if (copy_from_user(&vcpu->arch.ctxt.vregs[regnum], uptr,
			   sizeof(vcpu->arch.ctxt.vregs[regnum])))
		return -EFAULT;
	return 0;
}

static int set_sve_vls(struct kvm_vcpu *vcpu, const void __user *uptr)
{
	u64 vqs[KVM_ARM64_SVE_VLS_WORDS] = { 0 };
	unsigned int vq;

	if (!vcpu_has_sve(vcpu))
		return -ENOENT;

	if (kvm_arm_vcpu_sve_finalized(vcpu))
		return -EPERM;

	if (copy_from_user(vqs, uptr, sizeof(vqs)))
		return -EFAULT;

	/* only 128 bit and 1 VQ are supported , nothing saved just check validity */
	for (vq = KVM_ARM64_SVE_VQ_MIN + 1; vq <= KVM_ARM64_SVE_VQ_MAX; ++vq)
		if (vq_present(vqs, vq))
			return -EINVAL;

	/* run with a vl of 0 not valid */
	if (!vq_present(vqs, KVM_ARM64_SVE_VQ_MIN))
		return -EINVAL;

	return 0;
}

static int get_sve_vls(struct kvm_vcpu *vcpu, void __user *uptr)
{
	u64 vqs[KVM_ARM64_SVE_VLS_WORDS] = { 0 };

	/* currently only 128 bit are supported so we only set bit 0  hardcoded */
	vqs[0] |= vq_mask(KVM_ARM64_SVE_VQ_MIN);

	if (copy_to_user(uptr, vqs, sizeof(vqs)))
		return -EFAULT;

	return 0;
}

static int get_sve_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	void __user *uptr = (void __user *)reg->addr;
	unsigned int regnum;
	int ret = -EFAULT;

	if (reg->id == KVM_REG_ARM64_SVE_VLS)
		ret = get_sve_vls(vcpu, uptr);
	else if (sve_ffr_index(reg->id, &regnum) >= 0)
		ret = get_sve_ffr_reg(vcpu, regnum, uptr);
	else if (sve_preg_index(reg->id, &regnum) >= 0)
		ret = get_sve_preg(vcpu, regnum, uptr);
	else if (sve_zreg_index(reg->id, &regnum) >= 0)
		ret = get_sve_zreg(vcpu, regnum, uptr);

	return ret;
}

static int set_sve_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	const void __user *uptr = (const void __user *)reg->addr;
	int ret = -EFAULT;
	unsigned int regnum;

	if (reg->id == KVM_REG_ARM64_SVE_VLS)
		ret = set_sve_vls(vcpu, uptr);
	else if (sve_ffr_index(reg->id, &regnum) >= 0)
		ret = set_sve_ffr_reg(vcpu, regnum, uptr);
	else if (sve_preg_index(reg->id, &regnum) >= 0)
		ret = set_sve_preg(vcpu, regnum, uptr);
	else if (sve_zreg_index(reg->id, &regnum) >= 0)
		ret = set_sve_zreg(vcpu, regnum, uptr);

	return ret;
}

int kvm_arm_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *uindices)
{
	int ret;

	ret = copy_core_reg_indices(vcpu, uindices);
	if (ret < 0)
		return ret;
	uindices += ret;

	ret = copy_sve_reg_indices(vcpu, uindices);
	if (ret < 0)
		return ret;
	uindices += ret;

	return kvm_arm_copy_sys_reg_indices(vcpu, uindices);
}

unsigned long kvm_arm_num_regs(struct kvm_vcpu *vcpu)
{
	unsigned long num = num_core_regs(vcpu);

	num += num_sve_regs(vcpu);
	num += kvm_arm_num_sys_reg_descs(vcpu);
	return num;
}

int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM64 >> 32)
		return -EINVAL;

	switch (reg->id & KVM_REG_ARM_COPROC_MASK) {
	case KVM_REG_ARM_CORE:
		return get_core_reg(vcpu, reg);
	case KVM_REG_ARM64_SVE:
		return get_sve_reg(vcpu, reg);
	default:
		return kvm_arm_sys_reg_get_reg(vcpu, reg);
	}
}

int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM64 >> 32)
		return -EINVAL;

	switch (reg->id & KVM_REG_ARM_COPROC_MASK) {
	case KVM_REG_ARM_CORE:
		return set_core_reg(vcpu, reg);
	case KVM_REG_ARM64_SVE:
		return set_sve_reg(vcpu, reg);
	default:
		return kvm_arm_sys_reg_set_reg(vcpu, reg);
	}
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				  struct kvm_translation *tr)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	return -EINVAL;
}
