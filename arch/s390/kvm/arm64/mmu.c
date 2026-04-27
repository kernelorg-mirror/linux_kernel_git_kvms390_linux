// SPDX-License-Identifier: GPL-2.0
#include <linux/kvm_host.h>

#include <arm64/kvm_emulate.h>

#include <faultin.h>

static inline bool kvm_s390_cur_gmap_fault_is_write(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.sae_block.hai.pic == PGM_PROTECTION ||
	       vcpu->arch.sae_block.hai.teid.fsi == TEID_FSI_STORE;
}

/*
 * user_mem_abort() - handle a dat fault for the gmap of a vcpu
 *
 * Return: 0 on success, < 0 in case of error.
 * Context: The mm lock must not be held before calling. May sleep.
 */
static int user_mem_abort(struct kvm_vcpu *vcpu, gpa_t fault_ipa,
			  struct kvm_memory_slot *slot, hva_t hva)
{
	struct guest_fault f = { };
	int ret;

	if (kvm_s390_cur_gmap_fault_is_write(vcpu))
		f.write_attempt = FOLL_WRITE;
	f.gfn = gpa_to_gfn(fault_ipa);

	ret = kvm_s390_faultin_gfn(vcpu, NULL, &f);
	if (ret <= 0)
		return ret;
	if (ret == PGM_ADDRESSING) {
		/*
		 * There is no page with the requested address. Inject size fault
		 * which is the closest arm match to PGM-addressing
		 */
		kvm_inject_size_fault(vcpu);
		return 1;
	}
	KVM_BUG_ON(ret, vcpu->kvm);
	return -EINVAL;
}

static int kvm_handle_pic(struct kvm_vcpu *vcpu, bool *translation)
{
	switch (kvm_vcpu_fault_pic(vcpu)) {
	/* expected cases: */
	case PGM_ASCE_TYPE:
	case PGM_REGION_FIRST_TRANS:
	case PGM_REGION_SECOND_TRANS:
	case PGM_REGION_THIRD_TRANS:
	case PGM_SEGMENT_TRANSLATION:
	case PGM_PAGE_TRANSLATION:
		*translation = true;
		break;
	case PGM_PROTECTION:
		break;
	/* unexpected cases: */
	case 0:
		KVM_BUG(1, vcpu->kvm, "On MMU fault path but no fault occurred");
		return -EFAULT;
	default:
		KVM_BUG(1, vcpu->kvm, "Unexpected program interrupt 0x%x, TEID 0x%016lx",
			vcpu->arch.sae_block.hai.pic, vcpu->arch.sae_block.hai.teid.val);
		send_sig(SIGSEGV, current, 0);
		return -EFAULT;
	}

	return 0;
}

size_t kvm_parange_to_address_sanitized(u32 id_parange)
{
	static u32 ranges_map[6] = {
		[ID_AA64MMFR0_EL1_PARANGE_32] = 32,
		[ID_AA64MMFR0_EL1_PARANGE_36] = 36,
		[ID_AA64MMFR0_EL1_PARANGE_40] = 40,
		[ID_AA64MMFR0_EL1_PARANGE_42] = 42,
		[ID_AA64MMFR0_EL1_PARANGE_44] = 44,
		[ID_AA64MMFR0_EL1_PARANGE_48] = 48,
	};
	u32 parange;

	/*
	 * Future values must be higher than we know already.
	 * See ARM DDI 0487C.a. Return a safe limit.
	 */
	parange = ranges_map[min(id_parange, ID_AA64MMFR0_EL1_PARANGE_48)];
	return BIT_ULL(parange);
}

static size_t kvm_get_pa_address(struct kvm *kvm)
{
	u32 id_parange = get_idreg_field_enum(kvm, ID_AA64MMFR0_EL1, PARANGE);

	return kvm_parange_to_address_sanitized(id_parange);
}

int kvm_handle_guest_abort(struct kvm_vcpu *vcpu)
{
	struct kvm_memory_slot *memslot;
	bool translation = false;
	phys_addr_t fault_ipa;
	unsigned long esr;
	unsigned long hva;
	bool write_fault;
	bool guest_size_err;
	bool writable;
	bool is_iabt;
	int ret;
	gfn_t gfn;
	int idx;

	esr = kvm_vcpu_get_esr(vcpu);
	fault_ipa = kvm_vcpu_get_fault_ipa(vcpu);
	is_iabt = kvm_vcpu_trap_is_iabt(vcpu);
	guest_size_err = vcpu->arch.sae_block.icptr == SAE_ICPTR_GUEST_ADDRESS_SIZE;

	if (guest_size_err) {
		translation = true;
	} else {
		ret = kvm_handle_pic(vcpu, &translation);
		if (ret)
			return ret;
	}

	if (translation) {
		/* Beyond sanitised PA range (which is the IPA limit) */
		if (fault_ipa >= kvm_get_pa_address(vcpu->kvm)) {
			kvm_inject_size_fault(vcpu);
			return 1;
		}

		/* Falls between the IPA range and the PA range? */
		if (fault_ipa >= vcpu->kvm->arch.guest_phys_size) {
			fault_ipa |= kvm_vcpu_get_hfar(vcpu) & GENMASK(11, 0);
			return kvm_inject_sea(vcpu, is_iabt, fault_ipa);
		}
	}

	idx = srcu_read_lock(&vcpu->kvm->srcu);

	gfn = fault_ipa >> PAGE_SHIFT;

	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	hva = gfn_to_hva_memslot_prot(memslot, gfn, &writable);
	write_fault = kvm_is_write_fault(vcpu);
	if (kvm_is_error_hva(hva) || (write_fault && !writable)) {
		ret = -ENOEXEC;
		/*
		 * The guest has put either its instructions or its page-tables
		 * somewhere it shouldn't have. Userspace won't be able to do
		 * anything about this (there's no syndrome for a start).
		 */
		if (is_iabt) {
			ret = kvm_inject_sea_iabt(vcpu, kvm_vcpu_get_hfar(vcpu));
			goto out_unlock;
		}

		if (kvm_vcpu_abt_iss1tw(vcpu)) {
			ret = kvm_inject_sea_dabt(vcpu, kvm_vcpu_get_hfar(vcpu));
			goto out_unlock;
		}

		/*
		 * Check for a cache maintenance operation. Assume the guest is
		 * cautious and skip instruction
		 */
		if (kvm_is_error_hva(hva) && kvm_vcpu_dabt_is_cm(vcpu)) {
			kvm_incr_pc(vcpu);
			ret = 1;
			goto out_unlock;
		}

		/*
		 * The IPA is reported as [MAX:12], so we need to
		 * complement it with the bottom 12 bits from the
		 * faulting VA. This is always 12 bits, irrespective
		 * of the page size.
		 */
		fault_ipa |= kvm_vcpu_get_hfar(vcpu) & ((1 << 12) - 1);
		ret = io_mem_abort(vcpu, fault_ipa);
		goto out_unlock;
	}

	/* Userspace should not be able to register out-of-bounds IPAs */
	VM_BUG_ON(fault_ipa >= vcpu->kvm->arch.guest_phys_size);
	/*
	 * Proper guest size faults have been injected.
	 * In theory it's fine to have device memory higher than MSL,
	 * even if not currently possible, but that would have been handled above.
	 * So if we get here with a guest size intercept, we have a bug somewhere.
	 */
	VM_BUG_ON(guest_size_err);

	ret = user_mem_abort(vcpu, fault_ipa, memslot, hva);
	if (!ret)
		ret = 1;
out_unlock:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
	return ret;
}
