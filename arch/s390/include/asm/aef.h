/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_S390_AEF_H
#define _ASM_S390_AEF_H

#include <asm/kvm_host_arm64_types.h>

/**
 * kvm_init_save_area() - Initialize Guest Save Area
 * @save_area: Pointer to kvm_sae_save_area structure to initialize
 *
 * Context: Must be called before using the save area with lasrm/stiasrm instructions.
 */
void kvm_vcpu_init_save_area(struct kvm_sae_save_area *sa);
struct qaaf_qmc_block *aef_qmc(void);

struct aef_info {
	unsigned long arm_guest_supp;
	unsigned long sae_avail;
	unsigned long ptff_avail;
	unsigned long supp_state_desc_formats;
	unsigned long supp_save_area_formats;
	unsigned long max_num_vcpu;
};

const struct aef_info *aef_info(void);

#endif /* _ASM_S390_AEF_H */
