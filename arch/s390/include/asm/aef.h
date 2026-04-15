/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_S390_AEF_H
#define _ASM_S390_AEF_H

#include <asm/kvm_host_arm64_types.h>

const struct kvm_sae_save_area *aef_gisrsa(void);
const struct qaaf_qmc_block *aef_qmc(void);
bool aef_usable(void);

#endif /* _ASM_S390_AEF_H */
