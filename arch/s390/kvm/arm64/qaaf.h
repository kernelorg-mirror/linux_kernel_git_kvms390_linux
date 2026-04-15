/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ARCH_S390_KVM_ARM64_QAAF_H
#define ARCH_S390_KVM_ARM64_QAAF_H

#include <asm/aef.h>

__init void kvm_init_qaaf(void);
struct qaaf_qmc_block *kvm_qaaf_qmc(void);
u64 kvm_qaaf_read_ftr_reg(u32 id);

#endif
