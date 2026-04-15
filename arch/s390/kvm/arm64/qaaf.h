/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ARCH_S390_KVM_ARM64_QAAF_H
#define ARCH_S390_KVM_ARM64_QAAF_H

#include <asm/aef.h>

u64 kvm_qaaf_read_ftr_reg(u32 id);

#endif
