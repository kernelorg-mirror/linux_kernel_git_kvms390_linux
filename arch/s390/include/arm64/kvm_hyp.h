/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __S390_ARM64_KVM_HYP_H__
#define __S390_ARM64_KVM_HYP_H__

#include <linux/compiler.h>

static __always_inline bool has_vhe(void)
{
	return true;
}

static __always_inline bool is_protected_kvm_enabled(void)
{
	return false;
}

#endif /* __S390_ARM64_KVM_HYP_H__ */
