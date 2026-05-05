/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(KVM_ARM64_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define KVM_ARM64_TRACE_KVM_H

#include <linux/tracepoint.h>

#include <arm64/sys_regs.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_arm64

TRACE_EVENT(kvm_mmio_nisv,
	TP_PROTO(unsigned long vcpu_pc, unsigned long esr,
		 unsigned long far, unsigned long ipa),
	TP_ARGS(vcpu_pc, esr, far, ipa),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
		__field(	unsigned long,	esr		)
		__field(	unsigned long,	far		)
		__field(	unsigned long,	ipa		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
		__entry->esr			= esr;
		__entry->far			= far;
		__entry->ipa			= ipa;
	),

	TP_printk("ipa %#016lx, esr %#016lx, far %#016lx, pc %#016lx",
		  __entry->ipa, __entry->esr,
		  __entry->far, __entry->vcpu_pc)
);

TRACE_EVENT(kvm_handle_sys_reg,
	TP_PROTO(unsigned long hsr),
	TP_ARGS(hsr),

	TP_STRUCT__entry(
		__field(unsigned long,	hsr)
	),

	TP_fast_assign(
		__entry->hsr = hsr;
	),

	TP_printk("HSR 0x%08lx", __entry->hsr)
);

TRACE_EVENT(kvm_sys_access,
	TP_PROTO(unsigned long vcpu_pc, struct sys_reg_params *params, const struct sys_reg_desc *reg),
	TP_ARGS(vcpu_pc, params, reg),

	TP_STRUCT__entry(
		__field(unsigned long,			vcpu_pc)
		__field(bool,				is_write)
		__field(const char *,			name)
		__field(u8,				Op0)
		__field(u8,				Op1)
		__field(u8,				CRn)
		__field(u8,				CRm)
		__field(u8,				Op2)
	),

	TP_fast_assign(
		__entry->vcpu_pc = vcpu_pc;
		__entry->is_write = params->is_write;
		__entry->name = reg->name;
		__entry->Op0 = reg->Op0;
		__entry->Op0 = reg->Op0;
		__entry->Op1 = reg->Op1;
		__entry->CRn = reg->CRn;
		__entry->CRm = reg->CRm;
		__entry->Op2 = reg->Op2;
	),

	TP_printk("PC: %lx %s (%d,%d,%d,%d,%d) %s",
		  __entry->vcpu_pc, __entry->name ?: "UNKN",
		  __entry->Op0, __entry->Op1, __entry->CRn,
		  __entry->CRm, __entry->Op2,
		  str_write_read(__entry->is_write))
);

#endif /* KVM_ARM64_TRACE_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
