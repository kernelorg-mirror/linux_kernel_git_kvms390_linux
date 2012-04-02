#if !defined(_TRACE_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace

/* Former VM_EVENTs. */
TRACE_EVENT(kvm_s390_create_vm,
	    TP_PROTO(struct kvm *kvm),
	    TP_ARGS(kvm),

	    TP_STRUCT__entry(
		    __field(struct kvm *, kvm)
		    ),

	    TP_fast_assign(
		    __entry->kvm = kvm;
		    ),

	    TP_printk("vm created at %p", __entry->kvm)
	);

TRACE_EVENT(kvm_s390_create_vcpu,
	    TP_PROTO(unsigned int id, struct kvm_vcpu *vcpu,
		     struct kvm_s390_sie_block *sie_block),
	    TP_ARGS(id, vcpu, sie_block),

	    TP_STRUCT__entry(
		    __field(unsigned int, id)
		    __field(struct kvm_vcpu *, vcpu)
		    __field(struct kvm_s390_sie_block *, sie_block)
		    ),

	    TP_fast_assign(
		    __entry->id = id;
		    __entry->vcpu = vcpu;
		    __entry->sie_block = sie_block;
		    ),

	    TP_printk("create cpu %d at %p, sie block at %p", __entry->id,
		      __entry->vcpu, __entry->sie_block)
	);

TRACE_EVENT(kvm_s390_inject_virtio_int,
	    TP_PROTO(__u32 parm, __u64 parm64),
	    TP_ARGS(parm, parm64),

	    TP_STRUCT__entry(
		    __field(__u32, parm)
		    __field(__u64, parm64)
		    ),

	    TP_fast_assign(
		    __entry->parm = parm;
		    __entry->parm64 = parm64;
		    ),

	    TP_printk("inject: virtio parm:%x,parm64:%llx", __entry->parm,
		      __entry->parm64)
	);

TRACE_EVENT(kvm_s390_inject_sclp_int,
	    TP_PROTO(__u32 parm),
	    TP_ARGS(parm),

	    TP_STRUCT__entry(
		    __field(__u32, parm)
		    ),

	    TP_fast_assign(
		    __entry->parm = parm;
		    ),

	    TP_printk("inject: sclp parm:%x", __entry->parm)
	);

/* Former VCPU_EVENTs. */
#define VCPU_PROTO_COMMON int id, unsigned long pswmask, unsigned long pswaddr
#define VCPU_ARGS_COMMON id, pswmask, pswaddr
#define VCPU_FIELD_COMMON __field(int, id)	\
	__field(unsigned long, pswmask)		\
	__field(unsigned long, pswaddr)
#define VCPU_ASSIGN_COMMON __entry->id = id;	\
	__entry->pswmask = pswmask;		\
	__entry->pswaddr = pswaddr;
#define VCPU_TP_PRINTK(p_str, p_args...)				\
	TP_printk("%02d[%016lx-%016lx]: " p_str, __entry->id, __entry->pswmask,\
		  __entry->pswaddr, p_args)

TRACE_EVENT(kvm_s390_diag_10,
	    TP_PROTO(VCPU_PROTO_COMMON, unsigned long start, unsigned long end),
	    TP_ARGS(VCPU_ARGS_COMMON, start, end),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(unsigned long, start)
		    __field(unsigned long, end)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->start = start;
		    __entry->end = end;
		    ),

	    VCPU_TP_PRINTK("diag release pages %lX %lX",
			   __entry->start, __entry->end)
	);

TRACE_EVENT(kvm_s390_diag_44,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "diag time slice end")
	);

TRACE_EVENT(kvm_s390_diag_308,
	    TP_PROTO(VCPU_PROTO_COMMON, unsigned long subcode),
	    TP_ARGS(VCPU_ARGS_COMMON, subcode),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(unsigned long, subcode)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->subcode = subcode;
		    ),

	    VCPU_TP_PRINTK("diag ip functions, subcode %lx",
			   __entry->subcode)
	);

TRACE_EVENT(kvm_s390_request_resets,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 resets),
	    TP_ARGS(VCPU_ARGS_COMMON, resets),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u64, resets)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->resets = resets;
		    ),

	    VCPU_TP_PRINTK("requesting userspace resets %llx",
			   __entry->resets)
	);

TRACE_EVENT(kvm_s390_load_ctl,
	    TP_PROTO(VCPU_PROTO_COMMON, int g, int reg1, int reg3, int base2,
		     int disp2),
	    TP_ARGS(VCPU_ARGS_COMMON, g, reg1, reg3, base2, disp2),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, g)
		    __field(int, reg1)
		    __field(int, reg3)
		    __field(int, base2)
		    __field(int, disp2)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->g = g;
		    __entry->reg1 = reg1;
		    __entry->reg3 = reg3;
		    __entry->base2 = base2;
		    __entry->disp2 = disp2;
		    ),

	    VCPU_TP_PRINTK("%s r1: %x, r3: %x, b2: %x, d2: %x",
			   __entry->g ? "lctlg" : "lctl",
			   __entry->reg1, __entry->reg3, __entry->base2,
			   __entry->disp2)
	);

TRACE_EVENT(kvm_s390_cpu_stopped,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "cpu stopped")
	);

TRACE_EVENT(kvm_s390_validity_icpt,
	    TP_PROTO(VCPU_PROTO_COMMON, int viwhy),
	    TP_ARGS(VCPU_ARGS_COMMON, viwhy),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, viwhy)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->viwhy = viwhy;
		    ),

	    VCPU_TP_PRINTK("unhandled validity intercept code %d",
			   __entry->viwhy)
	);

TRACE_EVENT(kvm_s390_destroy_cpu,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "free cpu")
	);

TRACE_EVENT(kvm_s390_enter_sie,
	    TP_PROTO(VCPU_PROTO_COMMON, int cpuflags),
	    TP_ARGS(VCPU_ARGS_COMMON, cpuflags),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, cpuflags)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->cpuflags = cpuflags;
		    ),

	    VCPU_TP_PRINTK("entering sie flags %x", __entry->cpuflags)
	);

TRACE_EVENT(kvm_s390_sie_fault,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "fault in sie instruction")
	);

TRACE_EVENT(kvm_s390_exit_sie,
	    TP_PROTO(VCPU_PROTO_COMMON, int icptcode),
	    TP_ARGS(VCPU_ARGS_COMMON, icptcode),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, icptcode)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->icptcode = icptcode;
		    ),

	    VCPU_TP_PRINTK("exit sie icptcode %d", __entry->icptcode)
	);

#define kvm_int_type					\
	{KVM_S390_SIGP_STOP, "sigp stop"},		\
	{KVM_S390_PROGRAM_INT, "program interrupt"},	\
	{KVM_S390_SIGP_SET_PREFIX, "sigp set prefix"},	\
	{KVM_S390_RESTART, "sigp restart"},		\
	{KVM_S390_INT_VIRTIO, "virtio interrupt"},	\
	{KVM_S390_INT_SERVICE, "sclp interrupt"},	\
	{KVM_S390_INT_EMERGENCY, "sigp emergency"},	\
	{KVM_S390_INT_EXTERNAL_CALL, "sigp ext call"},	\
	{0xfffe0004u, "sigp sense"},			\
	{0xfffe0005u, "sigp sense running"},		\
	{0xfffe0006u, "sigp restart"}


TRACE_EVENT(kvm_s390_int,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type),
	    TP_ARGS(VCPU_ARGS_COMMON, type),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    ),

	    VCPU_TP_PRINTK("interrupt: %s",
			   __print_symbolic(__entry->inttype, kvm_int_type))
	);

TRACE_EVENT(kvm_s390_int_parm,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, int parm),
	    TP_ARGS(VCPU_ARGS_COMMON, type, parm),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(int, parm)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->parm = parm;
		    ),

	    VCPU_TP_PRINTK("interrupt: %s, parm: %x",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   __entry->parm)
	);

TRACE_EVENT(kvm_s390_virtio_int,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, __u32 parm, __u64 parm64),
	    TP_ARGS(VCPU_ARGS_COMMON, type, parm, parm64),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(__u32, parm)
		    __field(__u64, parm64)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->parm = parm;
		    __entry->parm64 = parm64;
		    ),

	    VCPU_TP_PRINTK("interrupt: %s, parm: %x, parm64: %llx",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   __entry->parm, __entry->parm64)
	);

TRACE_EVENT(kvm_s390_program_int,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, int code, int ilc),
	    TP_ARGS(VCPU_ARGS_COMMON, type, code, ilc),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(int, code)
		    __field(int, ilc)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->code = code;
		    __entry->ilc = ilc;
		    ),

	    VCPU_TP_PRINTK("interrupt: %s, code: %x, ilc: %x",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   __entry->code, __entry->ilc)
	);

TRACE_EVENT(kvm_s390_wait_state,
	    TP_PROTO(VCPU_PROTO_COMMON, int enabled, __u64 sltime),
	    TP_ARGS(VCPU_ARGS_COMMON, enabled, sltime),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, enabled)
		    __field(__u64, sltime)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->enabled = enabled;
		    __entry->sltime = sltime;
		    ),

	    VCPU_TP_PRINTK("%s wait %s(%lld ns)",
			   __entry->enabled ? "enabled" : "disabled",
			   __entry->enabled ?
			   (__entry->sltime ?
			    "via clock comparator " : "w/o timer ") : "",
			   __entry->sltime)
	);

TRACE_EVENT(kvm_s390_inject_int,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, int who, int parm),
	    TP_ARGS(VCPU_ARGS_COMMON, type, who, parm),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(int, who)
		    __field(int, parm)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->who = who;
		    __entry->parm = parm;
		    ),

	    VCPU_TP_PRINTK("inject: %s %s,parm %x",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   (__entry->who == 1) ? "(from kernel) " :
			   (__entry->who == 2) ? "(from user) " : "",
			   __entry->parm)
	);

TRACE_EVENT(kvm_s390_priv_prefix,
	    TP_PROTO(VCPU_PROTO_COMMON, int set, __u32 address),
	    TP_ARGS(VCPU_ARGS_COMMON, set, address),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, set)
		    __field(__u32, address)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->set = set;
		    __entry->address = address;
		    ),

	    VCPU_TP_PRINTK("%s prefix to %x",
			   __entry->set ? "setting" : "storing",
			   __entry->address)
	);

TRACE_EVENT(kvm_s390_priv_stap,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 address),
	    TP_ARGS(VCPU_ARGS_COMMON, address),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u64, address)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->address = address;
		    ),

	    VCPU_TP_PRINTK("storing cpu address to %llx",
			   __entry->address)
	);

TRACE_EVENT(kvm_s390_priv_skey,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "retrying storage key operation")
	);

TRACE_EVENT(kvm_s390_priv_ioinst,
	    TP_PROTO(VCPU_PROTO_COMMON, __u32 ipa),
	    TP_ARGS(VCPU_ARGS_COMMON, ipa),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, ipa)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->ipa = ipa;
		    ),

	    VCPU_TP_PRINTK("I/O instruction %04x", __entry->ipa)
	);

TRACE_EVENT(kvm_s390_priv_stfl,
	    TP_PROTO(VCPU_PROTO_COMMON, unsigned int facility_list),
	    TP_ARGS(VCPU_ARGS_COMMON, facility_list),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(unsigned int, facility_list)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->facility_list = facility_list;
		    ),

	    VCPU_TP_PRINTK("store facility list value %x",
			   __entry->facility_list)
	);

TRACE_EVENT(kvm_s390_priv_stidp,
	    TP_PROTO(VCPU_PROTO_COMMON),
	    TP_ARGS(VCPU_ARGS_COMMON),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    ),

	    VCPU_TP_PRINTK("%s", "store cpu id")
	);

TRACE_EVENT(kvm_s390_priv_stsi,
	    TP_PROTO(VCPU_PROTO_COMMON, int fc, int sel1, int sel2),
	    TP_ARGS(VCPU_ARGS_COMMON, fc, sel1, sel2),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(int, fc)
		    __field(int, sel1)
		    __field(int, sel2)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->fc = fc;
		    __entry->sel1 = sel1;
		    __entry->sel2 = sel2;
		    ),

	    VCPU_TP_PRINTK("stsi: fc: %x sel1: %x sel2: %x",
			   __entry->fc, __entry->sel1, __entry->sel2)
	);

TRACE_EVENT(kvm_s390_sigp,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, int cpu_addr),
	    TP_ARGS(VCPU_ARGS_COMMON, type, cpu_addr),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(int, cpu_addr)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->cpu_addr = cpu_addr;
		    ),

	    VCPU_TP_PRINTK("sent %s to cpu %x",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   __entry->cpu_addr)
	);

TRACE_EVENT(kvm_s390_sigp_parm,
	    TP_PROTO(VCPU_PROTO_COMMON, __u64 type, int cpu_addr, int parm),
	    TP_ARGS(VCPU_ARGS_COMMON, type, cpu_addr, parm),

	    TP_STRUCT__entry(
		    VCPU_FIELD_COMMON
		    __field(__u32, inttype)
		    __field(int, cpu_addr)
		    __field(int, parm)
		    ),

	    TP_fast_assign(
		    VCPU_ASSIGN_COMMON
		    __entry->inttype = type & 0x00000000ffffffff;
		    __entry->cpu_addr = cpu_addr;
		    __entry->parm = parm;
		    ),

	    VCPU_TP_PRINTK("sent %s to cpu %x, parm: %x",
			   __print_symbolic(__entry->inttype, kvm_int_type),
			   __entry->cpu_addr, __entry->parm)
	);

#endif /* _TRACE_KVM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
