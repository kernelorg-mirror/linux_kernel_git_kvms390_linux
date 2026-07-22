/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_KVM_HOST_ARM64_H
#define ASM_KVM_HOST_ARM64_H

#include <linux/bug.h>
#include <linux/bitfield.h>

#include <asm/kvm_host_types.h>
#include <asm/debug.h>

#define vcpu_gp_regs(v)		((v)->arch.sae_block.gpr)
enum vcpu_sysreg;

#include <arm64/kvm_host.h>
#include <arm64/ptrace.h>

#include <asm/sae.h>

enum {
	ARM64_HAS_WFXT,
	ARM64_HAS_RASV1P1_EXTN,
	ARM64_HAS_STAGE2_FWB,
	ARM64_HAS_RAS_EXTN,
	ARM64_HAS_EVT,
	ARM64_HAS_HCR_NV1,
	ARM64_MISMATCHED_CACHE_TYPE,
	ARM64_HAS_ECV_CNTPOFF,
};

bool cpus_have_final_cap(unsigned int num);

#define KVM_HAVE_MMU_RWLOCK
#define KVM_MAX_VCPUS 1
#define KVM_S390_ARM64_IMPL_FEATURES (		\
	 BIT(KVM_ARM_VCPU_PTRAUTH_ADDRESS) |	\
	 BIT(KVM_ARM_VCPU_PTRAUTH_GENERIC) |	\
	 BIT(KVM_ARM_VCPU_SVE)			\
)

#define KVM_HALT_POLL_NS_DEFAULT 50000

#define KVM_S390_MANAGES_S390_GUEST 0

/* Minimal (=no) vgic definitions */
#define KVM_IRQCHIP_NUM_PINS 1
#define irqchip_in_kernel(_k) false

#define __ctxt_sys_reg(ctx, reg)					\
	({								\
		BUILD_BUG_ON(!__builtin_constant_p(reg));		\
		___ctxt_sys_reg(ctx, reg);				\
	})

struct kvm_cpu_context {
	/*
	 * These are just for 32 bit, which we don't have, making them RES0.
	 * They are exposed to user space.
	 */
	u64	spsr_abt;
	u64	spsr_und;
	u64	spsr_irq;
	u64	spsr_fiq;

	__vector128 __aligned(16) vregs[32];

	/* shadowed sysregs to comply with arm64 infrastructure */
	u64 elr_el1;
	u64 spsr_el1;
};

struct kvm_vcpu_arch {
	struct kvm_sae_block sae_block;
	struct kvm_sae_save_area save_area;
	struct kvm_cpu_context ctxt;

	/* Guest system registers not part of save area or ID registers */
	u64 sys_reg_clidr_el1;
	u64 sys_reg_csselr_el1;
	/* Per-vcpu CCSIDR override or NULL */
	u32 *ccsidr;

	u32 host_acrs[NUM_ACRS];

	/* Hypervisor Configuration Register */
	u64 hcr_elz;
	u64 hcrx_elz;

	u64 mpidr;

	/* Configuration flags, set once and for all before the vcpu can run */
	u8 cflags;

	/* Input flags to the hypervisor code, potentially cleared after use */
	u8 iflags;

	/* State flags for kernel bookkeeping, unused by the hypervisor code */
	u8 sflags;

	/*
	 * Don't run the guest (internal implementation need).
	 *
	 * Contrary to the flags above, this is set/cleared outside of
	 * a vcpu context, and thus cannot be mixed with the flags
	 * themselves (or the flag accesses need to be made atomic).
	 */
	bool pause;

	/* vcpu power state */
	struct kvm_mp_state mp_state;
	/* lock for mp_state & reset_state.reset */
	spinlock_t mp_state_lock;

	/* vcpu reset state */
	struct vcpu_reset_state reset_state;

	/* GMAP */
	struct gmap *gmap;
	struct kvm_s390_mmu_cache *mc;

	void *debugfs_state_data;
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	/* ARM64 stats */
	u64 hvc_exit_stat;
	u64 wfe_exit_stat;
	u64 wfi_exit_stat;
	u64 mmio_exit_user;
	u64 mmio_exit_kernel;
	u64 signal_exits;
	u64 exits;
	/* GMAP stats */
	u64 pfault_sync;
};

#define kvm_has_mte(_kvm) false

struct kvm_arch_memory_slot {
};

struct kvm_arch {
	struct gmap *gmap;
	u64 guest_phys_size;

	/* VM-wide vCPU feature set */
	unsigned long flags;

	/* Protects VM-scoped configuration data */
	struct mutex config_lock;

	debug_info_t *dbf;

	DECLARE_BITMAP(vcpu_features, KVM_VCPU_MAX_FEATURES);

	unsigned long mem_limit;

	/* Per-VM ID register storage */
	struct kvm_vm_id_regs id_regs;

	/* The EPD as it should be on all VCPUs. */
	u64 epd;
};

static inline bool __vcpu_has_feature(const struct kvm_arch *ka, int feature)
{
	return test_bit(feature, ka->vcpu_features);
}

struct kvm_vm_stat {
	struct kvm_vm_stat_generic generic;
};

#define kvm_vm_is_protected(_kvm) false
#define vcpu_is_protected(_vcpu) false

#define vcpu_is_loaded(_vcpu) ((_vcpu)->cpu != -1)

#define KVM_HVA_ERR_BAD		-1UL
#define KVM_HVA_ERR_RO_BAD	-2UL

static inline bool kvm_is_error_hva(unsigned long addr)
{
	return IS_ERR_VALUE(addr);
}

u32 get_kvm_ipa_limit(void);

/* unused, but required functions */
static inline void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *slot) {}
static inline void kvm_arch_memslots_updated(struct kvm *kvm, u64 gen) {}
static inline void kvm_arch_flush_shadow_all(struct kvm *kvm) {}
static inline void kvm_arch_flush_shadow_memslot(struct kvm *kvm, struct kvm_memory_slot *slot) {}
static inline void kvm_arch_vcpu_blocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_unblocking(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_sync_events(struct kvm *kvm) {}
static inline void kvm_arch_sched_in(struct kvm_vcpu *vcpu, int cpu) {}
static inline void kvm_arch_mmu_enable_log_dirty_pt_masked(struct kvm *kvm,
							   struct kvm_memory_slot *slot,
							   gfn_t gfn_offset,
							   unsigned long mask) {}

int kvm_handle_guest_abort(struct kvm_vcpu *vcpu);
void kvm_reset_vcpu(struct kvm_vcpu *vcpu);

/* arm64 guests do not use async-pf. Defined because Kbuild requires it as s390 kvm turns it on. */
#define ASYNC_PF_PER_VCPU 0
struct kvm_arch_async_pf {
	unsigned long pfault_token;
};

#define __unsupp_async_call(fn) WARN_ONCE(true, "async not supported on kvm-arm64 %s", fn)

static inline bool kvm_arch_can_dequeue_async_page_present(struct kvm_vcpu *vcpu)
{
	__unsupp_async_call(__func__);
	return false;
};

static inline void kvm_arch_async_page_ready(struct kvm_vcpu *vcpu,
					     struct kvm_async_pf *work)
{
	__unsupp_async_call(__func__);
};

static inline bool kvm_arch_async_page_not_present(struct kvm_vcpu *vcpu,
						   struct kvm_async_pf *work)
{
	__unsupp_async_call(__func__);
	return false;
};

static inline void kvm_arch_async_page_present(struct kvm_vcpu *vcpu,
					       struct kvm_async_pf *work)
{
	__unsupp_async_call(__func__);
};

static inline void kvm_arch_async_page_present_queued(struct kvm_vcpu *vcpu)
{
	__unsupp_async_call(__func__);
};

#define kvm_supports_32bit_el0() false

#define __vcpu_sys_reg(__vcpu, __reg) \
	vcpu_read_sys_reg(__vcpu, __reg)

#define __vcpu_assign_sys_reg(__vcpu, __reg, __val) \
	vcpu_write_sys_reg(__vcpu, __val, __reg)

#define __vcpu_rmw_sys_reg(C, V, OP, R)		\
({						\
	u64 __val = vcpu_read_sys_reg(C, R);	\
	__val OP V;				\
	vcpu_write_sys_reg(C, __val, R);	\
})

/**
 * _vcpu_read_sys_reg() - read a guest sysreg with easr
 * - R - sysreg id; must be readable by easr; must be compile time constant
 *
 *   if SYSREGS_ON_CPU: proceed with flags = 0
 *   otherwise:         proceed with either
 *                         read:  flags = EASR_FLAG_SA
 *                         write: flags = SASR_FLAG_INITIALIZED
 *
 */
#define _vcpu_read_sys_reg(C, R) \
	({	BUILD_BUG_ON(!__builtin_constant_p((R))); \
		BUG_ON(vcpu_is_loaded(C) && smp_processor_id() != (C)->cpu); \
		(vcpu_is_loaded(C)) \
			? __vcpu_read_sr((C), (R), 0) \
			: __vcpu_read_sr((C), (R), EASR_FLAG_SA); })

/**
 * _vcpu_write_sys_reg() - write a guest sysreg with sasr
 * - R - sysreg id; must be readable by sasr; must be compile time constant

 *   if SYSREGS_ON_CPU: proceed with flags = 0
 *   otherwise:         proceed with either
 *                         read:  flags = EASR_FLAG_SA
 *                         write: flags = SASR_FLAG_INITIALIZED
 */
#define _vcpu_write_sys_reg(C, V, R) \
	({	BUILD_BUG_ON(!__builtin_constant_p((R))); \
		BUG_ON(vcpu_is_loaded(C) && smp_processor_id() != (C)->cpu); \
		(vcpu_is_loaded(C)) \
			? __vcpu_write_sr((C), (V), (R), 0) \
			: __vcpu_write_sr((C), (V), (R), SASR_FLAG_INITIALIZED); })

/* Forward to easr / sasr
 * assert that F and R are constant
 */
#define __vcpu_read_sr(C, R, F) \
	({	BUILD_BUG_ON(!__builtin_constant_p((R))); \
		BUILD_BUG_ON(!__builtin_constant_p((F))); \
		easr((R), &(C)->arch.save_area, (F)); })

#define __vcpu_write_sr(C, V, R, F) \
	({	BUILD_BUG_ON(!__builtin_constant_p((R))); \
		BUILD_BUG_ON(!__builtin_constant_p((F))); \
		sasr((R), (V), &(C)->arch.save_area, (F)); })

#define SR_GROUP(NAME, ...)	\
	__##NAME##_BEGIN__,	\
	__VA_ARGS__		\
	__##NAME##_END__

/** enum vcpu_sysreg - available guest sysregs
 *
 * Contains all arm64 guest-syregs supported by s390.
 */
enum vcpu_sysreg {
	__INVALID_SYSREG__, /* 0 is reserved as an invalid value */

	/* EL 0,1 Register from state description in order of appearance */
	SR_GROUP(STATE_DESC,
	CNTP_CTL_EL0,
	CNTV_CTL_EL0,
	CONTEXTIDR_EL1,
	SP_EL1,
	),

	/* EL 0,1 Register requiring special handling. */
	SR_GROUP(SPECIAL,
	CSSELR_EL1,
	CLIDR_EL1,
	MPIDR_EL1,
	ELR_EL1,
	SPSR_EL1,
	),

	/* EL 0,1 register from save area in order of appearance */
	SR_GROUP(SAVE_AREA,
	ACTLR_EL1,
	AFSR0_EL1,
	AFSR1_EL1,
	CNTFRQ_EL0,
	CNTP_CVAL_EL0,
	CNTV_CVAL_EL0,
	DISR_EL1,
	MIDR_EL1,
	OSLSR_EL1,
	PAR_EL1,
	OSLAR_EL1,
	SCTLR_EL1,
	CPACR_EL1,
	VBAR_EL1,
	ESR_EL1,
	TCR_EL1,
	MAIR_EL1,
	TTBR0_EL1,
	TTBR1_EL1,
	FAR_EL1,
	TPIDR_EL0,
	TPIDR_EL1,
	TPIDRRO_EL0,
	CNTKCTL_EL1,
	ZCR_EL1,
	SCXTNUM_EL0,
	SCXTNUM_EL1,
	APIBKEYLO_EL1,
	APIBKEYHI_EL1,
	APIAKEYLO_EL1,
	APIAKEYHI_EL1,
	APGAKEYLO_EL1,
	APGAKEYHI_EL1,
	APDBKEYLO_EL1,
	APDBKEYHI_EL1,
	APDAKEYLO_EL1,
	APDAKEYHI_EL1,
	MDSCR_EL1,
	),

	NR_SYS_REGS /* Nothing after this line! */
};

static __always_inline u64 *___ctxt_sys_reg(struct kvm_cpu_context *ctxt,
					    const enum vcpu_sysreg reg)
{
	switch (reg) {
	case ELR_EL1:
		return &ctxt->elr_el1;
	case SPSR_EL1:
		return &ctxt->spsr_el1;
	default:
		BUG();
		break;
	}
}

void vcpu_write_host_sys_reg(struct kvm_vcpu *vcpu, u64 val, int reg);
u64 vcpu_read_host_sys_reg(const struct kvm_vcpu *vcpu, int reg);

#define kvm_debug_handle_oslar(_v, _val) /* debug not implemented yet*/

static inline u8 kvm_arm_pmu_get_pmuver_limit(void)
{
	return 0;
}

int __init kvm_sys_reg_table_init(void);

static inline bool system_supports_poe(void)
{
	return false;
}

static inline bool vgic_host_has_gicv3(void)
{
	return false;
}

static inline bool vgic_host_has_gicv5(void)
{
	return false;
}

static inline bool has_broken_cntvoff(void)
{
	return false;
}

void kvm_adjust_pc(struct kvm_vcpu *vcpu);
size_t kvm_parange_to_address_sanitized(u32 id_parange);

#endif /* ASM_KVM_HOST_ARM64_H */
