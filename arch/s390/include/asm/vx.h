/*
 * In-kernel vector extension support functions
 *
 *
 * Consider these guidelines when you want to use vector instructions in
 * the kernel:
 *
 *  1. Use kernel_vx_begin() and kernel_vx_end() to enclose all in-kernel
 *     use of vector registers and instructions.
 *
 *  2. For kernel_vx_begin(), specify the vector register range you want to
 *     use with the KERNEL_VXR_* constants. Consider these usage guidelines:
 *
 *     a) If your function typically runs in process-context, use the lower
 *	  half of the vector registers, for example, specify KERNEL_VXR_LOW.
 *     b) If your function typically runs in soft-irq or hard-irq context,
 *	  prefer using the upper half of the vector registers, for example,
 *	  specify KERNEL_VXR_HIGH.
 *
 *     If you adhere to these guidelines, an interrupted process context
 *     does not require to save and restore vector registers because of
 *     disjoint register ranges.
 *
 *     Also note that the __kernel_vx_begin()/__kernel_vx_end() functions
 *     has some logic to save/restore up to 16 vector registers at once.
 *
 *  3. You can nest kernel_vx_begin()/kernel_vx_end() by using different
 *     struct kernel_vx states.  Vector registers that are in use by outer
 *     levels are saved and restored.  You can minimize the save and restore
 *     effort by choosing disjoint vector register ranges.
 *
 *  5. To use vector floating-point instructions, specify the KERNEL_VX_FPC
 *     flag to save and restore floating-point controls in addition to any
 *     vector register range.
 *
 *  6. To use floating-point registers and instructions only, specify the
 *     KERNEL_FPR flag.  This flag triggers a save and restore of vector
 *     registers V0 to V15 and floating-point controls.
 *
 * Copyright IBM Corp. 2015
 * Author(s): Hendrik Brueckner <brueckner@linux.vnet.ibm.com>
 */
#ifndef __ASM_S390_VX_H
#define __ASM_S390_VX_H

#include <linux/preempt.h>
#include <asm/fpu-internal.h>

struct kernel_vx {
	u32	    mask;
	u32	    fpc;
	__vector128 vxrs[__NUM_VXRS];
};

#define KERNEL_VXR_V0V7		1
#define KERNEL_VXR_V8V15	2
#define KERNEL_VXR_V16V23	4
#define KERNEL_VXR_V24V31	8
#define KERNEL_VX_FPC		256

#define KERNEL_VXR_LOW		(KERNEL_VXR_V0V7|KERNEL_VXR_V8V15)
#define KERNEL_VXR_MID		(KERNEL_VXR_V8V15|KERNEL_VXR_V16V23)
#define KERNEL_VXR_HIGH		(KERNEL_VXR_V16V23|KERNEL_VXR_V24V31)

#define KERNEL_FPR		(KERNEL_VXR_LOW|KERNEL_VX_FPC)

#define KERNEL_VXR_MASK		(KERNEL_VXR_LOW|KERNEL_VXR_HIGH)

/* Note the functions must be called with preempt disabled.  Do not
 * enable preemption before calling __kernel_vx_end() to not corrupt
 * an existing kernel VX state.
 *
 * Prefer using the kernel_vx_begin()/kernel_vx_end() pair of functions.
 */
void __kernel_vx_begin(struct kernel_vx *state, u32 flags);
void __kernel_vx_end(struct kernel_vx *state);


static inline void kernel_vx_begin(struct kernel_vx *state, u32 flags)
{
	preempt_disable();
	__kernel_vx_begin(state, flags);
}

static inline void kernel_vx_end(struct kernel_vx *state)
{
	__kernel_vx_end(state);
	preempt_enable();
}

#endif /* __ASM_S390_VX_H */
