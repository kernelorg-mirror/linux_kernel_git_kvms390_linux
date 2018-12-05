// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _ORC_TYPES_H
#define _ORC_TYPES_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/compiler.h>

/*
 * This struct is more or less a vastly simplified version of the DWARF Call
 * Frame Information standard. It tells the unwinder how to find the previous
 * SP (and sometimes entry regs) and the stored registers for the function.
 * After restoring the stored register the return address will be in %r14.
 * Each instance of the struct corresponds to the code location and
 * all following code locations unless superseded by the next orc_entry.
 *
 * Encoding: the type field determines how the ORC entry is interpreted
 * 1) type==ORC_TYPE_REGISTER
 *    No register need to be restored, the original stack pointer is at
 *    offset+reg0, the return address is in reg1. The typical ORC
 *    entry of this type is 0ef00000, cfa=0(%r15), ra=%r14.
 * 2) type==ORC_TYPE_RESTORE
 *    The first step to unwind this type is to restore a set of registers,
 *    namely the registers in the set %r6..%r15 marked with a 1 in 'mask'.
 *    Mask bit for %r6 is bit 0x2000, %r15 is bit 0x0001. After the restore
 *    the stack pointer is in %r15 and the return address in %r14.
 * 3) type==ORC_TYPE_PTREGS
 *    The full set of register stored by the first level interrupt handlers
 *    can be found in a struct pt_regs at offset+reg0.
 * 4) type==ORC_TYPE_EXPOLINE
 *    This is a special entry for expoline thunks. This should appear in
 *    the call chain only as return target of an interrupt frame with an
 *    associated struct pt_regs. To unwind this case pick up the branch
 *    target address from register reg0 and use the ORC information
 *    associated with it.
 */
struct orc_entry {
	union {
		struct {
			unsigned type:2;
			unsigned mask:10;
			unsigned reg0:4;
		} __packed;
		struct {
			unsigned :8;
			unsigned reg1:4;
			unsigned :4;
		} __packed;
	};
	s16 offset;
} __packed;

#define ORC_TYPE_REGISTER	0
#define ORC_TYPE_RESTORE	1
#define ORC_TYPE_PTREGS		2
#define ORC_TYPE_EXPOLINE	3

/*
 * This struct is used by asm and inline asm code to manually annotate the
 * location of the call frame address and the return address for the
 * ORC unwinder.
 */
struct unwind_hint {
	s32		ip;
	s16		sp_offset;
	u8		sp_reg;
	u8		sp_ptregs;
	u8		ra_reg;
	u8		clear;
	u8		skip;
};
#endif /* __ASSEMBLY__ */

#endif /* _ORC_TYPES_H */
