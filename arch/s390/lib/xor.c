/*
 * Optimized xor_block operation for RAID4/5
 *
 * Copyright IBM Corp. 2016
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <linux/types.h>
#include <linux/module.h>

void xor_xc_2(unsigned long, unsigned long *, unsigned long *);
asm(
	"	.globl xor_xc_2\n"
	"	.align	4, 0x07\n"
	"xor_xc_2:\n"
	"	larl	%r1,2f\n"
	"	aghi	%r2,-1\n"
	"	bmr	%r14\n"
	"	srlg	%r0,%r2,8\n"
	"	ltgr	%r0,%r0\n"
	"	jz	1f\n"
	"0:	xc	0(256,%r3),0(%r4)\n"
	"	la	%r3,256(%r3)\n"
	"	la	%r4,256(%r4)\n"
	"	brctg	%r0,0b\n"
	"1:	ex	%r2,0(%r1)\n"
	"	br	%r14\n"
	"2:	xc	0(1,%r3),0(%r4)\n"
	"	.size xor_xc_2, . - xor_xc_2\n"
	"	.type xor_xc_2, @function\n");

EXPORT_SYMBOL(xor_xc_2);

void xor_xc_3(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *);
asm(
	"	.globl xor_xc_3\n"
	"	.align	4, 0x07\n"
	"xor_xc_3:\n"
	"	larl	%r1,2f\n"
	"	aghi	%r2,-1\n"
	"	bmr	%r14\n"
	"	srlg	%r0,%r2,8\n"
	"	ltgr	%r0,%r0\n"
	"	jz	1f\n"
	"0:	xc	0(256,%r3),0(%r4)\n"
	"	xc	0(256,%r3),0(%r5)\n"
	"	la	%r3,256(%r3)\n"
	"	la	%r4,256(%r4)\n"
	"	la	%r5,256(%r5)\n"
	"	brctg	%r0,0b\n"
	"1:	ex	%r2,0(%r1)\n"
	"	ex	%r2,6(%r1)\n"
	"	br	%r14\n"
	"2:	xc	0(1,%r3),0(%r4)\n"
	"	xc	0(1,%r3),0(%r5)\n"
	"	.size xor_xc_3, . - xor_xc_3\n"
	"	.type xor_xc_3, @function\n");

EXPORT_SYMBOL(xor_xc_3);

void xor_xc_4(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *, unsigned long *);
asm(
	"	.globl xor_xc_4\n"
	"	.align	4, 0x07\n"
	"xor_xc_4:\n"
	"	stg	%r6,72(%r15)\n"
	"	larl	%r1,2f\n"
	"	aghi	%r2,-1\n"
	"	bmr	%r14\n"
	"	srlg	%r0,%r2,8\n"
	"	ltgr	%r0,%r0\n"
	"	jz	1f\n"
	"0:	xc	0(256,%r3),0(%r4)\n"
	"	xc	0(256,%r3),0(%r5)\n"
	"	xc	0(256,%r3),0(%r6)\n"
	"	la	%r3,256(%r3)\n"
	"	la	%r4,256(%r4)\n"
	"	la	%r5,256(%r5)\n"
	"	la	%r6,256(%r6)\n"
	"	brctg	%r0,0b\n"
	"1:	ex	%r2,0(%r1)\n"
	"	ex	%r2,6(%r1)\n"
	"	ex	%r2,12(%r1)\n"
	"	ex	%r2,18(%r1)\n"
	"	lg	%r6,72(%r15)\n"
	"	br	%r14\n"
	"2:	xc	0(1,%r3),0(%r4)\n"
	"	xc	0(1,%r3),0(%r5)\n"
	"	xc	0(1,%r3),0(%r6)\n"
	"	.size xor_xc_4, . - xor_xc_4\n"
	"	.type xor_xc_4, @function\n");

EXPORT_SYMBOL(xor_xc_4);

void xor_xc_5(unsigned long, unsigned long *, unsigned long *,
	      unsigned long *, unsigned long *, unsigned long *);
asm(
	"	.globl xor_xc_5\n"
	"	.align	4, 0x07\n"
	"xor_xc_5:\n"
	"	stmg	%r6,%r7,72(%r15)\n"
	"	larl	%r1,2f\n"
	"	aghi	%r2,-1\n"
	"	bmr	%r14\n"
	"	lg	%r7,160(%r15)\n"
	"	srlg	%r0,%r2,8\n"
	"	ltgr	%r0,%r0\n"
	"	jz	1f\n"
	"0:	xc	0(256,%r3),0(%r4)\n"
	"	xc	0(256,%r3),0(%r5)\n"
	"	xc	0(256,%r3),0(%r6)\n"
	"	xc	0(256,%r3),0(%r7)\n"
	"	la	%r3,256(%r3)\n"
	"	la	%r4,256(%r4)\n"
	"	la	%r5,256(%r5)\n"
	"	la	%r6,256(%r6)\n"
	"	la	%r7,256(%r7)\n"
	"	brctg	%r0,0b\n"
	"1:	ex	%r2,0(%r1)\n"
	"	ex	%r2,6(%r1)\n"
	"	ex	%r2,12(%r1)\n"
	"	ex	%r2,18(%r1)\n"
	"	lmg	%r6,%r7,72(%r15)\n"
	"	br	%r14\n"
	"2:	xc	0(1,%r3),0(%r4)\n"
	"	xc	0(1,%r3),0(%r5)\n"
	"	xc	0(1,%r3),0(%r6)\n"
	"	xc	0(1,%r3),0(%r7)\n"
	"	.size xor_xc_5, . - xor_xc_5\n"
	"	.type xor_xc_5, @function\n");

EXPORT_SYMBOL(xor_xc_5);
