/*
 * Vector-accelerated GCM GHASH variant for Linux on z Systems
 *
 * Use the z/Architecture Vector Extension Facility to accelerate the
 * computing of GCM GHASH checksums.
 *
 * Copyright IBM Corp. 2015
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <linux/linkage.h>
#include <asm/vx-insn.h>

	.data
	.align 8
.Lgcm_gf_mul_constants:
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x4000000000000000,0x0200000000000000
	.quad	0x0101010101010101,0x0101010101010101
	.quad	0x0505050505050505,0x0505050505050505
	.previous

/*
 * Input    : x and y 128-bit
 * Output   : zh/zl = x * y in GF(2^256)
 * Work regs: tmp
 * Constants: zero, first 16 bytes of .gcm_gf_mul_vx_br_const
 */
	.macro GF_MUL x y zh zl tmp zero
	VPDI	\zh,\y,\y,4		# y0 | y1
	VGFMG	\zh,\x,\zh		# x1*y0+x0*y1
	VPDI	\zl,\zh,\zero,4		# L(x1*y0+x0*y1) | 00
	VPDI	\zh,\zero,\zh,0		# 00 | H(x1*y0+x0*y1)
	VPDI	\tmp,\zero,\x,1		# 00 | x0
	VGFMAG	\zl,\tmp,\y,\zl		# x0*y0+(L(x1*y0+x0*y1) | 00)
	VPDI	\tmp,\x,\zero,0		# x1 | 00
	VGFMAG	\zh,\tmp,\y,\zh		# x1*y1+(00 | H(x1*y0+x0*y1))
	.endm

/*
 * Input    : zh/zl 256-bit
 * Output   : (zh/zl << 1) 256-bit
 * Work regs: tmp
 */
	.macro GF_SLL1 zh zl tmp
	VACCQ	\tmp,\zl,\zl		# create carry
	VAQ	\zl,\zl,\zl		# add low 128 bits
	VACQ	\zh,\zh,\zh,\tmp	# add high 128 bits with carry
	.endm

/*
 * Input    : zl/zl 256-bit, bit reflected
 * Output   : z = zh/zl mod (x^128+x^7+x^2+x^1+1) in GF(2^128)
 *	      bit reflected
 * Work regs: tmp
 * Constants: mul1 mul2 shift1 shift5, bytes 16-79 of .gcm_gf_mul_vx_br_const
 */
	.macro GCM_MOD zh zl r tmp mul shift1 shift5
	# zh/zl = p3 | p2 | p1 | p0
	VREPG	\tmp,\zl,0		# p1 | p1
	VREPG	\r,\zl,1		# p0 | p0
	VGFMAG	\tmp,\r,\mul,\tmp	# ? | p1+(p0<<62)+(p0>>57)
	VPDI	\tmp,\tmp,\r,5		# p1+(p0<<62)+(p0>>57) | p0 = T
	VX	\r,\zh,\tmp		# (p3 | p2)^T
	VSRL	\tmp,\tmp,\shift1	# T>>1
	VX	\r,\r,\tmp		# (p3 | p2)^T^(T>>1)
	VSRL	\tmp,\tmp,\shift1	# T>>2
	VX	\r,\r,\tmp		# (p3 | p2)^T^(T>>1)^(T>>2)
	VSRL	\tmp,\tmp,\shift5	# T>>7
	VX	\r,\r,\tmp		# (p3 | p2)^T^(T>>1)^(T>>2)^(T>>7)
	.endm

/*
 * Input: %r2 pointer to hash-key
 *	  %r3 pointer to the hash-key array with H,H^2,..,H^8 in GCM GF
 */
	.globl ghash_vx_init
ghash_vx_init:
	larl	%r1,.Lgcm_gf_mul_constants
	VLM	%v5,%v8,0,%r1
	VL	%v0,0,,%r2
	VLR	%v1,%v0
	VST	%v1,0,,%r3
	lhi	%r0,7
0:	la	%r3,16(%r3)
	GF_MUL	%v0,%v1,%v2,%v3,%v4,%v5
	GF_SLL1	%v2,%v3,%v4
	GCM_MOD %v2,%v3,%v1,%v4,%v6,%v7,%v8
	VST	%v1,0,,%r3
	brct	%r0,0b
	br	%r14
	.size ghash_vx_init,.-ghash_vx_init

/*
 * Input: %r2 pointer to the string
 *	  %r3 length of the string
 *	  %r4 pointer to hashkey
 *	  %r5 pointer to the hash value
 */
	.globl ghash_vx
ghash_vx:
	larl	%r1,.Lgcm_gf_mul_constants
	VLM	%v28,%v31,0,%r1
	VLM	%v0,%v3,0,%r4
	VL	%v24,0,,%r5
	srlg	%r1,%r3,7
	ltgr	%r1,%r1
	jz	1f
	lghi	%r0,127
	ngr	%r3,%r0
	VLM	%v4,%v7,64,%r4
0:	VLM	%v16,%v23,0,%r2
	la	%r2,128(%r2)
	VX	%v16,%v16,%v24
	GF_MUL	%v7,%v16,%v24,%v25,%v27,%v28
	GF_MUL	%v6,%v17,%v26,%v27,%v16,%v28
	VX	%v16,%v24,%v26
	VX	%v17,%v25,%v27
	GF_MUL	%v5,%v18,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_MUL	%v4,%v19,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_MUL	%v3,%v20,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_MUL	%v2,%v21,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_MUL	%v1,%v22,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_MUL	%v0,%v23,%v24,%v25,%v27,%v28
	VX	%v16,%v16,%v24
	VX	%v17,%v17,%v25
	GF_SLL1	%v16,%v17,%v27
	GCM_MOD	%v16,%v17,%v24,%v27,%v29,%v30,%v31
	brctg	%r1,0b
1:	tmll	%r3,0x0040
	jz	2f
	nill	%r3,0x003f
	VLM	%v16,%v19,0,%r2
	la	%r2,64(%r2)
	VX	%v16,%v16,%v24
	GF_MUL	%v3,%v16,%v20,%v21,%v27,%v28
	GF_MUL	%v2,%v17,%v22,%v23,%v27,%v28
	VX	%v20,%v20,%v22
	VX	%v21,%v21,%v23
	GF_MUL	%v1,%v18,%v22,%v23,%v27,%v28
	VX	%v20,%v20,%v22
	VX	%v21,%v21,%v23
	GF_MUL	%v0,%v19,%v22,%v23,%v27,%v28
	VX	%v20,%v20,%v22
	VX	%v21,%v21,%v23
	GF_SLL1	%v20,%v21,%v27
	GCM_MOD	%v20,%v21,%v24,%v27,%v29,%v30,%v31
2:	tmll	%r3,0x0020
	jz	3f
	nill	%r3,0x001f
	VLM	%v16,%v17,0,%r2
	la	%r2,32(%r2)
	VX	%v16,%v16,%v24
	GF_MUL	%v1,%v16,%v18,%v19,%v27,%v28
	GF_MUL	%v0,%v17,%v20,%v21,%v27,%v28
	VX	%v18,%v18,%v20
	VX	%v19,%v19,%v21
	GF_SLL1	%v18,%v19,%v27
	GCM_MOD	%v18,%v19,%v24,%v27,%v29,%v30,%v31
3:	aghi	%r3,-1
	jm	5f
4:	VLL	%v16,%r3,0,%r2
	la	%r2,16(%r2)
	VX	%v16,%v16,%v24
	GF_MUL	%v0,%v16,%v17,%v18,%v27,%v28
	GF_SLL1	%v17,%v18,%v27
	GCM_MOD %v17,%v18,%v24,%v27,%v29,%v30,%v31
	aghi	%r3,-16
	jnm	4b
5:	VST	%v24,0,,%r5
	br	%r14
	.size ghash_vx,.-ghash_vx
