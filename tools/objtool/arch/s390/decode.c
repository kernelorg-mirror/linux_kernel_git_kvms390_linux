// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#include <stdio.h>
#include <stdlib.h>

#define unlikely(cond) (cond)

#include <asm/arch.h>
#include <asm/insn.h>
#include <warn.h>

static int is_s390_64(struct elf *elf)
{
	if (elf->ehdr.e_machine != EM_S390) {
		WARN("unexpected ELF machine type %d", elf->ehdr.e_machine);
		return -1;
	}
	return elf->ehdr.e_ident[EI_CLASS] == ELFCLASS64;
}

static void arch_clobber_lm(struct insn_ops *op, int r1, int r2)
{
	int i;

	for (i = r1; ; i = (i + 1) & 15) {
		op->clobber |= 1U << i;
		if (i == r2)
			break;
	}
}

int arch_decode_instruction(struct elf *elf, struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, unsigned char *type,
			    struct insn_ops *op)
{
	unsigned char *code;
	unsigned int opv[6];
	void *pinsn;

	if (is_s390_64(elf) == -1)
		return -1;

	code = sec->data->d_buf + offset;
	pinsn = insn_find(code);
	if (!pinsn)
		goto warn_unknown;
	*len = insn_length(code);
	*type = INSN_OTHER;
	memset(op, 0, sizeof(*op));

	/* Decode operand values of this instruction */
	insn_operand_values(pinsn, code, opv);

	switch (code[0]) {
	case 0x00:
		switch (code[1]) {
		case 0x00:	    /* illegal */
			break;
		case 0x02:	    /* brkpt */
			goto warn_forbidden;
		default:
			goto warn_unknown;
		}
		break;
	case 0x01:
		switch (code[1]) {
		case 0x01 ... 0x02: /* pr and upt */
		case 0x0a:	    /* pfpo */
		case 0xff:	    /* trap2 */
			goto warn_forbidden;
		case 0x04:	    /* ptff */
		case 0x07:	    /* sckpf */
		case 0x0b:	    /* tam */
		case 0x0c:	    /* sam24 */
		case 0x0d:	    /* sam31 */
		case 0x0e:	    /* sam64 */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0x04:		    /* spm */
		break;
	case 0x05:		    /* balr */
	case 0x0a:		    /* svc */
	case 0x51:		    /* lae */
	case 0x99:		    /* trace */
	case 0xaf:		    /* mc */
		goto warn_forbidden;
	case 0x06:		    /* bctr */
		/* Jump if branch register != 0 */
		*type = (opv[1] != 0) ? INSN_BRANCH_INDIRECT : INSN_OTHER;
		op->conditional = 1;
		op->src.r1 = opv[1];	/* branch target register */
		break;
	case 0x07:		    /* bcr */
		/* Jump if branch register != 0 and mask != 0 */
		*type = (opv[0] != 0 && opv[1] != 0) ?
			INSN_BRANCH_INDIRECT : INSN_NOP;
		op->conditional = (opv[0] != 15);
		op->src.r1 = opv[1];	/* branch target register */
		break;
	case 0x0b:		    /* bsm */
		/* Jump if branch register != 0 */
		*type = (opv[1] != 0) ? INSN_BRANCH_INDIRECT : INSN_OTHER;
		op->conditional = 0;
		op->clobber |= 1U << opv[0];
		break;
	case 0x0c ... 0x0d:	    /* bassm, basr */
		/* Jump if branch register != 0 */
		*type = (opv[1] != 0) ? INSN_BAS : INSN_OTHER;
		op->dest.r1 = opv[0];
		op->src.r1 = opv[1];
		op->clobber |= 1U << opv[0];
		break;
	case 0x0e ... 0x0f:	    /* mvcl, clcl */
		if ((opv[0] & 1) || (opv[1] & 1))
			goto warn_odd_reg;
		op->clobber |= 3U << opv[0];
		op->clobber |= 3U << opv[1];
		break;
	case 0x10 ... 0x14:	    /* lpr, lnr, ltr, lcr, nr */
	case 0x16 ... 0x18:	    /* or, xr, lr */
	case 0x1a ... 0x1b:	    /* ar, sr */
	case 0x1e ... 0x1f:	    /* alr, slr */
	case 0x43:		    /* ic */
	case 0x48:		    /* lh */
	case 0x4a ... 0x4c:	    /* ah, sh, mh */
	case 0x4f:		    /* cvb */
	case 0x54:		    /* n */
	case 0x56 ... 0x58:	    /* o, x, l */
	case 0x5a ... 0x5b:	    /* a, s */
	case 0x5e ... 0x5f:	    /* al, sl */
	case 0x71:		    /* ms */
	case 0x88 ... 0x8b:	    /* srl, sll, sra, sla */
	case 0xa5:		    /* iihh, iihl, iilh, iill, nihh, nihl,
				     * nilh, nill, oihh, oihl, oilh, oill,
				     * llihh, llihl, llilh, llill */
	case 0xae:		    /* sigp */
	case 0xb1:		    /* lra */
	case 0xba ... 0xbb:	    /* cs, cds */
	case 0xbf:		    /* icm */
		op->clobber |= 1U << opv[0];
		break;
	case 0x1c ... 0x1d:	    /* mr, dr */
	case 0x5c ... 0x5d:	    /* m, d */
	case 0x8c ... 0x8f:	    /* srdl, sldl, srda, slda */
		if (opv[0] & 1)
			goto warn_odd_reg;
		op->clobber |= 3U << opv[0];
		break;
	case 0x15:		    /* clr */
	case 0x19:		    /* cr */
	case 0x20 ... 0x3f:	    /* lpdr, lndr, ltdr lcdr, hdr, ldxr, mxr,
				     * mxdr, ldr, cdr, adr, sdr, mdr, ddr,
				     * awr, swr, lper, lner, lter, lcer, her,
				     * ledr, axr, sxr, ler, cer, aer, ser,
				     * mder, der, aur, sur */
	case 0x40:		    /* sth */
	case 0x42:		    /* stc */
	case 0x49:		    /* ch */
	case 0x4e:		    /* cvd */
	case 0x50:		    /* st */
	case 0x55:		    /* cl */
	case 0x59:		    /* c */
	case 0x60:		    /* std */
	case 0x67 ... 0x6f:	    /* mxd, ld, cd, ad, sd, md, dd, aw, sw */
	case 0x70:		    /* ste */
	case 0x78 ... 0x7f:	    /* le, le, ce, ae, se, mde, de, au, su,
				     * sw */
	case 0x80:		    /* ssm */
	case 0x82:		    /* lpsw */
	case 0x83:		    /* diag */
	case 0x90 ... 0x97:	    /* stm, tm, mvi, ts, ni, cli, oi, xi */
	case 0x9a ... 0x9b:	    /* lam, stam */
	case 0xac ... 0xad:	    /* stnsm, stosm */
	case 0xb6 ... 0xb7:	    /* stctl, lctl */
	case 0xbd ... 0xbe:	    /* clm, stcm */
	case 0xc5:		    /* bprp */
	case 0xc7:		    /* bpp */
	case 0xd1 ... 0xd7:	    /* mvn, mvc, mvz, nc, clc, oc, xc */
	case 0xd9 ... 0xdf:	    /* mvck, mvcp, mvcs, tr, trt, ed, edmk */
	case 0xe1 ... 0xe2:	    /* pku, unpku */
	case 0xe8 ... 0xea:	    /* mvcin, pka, unpka */
	case 0xf0 ... 0xf3:	    /* srp, mvo, pack, unpk */
	case 0xf8 ... 0xfd:	    /* zap, cp, ap, sp, mp, dp */
		break;
	case 0x41:		    /* la */
		op->dest.r1 = opv[0];
		op->src.offset = opv[1];
		if (opv[2] && opv[3]) {
			*type = INSN_REG_ADD2;
			op->src.r2 = opv[2];
			op->src.r1 = opv[3];
		} else if (opv[2]) {
			*type = INSN_REG_ADD1;
			op->src.r1 = opv[2];
		} else if (opv[3]) {
			*type = INSN_REG_ADD1;
			op->src.r1 = opv[3];
		} else {
			*type = INSN_REG_CONST;
		}
		break;
	case 0x44:		    /* ex */
		*type = INSN_EX;
		op->src.offset = opv[1];
		op->src.r2 = opv[2];	/* index register */
		op->src.r1 = opv[3];	/* base register */
		break;
	case 0x45:		    /* bal */
	case 0x4d:		    /* bas */
		*type = INSN_BAS;
		op->clobber |= 1U << opv[0];
		break;
	case 0x46:		    /* bct */
		*type = INSN_BRANCH_INDIRECT;
		op->conditional = 1;
		op->clobber |= 1U << opv[0];
		break;
	case 0x47:		    /* bc */
		*type = (opv[0] != 0) ? INSN_BRANCH_INDIRECT : INSN_NOP;
		op->conditional = (opv[0] != 15);
		op->src.offset = opv[1];
		op->src.r2 = opv[2];	/* index register */
		op->src.r1 = opv[3];	/* base register */
		break;
	case 0x84 ... 0x85:	    /* brxh, brxle */
		*type = INSN_BRANCH_RELATIVE;
		op->conditional = 1;
		op->src.offset = (int) opv[2];
		break;
	case 0x86 ... 0x87:	    /* bxh, bxle */
		*type = INSN_BRANCH_INDIRECT;
		op->conditional = 1;
		break;
	case 0x98:		    /* lm */
		arch_clobber_lm(op, opv[0], opv[1]);
		break;
	case 0xa7:
		switch (code[1] & 0x0f) {
		case 0x0:	    /* tmlh */
		case 0x1:	    /* tmll */
		case 0x2:	    /* tmhh */
		case 0x3:	    /* tmhl */
			break;
		case 0x4:	    /* brc */
			/* Branch with mask 0 is a nop */
			*type = (opv[0] != 0) ?
				INSN_BRANCH_RELATIVE : INSN_NOP;
			op->conditional = (opv[0] != 15);
			op->src.offset = (int) opv[1];
			if (opv[1] == 2) {
				/*
				 * Special case of a branch into itself.
				 * There are several cases where this is done:
				 * 1) BUG() statements, the instruction is
				 *    a dead-end
				 * 2) WARN() statements, after the program
				 *    check handler printed the warning the
				 *    code will continue with the next
				 *    sequential instruction
				 * 3) kernel stack overflow detection, this
				 *    is treated as another fall-through
				 */
				*type = op->conditional ?
					INSN_OTHER : INSN_BUG;
			}
			break;
		case 0x5:	    /* bras */
			*type = INSN_BRAS;
			op->dest.r1 = opv[0];
			op->clobber |= 1U << opv[0];
			op->src.offset = (int) opv[1];
			break;
		case 0x6 ... 0x7:   /* brct, brctg */
			*type = INSN_BRANCH_RELATIVE;
			op->conditional = 1;
			op->clobber |= 1U << opv[0];
			op->src.offset = (int) opv[1];
			break;
		case 0x8:	    /* lhi */
		case 0xa:	    /* ahi */
		case 0xc ... 0xd:   /* mhi, mghi */
			op->clobber |= 1U << opv[0];
			break;
		case 0x9:	    /* lghi */
			*type = INSN_REG_CONST;
			op->clobber |= 1U << opv[0];
			op->dest.r1 = opv[0];
			op->src.offset = (int) opv[1];
			break;
		case 0xb:	    /* aghi */
			*type = INSN_REG_ADD1;
			op->dest.r1 = opv[0];
			op->src.r1 = opv[0];
			op->src.offset = (int) opv[1];
			break;
		case 0xe ... 0xf:   /* chi. cghi */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xa8 ... 0xa9:	    /* mvcle, clcle */
		if ((opv[0] & 1) || (opv[1] & 1))
			goto warn_odd_reg;
		op->clobber |= 3U << opv[0];
		op->clobber |= 3U << opv[1];
		break;
	case 0xaa:
		switch (code[1] & 0x0f) {
		case 0x0:	    /* rinext */
		case 0x1:	    /* rion */
		case 0x2:	    /* tric */
		case 0x3:	    /* rioff */
		case 0x4:	    /* riemit */
			goto warn_forbidden;
		default:
			goto warn_unknown;
		}
		break;
	case 0xb2:
		switch (code[1]) {
		case 0x02:	    /* stidp */
		case 0x04 ... 0x0a: /* sck, stck, sckc, stckc, spt, stpt
				     * spka */
		case 0x0d:	    /* ptlb */
		case 0x10 ... 0x12: /* spx, stpx, stap */
		case 0x14:	    /* sie */
		case 0x19:	    /* sac */
		case 0x20 ... 0x21: /* servc, ipte */
		case 0x25:	    /* ssar */
		case 0x2a ... 0x2c: /* rrbe, sske, tb */
		case 0x2d:	    /* dxr */
		case 0x2e ... 0x2f: /* pgin, pgout */
		case 0x30 ... 0x3c: /* csch, hsch, msch, ssch, stsch, tsch,
				     * tpi, sal, rsch, stcrw, stcps, rchp,
				     * schm */
		case 0x44 ... 0x45: /* sqdr, sqer */
		case 0x46:	    /* stura */
		case 0x4d ... 0x4e: /* cpya, sar */
		case 0x50:	    /* csp */
		case 0x54:	    /* mvpg */
		case 0x74:	    /* siga */
		case 0x76:	    /* xsch */
		case 0x78 ... 0x79: /* stcke, sacf */
		case 0x7c:	    /* stckf */
		case 0x80:	    /* lpp */
		case 0x84 ... 0x85: /* lcctl, lpctl */
		case 0x86 ... 0x87: /* qsi, lsctl */
		case 0x8e:	    /* qctri */
		case 0x99:	    /* srnm */
		case 0x9c ... 0x9d: /* stfpc, lfpc */
		case 0xb1:	    /* stfl */
		case 0xb2:	    /* lpswe */
		case 0xb8 ... 0xb9: /* srnmb, srnmt */
		case 0xbd:	    /* lfas */
		case 0xe0 ... 0xe1: /* scctr, spctr */
		case 0xe8:	    /* ppa */
		case 0xfa:	    /* niai */
			break;
		case 0x0b:	    /* ipk */
			op->dest.r1 = op->dest.r2 = 2;
			break;
		case 0x18:	    /* pc */
		case 0x28:	    /* pt */
		case 0x40:	    /* bakr */
		case 0x47 ... 0x4a: /* msta, palb, ereg, esta */
		case 0x4c:	    /* tar */
		case 0x58 ... 0x5a: /* bsg, bsa */
		case 0x77:	    /* rp */
		case 0xec:	    /* etnd */
		case 0xf8:	    /* tend */
		case 0xfc:	    /* tabort */
		case 0xff:	    /* trap4 */
			goto warn_forbidden;
		case 0x1a:	    /* cfc */
			op->clobber |= 0x0a;
			break;
		case 0x22 ... 0x24: /* ipm, ivsk, iac */
		case 0x26 ... 0x27: /* epar, esar */
		case 0x29:	    /* iske */
		case 0x4b:	    /* lura */
		case 0x4f:	    /* ear */
		case 0x52:	    /* msr */
		case 0x5f:	    /* chsc */
		case 0x7d: /* stsi */
		case 0xe4 ... 0xe5: /* ecctr, epctr */
		case 0xed:	    /* ecpga */
			op->clobber |= 1U << opv[0];
			break;
		case 0x41:	    /* cksm */
			if (opv[1] & 1)
				goto warn_odd_reg;
			op->clobber |= 1U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0x55:	    /* mvst */
		case 0x5d:	    /* clst */
		case 0x5e:	    /* srst */
		case 0xf0:	    /* iucv */
			op->clobber |= 1U << opv[0];
			op->clobber |= 1U << opv[1];
			break;
		case 0x56:	    /* sthyi */
			// FIXME: sthyi output registers ?
			break;
		case 0x57:	    /* cuse */
		case 0xa6:	    /* cu21 */
		case 0xa7:	    /* cu12 */
			if ((opv[0] & 1) || (opv[1] & 1))
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0x63:	    /* cmpsc */
			op->clobber |= 3U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0xa5:	    /* tre */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			break;
			if ((opv[0] & 1) || (opv[1] & 1))
				goto warn_odd_reg;
		case 0xad:	    /* NQAP */
			op->clobber |= 3U;
			op->clobber |= 3U << opv[1];
			break;
		case 0xae:	    /* DQAP */
			op->clobber |= 3U;
			op->clobber |= 3U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0xaf:	    /* PQAP */
			op->clobber |= 6U;
			break;
		case 0xb0:	    /* stfle */
			op->clobber |= 1U;
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xb3:
		switch (code[1]) {
		case 0x00 ... 0x1f: /* lpebr, lnebr, ltebr, lcebr, ldebr,
				     * lxdbr, lxebr, mxdbr, kebr, cebr, aebr,
				     * sebr, mdebr, debr, maebr, msebr, lpdbr,
				     * lndbr, ltdbr, lcdbr, sqebr, sqdbr,
				     * sqxbr, meebr, kdbr, cdbr, adbr, sdbr,
				     * mdbr, ddbr, madbr, msdbr */
		case 0x24 ... 0x26: /* lder, lxdr, lxer */
		case 0x2e ... 0x2f: /* maer, mser */
		case 0x36 ... 0x4d: /* sqxr, meer, maylr, mylr, mayr, myr,
				     * mayhr, myhr, madr, msdr, lpxbr, lnxbr,
				     * ltxbr, lcxbr, ledbra, ldxbra, lexbra,
				     * fixbra, kxbr, cxbr, axbr, sxbr, mxbr,
				     * dxbr */
		case 0x50 ... 0x51: /* tbedr, tbdr */
		case 0x53:	    /* diebr */
		case 0x57 ... 0x59: /* fiebra, thder, thdr */
		case 0x5b:	    /* didbr */
		case 0x5f ... 0x63: /* fidbra, lpxr, lnxr, ltxr, lcxr */
		case 0x65 ... 0x67: /* lxr, lexr, fixr */
		case 0x69:	    /* cxr */
		case 0x70 ... 0x77: /* lpdfr, lndfr, cpsdr, lcdfr, lzer,
				     * lzdr, lzxr, fier */
		case 0x7f:	    /* fidr */
		case 0x84 ... 0x85: /* sfpc, sfasr */
		case 0x90 ... 0x92: /* celfbr, cdlfbr, cxlfbr */
		case 0x94 ... 0x96: /* cefbra, cdfbra, cxfbra */
		case 0xa0 ... 0xa2: /* celgbr, cdlgbr, cxlgbr */
		case 0xa4 ... 0xa6: /* cegbra, cdgbra, cxgbra */
		case 0xb4 ... 0xb6: /* cefr, cdfr, cxfr */
		case 0xc1:	    /* ldgr */
		case 0xc4 ... 0xc6: /* cegr, cdgr, cxgr */
		case 0xcd:	    /* lgdr */
		case 0xd0 ... 0xe0: /* mdtra, ddtra, adtra, sdtra, ldetr,
				     * ledtr, ltdtr, fidtr, mxtra, dxtra,
				     * axtra, sxtra, lxdtr, ldxtr, ltxtr,
				     * fixtr, kdtr */
		case 0xe4:	    /* cdtr */
		case 0xe8:	    /* kxtr */
		case 0xec:	    /* cxtr */
		case 0xf1 ... 0xf7: /* cdgtra, cdutr, cdstr, cedtr, qadtr,
				     * iedtr, rrdtr */
		case 0xf9 ... 0xff: /* cxgtra, cxutr, cxstr, cextr, qaxtr,
				     * iextr, rrxtr */
			break;

		case 0x8c:	    /* efpc */
		case 0x98 ... 0x9a: /* cfebra, cfdbra, cfxbra */
		case 0x9c ... 0x9e: /* clfebr, clfdbr, clfxbr */
		case 0xa8 ... 0xaa: /* cgebra, cgdbra, cgxbra */
		case 0xac ... 0xae: /* clgebr, clgdbr, clgxbr */
		case 0xb8 ... 0xba: /* cfer, cfdr, cfxr */
		case 0xc8 ... 0xca: /* cger, cgdr, cgxr */
		case 0xe1 ... 0xe3: /* cgdtra, cudtr, csdtr */
		case 0xe5:	    /* eedtr */
		case 0xe7:	    /* esdtr */
		case 0xe9 ... 0xeb: /* cgxtra, cuxtr, csxtr */
		case 0xed:	    /* eextr */
		case 0xef:	    /* esxtr */
			op->clobber |= 1U << opv[0];
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xb9:
		switch (code[1]) {
		case 0x20 ... 0x21: /* cgr, clgr */
		case 0x25:	    /* sturg */
		case 0x28:	    /* pckmo */
		case 0x30:	    /* cgfr */
		case 0x31:	    /* clgfr */
		case 0x51 ... 0x53: /* cdftr, cdlgtr, cdlftr */
		case 0x59 ... 0x5b: /* cxftr, cxlgtr, cxlftr */
		case 0x60 ... 0x61: /* cgrt, clgrt */
		case 0x72 ... 0x73: /* crt, clrt */
		case 0x8e:	    /* idte */
		case 0xa2:	    /* ptf */
		case 0xa4:	    /* uvc */
		case 0xcd:	    /* chhr */
		case 0xcf:	    /* clhhr */
		case 0xd5:	    /* pciwb */
		case 0xdd:	    /* chlr */
		case 0xdf:	    /* clhlr */
			break;
		case 0x00 ... 0x01: /* lpgr, lngr */
		case 0x03:	    /* lcgr */
		case 0x05 ... 0x07: /* lurag, lgbr, lghr */
		case 0x0c:	    /* msgr */
		case 0x1c:	    /* msgfr */
		case 0x0f ... 0x17: /* lrvgr, lpgfr, lngfr, ltgfr, lcgfr,
				     * lgfr, llgfr, llgtr */
		case 0x1f:	    /* lrvr */
		case 0x26 ... 0x27: /* lbr, lhr */
		case 0x41 ... 0x43: /* cfdtr, clgdtr, clfdtr */
		case 0x46:	    /* bctgr */
		case 0x49 ... 0x4b: /* cfxtr, clgxtr, clfxtr */
		case 0x80 ... 0x82: /* ngr, ogr, xgr */
		case 0x84 ... 0x85: /* llgcr, llghr */
		case 0x88 ... 0x89: /* alcgr, slbgr */
		case 0x94 ... 0x95: /* llcr, llhr */
		case 0x98 ... 0x99: /* alcr, slbr */
		case 0xa0 ... 0xa1: /* clp, tpei */
		case 0xaa:	    /* lptea */
		case 0xab:	    /* essa */
		case 0xac:	    /* irbm */
		case 0xae:	    /* rrbm */
		case 0xd8 ... 0xdb: /* ahhlr, shhlr, alhhlr, slhhlr */
		case 0xe0 ... 0xe2: /* locfhr, popcnt, locgr */
		case 0xe4:	    /* ngrk */
		case 0xe6 ... 0xeb: /* ogrk, xgrk, agrk, sgrk, algrk, slgrk */
		case 0xec ... 0xed: /* mgrk, msgrkc */
		case 0xf2:	    /* locr */
		case 0xf4:	    /* nrk */
		case 0xf6 ... 0xfb: /* ork, xrk, ark, srk, alrk, slrk */
		case 0xfd:	    /* msrkc */
			op->clobber |= 1U << opv[0];
			break;
		case 0x9c:	    /* eqbs */
		case 0xaf:	    /* pfmf */
		case 0xbe:	    /* srstu */
		case 0xc8 ... 0xcb: /* ahhhr, shhhr, alhhhr, slhhhr */
			op->clobber |= 1U << opv[1];
			break;
		case 0x8d:	    /* epsw */
			op->clobber |= 1U << opv[0];
			op->clobber |= 1U << opv[1];
			break;
		case 0x0d:	    /* dsgr */
		case 0x1d:	    /* dsgfr */
		case 0x83:	    /* flogr */
		case 0x86 ... 0x87: /* mlgr, dlgr */
		case 0x96 ... 0x97: /* mlr, dlr */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			break;
		case 0x1e:	    /* kmac */
			if (opv[1] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[1];
			break;
		case 0x8a:	    /* cspg */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 1U << opv[0];
			op->clobber |= 1U << opv[1];
			break;
		case 0x8f:	    /* crdte */
			if ((opv[0] & 1) || (opv[2] & 1))
				goto warn_odd_reg;
			break;
		case 0x90 ... 0x93: /* trtt, trto, trot, troo */
		case 0xbd:	    /* trtre */
		case 0xbf:	    /* trte */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			op->clobber |= 1U << opv[1];
			break;
		case 0xb0 ... 0xb3: /* cu14, cu24, cu41, cu42 */
			if ((opv[0] & 1) || (opv[1] & 1))
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0xd0:	    /* pcistg */
		case 0xd4:	    /* pcistgi */
			if (opv[1] & 1)
				goto warn_odd_reg;
			op->clobber |= 1U << opv[1];
			break;
		case 0xd2:	    /* pcilg */
		case 0xd6:	    /* pcilgi */
			if (opv[1] & 1)
				goto warn_odd_reg;
			op->clobber |= 1U << opv[0];
			op->clobber |= 1U << opv[1];
			break;
		case 0xd3:	    /* rpcit */
			if (opv[1] & 1)
				goto warn_odd_reg;
			op->clobber |= 1U << opv[0];
			break;
		case 0x0e:	    /* eregg */
		case 0x9a ... 0x9b: /* epair, esair */
		case 0x9d ... 0x9f: /* esea, pti, ssair */
			goto warn_forbidden;
		case 0x29:	    /* kma */
		case 0x2a:	    /* kmf */
		case 0x2b:	    /* kmo */
		case 0x2c:	    /* pcc */
		case 0x2d:	    /* kmctr */
		case 0x2e:	    /* km */
		case 0x2f:	    /* kmc */
		case 0x38:	    /* sortl */
		case 0x39:	    /* dflcc */
		case 0x3a:	    /* kdsa */
		case 0x3c:	    /* ppno */
		case 0x3e:	    /* kimd */
		case 0x3f:	    /* klmd */
			// FIXME: urgs, crypto intruction output registers
			break;

		/* insn state relevant b9xx instructions follow .. */
		case 0x02:	    /* ltgr */
		case 0x04:	    /* lgr */
			*type = INSN_REG_ADD1;
			op->dest.r1 = opv[0];
			op->src.r1 = opv[1];
			op->clobber |= 1U << opv[0];
			break;
		case 0x08:	    /* agr */
		case 0x0a:	    /* algr */
		case 0x18:	    /* agfr */
		case 0x1a:	    /* algfr */
			*type = INSN_REG_ADD2;
			op->dest.r1 = opv[0];
			op->src.r1 = opv[0];
			op->src.r2 = opv[1];
			op->clobber |= 1U << opv[0];
			break;
		case 0x09:	    /* sgr */
		case 0x0b:	    /* slgr */
		case 0x19:	    /* sgfr */
		case 0x1b:	    /* slgfr */
			*type = INSN_REG_SUB2;
			op->dest.r1 = opv[0];
			op->src.r1 = opv[0];
			op->src.r2 = opv[1];
			op->clobber |= 1U << opv[0];
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xc0:
		switch (code[1] & 0x0f) {
		case 0x0:	    /* larl */
			*type = INSN_REG_ADDR;
			op->dest.r1 = opv[0];
			op->src.offset = opv[1];
			break;
		case 0x1:	    /* lgfi */
			*type = INSN_REG_CONST;
			op->dest.r1 = opv[0];
			op->src.offset = opv[1];
			break;
		case 0x4:	    /* brcl */
			*type = (opv[0] != 0) ?
				INSN_BRANCH_RELATIVE : INSN_NOP;
			op->conditional = (opv[0] != 15);
			op->src.offset = (int) opv[1];
			break;
		case 0x5:	    /* brasl */
			*type = INSN_BRAS;
			op->dest.r1 = opv[0];
			op->src.offset = (int) opv[1];
			op->clobber |= 1U << opv[0];
			break;
		case 0x6 ... 0xf:   /* xihf, xilf, iihf, iilf, nihf, nilf
				     * oihf, oilf, llihf, llilf */
			op->clobber |= 1U << opv[0];
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xc2:
		switch (code[1] & 0x0f) {
		case 0x0 ... 0x1:   /* msgfi, msfi */
		case 0x4 ... 0x5:   /* slgfi, slfi */
		case 0x8 ... 0xb:   /* agfi, afi, algfi, alfi */
			op->clobber |= 1U << opv[0];
			break;
		case 0xc ... 0xf:   /* cgfi, cfi, clgfi, clfi */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xc4:
		switch (code[1] & 0x0f) {
		case 0x2:	    /* llhrl */
		case 0x4 ... 0x6:   /* lghrl, lhrl, llghrl */
		case 0x8:	    /* lgrl */
		case 0xc ... 0xe:   /* lgfrl, lrl, llgfrl */
			op->clobber |= 1U << opv[0];
			break;
		case 0x7:	    /* sthrl */
		case 0xb:	    /* stgrl */
		case 0xf:	    /* strl */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xc6:
		switch (code[1] & 0x0f) {
		case 0x0:	    /* exrl */
			*type = INSN_EXRL;
			op->src.offset = (int) opv[1];
			break;
		case 0x2:	    /* pfdrl */
		case 0x4 ... 0x8:   /* cghrl, clghrl, clhrl, cgrl */
		case 0xa:	    /* clgrl */
		case 0xc ... 0xf:   /* cgfrl, crl, clgfrl, clrl */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xc8:
		switch (code[1] & 0x0f) {
		case 0x0:	    /* mvcos */
			break;
		case 0x1:	    /* ectg */
			op->clobber |= 3U;
			op->clobber |= 1U << opv[4];
			break;
		case 0x2:	    /* csst */
			op->clobber |= 1U << opv[4];
			break;
		case 0x4 ... 0x5:   /* lpd, lpdg */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xcc:
		switch (code[1] & 0x0f) {
		case 0x6:	    /* brcth */
			*type = INSN_BRANCH_RELATIVE;
			op->conditional = 1;
			op->src.offset = (int) opv[1];
			break;
		case 0x8:	    /* aih */
		case 0xa ... 0xb:   /* alsih, alsihn */
			op->src.offset = (int) opv[0];
			break;
		case 0xd:	    /* cih */
		case 0xf:	    /* clih */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xd0:		    /* trtr */
		op->clobber |= 6U;
		break;
	case 0xe3:
		switch (code[5]) {
		case 0x20 ... 0x21: /* cg, clg */
		case 0x26:	    /* cvdy */
		case 0x2e ... 0x2f: /* cvdg, strvg */
		case 0x30 ... 0x31: /* cgf, clgf */
		case 0x34:	    /* cgh */
		case 0x36:	    /* pfd */
		case 0x3e ... 0x3f: /* strv, strvh */
		case 0x49:	    /* stgsc */
		case 0x4d:	    /* lgsc */
		case 0x50:	    /* sty */
		case 0x55:	    /* cly */
		case 0x59:	    /* cy */
		case 0x70:	    /* sthy */
		case 0x72:	    /* stcy */
		case 0x79:	    /* chy */
		case 0x85:	    /* lgat */
		case 0xc3:	    /* stch */
		case 0xc7:	    /* sthh */
		case 0xcb:	    /* stfh */
		case 0xcd:	    /* chf */
		case 0xcf:	    /* clhf */
			break;
		case 0x03:	    /* lrag */
		case 0x06:	    /* cvby */
		case 0x09 ... 0x0f: /* sg, alg, slg, msg, dsg, cvbg,
				     * lrvg */
		case 0x12 ... 0x17: /* lt, lray, lgf, lgh, llgf, llgt */
		case 0x18 ... 0x1f: /* agf, sgf, algf, slgf, msgf, dsgf,
				    * lrv, lrvh */
		case 0x2a:	    /* lzrg */
		case 0x32:	    /* ltgf */
		case 0x38 ... 0x3c: /* agh, sgh, llzrgf, lzrf, mgh */
		case 0x51:	    /* msy */
		case 0x53 ... 0x54: /* msc, ny */
		case 0x56 ... 0x58: /* oy, xy, ly */
		case 0x5a ... 0x5b: /* ay, sy */
		case 0x5e ... 0x5f: /* aly, sly */
		case 0x73:	    /* icy */
		case 0x76 ... 0x77: /* lb, lbg */
		case 0x78:	    /* lhy */
		case 0x7a ... 0x7c: /* ahy, shy, mhy */
		case 0x80 ... 0x83: /* ng, og, xg, msgc */
		case 0x88 ... 0x89: /* alcg */
		case 0x90 ... 0x95: /* llgc, llgh, llc, llh */
		case 0x98 ... 0x99: /* alc, slb */
		case 0x9c ... 0x9d: /* llgtat, llgfat */
		case 0x9f:	    /* lat */
		case 0xc0:	    /* lbh */
		case 0xc2:	    /* llch */
		case 0xc4:	    /* lhh */
		case 0xc6:	    /* llhh */
		case 0xc8:	    /* lfhat */
		case 0xca:	    /* lfh */
		case 0xd0:	    /* mpcifc */
		case 0xd4:	    /* stpcifc */
			op->clobber |= 1U << opv[0];
			break;
		case 0x5c:	    /* mfy */
		case 0x84:	    /* mg */
		case 0x86 ... 0x87: /* mlg, dlg */
		case 0x8f:	    /* lpq */
		case 0x96 ... 0x97: /* ml, dl */
			if (opv[0] & 1)
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			break;
		case 0x8e:	    /* stpq */
			if (opv[0] & 1)
				goto warn_odd_reg;
			break;
		case 0x25:	    /* ntstg */
		case 0x48:	    /* llgfsg */
		case 0x4c:	    /* lgg */
		case 0x75:	    /* laey */
			goto warn_forbidden;

		/* insn state relevant e3xx instructions follow .. */
		case 0x02:	    /* ltg */
		case 0x04:	    /* lg */
			*type = INSN_MEM_LOAD;
			op->dest.r1 = opv[0];
			op->dest.r2 = opv[0];
			op->src.offset = opv[1];
			op->src.r2 = opv[2];	/* index register */
			op->src.r1 = opv[3];	/* base register */
			op->clobber |= 1U << opv[0];
			break;
		case 0x08:	    /* ag */
			*type = INSN_MEM_ADD;
			op->dest.r1 = opv[0];
			op->dest.r2 = opv[0];
			op->src.offset = opv[1];
			op->src.r2 = opv[2];	/* index register */
			op->src.r1 = opv[3];	/* base register */
			op->clobber |= 1U << opv[0];
			break;
		case 0x24:	    /* stg */
			*type = INSN_MEM_STORE;
			op->src.r1 = opv[0];
			op->src.r2 = opv[0];
			op->src.offset = 0;
			op->dest.offset = opv[1];
			op->dest.r2 = opv[2];	/* index register */
			op->dest.r1 = opv[3];	/* base register */
			break;
		case 0x46:	    /* bctg */
			*type = INSN_BRANCH_INDIRECT;
			op->conditional = 1;
			op->clobber |= 1U << opv[0];
			break;
		case 0x47:	    /* bic */
			*type = INSN_BAS;
			break;
		case 0x71:	    /* lay */
			op->dest.r1 = opv[0];
			op->src.offset = opv[1];
			if (opv[2] && opv[3]) {
				*type = INSN_REG_ADD2;
				op->src.r2 = opv[2];
				op->src.r1 = opv[3];
			} else if (opv[2]) {
				*type = INSN_REG_ADD1;
				op->src.r1 = opv[2];
			} else if (opv[3]) {
				*type = INSN_REG_ADD1;
				op->src.r1 = opv[3];
			} else {
				*type = INSN_REG_CONST;
			}
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xe5:
		switch (code[1]) {
		case 0x00:	    /* lasp */
		case 0x60:	    /* tbegin */
		case 0x61:	    /* tbeginc */
			goto warn_forbidden;
		case 0x01:	    /* tprot */
		case 0x02:	    /* strag */
		case 0x0e ... 0x0f: /* mvcsk, mvcdk */
		case 0x44:	    /* mvhhi */
		case 0x48:	    /* mvghi */
		case 0x4c:	    /* mvhi */
		case 0x54:	    /* chhsi */
		case 0x55:	    /* clhhsi */
		case 0x58:	    /* cghsi */
		case 0x59:	    /* clghsi */
		case 0x5c:	    /* chsi */
		case 0x5d:	    /* clfhsi */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xe6:
		switch (code[5]) {
		case 0x34:	    /* vpkz */
		case 0x35:	    /* vlrl */
		case 0x37:	    /* vlrlr */
		case 0x3c:	    /* vupkz */
		case 0x3d:	    /* vstrl */
		case 0x3f:	    /* VSTRLR */
		case 0x49:	    /* vlip */
		case 0x50:	    /* vcvb */
		case 0x52:	    /* vcvbg */
		case 0x58:	    /* vcvd */
		case 0x59:	    /* vsrp */
		case 0x5a:	    /* vcvdg */
		case 0x5b:	    /* vpsop */
		case 0x5f:	    /* vtp */
		case 0x71:	    /* vap */
		case 0x73:	    /* vsp */
		case 0x77:	    /* vcp */
		case 0x78:	    /* vmp */
		case 0x79:	    /* vmsp */
		case 0x7a:	    /* vdp */
		case 0x7b:	    /* vrp */
		case 0x7e:	    /* vsdp */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xe7:
		switch (code[5]) {
		case 0x00 ... 0x0b: /* vleb, vleh, vleg, vlef, vllez, vlrep,
				     * vl, vlbb, vsteb, vsteh, vsteg, vstef */
		case 0x0e:	    /* vst */
		case 0x12 ... 0x13: /* vgeg, vgef */
		case 0x1a ... 0x1b: /* vsceg, vscef */
		case 0x21 ... 0x22: /* vlgv, vlvg */
		case 0x30:	    /* vesl */
		case 0x33:	    /* verll */
		case 0x36 ... 0x38: /* vlm, vll, vesrl */
		case 0x3a:	    /* vesra */
		case 0x3e ... 0x3f: /* vstm, vstl */
		case 0x40 ... 0x46: /* vleib, vleih, vleig, vleif, vgbm,
				     * vrepi, vgm */
		case 0x4a:	    /* vftci */
		case 0x4d:	    /* vrep */
		case 0x50:	    /* vpopct */
		case 0x52 ... 0x53: /* vctz, vclz */
		case 0x56:	    /* vlr */
		case 0x5c:	    /* vistr */
		case 0x5f:	    /* vseg */
		case 0x60 ... 0x62: /* vmrl, vmrh, vlvgp */
		case 0x64 ... 0x70: /* vsum, vsumg, vcksm, vsumq, vn, vnc, vo,
				    * vno, vnx, vx, vnn, voc, veslv */
		case 0x72 ... 0x75: /* verim, verllv, vsl, vslb */
		case 0x77 ... 0x78: /* vsldb, vesrlv */
		case 0x7a:	    /* vesrav */
		case 0x7c ... 0x85: /* vsrl, vsrlb, vsra, vsrab, vfee, vfene,
				    * vfae, vpdi, vbperm */
		case 0x8a:	    /* vstrc */
		case 0x8c ... 0x8f: /* vperm, vsel, vfms, vfma */
		case 0x94 ... 0x95: /* vpk, vpkls */
		case 0x97:	    /* vpks */
		case 0x9e ... 0x9f: /* vfnms, vfnma */
		case 0xa1 ... 0xa7: /* vmlh, vml, vmh, vmle, vmlo, vme, vmo */
		case 0xa9 ... 0xaf: /* vmalh, vmal, vmah, vmale, vmalo,
				     * vmae, vmao */
		case 0xb4:	    /* vgfm */
		case 0xb8 ... 0xb9: /* vmsl, vaccc */
		case 0xbb ... 0xbd: /* vac, vgfma, vsbcbi */
		case 0xbf:	    /* vsbi */
		case 0xc0 ... 0xc5: /* vclgd, vcdlg, vcgd, vcdg, vlde, vled */
		case 0xc7:	    /* vfi */
		case 0xca ... 0xcc: /* wfk, wfc, vfpso */
		case 0xce:	    /* vfsq */
		case 0xd4 ... 0xd9: /* vupll, vuplh, vupl, vuph, vtm, vecl */
		case 0xdb:	    /* vec */
		case 0xde ... 0xdf: /* vlc, vlp */
		case 0xe2 ... 0xe3: /* vfs, vfa */
		case 0xe5:	    /* vfd */
		case 0xe7 ... 0xe8: /* vfm, vfce */
		case 0xea ... 0xeb: /* vfche, vfch */
		case 0xee ... 0xef: /* vfmin, vfmax */
		case 0xf0 ... 0xf3: /* vavgl, vacc, vavg, va */
		case 0xf5:	    /* vscbi */
		case 0xf7 ... 0xf9: /* vs, vceq, vchl, vch */
		case 0xfb ... 0xff: /* vch, vmnl, vmxl, vmn, vmx */
			break;
		case 0x27:	    /* lcbb */
			op->clobber = 1U << opv[0];
			break;
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xeb:
		switch (code[5]) {
		case 0x17:	    /* stcctm */
		case 0x20 ... 0x23: /* clmh, clmy, clt */
		case 0x25 ... 0x26: /* stctg, stmh */
		case 0x2b ... 0x2d: /* clgt, stcmh, stcmy */
		case 0x2f:	    /* lctlg */
		case 0x51 ... 0x52: /* tmy, mviy */
		case 0x54 ... 0x57: /* niy, cliy, oiy, xiy */
		case 0x60 ... 0x62: /* lric, stric, mric */
		case 0x6a:	    /* asi */
		case 0x6e:	    /* alsi */
		case 0x7a:	    /* agsi */
		case 0x7e:	    /* algsi */
		case 0x8a:	    /* sqbs */
		case 0x90:	    /* stmy */
		case 0x9a ... 0x9b: /* lamy, stamy */
		case 0xc0:	    /* tp */
		case 0xd1:	    /* sic */
		case 0xe1:	    /* stocfh */
		case 0xe3:	    /* stocg */
		case 0xf3:	    /* stoc */
			break;
		case 0x0a ... 0x0d: /* srag, slag, srlg, sllg */
		case 0x14:	    /* csy */
		case 0x1c ... 0x1d: /* rllg, rll */
		case 0x30 ... 0x31: /* csg, cdsy */
		case 0x3e:	    /* cdsg */
		case 0x4c:	    /* ecag */
		case 0x80 ... 0x81: /* icmh, icmy */
		case 0xd0:	    /* pcistb */
		case 0xd4:	    /* pcistbi */
		case 0xdc ... 0xdf: /* srak, slak, srlk, sllk */
		case 0xe0:	    /* locfh */
		case 0xe2:	    /* locg */
		case 0xe4:	    /* lang */
		case 0xe6:	    /* laog */
		case 0xe7:	    /* laxg */
		case 0xe8:	    /* laag */
		case 0xea:	    /* laalg */
		case 0xf2:	    /* loc */
		case 0xf4:	    /* lan */
		case 0xf6:	    /* lao */
		case 0xf7:	    /* lax */
		case 0xf8:	    /* laa */
		case 0xfa:	    /* laal */
			op->clobber |= 1U << opv[0];
			break;
		case 0x8e ... 0x8f: /* mvclu, clclu */
			if ((opv[0] & 1) || (opv[1] & 1))
				goto warn_odd_reg;
			op->clobber |= 3U << opv[0];
			op->clobber |= 3U << opv[1];
			break;
		case 0x96:	    /* lmh */
		case 0x98:	    /* lmy */
			arch_clobber_lm(op, opv[0], opv[1]);
			break;
		case 0x0f:	    /* tracg */
			goto warn_forbidden;

		/* insn state relevant ebxx instructions follow .. */
		case 0x04:	    /* lmg */
			*type = INSN_MEM_LOAD;
			op->dest.r1 = opv[0];
			op->dest.r2 = opv[1];
			op->src.offset = opv[2];
			op->src.r1 = opv[3];
			op->src.r2 = 0;
			arch_clobber_lm(op, opv[0], opv[1]);
			break;
		case 0x24:	    /* stmg */
			*type = INSN_MEM_STORE;
			op->src.r1 = opv[0];
			op->src.r2 = opv[1];
			op->dest.offset = opv[2];
			op->dest.r1 = opv[3];
			break;
		case 0x44:	    /* bxhg */
		case 0x45:	    /* bxleg */
			*type = INSN_BRANCH_INDIRECT;
			op->conditional = 1;
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xec:
		switch (code[5]) {
		case 0x42:	    /* lochi */
		case 0x46:	    /* locghi */
		case 0x4e:	    /* lochhi */
		case 0x51:	    /* risblg */
		case 0x54 ... 0x57: /* rnsbg, risbg, rosbg, rxsbg */
		case 0x59:	    /* risbgn */
		case 0x5d:	    /* risbhg */
		case 0xd8 ... 0xd9: /* ahik, aghik */
		case 0xda ... 0xdb: /* alhsik, alghsik */
			op->clobber |= 1U << opv[0];
			break;
		case 0x70 ... 0x73: /* cgit */
		case 0xe4 ... 0xe5: /* cgrb, clgrb */
		case 0xf6 ... 0xf7: /* crb, clrb */
		case 0xfc ... 0xff: /* cgib, clgib, cib, clib */
			break;

		/* insn state relevant ebxx instructions follow .. */
		case 0x44 ... 0x45: /* brxhg, brxlg */
			*type = INSN_BRANCH_RELATIVE;
			op->conditional = 1;
			op->src.offset = (int) opv[2];
			break;
		case 0x64 ... 0x65: /* cgrj, clgrj */
		case 0x76 ... 0x77: /* crj, clrj */
		case 0x7c ... 0x7f: /* cgij, clgij, cij, clij */
			*type = INSN_BRANCH_RELATIVE;
			op->conditional = 1;
			op->src.offset = (int) opv[3];
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xed:
		switch (code[5]) {
		case 0x04 ... 0x12: /* ldeb, lxdb, lxeb, mxdb, keb, ceb, aeb,
				     * seb, mdeb, deb, maeb, mseb, tceb,
				     * tcdb, tcxb */
		case 0x14 ... 0x15: /* sqeb, sqdb */
		case 0x17 ... 0x1f: /* meeb, kdb, cdb, adb, sdb, mdb, ddb,
				     * madb, msdb */
		case 0x24 ... 0x26: /* lde, lxd, lxe */
		case 0x2e ... 0x2f: /* mae, mse */
		case 0x34 ... 0x35: /* sqe, sqd */
		case 0x37 ... 0x41: /* mee, mayl, myl, may, my, mayh, myh,
				     * mad, msd, sldt, srdt */
		case 0x48 ... 0x49: /* slxt, srxt */
		case 0x50 ... 0x51: /* tdcet, tdget */
		case 0x54 ... 0x55: /* tdcdt, tdgdt */
		case 0x58 ... 0x59: /* tdcxt, tdgxt */
		case 0x64 ... 0x67: /* ley, ldy, stey, stdy */
		case 0xa8 ... 0xaf: /* czdt, czxt, cdzt, cxzt, cpdt, cpxt,
				     * cdpt, cxpt */
			break;
		default:
			goto warn_unknown;
		}
		break;
	case 0xee:		    /* plo */
		// FIXME: urgs, plo output registers
		break;
	case 0xef:		    /* lmd */
		arch_clobber_lm(op, opv[0], opv[1]);
		break;
	default:
		goto warn_unknown;
	}
	return 0;

warn_unknown:
	WARN_FUNC("can't decode instruction", sec, offset);
	return -1;

warn_forbidden:
	WARN_FUNC("forbidden instruction", sec, offset);
	return -1;

warn_odd_reg:
	WARN_FUNC("invalid odd-even register pair", sec, offset);
	return -1;
}
