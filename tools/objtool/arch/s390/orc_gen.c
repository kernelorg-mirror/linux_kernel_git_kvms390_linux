// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#include <stdlib.h>
#include <string.h>
#include <asm/check.h>

#include <orc.h>
#include <warn.h>

static struct cfi_reg *create_orc_find_cfa(struct cfi_reg *regs)
{
	struct cfi_reg *cfa;
	int i;

	cfa = NULL;
	for (i = CFI_NUM_REGS - 1; i >= 0; i--) {
		if (regs[i].base == REG_PTREGS)
			return regs + i;
		if (regs[i].base == REG_CFA)
			cfa = cfa ? : regs + i;
	}
	return cfa;
}

static struct cfi_reg *create_orc_find_ra(struct cfi_reg *regs)
{
	int i;

	for (i = CFI_NUM_REGS - 1; i >= 0; i--) {
		if (regs[i].base == REG_RA)
			return regs + i;
	}
	return NULL;
}

static bool create_orc_restore(struct instruction *insn, struct cfi_reg *cfa)
{
	struct cfi_reg *regs;
	int i, j, rx, ry;
	int num_regs;
	s16 offset;
	u16 mask;

	/* Search the stack area for saved registers */
	num_regs = insn->state->num_regs;
	regs = insn->state->regs;
	for (i = CFI_NUM_REGS; i < num_regs; i++) {
		ry = regs[i].base;
		if (regs[i].offset == 0 &&
		    ry >= REG_ORIG_R6 && ry <= REG_ORIG_R15)
			break;
	}
	if (i >= num_regs)
		return false;
	offset = 152 - cfa->offset - (i - CFI_NUM_REGS)*8;
	rx = ry;
	mask = 0x8000U >> rx;
	for (j = ry - 1; i < num_regs && j >= REG_ORIG_R6; i++, j--) {
		if (regs[i + 1].base == j && regs[i + 1].offset == 0) {
			rx = j;
			mask |= 0x8000U >> rx;
			offset -= 8;
		}
	}
	/*
	 * Registers in 'mask' can be restored. Now check if these
	 * registers already have their original content. If they do
	 * there is no point in restoring any of them again.
	 */
	for (i = rx; i <= ry; i++)
		if ((mask & (0x8000U >> i)) &&
		    (regs[i].base != i || regs[i].offset != 0))
			break;
	if (i > ry)
		return false;

	insn->orc.type = ORC_TYPE_RESTORE;
	insn->orc.reg0 = cfa - insn->state->regs;
	insn->orc.mask = mask;
	insn->orc.offset = offset;
	return true;
}

int create_orc(struct objtool_file *file)
{
	struct cfi_reg *regs, *cfa, *ra;
	struct instruction *insn;
	char *str;

	for_each_insn(file, insn) {
		if (insn->expoline) {
			/*
			 * Expoline thunks miss the .size statement,
			 * therefore decode_instructions will not have
			 * assigned insn->func. Use the section name to
			 * identify the expoline register.
			 */
			str = strstr(insn->sec->name,
				     "__s390_indirect_jump_r");
			if (str) {
				insn->orc.reg0 = atoi(str + 22);
			} else {
				str = strstr(insn->sec->name,
					     "__s390_indirect_branch_r");
				insn->orc.reg0 = atoi(str + 24);
			}
			insn->orc.type = ORC_TYPE_EXPOLINE;
			continue;
		}

		if (!insn->state || insn->state->skip)
			continue;
		regs = insn->state->regs;

		/* Search for a register that links to the CFA */
		cfa = create_orc_find_cfa(regs);
		if (!cfa) {
			/* Report an error if there is no CFA register */
			WARN_FUNC("no CFA base register found",
				  insn->sec, insn->offset);
			return -1;
		}

		/* Found a register that links to the CFA, handle ptregs */
		if (cfa->base == REG_PTREGS) {
			insn->orc.type = ORC_TYPE_PTREGS;
			insn->orc.reg0 = cfa - insn->state->regs;
			insn->orc.offset = -cfa->offset;
			continue;
		}

		/* Search the stack if there are registers to restore */
		if (create_orc_restore(insn, cfa)) {
			/*
			 * There are registers to restore. After the restore
			 * the return address needs to be in %r14.
			 */
			ra = regs + CFI_R14;
			if ((ra->base != REG_RA || ra->offset != 0) &&
			    !(insn->orc.mask & (0x8000U >> 14))) {
				WARN_FUNC("return address is not available",
					  insn->sec, insn->offset);
				return -1;
			}
		} else {
			/*
			 * No registers need to be restored. Search for the
			 * register that has the return address.
			 */
			ra = create_orc_find_ra(regs);
			if (!ra) {
				WARN_FUNC("return address is not available",
					  insn->sec, insn->offset);
				return -1;
			}
			insn->orc.type = ORC_TYPE_REGISTER;
			insn->orc.reg0 = cfa - insn->state->regs;
			insn->orc.offset = -cfa->offset;
			insn->orc.reg1 = ra - insn->state->regs;
		}
	}

	return 0;
}

static int create_orc_entry(struct section *sec_orc, struct section *sec_rela,
				unsigned int idx, struct section *insn_sec,
				unsigned long insn_off, struct orc_entry *o)
{
	struct orc_entry *orc;
	struct rela *rela;

	if (!insn_sec->sym) {
		WARN("missing symbol for section %s", insn_sec->name);
		return -1;
	}

	/* populate ORC data */
	orc = (struct orc_entry *) sec_orc->data->d_buf + idx;
	memcpy(orc, o, sizeof(*orc));

	/* populate rela for ip */
	rela = malloc(sizeof(*rela));
	if (!rela) {
		perror("malloc");
		return -1;
	}
	memset(rela, 0, sizeof(*rela));

	rela->sym = insn_sec->sym;
	rela->addend = insn_off;
	rela->type = R_390_PC32;
	rela->offset = idx * sizeof(int);

	list_add_tail(&rela->list, &sec_rela->rela_list);
	hash_add(sec_rela->rela_hash, &rela->hash, rela->offset);

	return 0;
}

static char *strdupcat(const char *str1, const char *str2)
{
	size_t len1, len2;
	char *cstr;

	len1 = strlen(str1);
	len2 = strlen(str2);
	cstr = malloc(len1 + len2 + 1);
	if (cstr) {
		memcpy(cstr, str1, len1);
		memcpy(cstr + len1, str2, len2);
		cstr[len1 + len2] = 0;
	}
	return cstr;
}

int create_orc_sections(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec, *sec_group;
	struct section *sec_orc, *sec_ip, *sec_rela;
	struct orc_entry *prev_orc, invalid_orc;
	unsigned int idx, nr_orcs;
	char *str;

	/* populate sections */
	memset(&invalid_orc, 0x00, sizeof(invalid_orc));
rescan:
	for_each_sec(file, sec) {
		if (!sec->text)
			continue;
		str = strdupcat(".orc_unwind", sec->name);
		if (!str) {
			WARN("malloc failed");
			return -1;
		}
		/* check if the orc sections for this section already exist */
		if (find_section_by_name(file->elf, str)) {
			free(str);
			continue;
		}

		/* find the group section if there is one */
		sec_group = NULL;
		if (sec->sh.sh_flags & SHF_GROUP)
			sec_group = find_section_group(file->elf, sec);

		/* counter the number of needed orcs for this section */
		nr_orcs = 0;
		prev_orc = &invalid_orc;
		sec_for_each_insn(file, sec, insn) {
			if (!insn->expoline && !insn->state)
				continue;
			if (memcmp(&insn->orc, prev_orc, sizeof(insn->orc)))
				nr_orcs++;
			prev_orc = &insn->orc;
		}
		if (!nr_orcs) {
			free(str);
			continue;
		}

		/* create .orc_unwind for this section */
		sec_orc = elf_create_section(file->elf, str,
					     sizeof(struct orc_entry),
					     nr_orcs);
		if (!sec_orc)
			return -1;
		free(str);

		/* create .orc_unwind_ip for this section */
		str = strdupcat(".orc_unwind_ip", sec->name);
		if (!str) {
			WARN("malloc failed");
			return -1;
		}
		sec_ip = elf_create_section(file->elf, str,
					    sizeof(int), nr_orcs);
		if (!sec_ip)
			return -1;
		free(str);

		/* create .rela.orc_unwind_ip for this section */
		sec_rela = elf_create_rela_section(file->elf, sec_ip);
		if (!sec_rela)
			return -1;

		if (sec_group) {
			/* add the three new sections to the section group */
			add_to_section_group(file->elf, sec_group, sec_orc);
			add_to_section_group(file->elf, sec_group, sec_ip);
			add_to_section_group(file->elf, sec_group, sec_rela);
		}

		idx = 0;
		prev_orc = &invalid_orc;
		sec_for_each_insn(file, sec, insn) {
			if (!insn->expoline && !insn->state)
				continue;
			if (memcmp(&insn->orc, prev_orc, sizeof(insn->orc))) {
				if (create_orc_entry(sec_orc, sec_rela, idx,
						     insn->sec, insn->offset,
						     &insn->orc))
					return -1;
				idx++;
			}
			prev_orc = &insn->orc;
		}

		if (elf_rebuild_rela_section(sec_rela))
			return -1;

		/* elf_create_section modified file->elf->sections list */
		goto rescan;
	}

	return 0;
}
