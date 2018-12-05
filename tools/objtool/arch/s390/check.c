// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#include <string.h>
#include <stdlib.h>
#include <asm/check.h>
#include <asm/arch.h>

#include <builtin.h>
#include <elfdefs.h>
#include <warn.h>
#include "special.h"

#include <linux/hashtable.h>
#include <linux/kernel.h>

const char *objname;	/* global for WARN/WARN_FUNC */
static int warnings = 0;

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset)
{
	struct instruction *insn;

	hash_for_each_possible(file->insn_hash, insn, hash, offset)
		if (insn->sec == sec && insn->offset == offset)
			return insn;
	return NULL;
}

static struct instruction *next_insn_same_sec(struct objtool_file *file,
					      struct instruction *insn)
{
	struct instruction *next = list_next_entry(insn, list);

	if (!next || &next->list == &file->insn_list || next->sec != insn->sec)
		return NULL;
	return next;
}

static struct instruction *next_insn_same_func(struct objtool_file *file,
					       struct instruction *insn)
{
	struct instruction *next = list_next_entry(insn, list);
	struct symbol *func = insn->func;

	if (!func)
		return NULL;

	if (&next->list != &file->insn_list && next->func == func)
		return next;

	/* Check if we're already in the subfunction: */
	if (func == func->cfunc)
		return NULL;

	/* Move to the subfunction: */
	return find_insn(file, func->cfunc->sec, func->cfunc->offset);
}

#define func_for_each_insn_all(file, func, insn)			\
	for (insn = find_insn(file, func->sec, func->offset);		\
	     insn;							\
	     insn = next_insn_same_func(file, insn))

#define func_for_each_insn(file, func, insn)				\
	for (insn = find_insn(file, func->sec, func->offset);		\
	     insn && &insn->list != &file->insn_list &&			\
		insn->sec == func->sec &&				\
		insn->offset < func->offset + func->len;		\
	     insn = list_next_entry(insn, list))

#define func_for_each_insn_continue_reverse(file, func, insn)		\
	for (insn = list_prev_entry(insn, list);			\
	     &insn->list != &file->insn_list &&				\
		insn->sec == func->sec && insn->offset >= func->offset;	\
	     insn = list_prev_entry(insn, list))

#define sec_for_each_insn_from(file, insn)				\
	for (; insn; insn = next_insn_same_sec(file, insn))

#define sec_for_each_insn_continue(file, insn)				\
	for (insn = next_insn_same_sec(file, insn); insn;		\
	     insn = next_insn_same_sec(file, insn))

/*
 * Insn state helpers
 */
static struct insn_state *alloc_state(void)
{
	struct insn_state *state;
	unsigned long size;
	int i;

	state = malloc(sizeof(*state));
	if (state) {
		/* 16 gprs + 20 8-byte stack slots */
		state->skip = 0;
		state->num_regs = CFI_NUM_REGS + 20;
		size = state->num_regs * sizeof(struct cfi_reg);
		state->regs = malloc(size);
		if (state->regs) {
			for (i = 0; i < state->num_regs; i++) {
				state->regs[i].base = REG_UNDEF;
				state->regs[i].offset = 0;
			}
			return state;
		}
		free(state);
	}
	return NULL;
}

static struct insn_state *copy_state(struct insn_state *old)
{
	struct insn_state *new;
	unsigned long size;

	new = malloc(sizeof(*new));
	if (new) {
		memcpy(new, old, sizeof(*new));
		size = old->num_regs * sizeof(struct cfi_reg);
		new->regs = malloc(size);
		if (new->regs) {
			memcpy(new->regs, old->regs, size);
			return new;
		}
		free(new);
	}
	return NULL;
}

static int extent_state(struct insn_state *state, long offset)
{
	long num_regs, new_size;
	int i;

	num_regs = (CFI_NUM_REGS*8 + 160 - offset) / 8;
	if (state->num_regs < num_regs) {
		new_size = num_regs * sizeof(struct cfi_reg);
		state->regs = realloc(state->regs, new_size);
		if (!state->regs)
			return -1;
		for (i = state->num_regs; i < num_regs; i++) {
			state->regs[i].base = REG_UNDEF;
			state->regs[i].offset = 0;
		}
		state->num_regs = num_regs;
	}
	return 0;
}

static void free_state(struct insn_state *state)
{
	free(state->regs);
	free(state);
}

/*
 * Call the instruction decoder for all the instructions and add
 * them to the global instruction list.
 */
static int decode_instructions(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	unsigned long offset;
	struct instruction *insn;
	int ret;

	for_each_sec(file, sec) {
		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;

		if (strcmp(sec->name, ".altinstr_replacement") &&
		    strcmp(sec->name, ".altinstr_aux") &&
		    strncmp(sec->name, ".discard.", 9))
			sec->text = true;

		for (offset = 0; offset < sec->len; offset += insn->len) {
			insn = malloc(sizeof(*insn));
			if (!insn) {
				WARN("malloc failed");
				return -1;
			}
			memset(insn, 0, sizeof(*insn));
			INIT_LIST_HEAD(&insn->tree);
			INIT_LIST_HEAD(&insn->group_alts);
			insn->sec = sec;
			insn->offset = offset;

			ret = arch_decode_instruction(file->elf, sec, offset,
						      sec->len - offset,
						      &insn->len, &insn->type,
						      &insn->insn_ops);
			if (ret)
				goto err;

			if (!insn->type || insn->type > INSN_LAST) {
				WARN_FUNC("invalid instruction type %d",
					  insn->sec, insn->offset, insn->type);
				ret = -1;
				goto err;
			}
			hash_add(file->insn_hash, &insn->hash, insn->offset);
			list_add_tail(&insn->list, &file->insn_list);
		}

		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC)
				continue;
			if (!find_insn(file, sec, func->offset)) {
				WARN("%s(): can't find starting instruction",
				     func->name);
				return -1;
			}
			func_for_each_insn(file, func, insn)
				if (!insn->func)
					insn->func = func;
		}
	}
	return 0;

err:
	free(insn);
	return ret;
}

/*
 * Mark "j .+2" instructions and manually annotated unreachable / reachable
 * code locations.
 */
static int mark_dead_ends(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	struct rela *rela;

	/* Check for manually annotated dead ends. */
	sec = find_section_by_name(file->elf, ".rela.discard.unreachable");
	if (!sec)
		goto reachable;

	list_for_each_entry(rela, &sec->rela_list, list) {
		if (rela->sym->type != STT_SECTION) {
			WARN("unexpected relocation symbol type in %s",
			     sec->name);
			return -1;
		}
		/* special case of a BUG at the end of a section */
		if (rela->addend >= rela->sym->sec->len)
			continue;
		insn = find_insn(file, rela->sym->sec, rela->addend);
		if (!insn) {
			WARN("can't find unreachable insn at %s+0x%x",
			     rela->sym->sec->name, rela->addend);
			return -1;
		}
		/*
		 * special case of a BUG at the end of a function,
		 * we do *not* want to mark the first instruction of
		 * the next function as unreachable.
		 */
		if (insn->func && insn->offset == insn->func->offset)
			continue;
		insn->dead_end = true;
	}

reachable:
	/* Check for manually annotated reachable instructions. */
	sec = find_section_by_name(file->elf, ".rela.discard.reachable");
	if (!sec)
		return 0;

	list_for_each_entry(rela, &sec->rela_list, list) {
		if (rela->sym->type != STT_SECTION) {
			WARN("unexpected relocation symbol type in %s",
			     sec->name);
			return -1;
		}
		insn = find_insn(file, rela->sym->sec, rela->addend);
		if (!insn) {
			WARN("can't find reachable insn at %s+0x%x",
			     rela->sym->sec->name, rela->addend);
			return -1;
		}
		insn->dead_end = false;
	}
	return 0;
}

/*
 * Check if the function has been manually whitelisted with the
 * STACK_FRAME_NON_STANDARD macro, or if it should be automatically whitelisted
 * due to its use of a context switching instruction.
 */
static bool ignore_func(struct objtool_file *file, struct symbol *func)
{
	struct section *whitelist;
	struct rela *rela;

	/* check for STACK_FRAME_NON_STANDARD annotations */
	whitelist = file->whitelist;
	if (whitelist && whitelist->rela)
		list_for_each_entry(rela, &whitelist->rela->rela_list, list) {
			if (rela->sym->type == STT_SECTION &&
			    rela->sym->sec == func->sec &&
			    rela->addend == func->offset)
				return true;
			if (rela->sym->type == STT_FUNC && rela->sym == func)
				return true;
		}
	return false;
}

/*
 * Warnings shouldn't be reported for ignored functions.
 */
static void mark_ignores(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	struct symbol *func;

	for_each_sec(file, sec) {
		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC)
				continue;
			if (!ignore_func(file, func))
				continue;
			func_for_each_insn_all(file, func, insn)
				insn->ignore = true;
		}
	}
}

/*
 * Decode the expoline branch register from the name of the expoline thunk.
 */
static int find_expoline_register(struct instruction *insn, struct symbol *sym)
{
	int reg, use;
	char *str;

	str = sym->name;
	if (strncmp(sym->name, "__s390_indirect_jump_r", 22) == 0)
		str = sym->name + 22;
	else if (strncmp(sym->name, "__s390_indirect_branch_r", 24) == 0)
		str = sym->name + 24;
	else
		return -1;
	if (sscanf(str, "%iuse_r%i", &use, &reg) == 2)
		return reg;
	if (sscanf(str,"%i", &reg) == 1)
		return reg;
	return -1;
}

static int find_jump_destination(struct objtool_file *file,
				 struct instruction *insn)
{
	struct section *dest_sec;
	struct rela *rela;
	unsigned long dest_off;
	int ereg;

	rela = find_rela_by_dest_range(insn->sec, insn->offset,
				       insn->len);
	if (!rela) {
		dest_sec = insn->sec;
		dest_off = insn->offset + insn->insn_ops.src.offset;
	} else if (rela->sym->type == STT_SECTION) {
		dest_sec = rela->sym->sec;
		dest_off = rela->addend - rela->offset + insn->offset;
	} else if (rela->sym->sec->idx) {
		/*
		 * Relative branches to expoline thunks are really
		 * indirect branches in disguise, mark them as
		 * INSN_BRANCH_EXPOLINE.
		 */
		ereg = find_expoline_register(insn, rela->sym);
		if (ereg > 0) {
			insn->type = INSN_BRANCH_EXPOLINE;
			insn->insn_ops.src.r1 = ereg;
			insn->jump_dest = 0;
			return 0;
		}
		dest_sec = rela->sym->sec;
		dest_off = rela->sym->sym.st_value + rela->addend
			- rela->offset + insn->offset;
	} else {
		/* sibling call */
		insn->jump_dest = 0;
		return 0;
	}

	insn->jump_dest = find_insn(file, dest_sec, dest_off);
	if (!insn->jump_dest) {
		/*
		 * This is a special case where an alt instruction
		 * jumps past the end of the section.  These are
		 * handled later in handle_group_alt().
		 */
		if (!strcmp(insn->sec->name, ".altinstr_replacement"))
			return 0;

		WARN_FUNC("can't find jump dest instruction at %s+0x%lx",
			  insn->sec, insn->offset, dest_sec->name,
			  dest_off);
		return -1;
	}

	/*
	 * For GCC 8+, create parent/child links for any cold
	 * subfunctions.  This is _mostly_ redundant with a similar
	 * initialization in read_symbols().
	 *
	 * If a function has aliases, we want the *first* such function
	 * in the symbol table to be the subfunction's parent. In that
	 * case we overwrite the initialization done in read_symbols().
	 *
	 * However this code can't completely replace the
	 * read_symbols() code because this doesn't detect the case
	 * where the parent function's only reference to a subfunction
	 * is through a switch table.
	 */
	if (insn->func && insn->jump_dest->func &&
	    insn->func != insn->jump_dest->func &&
	    !strstr(insn->func->name, ".cold.") &&
	    strstr(insn->jump_dest->func->name, ".cold.")) {
		insn->func->cfunc = insn->jump_dest->func;
		insn->jump_dest->func->pfunc = insn->func;
	}
	return 0;
}

static int find_abs_destination(struct objtool_file *file,
				struct instruction *insn)
{
	struct insn_ops *op;
	struct cfi_reg *reg;
	unsigned long dest_off;

	op = &insn->insn_ops;
	if (op->src.r2 != 0) {
		WARN_FUNC("abs destinaton with non-zero index register",
			  insn->sec, insn->offset);
		return -1;
	}
	reg = insn->state->regs + op->src.r1;
	if (reg->base != REG_ADDR) {
		WARN_FUNC("abs destination with non-local base register",
			  insn->sec, insn->offset);
		return -1;
	};
	dest_off = reg->offset + op->src.offset;
	insn->jump_dest = find_insn(file, insn->sec, dest_off);
	if (!insn->jump_dest) {
		WARN_FUNC("can't find abs destination",
			  insn->sec, insn->offset);
		return -1;
	}
	return 0;
}

/*
 * Find the destination instructions for all jumps.
 */
static int add_jump_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	int ret;

	for_each_insn(file, insn) {
		if (insn->type != INSN_BRANCH_RELATIVE || insn->ignore)
			continue;

		ret = find_jump_destination(file, insn);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Find the potential read-only data associated with a switch table
 */
static int add_rodata_targets(struct objtool_file *file)
{
	struct instruction *insn;
	struct symbol *func;
	struct rela *rela, *table;
	struct rodata *rodata;
	unsigned long offset;
	unsigned int len;

	for_each_insn(file, insn) {
		if (insn->type != INSN_REG_ADDR)
			continue;
		/* Look for a relocation which references .rodata */
		rela = find_rela_by_dest_range(insn->sec, insn->offset,
					       insn->len);
		if (!rela || rela->sym->type != STT_SECTION ||
		    !rela->sym->sec->rodata)
			continue;
		/*
		 * Calculate the offset and the maximum length of the
		 * read-only data
		 */
		offset = rela->addend - rela->offset + insn->offset;
		len = rela->sym->sec->len - offset;
		/*
		 * Use this new rodata offset to limit the sizes
		 * of rodata objects prior to this one.
		 */
		list_for_each_entry(rodata, &file->rodata_list, list) {
			if (rodata->sec != rela->sym->sec)
				continue;
			if (rodata->offset <= offset &&
			    rodata->offset + rodata->len > offset)
				rodata->len = offset - rodata->offset;
			if (offset <= rodata->offset &&
			    offset + len > rodata->offset)
				len = rodata->offset - offset;
		}
		/*
		 * Check if the .rodata address is associated with a
		 * symbol. gcc jump tables are anonymous data.
		 */
		if (find_symbol_containing(rela->sym->sec, offset))
			continue;
		func = insn->func;
		/*
		 * Check if there is a relocation to a instruction at the
		 * start of the table. If the instruction location is inside
		 * the limits of the function that 'insn' belongs to, then
		 * this could be the load-address for an indirect jump table.
		 */
		table = find_rela_by_dest(rela->sym->sec, offset);
		if (!table || table->sym->sec != func->sec ||
		    table->addend < func->offset ||
		    table->addend >= func->offset + func->len)
			continue;
		/*
		 * Create a new read-only data entry for a potential switch
		 * table
		 */
		rodata = malloc(sizeof(*rodata));
		if (!rodata) {
			WARN("malloc failed");
			return -1;
		}
		rodata->sec = rela->sym->sec;
		rodata->table = table;
		rodata->offset = offset;
		rodata->len = len;
		list_add_tail(&rodata->list, &file->rodata_list);
		/* Link rodata to load-address instruction */
		insn->rodata = rodata;
	}

	return 0;
}

/*
 * Find the destination instructions for all bras/brasl instructions.
 */
static int add_bras_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	unsigned long dest_off;
	struct rela *rela;

	for_each_insn(file, insn) {
		if (insn->type != INSN_BRAS)
			continue;

		rela = find_rela_by_dest_range(insn->sec, insn->offset,
					       insn->len);
		if (!rela) {
			dest_off = insn->offset + insn->insn_ops.src.offset;
			insn->call_dest =
				find_symbol_by_offset_and_type(insn->sec,
							       dest_off,
							       STT_FUNC);
			if (insn->call_dest)
				continue;
			insn->jump_dest = find_insn(file, insn->sec, dest_off);
			if (insn->jump_dest || insn->ignore)
				continue;
			WARN_FUNC("unsupported intra-function call",
				  insn->sec, insn->offset);
			return -1;
		}
		if (rela->sym->type != STT_SECTION) {
			insn->call_dest = rela->sym;
			continue;
		}

		insn->call_dest =
			find_symbol_by_offset_and_type(rela->sym->sec,
				rela->addend - rela->offset + insn->offset,
				STT_FUNC);
		if (insn->call_dest)
			continue;
		WARN_FUNC("can't find call dest symbol at %s+0x%x",
			  insn->sec, insn->offset, rela->sym->sec->name,
			  rela->addend + (int)(insn->offset - rela->offset));
		return -1;
	}
	return 0;
}

/*
 * The .alternatives section requires some extra special care, over and above
 * what other special sections require:
 *
 * 1. Because alternatives are patched in-place, we need to insert a fake jump
 *    instruction at the end so that validate_insn() skips all the original
 *    replaced instructions when validating the new instruction path.
 *
 * 2. An added wrinkle is that the new instruction length might be zero.  In
 *    that case the old instructions are replaced with noops.  We simulate that
 *    by creating a fake jump as the only new instruction.
 *
 * 3. In some cases, the alternative section includes an instruction which
 *    conditionally jumps to the _end_ of the entry.  We have to modify these
 *    jumps' destinations to point back to .text rather than the end of the
 *    entry in .altinstr_replacement.
 */
static int handle_group_alt(struct objtool_file *file,
			    struct special_alt *special_alt,
			    struct instruction *orig_insn,
			    struct instruction **new_insn)
{
	struct instruction *last_orig_insn, *last_new_insn, *insn, *fake_jump;
	unsigned long dest_off, alt_end;

	insn = orig_insn;
	last_orig_insn = NULL;
	alt_end = special_alt->orig_off + special_alt->orig_len;
	sec_for_each_insn_from(file, insn) {
		if (insn->offset >= alt_end)
			break;
		insn->alt_group = true;
		last_orig_insn = insn;
	}

	fake_jump = NULL;
	if (next_insn_same_sec(file, last_orig_insn)) {
		fake_jump = malloc(sizeof(*fake_jump));
		if (!fake_jump) {
			WARN("malloc failed");
			return -1;
		}
		memset(fake_jump, 0, sizeof(*fake_jump));
		INIT_LIST_HEAD(&fake_jump->tree);
		INIT_LIST_HEAD(&fake_jump->group_alts);

		fake_jump->sec = special_alt->new_sec;
		fake_jump->offset = -1;
		fake_jump->type = INSN_BRANCH_RELATIVE;
		fake_jump->insn_ops.conditional = 0;
		fake_jump->jump_dest = list_next_entry(last_orig_insn, list);
		fake_jump->func = orig_insn->func;
	}

	if (!special_alt->new_len) {
		if (!fake_jump) {
			WARN("%s: empty alternative at end of section",
			     special_alt->orig_sec->name);
			return -1;
		}
		*new_insn = fake_jump;
		return 0;
	}

	last_new_insn = NULL;
	insn = *new_insn;
	sec_for_each_insn_from(file, insn) {
		if (insn->offset >= special_alt->new_off + special_alt->new_len)
			break;

		last_new_insn = insn;

		insn->func = orig_insn->func;

		if (insn->type != INSN_BRANCH_RELATIVE)
			continue;

		if (!insn->insn_ops.src.offset)
			continue;

		dest_off = insn->offset + insn->insn_ops.src.offset;
		if (dest_off == special_alt->new_off + special_alt->new_len) {
			if (!fake_jump) {
				WARN("%s: alternative jump to end of section",
				     special_alt->orig_sec->name);
				return -1;
			}
			insn->jump_dest = fake_jump;
		}

		if (!insn->jump_dest) {
			WARN_FUNC("can't find alternative jump destination",
				  insn->sec, insn->offset);
			return -1;
		}
	}

	if (!last_new_insn) {
		WARN_FUNC("can't find last new alternative instruction",
			  special_alt->new_sec, special_alt->new_off);
		return -1;
	}

	if (fake_jump)
		list_add(&fake_jump->list, &last_new_insn->list);

	return 0;
}

/*
 * A jump table entry can either convert a nop to a jump or a jump to a nop.
 * If the original instruction is a jump, make the alt entry an effective nop
 * by just skipping the original instruction.
 */
static int handle_jump_alt(struct objtool_file *file,
			   struct special_alt *special_alt,
			   struct instruction *orig_insn,
			   struct instruction **new_insn)
{
	if (orig_insn->type == INSN_NOP)
		return 0;

	if (orig_insn->type != INSN_BRANCH_RELATIVE) {
		WARN_FUNC("unsupported instruction at jump label",
			  orig_insn->sec, orig_insn->offset);
		return -1;
	}

	*new_insn = list_next_entry(orig_insn, list);
	return 0;
}

/*
 * Read all the special sections which have alternate instructions which can
 * be patched in or redirected to at runtime. The redirection alternative is
 * stored in insn->jump_alt and only a single alternative may exist. The
 * group alternatives multiple instruction replacement sequences may exist,
 * these are store in the insn->group_alts list. Both insn->jump_alt and
 * the entries on insn->group_alts are visited in validate_insn().
 */
static int add_special_section_alts(struct objtool_file *file)
{
	struct special_alt *special_alt, *tmp;
	struct list_head special_alts;
	struct instruction *insn;
	struct alternative *alt;
	int ret;

	ret = special_get_alts(file->elf, &special_alts);
	if (ret)
		return ret;

	list_for_each_entry_safe(special_alt, tmp, &special_alts, list) {

		insn = find_insn(file, special_alt->orig_sec,
				      special_alt->orig_off);
		if (!insn) {
			WARN_FUNC("special: can't find orig instruction",
				  special_alt->orig_sec, special_alt->orig_off);
			return -1;
		}

		alt = malloc(sizeof(*alt));
		if (!alt) {
			WARN("malloc failed");
			return -1;
		}
		INIT_LIST_HEAD(&alt->list);
		alt->insn = NULL;

		if (special_alt->has_new_insn) {
			alt->insn = find_insn(file, special_alt->new_sec,
					      special_alt->new_off);
			if (!alt->insn) {
				WARN_FUNC("special: can't find new instruction",
					  special_alt->new_sec,
					  special_alt->new_off);
				return -1;
			}
		}

		switch (special_alt->type) {
		case SPECIAL_EX_TABLE:
			insn->jump_alt = alt;
			break;
		case SPECIAL_JUMP_LABEL:
			ret = handle_jump_alt(file, special_alt,
					      insn, &alt->insn);
			if (ret)
				return ret;
			insn->jump_alt = alt;
			break;
		case SPECIAL_ALTERNATIVE:
			ret = handle_group_alt(file, special_alt,
					       insn, &alt->insn);
			if (ret)
				return ret;
			list_add_tail(&alt->list, &insn->group_alts);
			break;
		}

		list_del(&special_alt->list);
		free(special_alt);
	}

	return 0;
}

/*
 * Read the __bug_table to find out if a "j .+2" is a BUG or a WARN
 * statement.
 */
static int read_bug_table(struct objtool_file *file)
{
	struct section *sec, *relasec;
	struct rela *rela;
	struct instruction *insn;
	unsigned long offset;
	unsigned short flags;
	int i;

	sec = find_section_by_name(file->elf, "__bug_table");
	if (!sec)
		return 0;

	relasec = sec->rela;
	if (!relasec) {
		WARN("missing .rela__bug_table section");
		return -1;
	}

	if (sec->sh.sh_entsize != sizeof(struct bug_entry) &&
	    sec->sh.sh_entsize != sizeof(struct bug_entry_verbose)) {
		WARN("struct bug_entry size mismatch");
		return -1;
	}

	for (i = 0; i < sec->len / sec->sh.sh_entsize; i++) {
		if (sec->sh.sh_entsize == sizeof(struct bug_entry)) {
			struct bug_entry *bug;

			offset = sizeof(struct bug_entry) * i;
			bug = (struct bug_entry *)(sec->data->d_buf + offset);
			flags = bug->flags;
			rela = find_rela_by_dest(sec, offset);
		} else {
			struct bug_entry_verbose *bug;

			offset = sizeof(struct bug_entry_verbose) * i;
			bug = (struct bug_entry_verbose *) sec->data->d_buf + i;
			flags = bug->flags;
			rela = find_rela_by_dest(sec, offset);
		}

		if (!rela) {
			WARN("can't find rela for bug_table[%d]", i);
			return -1;
		}

		/*
		 * The "j .+2" BUG/WARN instruction results in a PSW that
		 * points *after* the instruction, therefore -4
		 */
		insn = find_insn(file, rela->sym->sec, rela->addend - 4);
		if (!insn) {
			WARN("can't find insn for bug_table[%d]", i);
			return -1;
		}
		if (flags & BUGFLAG_WARNING)
			insn->type = INSN_OTHER;
	}

	return 0;
}

/*
 * Read the unwind hints added with the UNWIND_HINT macros from
 * unwind_hints.h. These are used for functions where objtool
 * needs help to understand the state for the call frame address
 * and the return address. Most heavily used for entry.S.
 */
static int read_unwind_hints(struct objtool_file *file)
{
	struct section *sec, *relasec;
	struct rela *rela;
	struct unwind_hint *hint;
	struct instruction *insn;
	int i;

	sec = find_section_by_name(file->elf, ".discard.unwind_hints");
	if (!sec)
		return 0;

	relasec = sec->rela;
	if (!relasec) {
		WARN("missing .rela__bug_table section");
		return -1;
	}

	if (sec->len % sizeof(struct unwind_hint)) {
		WARN("struct unwind_hint size mismatch");
		return -1;
	}

	for (i = 0; i < sec->len / sizeof(struct unwind_hint); i++) {
		hint = (struct unwind_hint *) sec->data->d_buf + i;

		rela = find_rela_by_dest(sec, i * sizeof(*hint));
		if (!rela) {
			WARN("can't find rela for unwind_hints[%d]", i);
			return -1;
		}

		insn = find_insn(file, rela->sym->sec, rela->addend);
		if (!insn) {
			WARN("can't find insn for unwind_hints[%d]", i);
			return -1;
		}
		insn->hint = hint;
	}

	return 0;
}

static void mark_rodata(struct objtool_file *file)
{
	struct section *sec;

	/*
	 * This searches for the .rodata section or multiple .rodata.func_name
	 * sections if -fdata-sections is being used. The .str.1.1 and .str.1.8
	 * rodata sections are ignored as they don't contain jump tables.
	 */
	for_each_sec(file, sec) {
		if (strncmp(sec->name, ".rodata", 7) == 0 &&
		    strstr(sec->name, ".str1.") == NULL)
			sec->rodata = true;
	}
}

static void mark_expolines(struct objtool_file *file)
{
	struct instruction *insn;
	struct symbol *func;
	struct section *sec;

	for_each_sec(file, sec) {
		if (!strstr(sec->name, "__s390_indirect_jump_r") &&
		    !strstr(sec->name, "__s390_indirect_branch_r"))
			continue;
		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC)
				continue;
			insn = find_insn(file, func->sec, func->offset);
			sec_for_each_insn_from(file, insn)
				insn->expoline = true;
		}
	}
}

static int decode_sections(struct objtool_file *file)
{
	int ret;

	mark_rodata(file);

	/* Create the instruction list */
	ret = decode_instructions(file);
	if (ret)
		return ret;

	/* Find jump and call targets */
	ret = add_jump_destinations(file);
	if (ret)
		return ret;
	ret = add_bras_destinations(file);
	if (ret)
		return ret;

	/* Add the alternatives from special sections */
	ret = add_special_section_alts(file);
	if (ret)
		return ret;

	/* Read additional sections that describe the instructions */
	ret = read_bug_table(file);
	if (ret)
		return ret;
	ret = read_unwind_hints(file);
	if (ret)
		return ret;
	mark_ignores(file);
	mark_expolines(file);
	ret = mark_dead_ends(file);
	if (ret)
		return ret;

	/* Find potential switch tables */
	ret = add_rodata_targets(file);
	if (ret)
		return ret;

	return 0;
}

static bool has_valid_stack_frame(struct insn_state *state)
{
	struct cfi_reg *r15;

	/*
	 * The most common case is just a "lay %r15,-xx(%r15)" or
	 * "aghi %r15,-xx" to buy some stack space. The check
	 * returns false if r15 still has the original value, type
	 * REG_CFA and offset == 0. It returns true for all other
	 * cases, that includes %r15 set to REG_UNDEF to cover
	 * the CALL_ON_STACK case which switches to a new stack.
	 */
	r15 = state->regs + CFI_R15;
	if (r15->base == REG_CFA && r15->offset == 0)
		return false;
	return true;
}

static void check_modified_stack_frame(struct instruction *insn,
				       struct insn_state *state)
{
	struct cfi_reg *r15;

	if (insn->state->skip)
		return;

	r15 = state->regs + CFI_R15;
	if (r15->base == REG_PTREGS && r15->offset == -160)
		return;

	if (r15->base != REG_CFA || r15->offset != 0) {
		WARN_FUNC("sibling call with modified stack pointer",
			  insn->sec, insn->offset);
		warnings++;
	}
}

static void clobber_registers(unsigned short clobber, struct insn_state *new)
{
	int r;

	for (r = 0; clobber; r++) {
		if (clobber & 1)
			new->regs[r].base = REG_UNDEF;
		clobber >>= 1;
	}
}

static int update_stack_store(struct instruction *insn,
			      struct insn_state *old,
			      struct insn_state *new)
{
	struct cfi_reg *src;
	struct insn_ops *op;
	long offset, ix;
	int r;

	op = &insn->insn_ops;
	if (op->dest.r2 != 0)
		return 0;
	offset = op->dest.offset + old->regs[op->dest.r1].offset;
	if ((offset % 8) != 0)
		/* unaligned store to the stack */
		return 0;
	ix = (CFI_NUM_REGS*8 + 160 - offset) / 8 - 1;
	if (ix >= new->num_regs) {
		/* store to a stack area never allocated */
		WARN_FUNC("invalid stack store", insn->sec, insn->offset);
		return 0;
	}
	for (r = op->src.r1; r <= op->src.r2; r++, ix--) {
		if (ix < CFI_NUM_REGS)
			break;
		src = old->regs + r;
		if (src->base >= REG_ORIG_R0 && src->base <= REG_ORIG_R15) {
			/* Only store orig register if the offset is zero */
			if (src->offset != 0) {
				new->regs[ix].base = REG_UNDEF;
				new->regs[ix].offset = 0;
				continue;
			}
		}
		/* copy %rx old->regs[r] to stack slot new->regs[ix] */
		new->regs[ix] = *src;
	}
	return 0;
}

static int update_stack_load(struct instruction *insn,
			     struct insn_state *old,
			     struct insn_state *new)
{
	struct insn_ops *op;
	long offset, ix;
	int r;

	op = &insn->insn_ops;
	if (op->src.r2 != 0)
		return 0;
	offset = op->src.offset + old->regs[op->src.r1].offset;
	if ((offset % 8) != 0)
		/* unaligned store to the stack */
		return 0;
	ix = (CFI_NUM_REGS*8 + 160 - offset) / 8 - 1;
	if (ix >= new->num_regs) {
		/* store to a stack area never allocated */
		WARN_FUNC("invalid stack load", insn->sec, insn->offset);
		return 0;
	}
	for (r = op->dest.r1; r <= op->dest.r2; r++, ix--) {
		if (ix < CFI_NUM_REGS)
			break;
		/* copy stack slot new->regs[ix] to %rx old->regs[r] */
		new->regs[r] = old->regs[ix];
	}
	return 0;
}

static void apply_insn_hint(struct unwind_hint *hint,
			    struct insn_state *state)
{
	struct cfi_reg *reg;
	int i;

	if (hint->clear) {
		state->skip = 0;
		for (i = 0; i < state->num_regs; i++) {
			state->regs[i].base = REG_UNDEF;
			state->regs[i].offset = 0;
		}
	}
	if (hint->skip)
		state->skip = 1;
	if (hint->sp_reg < 16) {
		reg = state->regs + hint->sp_reg;
		if (hint->sp_ptregs)
			reg->base = REG_PTREGS;
		else
			reg->base = REG_CFA;
		reg->offset = hint->sp_offset;
	}
	if (hint->ra_reg < 16) {
		reg = state->regs + hint->ra_reg;
		reg->base = REG_RA;
		reg->offset = 0;
	}
}

/*
 * If an already visited instruction is reached a second time
 * update the register state for all instruction that descended
 * from the target instruction.
 */
static int update_insn_state(struct instruction *insn,
			     struct insn_state *old)
{
	struct cfi_reg *regs, *sregs;
	struct instruction *follow;
	struct insn_state *copy;
	struct insn_ops *op;
	long offset, ix;
	int r, nr, ret;

	sregs = old->regs;
	while (1) {
		/* Re-apply the insn hint */
		if (insn->hint)
			apply_insn_hint(insn->hint, old);
		op = &insn->insn_ops;
		nr = min(insn->state->num_regs, old->num_regs);
		regs = insn->state->regs;
		for (r = 0; r < nr; r++) {
			if (regs[r].base == REG_UNDEF ||
			    sregs[r].base == REG_IGNORE)
				continue;
			if (regs[r].base == sregs[r].base &&
			    regs[r].offset == sregs[r].offset)
				continue;
			regs[r].base = REG_UNDEF;
			/* An %rx loaded from a clobbered source will
			 * get clobbered as well */
			if (insn->type == INSN_REG_ADD1 && r == op->src.r1)
				sregs[op->dest.r1].base = REG_UNDEF;
			else if (insn->type == INSN_REG_ADD2 &&
				 (r == op->src.r1 || r == op->src.r2))
				sregs[op->dest.r1].base = REG_UNDEF;
			else if (insn->type == INSN_REG_SUB2 &&
				 (r == op->src.r1 || r == op->src.r2))
				sregs[op->dest.r1].base = REG_UNDEF;
		}
		switch (insn->type) {
		case INSN_BRAS:
		case INSN_REG_CONST:
		case INSN_REG_ADDR:
			sregs[op->dest.r1].base = REG_IGNORE;
			break;
		case INSN_REG_ADD1:
			if (op->src.r2 == 0 &&
			    regs[op->src.r1].base != REG_UNDEF)
				sregs[op->dest.r1].base = REG_IGNORE;
			break;
		case INSN_REG_ADD2:
			break;
		case INSN_REG_SUB2:
			break;
		case INSN_MEM_LOAD:
			for (r = op->dest.r1; r <= op->dest.r2; r++)
				sregs[r].base = REG_IGNORE;
			break;
		case INSN_MEM_STORE:
			if (regs[op->dest.r1].base != REG_CFA)
				break;
			offset = op->dest.offset + regs[op->dest.r1].offset;
			if ((offset % 8) != 0)
				break;
			ix = (CFI_NUM_REGS*8 + 160 - offset) / 8 - 1;
			for (r = op->src.r1; r <= op->src.r2; r++, ix--) {
				if (ix >= old->num_regs)
					continue;
				if (ix < CFI_NUM_REGS)
					break;
				sregs[ix].base = REG_IGNORE;
			}
			break;
		}
		if (list_empty(&insn->tree))
			break;
		list_for_each_entry(follow, &insn->tree, node) {
			if (list_is_last(&follow->node, &insn->tree)) {
				/* re-use passed state for the last insn */
				insn = follow;
				break;
			}
			copy = copy_state(old);
			if (!copy) {
				WARN("malloc failed");
				return -1;
			}
			ret = update_insn_state(follow, copy);
			if (ret)
				return ret;
		}
	}
	free_state(old);
	return 0;
}

static void update_address_register(struct objtool_file *file,
				    struct instruction *insn,
				    struct insn_state *new)
{
	struct rodata *rodata;
	struct insn_ops *op;
	struct cfi_reg *reg;

	op = &insn->insn_ops;
	rodata = insn->rodata;
	reg = new->regs + op->dest.r1;
	/* Check if this is a register pointing to read-only data */
	if (rodata && rodata->table) {
		reg->base = REG_TABLE;
		reg->ptr = rodata;
	} else {
		reg->base = REG_ADDR;
		reg->offset = op->src.offset + insn->offset;
	}
}

static int validate_insn(struct objtool_file *file, struct symbol *func,
			 struct instruction *insn, struct insn_state *cur,
			 struct list_head *root);

/*
 * find_switch_table() and friends - Try to identify an indirect branch
 * as a switch table branch. If one is found, read all branch targets
 * from the switch table and add them as alternatives.
 *
 * There are two patterns found in code generated by gcc, each has three
 * instructions. One to load the address of the switch table into a
 * register, a second to load an entry from the switch table and the
 * third is the actual indirect branch.
 *
 * The pattern with absolute addresses in the switch table,
 * %r1 has the switch value *8:
 *	larl	%r2,.L1
 *	...
 *	lg	%r3,0(%r1,%r2)
 *	...
 *	br	%r3
 *	.section .rodata
 * .L1:
 *	.quad	.L2	# creates a R_390_64 relocation
 *	.quad	.L3	# creates a R_390_64 relocation
 *	.text
 * .L2:
 *	...
 * .L3:
 *	...
 *
 * The pattern with relative addresses in the switch table:
 * %r1 has the switch value *8:
 *	larl	%r2,.L1
 *	...
 *	lg	%r3,0(%r1,%r2)
 *	...
 *	b	0(%r3,%r2)
 *	.section .rodata
 * .L1:
 *	.quad	.L2-.L1	# creates a R_390_PC64 relocation
 *	.quad	.L3-.L1	# creates a R_390_PC64 relocation
 *	.text
 * .L2:
 *	...
 * .L3:
 *	...
 */
static struct instruction *find_switch_load(struct objtool_file *file,
					    struct instruction *jump,
					    struct insn_state *cur)
{
	struct cfi_reg *reg;
	struct insn_ops *op;

	/* Find the load instruction that retrieved the branch target */
	op = &jump->insn_ops;
	reg = cur->regs + op->src.r1;
	if (op->src.r1 && reg->base == REG_INSN_ADDR)
		return (struct instruction *) reg->ptr;
	reg = cur->regs + op->src.r2;
	if (op->src.r2 && reg->base == REG_INSN_ADDR)
		return (struct instruction *) reg->ptr;
	return NULL;
}

static struct rodata *find_switch_table(struct objtool_file *file,
					struct instruction *load)
{
	struct cfi_reg *reg;
	struct insn_ops *op;

	/* Find the address of the switch table */
	op = &load->insn_ops;
	reg = load->state->regs + op->src.r1;
	if (op->src.r1 && reg && reg->base == REG_TABLE)
		/* r2 is the index */
		return (struct rodata *) reg->ptr;
	reg = load->state->regs + load->insn_ops.src.r2;
	if (op->src.r2 && reg && reg->base == REG_TABLE)
		/* r1 is the index */
		return (struct rodata *) reg->ptr;
	return NULL;
}

static unsigned long find_switch_offset(struct objtool_file *file,
					struct instruction *jump)
{
	struct cfi_reg *reg;
	struct insn_ops *op;
	struct rodata *rodata;
	unsigned long offset;

	/* Calculate the offset to be added to the switch table entries */
	op = &jump->insn_ops;
	offset = op->src.offset;
	reg = jump->state->regs + op->src.r1;
	if (op->src.r1 && reg && reg->base == REG_TABLE) {
		rodata = (struct rodata *) reg->ptr;
		offset += (unsigned long) rodata->table->offset;
	}
	reg = jump->state->regs + op->src.r2;
	if (op->src.r2 && reg && reg->base == REG_TABLE) {
		rodata = (struct rodata *) reg->ptr;
		offset += (unsigned long) rodata->table->offset;
	}
	return offset;
}


static int find_switch_branches(struct objtool_file *file,
				struct symbol *func,
				struct instruction *jump,
				struct insn_state *cur,
				struct list_head *root)
{
	struct instruction *load, *jump_dest;
	struct rela *table, *rela;
	struct insn_state *copy;
	struct rodata *rodata;
	struct symbol *pfunc;
	unsigned int prev_offset;
	unsigned long offset, location;
	int ret;

	/* Find the load instruction that retrieved the branch target */
	load = find_switch_load(file, jump, cur);
	if (!load)
		return 0;

	/* Get the read-only data associated to the switch table */
	rodata = find_switch_table(file, load);
	if (!rodata)
		return 0;

	/* Get offset that needs to be added to the switch table entries */
	offset = find_switch_offset(file, jump);

	prev_offset = 0;
	pfunc = jump->func->pfunc;
	table = rela = rodata->table;
	list_for_each_entry_from(rela, &table->rela_sec->rela_list, list) {
		/* Check size limit of the read-only switch table */
		if (rela->offset >= rodata->offset + rodata->len)
			break;

		/* Make sure the switch table entries are consecutive: */
		if (prev_offset && rela->offset != prev_offset + 8)
			break;

		/* Detect function pointers from contiguous objects: */
		if (rela->sym->sec == pfunc->sec &&
		    rela->addend == pfunc->offset)
			break;

		location = offset + rela->addend;
		if (rela->type == R_390_PC64) {
			location -= (unsigned long) rela->offset;
			if (load->type == INSN_MEM_ADD)
				location += table->offset;
		} else if (rela->type!= R_390_64) {
			break;
		}

		jump_dest = find_insn(file, rela->sym->sec, location);
		if (!jump_dest)
			break;

		/* Make sure the jmp dest is in the function or subfunction: */
		if (jump_dest->func->pfunc != pfunc)
			break;
		jump->switch_branch = 1;

		copy = copy_state(cur);
		if (!copy) {
			WARN("malloc failed");
			return -1;
		}
		ret = validate_insn(file, func, jump_dest, copy, root);
		if (ret)
			return ret;

		prev_offset = rela->offset;
	}

	if (!prev_offset) {
		WARN_FUNC("can't find switch jump table",
			  jump->sec, jump->offset);
		return -1;
	}

	return 0;
}

static int validate_function(struct objtool_file *file,
			     struct symbol *func);

/*
 * Inspect a call target symbol to find two pieces of information:
 * 1) dead_end: does the target function return?
 * 2) uses_stack: does the target function uses the stack?
 *
 * For global functions uses_stack is true and in general dead_end is false.
 * There are a few exceptions of global functions that do not return,
 * these are listed in global_noreturns[].
 *
 * For local functions, we try to analyse the function to find indirect
 * branches with a REG_RA register that are used for the function returns,
 * and to find INSN_MEM_STORE instructions with a REG_CFA register which
 * indicate stack usage.
 *
 * validate_function()/validate_insn() and inspect_call_target call each
 * other recursively, for local function that call each other we might end
 * up with a dead lock. To break these dead locks we assume that these
 * function are no dead-ends.
 *
 * Returns -1 on error, 0 otherwise
 */
static int inspect_call_target(struct objtool_file *file, struct symbol *func)
{
	struct instruction *insn, *dest;
	struct cfi_reg *reg;
	int no_return, uses_stack;
	int i, ret;

	/*
	 * Unfortunately these have to be hard coded because the noreturn
	 * attribute isn't provided in ELF data.
	 */
	static const char * const global_noreturns[] = {
		"__module_put_and_exit",
		"__reiserfs_panic",
		"__stack_chk_fail",
		"cpu_die",
		"complete_and_exit",
		"do_exit",
		"do_group_exit",
		"do_task_dead",
		"fortify_panic",
		"panic",
		"usercopy_abort",
	};

	/*
	 * Set symbol arch_flags to uses_stack=0, no_return=0 and
	 * inspected=1. This declares the function as inspected before
	 * true values for uses_stack and no_return are known. This
	 * is necessary to avoid infinite recursion for the dead end
	 * detection.
	 */
	func->arch_flags = SYMBOL_INSPECTED;

	/* check the list of global dead-end functions */
	if (func->bind == STB_GLOBAL) {
		for (i = 0; i < ARRAY_SIZE(global_noreturns); i++) {
			if (strcmp(func->name, global_noreturns[i]) != 0)
				continue;
			func->arch_flags |= SYMBOL_NO_RETURN;
			break;
		}
	}

	insn = find_insn(file, func->sec, func->offset);
	if (!insn || !insn->func || insn->ignore) {
		func->arch_flags |= SYMBOL_USES_STACK;
		return 0;
	}
	if (!insn->visited) {
		ret = validate_function(file, func);
		if (ret)
			return ret;
	}

	no_return = func->bind != STB_WEAK && func->len > 0;
	uses_stack = 0;

	func_for_each_insn_all(file, func, insn) {
		if (insn->type == INSN_MEM_STORE && insn->state) {
			reg = insn->state->regs + insn->insn_ops.dest.r1;
			if (reg->base == REG_CFA)
				uses_stack = 1;
		}
		if (insn->type == INSN_BRANCH_INDIRECT ||
		    insn->type == INSN_BRANCH_EXPOLINE) {
			if (!insn->switch_branch)
				no_return = 0;
		}
		if (!no_return && uses_stack)
			break;
		if (insn->type != INSN_BRANCH_RELATIVE)
			continue;
		/* find out where the branch leads to */
		dest = insn->jump_dest;
		if (!dest) {
			/* sibling call to another file */
			no_return = 0;
			uses_stack = 1;
		} else if (dest->func &&
			   dest->func->pfunc != insn->func->pfunc) {
			/* sibling target function in the same file */
			if (!(dest->func->arch_flags & SYMBOL_INSPECTED)) {
				ret = inspect_call_target(file, dest->func);
				if (ret)
					return ret;
			}
			if (!(dest->func->arch_flags & SYMBOL_NO_RETURN))
				no_return = 0;
			if (dest->func->arch_flags & SYMBOL_USES_STACK)
				uses_stack = 1;
		}
	}

	if (no_return)
		func->arch_flags |= SYMBOL_NO_RETURN;
	if (uses_stack)
		func->arch_flags |= SYMBOL_USES_STACK;
	return 0;
}

static bool fixup_func(struct objtool_file *file, struct symbol *func,
		      struct instruction *insn)
{
	struct section *sec;

	sec = insn->sec;
	if (!strcmp(sec->name, ".altinstr_replacement") &&
	    !strcmp(sec->name, ".fixup"))
		return false;
	insn->func = func;
	return true;
}

/*
 * Follow the code starting at the given instruction, and recursively follow
 * all branches.  Meanwhile, track the register state for each instruction,
 * starting from the state passed in via 'cur'.
 */
static int validate_insn(struct objtool_file *file, struct symbol *func,
			 struct instruction *insn, struct insn_state *cur,
			 struct list_head *root)
{
	struct instruction *ex_insn, *next_insn, *jump_dest;
	struct insn_state *new, *copy;
	struct symbol *pfunc, *sym;
	struct alternative *alt;
	struct cfi_reg *r1, *r2;
	struct insn_ops *op;
	int i, ret, stop;
	long offset;

	if (insn->alt_group && list_empty(&insn->group_alts)) {
		WARN_FUNC("branch into alternative instruction group",
			  insn->sec, insn->offset);
		return -1;
	}

	if (!insn->func && !fixup_func(file, func, insn)) {
		WARN_FUNC("validating an instruction not part of a function\n",
			  insn->sec, insn->offset);
		return -1;
	}

	stop = 0;
	pfunc = insn->func->pfunc;
	while (1) {
		if (insn->ignore) {
			WARN_FUNC("BUG: validating an ignored instruction",
				  insn->sec, insn->offset);
			return -1;
		}

		if (insn->visited)
			return update_insn_state(insn, cur);

		/* Apply hints to current state */
		if (insn->hint)
			apply_insn_hint(insn->hint, cur);

		/*
		 * After the hints have been applied create a copy of
		 * the state that exists prior to this insn being executed.
		 */
		insn->visited = true;
		insn->state = cur;
		if (root)
			list_add(&insn->node, root);

		/* Visit jump alternative with a copy of the current state */
		alt = insn->jump_alt;
		if (alt) {
			copy = copy_state(insn->state);
			if (!copy) {
				WARN("malloc failed");
				return -1;
			}
			ret = validate_insn(file, func, alt->insn, copy, root);
			if (ret)
				return ret;
		}

		/* Visit group alternatives with a copy of the current state */
		list_for_each_entry(alt, &insn->group_alts, list) {
			copy = copy_state(insn->state);
			if (!copy) {
				WARN("malloc failed");
				return -1;
			}
			ret = validate_insn(file, func, alt->insn, copy, root);
			if (ret)
				return ret;
		}

		/* Handle instructions reached via execute */
		ex_insn = insn;
		if (insn->type == INSN_EXRL || insn->type == INSN_EX) {
			if (insn->type == INSN_EXRL)
				ret = find_jump_destination(file, insn);
			else
				ret = find_abs_destination(file, insn);
			if (ret)
				return ret;
			/*
			 * insn->jump_dest now points to the target of
			 * the execute intruction. Use the execute target
			 * for the opcode but the state of the execute
			 * instruction.
			 */
			ex_insn = insn->jump_dest;
			ex_insn->ex_target = true;
			if (!list_empty(&ex_insn->group_alts)) {
				WARN_FUNC("executed instruction with an alternative\n",
					  ex_insn->sec, ex_insn->offset);
				return -1;
			}
		}

		/* Create a new state for the next instruction */
		new = copy_state(cur);
		if (!new) {
			WARN("malloc failed");
			return -1;
		}
		/* Clobber registers */
		clobber_registers(ex_insn->insn_ops.clobber, new);

		op = &ex_insn->insn_ops;
		switch (ex_insn->type) {
		case INSN_BUG:
			stop = 1;
			break;

		case INSN_BRAS:
			offset = ex_insn->offset + ex_insn->len;
			new->regs[op->dest.r1].base = REG_ADDR;
			new->regs[op->dest.r1].offset = offset;

			jump_dest = ex_insn->jump_dest;
			if (!ex_insn->state->skip &&
			    jump_dest && !jump_dest->func) {
				WARN_FUNC("branch to an instruction not part of a function",
					  insn->sec, insn->offset);
				return -1;
			}

			if (jump_dest && pfunc == jump_dest->func->pfunc) {
				/* bras/brasl to a local instruction */
				return validate_insn(file, jump_dest->func,
						     jump_dest, new,
						     &insn->tree);
			}

			sym = ex_insn->call_dest;
			if (!(sym->arch_flags & SYMBOL_INSPECTED)) {
				ret = inspect_call_target(file, sym);
				if (ret)
					return ret;
			}
			if (sym->arch_flags & SYMBOL_NO_RETURN) {
				stop = 1;
				break;
			}
			/* normal function call with return */
			if ((sym->arch_flags & SYMBOL_USES_STACK) &&
			    !ex_insn->state->skip &&
			    !has_valid_stack_frame(cur)) {
				WARN_FUNC("call without stack frame setup",
					  insn->sec, insn->offset);
				warnings++;
			}
			/* Clear call clobbered registers */
			for (i = CFI_R0; i < CFI_R6; i++) {
				new->regs[i].base = REG_UNDEF;
				new->regs[i].offset = 0;
			}
			break;

		case INSN_BAS:
			offset = ex_insn->offset + ex_insn->len;
			new->regs[op->dest.r1].base = REG_ADDR;
			new->regs[op->dest.r1].offset = offset;

			if (!ex_insn->state->skip &&
			    !has_valid_stack_frame(cur)) {
				WARN_FUNC("call without stack frame setup",
					  insn->sec, insn->offset);
				warnings++;
			}
			/* Clear call clobbered registers */
			for (i = 0; i < 6; i++) {
				new->regs[i].base = REG_UNDEF;
				new->regs[i].offset = 0;
			}
			break;

		case INSN_BRANCH_RELATIVE:
			jump_dest = ex_insn->jump_dest;
			if (!ex_insn->state->skip &&
			    jump_dest && !jump_dest->func) {
				WARN_FUNC("branch to an instruction not part of a function",
					  insn->sec, insn->offset);
				return -1;
			}
			if (jump_dest && pfunc == jump_dest->func->pfunc) {
				copy = copy_state(new);
				if (!copy) {
					WARN("malloc failed");
					return -1;
				}
				ret = validate_insn(file, jump_dest->func,
						    jump_dest, copy,
						    &insn->tree);
				if (ret)
					return ret;
			} else {
				check_modified_stack_frame(insn, cur);
			}
			if (!op->conditional)
				stop = 1;
			break;

		case INSN_BRANCH_INDIRECT:
		case INSN_BRANCH_EXPOLINE:
			/* Search for potential switch table jumps */
			ret = find_switch_branches(file, func, ex_insn,
						   new, root);
			if (ret)
				return ret;
			/*
			 * find_switch_branches returns 1 if it found the
			 * switch table and associated branches. In this
			 * case the indirect branch is not a sibling call.
			 */
			if (!insn->switch_branch)
				check_modified_stack_frame(insn, cur);
			if (!op->conditional)
				stop = 1;
			break;

		case INSN_MEM_ADD:
			r1 = cur->regs + op->src.r1;
			r2 = cur->regs + op->src.r2;
			if (r1->base == REG_TABLE || r2->base == REG_TABLE) {
				new->regs[op->dest.r1].base = REG_INSN_ADDR;
				new->regs[op->dest.r1].ptr = ex_insn;
			}
			break;

		case INSN_MEM_LOAD:
			r1 = cur->regs + op->src.r1;
			r2 = cur->regs + op->src.r2;
			if (r1->base == REG_CFA) {
				ret = update_stack_load(ex_insn, cur, new);
				if (ret)
					return ret;
				break;
			}
			if (r1->base == REG_TABLE || r2->base == REG_TABLE) {
				new->regs[op->dest.r1].base = REG_INSN_ADDR;
				new->regs[op->dest.r1].ptr = ex_insn;
			}
			break;

		case INSN_MEM_STORE:
			r1 = cur->regs + op->dest.r1;
			if (r1->base == REG_CFA) {
				ret = update_stack_store(ex_insn, cur, new);
				if (ret)
					return ret;
			}
			break;

		case INSN_REG_CONST:
			new->regs[op->dest.r1].base = REG_CONST;
			new->regs[op->dest.r1].offset = op->src.offset;
			break;

		case INSN_REG_ADDR:
			update_address_register(file, ex_insn, new);
			break;

		case INSN_REG_ADD1:
			r1 = cur->regs + op->src.r1;
			if (r1) {
				offset = r1->offset + op->src.offset;
				new->regs[op->dest.r1].base = r1->base;
				new->regs[op->dest.r1].offset = offset;
				if (op->dest.r1 == CFI_R15 &&
				    r1->base == REG_CFA) {
					ret = extent_state(new, offset);
					if (ret)
						return ret;
				}
			}
			break;

		case INSN_REG_ADD2:
			r1 = cur->regs + op->src.r1;
			r2 = cur->regs + op->src.r2;
			offset = op->src.offset + r1->offset + r2->offset;
			if (r1->base == INSN_REG_CONST) {
				new->regs[op->dest.r1].base = r2->base;
				new->regs[op->dest.r1].offset = offset;
				if (op->dest.r1 == CFI_R15 &&
				    r1->base == REG_CFA) {
					ret = extent_state(new, offset);
					if (ret)
						return ret;
				}
			} else if (r2->base == INSN_REG_CONST) {
				new->regs[op->dest.r1].base = r1->base;
				new->regs[op->dest.r1].offset = offset;
				if (op->dest.r1 == CFI_R15 &&
				    r1->base == REG_CFA) {
					ret = extent_state(new, offset);
					if (ret)
						return ret;
				}
			}
			break;

		case INSN_REG_SUB2:
			r1 = cur->regs + op->src.r1;
			r2 = cur->regs + op->src.r2;
			if (r2->base != INSN_REG_CONST)
				break;
			offset = op->src.offset + r1->offset - r2->offset;
			new->regs[op->dest.r1].base = r1->base;
			new->regs[op->dest.r1].offset = offset;
			if (op->dest.r1 == CFI_R15 &&
			    r1->base == REG_CFA) {
				ret = extent_state(new, offset);
				if (ret)
					return ret;
			}
			break;

		default:
			break;
		}

		if (stop)
			break;

		next_insn = next_insn_same_sec(file, insn);
		if (!next_insn) {
			WARN("%s: unexpected end of section",
			     insn->sec->name);
			return -1;
		}
		if (next_insn->dead_end)
			break;

		if (!next_insn->func && !fixup_func(file, func, next_insn)) {
			WARN_FUNC("fall-through to an instructions not part of a function",
				  insn->sec, insn->offset);
			warnings++;
			break;
		}

		if (pfunc != next_insn->func->pfunc) {
			WARN("%s() falls through to next function %s()",
			     pfunc->name, next_insn->func->name);
			warnings++;
			break;
		}

		root = &insn->tree;
		insn = next_insn;
		cur = new;
	}
	free_state(new);
	return 0;
}

static int validate_function(struct objtool_file *file, struct symbol *func)
{
	struct instruction *insn;
	struct insn_state *state;
	int i;

	insn = find_insn(file, func->sec, func->offset);
	if (!insn) {
		WARN("%s() has no instructions", func->name);
		warnings++;
		return 0;
	}
	if (insn->ignore)
		return 0;

	/*
	 * Allocate initial state for the first instruction of the
	 * function. 20 stack slots for the 160 byte biased save area
	 * and the initial register state: %r15=cfa+0, %r14=ra+0
	 */
	state = alloc_state();
	if (!state) {
		WARN("malloc failed");
		return -1;
	}
	for (i = 0; i < CFI_NUM_REGS; i++)
		/* set CFI_Rx to REG_ORIG_Rx */
		state->regs[i].base = i;
	/* validate_insn consumes the passed state */
	return validate_insn(file, func, insn, state, NULL);
}

static void validate_expoline(struct objtool_file *file)
{
	struct instruction *insn;

	for_each_insn(file, insn) {
		if (insn->type != INSN_BRANCH_INDIRECT &&
		    insn->type != INSN_BAS)
			continue;

		/*
		 * .init.text code is ran before userspace and thus doesn't
		 * strictly need expolines, except for modules which are
		 * loaded late, they very much do need expoline in their
		 * .init.text
		 */
		if (!strcmp(insn->sec->name, ".init.text") && !module)
			continue;

		WARN_FUNC("indirect branch found in EXPOLINE build",
			  insn->sec, insn->offset);
		warnings++;
	}
}

static bool is_kasan_insn(struct instruction *insn)
{
	return (insn->type == INSN_BRAS &&
		!strcmp(insn->call_dest->name, "__asan_handle_no_return"));
}

static bool is_ubsan_insn(struct instruction *insn)
{
	return (insn->type == INSN_BRAS &&
		!strcmp(insn->call_dest->name,
			"__ubsan_handle_builtin_unreachable"));
}

static bool ignore_unreachable_insn(struct instruction *insn)
{
	struct symbol *func;
	int i;

	if (insn->ignore || insn->type == INSN_NOP)
		return true;

	/*
	 * Ignore any unused exceptions.  This can happen when a whitelisted
	 * function has an exception table entry.
	 *
	 * Also ignore alternative replacement instructions.  This can happen
	 * when a whitelisted function uses one of the ALTERNATIVE macros.
	 */
	if (!strcmp(insn->sec->name, ".fixup") ||
	    !strcmp(insn->sec->name, ".altinstr_replacement") ||
	    !strcmp(insn->sec->name, ".altinstr_aux"))
		return true;

	/*
	 * Check if this (or a subsequent) instruction is related to
	 * CONFIG_UBSAN or CONFIG_KASAN.
	 *
	 * End the search at 5 instructions to avoid going into the weeds.
	 */
	func = insn->func;
	if (!func)
		return false;
	for (i = 0; i < 5; i++) {

		if (is_kasan_insn(insn) || is_ubsan_insn(insn))
			return true;

		if (insn->type == INSN_BRANCH_RELATIVE) {
			if (insn->jump_dest && insn->jump_dest->func == func) {
				insn = insn->jump_dest;
				continue;
			}

			break;
		}

		if (insn->offset + insn->len >= func->offset + func->len)
			break;

		insn = list_next_entry(insn, list);
	}
	return false;
}

static int validate_all_functions(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	int ret;

	for_each_sec(file, sec) {
		if (strstr(sec->name, "__s390_indirect_jump_r") ||
		    strstr(sec->name, "__s390_indirect_branch_r"))
			continue;
		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC || func->pfunc != func)
				continue;
			ret = validate_function(file, func);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int validate_reachable_instructions(struct objtool_file *file)
{
	struct instruction *insn;

	if (no_unreachable)
		return 0;

	for_each_insn(file, insn) {
		if (insn->visited || insn->ex_target || insn->dead_end ||
		    insn->expoline || ignore_unreachable_insn(insn))
			continue;

		WARN_FUNC("unreachable instruction", insn->sec, insn->offset);
		return 1;
	}
	return 0;
}

static void cleanup(struct objtool_file *file)
{
	struct instruction *insn, *_insn;
	struct alternative *alt, *_alt;
	struct rodata *rodata, *_rodata;

	list_for_each_entry_safe(insn, _insn, &file->insn_list, list) {
		list_for_each_entry_safe(alt, _alt, &insn->group_alts, list) {
			list_del(&alt->list);
			free(alt);
		}
		if (insn->jump_alt)
			free(insn->jump_alt);
		free(insn);
	}
	list_for_each_entry_safe(rodata, _rodata, &file->rodata_list, list)
		free(rodata);
	elf_close(file->elf);
}

static void print_insn_list(struct objtool_file *file)
{
	const char *insn_names[INSN_LAST+1] = {
		[INSN_NOP] = "NOP",
		[INSN_BRANCH_RELATIVE] = "BRANCH RELATIVE",
		[INSN_BRANCH_INDIRECT] = "BRANCH INDIRECT",
		[INSN_BRANCH_EXPOLINE] = "BRANCH EXPOLINE",
		[INSN_BRAS] = "BRANCH RELATIVE AND SAVE",
		[INSN_BAS] = "BRANCH AND SAVE",
		[INSN_EX] = "EXECUTE INDIRECT",
		[INSN_EXRL] = "EXECUTE RELATIVE",
		[INSN_MEM_ADD] = "MEM ADD",
		[INSN_MEM_LOAD] = "MEM LOAD",
		[INSN_MEM_STORE] = "MEM STORE",
		[INSN_REG_ADDR] = "REG_ADDR",
		[INSN_REG_CONST] = "REG_CONST",
		[INSN_REG_ADD1] = "REG_ADD1",
		[INSN_REG_ADD2] = "REG_ADD2",
		[INSN_REG_SUB2] = "REG_SUB2",
		[INSN_BUG] = "BUG",
		[INSN_OTHER] = "OTHER"
	};
	const char *last_func_name, *func_name;
	const char *last_sec_name, *sec_name;
	struct instruction *insn;
	struct cfi_reg *reg;
	long offset;
	int i;

	last_func_name = NULL;
	last_sec_name = NULL;
	for_each_insn(file, insn) {
		func_name = insn->func ? insn->func->name : "n/a";
		sec_name = insn->sec->name;
		if (!last_func_name || strcmp(last_func_name, func_name) ||
		    !last_sec_name || strcmp(last_sec_name, sec_name)) {
			if (last_func_name)
				printf("\n");
			printf("%s: %s\n", sec_name, func_name);
			last_func_name = func_name;
			last_sec_name = sec_name;
		}
		if (insn->offset == -1UL)
			printf("\tinsn fake: ");
		else
			printf("\tinsn %06lx: ", insn->offset);
		printf("%s, ignored %i, skipped %i, dead_end %i\n",
		       insn_names[insn->type], insn->ignore,
		       insn->state ? insn->state->skip : 0,
		       insn->dead_end);
		if (!insn->state || insn->state->skip)
			continue;
		for (i = 0; i < CFI_NUM_REGS; i++) {
			reg = insn->state->regs + i;
			if (reg->base == REG_ORIG_R15)
				printf("\t\tr%02i: cfa%+li\n",
				       i, reg->offset);
			else if (reg->base == REG_ORIG_R14)
				printf("\t\tr%02i: ra%+li\n",
				       i, reg->offset);
			else if (reg->base >= REG_ORIG_R0 &&
				 reg->base <= REG_ORIG_R15)
				printf("\t\tr%02i: orig r%i%+li\n",
				       i, reg->base, reg->offset);
			else if (reg->base == REG_PTREGS)
				printf("\t\tr%02i: ptregs%+li\n",
				       i, reg->offset);
			else if (reg->base == REG_CONST)
				printf("\t\tr%02i:  constant 0x%lx\n",
				       i, reg->offset);
			else if (reg->base == REG_ADDR)
				printf("\t\tr%02i:  address\n", i);
			else if (reg->base == REG_TABLE)
				printf("\t\tr%02i:  table address\n", i);
			else if (reg->base == REG_INSN_ADDR)
				printf("\t\tr%02i:  instruction address\n", i);
		}
		offset = (CFI_NUM_REGS + 20 - insn->state->num_regs) * 8;
		for (i = insn->state->num_regs - 1; i >= CFI_NUM_REGS; i--) {
			reg = insn->state->regs + i;
			if (reg->base == REG_ORIG_R15)
				printf("\t\t%li(cfa): cfa%+li\n",
				       offset, reg->offset);
			else if (reg->base == REG_ORIG_R14)
				printf("\t\t%li(cfa): ra%+li\n",
				       offset, reg->offset);
			else if (reg->base >= REG_ORIG_R0 &&
				 reg->base <= REG_ORIG_R15)
				printf("\t\t%li(cfa): orig r%i + %li\n",
				       offset, reg->base, reg->offset);
			else if (reg->base == REG_PTREGS)
				printf("\t\t%li(cfa): ptregs + %li\n",
				       offset, reg->offset);
			else if (reg->base == REG_CONST)
				printf("\t\t%li(cfa):  constant 0x%lx\n",
				       offset, reg->offset);
			else if (reg->base == REG_ADDR)
				printf("\t\t%li(cfa):  address\n", offset);
			else if (reg->base == REG_TABLE)
				printf("\t\t%li(cfa):  table address\n",
				       offset);
			else if (reg->base == REG_INSN_ADDR)
				printf("\t\t%li(cfa):  instruction address\n",
				       offset);
			offset += 8;
		}
	}
}

int check(const char *_objname, bool orc)
{
	struct objtool_file file;
	int ret;

	objname = _objname;

	file.elf = elf_open(objname, orc ? O_RDWR : O_RDONLY);
	if (!file.elf)
		return 1;

	INIT_LIST_HEAD(&file.insn_list);
	INIT_LIST_HEAD(&file.rodata_list);
	hash_init(file.insn_hash);
	file.whitelist = find_section_by_name(file.elf, ".discard.func_stack_frame_non_standard");

	ret = decode_sections(&file);
	if (ret < 0)
		goto out;

	if (list_empty(&file.insn_list))
		goto out;

	if (retpoline)
		validate_expoline(&file);

	ret = validate_all_functions(&file);
	if (dump_insn)
		print_insn_list(&file);
	if (ret)
		goto out;

	if (!warnings) {
		ret = validate_reachable_instructions(&file);
		if (ret)
			goto out;
	}

	if (dump_insn)
		print_insn_list(&file);

	if (orc) {
		ret = create_orc(&file);
		if (ret)
			goto out;

		ret = create_orc_sections(&file);
		if (ret)
			goto out;

		ret = elf_write(file.elf);
		if (ret)
			goto out;
	}

out:
	cleanup(&file);

	/* ignore warnings for now until we get all the code cleaned up */
	if (ret || warnings)
		return 0;
	return 0;
}
