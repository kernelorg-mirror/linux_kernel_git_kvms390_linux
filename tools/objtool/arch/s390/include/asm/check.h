// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _CHECK_H
#define _CHECK_H

#include <stdbool.h>
#include <elfdefs.h>
#include <asm/arch.h>
#include <orc.h>
#include <linux/hashtable.h>

#define SYMBOL_INSPECTED	1
#define SYMBOL_NO_RETURN	2
#define SYMBOL_USES_STACK	4

struct rodata {
	struct list_head list;
	struct section *sec;
	struct rela *table;
	unsigned long offset;
	unsigned int len;
};

struct insn_state {
	/*
	 * The first CFI_NUM_REGS entries in the regs[] array are the
	 * general purpose registers %rx. The elements after CFI_NUM_REG
	 * are used to track 8-byte aligned stack slots, on function
	 * entry there are 20 of them for the 160 byte biased save area.
	 * The are sorted in inverse order, regs[CFI_NUM_REG] is stack
	 * slot cfa+152, regs[CFI_NUM_REG+1] is cfa+144 an so on. With
	 * the inverse order it is easy to extend the tracking area
	 * at the time stack space is reserved by lay/aghi.
	 */
	struct cfi_reg *regs;
	int num_regs;
	int skip;
};

struct alternative {
	struct list_head list;
	struct instruction *insn;
};

struct instruction {
	struct list_head list;
	struct list_head node;
	struct list_head tree;
	struct hlist_node hash;
	struct section *sec;
	unsigned long offset;
	unsigned int len;
	unsigned char type;
	int seq;
	bool alt_group;
	bool visited;
	bool dead_end;
	bool ignore;
	bool ex_target;
	bool switch_branch;
	bool expoline;
	struct unwind_hint *hint;
	struct symbol *call_dest;
	struct instruction *jump_dest;
	struct rodata *rodata;
	struct list_head group_alts;
	struct alternative *jump_alt;
	struct symbol *func;
	struct insn_ops insn_ops;
	struct insn_state *state;
	struct orc_entry orc;
};

struct objtool_file {
	struct elf *elf;
	struct section *whitelist;
	struct list_head insn_list;
	struct list_head rodata_list;
	DECLARE_HASHTABLE(insn_hash, 16);
};

int check(const char *objname, bool orc);

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset);

#define for_each_insn(file, insn)					\
	list_for_each_entry(insn, &file->insn_list, list)

#define sec_for_each_insn(file, sec, insn)				\
	for (insn = find_insn(file, sec, 0);				\
	     insn && &insn->list != &file->insn_list &&			\
			insn->sec == sec;				\
	     insn = list_next_entry(insn, list))


#endif /* _CHECK_H */
