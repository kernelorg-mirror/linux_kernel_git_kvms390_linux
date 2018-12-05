// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 *
 * This file reads all the special sections which have alternate
 * instructions which can be patched in or redirected to at runtime.
 */
#include <stdlib.h>
#include <string.h>

#include <warn.h>
#include "special.h"

#define EX_ENTRY_SIZE		8
#define EX_ORIG_OFFSET		0
#define EX_NEW_OFFSET		4

#define JUMP_ENTRY_SIZE		16
#define JUMP_ORIG_OFFSET	0
#define JUMP_NEW_OFFSET		4

#define ALT_ENTRY_SIZE		12
#define ALT_ORIG_OFFSET		0
#define ALT_NEW_OFFSET		4
#define ALT_ORIG_LEN_OFFSET	10
#define ALT_NEW_LEN_OFFSET	11

struct special_entry {
	enum special_type type;
	bool has_new_insn;
	const char *sec;
	unsigned char size, orig, new;
	unsigned char orig_len, new_len; /* group only */
};

struct special_entry entries[] = {
	{
		.type = SPECIAL_ALTERNATIVE,
		.sec = ".altinstructions",
		.size = ALT_ENTRY_SIZE,
		.orig = ALT_ORIG_OFFSET,
		.orig_len = ALT_ORIG_LEN_OFFSET,
		.new = ALT_NEW_OFFSET,
		.new_len = ALT_NEW_LEN_OFFSET,
	},
	{
		.type = SPECIAL_JUMP_LABEL,
		.has_new_insn = true,
		.sec = "__jump_table",
		.size = JUMP_ENTRY_SIZE,
		.orig = JUMP_ORIG_OFFSET,
		.new = JUMP_NEW_OFFSET,
	},
	{
		.type = SPECIAL_EX_TABLE,
		.has_new_insn = true,
		.sec = "__ex_table",
		.size = EX_ENTRY_SIZE,
		.orig = EX_ORIG_OFFSET,
		.new = EX_NEW_OFFSET,
	},
	{},
};

static int get_alt_entry(struct elf *elf, struct special_entry *entry,
			 struct section *sec, int idx,
			 struct special_alt *alt)
{
	struct rela *orig_rela, *new_rela;
	unsigned long offset;

	offset = idx * entry->size;

	alt->type = entry->type;
	alt->has_new_insn = entry->has_new_insn;

	if (alt->type == SPECIAL_ALTERNATIVE) {
		alt->orig_len = *(unsigned char *)(sec->data->d_buf + offset +
						   entry->orig_len);
		alt->new_len = *(unsigned char *)(sec->data->d_buf + offset +
						  entry->new_len);
		alt->has_new_insn = alt->new_len != 0;
	}

	orig_rela = find_rela_by_dest(sec, offset + entry->orig);
	if (!orig_rela) {
		WARN_FUNC("can't find orig rela", sec, offset + entry->orig);
		return -1;
	}
	if (orig_rela->sym->type != STT_SECTION) {
		WARN_FUNC("don't know how to handle non-section rela symbol %s",
			   sec, offset + entry->orig, orig_rela->sym->name);
		return -1;
	}

	alt->orig_sec = orig_rela->sym->sec;
	alt->orig_off = orig_rela->addend;

	if (alt->has_new_insn) {
		new_rela = find_rela_by_dest(sec, offset + entry->new);
		if (!new_rela) {
			WARN_FUNC("can't find new rela",
				  sec, offset + entry->new);
			return -1;
		}

		alt->new_sec = new_rela->sym->sec;
		alt->new_off = (unsigned int) new_rela->addend;
	}

	return 0;
}

/*
 * Read all the special sections and create a list of special_alt structs which
 * describe all the alternate instructions which can be patched in or
 * redirected to at runtime.
 */
int special_get_alts(struct elf *elf, struct list_head *alts)
{
	struct special_entry *entry;
	struct section *sec;
	unsigned int nr_entries;
	struct special_alt *alt;
	int idx, ret;

	INIT_LIST_HEAD(alts);

	for (entry = entries; entry->sec; entry++) {
		sec = find_section_by_name(elf, entry->sec);
		if (!sec)
			continue;

		if (sec->len % entry->size != 0) {
			WARN("%s size not a multiple of %d",
			     sec->name, entry->size);
			return -1;
		}

		nr_entries = sec->len / entry->size;

		for (idx = 0; idx < nr_entries; idx++) {
			alt = malloc(sizeof(*alt));
			if (!alt) {
				WARN("malloc failed");
				return -1;
			}
			memset(alt, 0, sizeof(*alt));

			ret = get_alt_entry(elf, entry, sec, idx, alt);
			if (ret)
				return ret;

			list_add_tail(&alt->list, alts);
		}
	}

	return 0;
}
