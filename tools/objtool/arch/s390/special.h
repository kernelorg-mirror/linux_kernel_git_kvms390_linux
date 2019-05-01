// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _SPECIAL_H
#define _SPECIAL_H

#include <stdbool.h>
#include <elfdefs.h>

enum special_type {
	SPECIAL_EX_TABLE,
	SPECIAL_JUMP_LABEL,
	SPECIAL_ALTERNATIVE
};

struct special_alt {
	struct list_head list;

	enum special_type type;
	bool has_new_insn;

	struct section *orig_sec;
	unsigned long orig_off;

	struct section *new_sec;
	unsigned long new_off;

	unsigned int orig_len, new_len; /* group only */
};

int special_get_alts(struct elf *elf, struct list_head *alts);

#endif /* _SPECIAL_H */
