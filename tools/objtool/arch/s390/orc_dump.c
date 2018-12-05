// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Coprt. 2019
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#include <unistd.h>
#include <orc.h>
#include <warn.h>

static void orc_dump_one_entry(struct orc_entry *orc)
{
	int first, i, j;
	u16 mask;

	printf(" %08x ", *(unsigned int *) orc);
	switch (orc->type) {
	default:
	case ORC_TYPE_REGISTER:
		if (orc->offset)
			printf("sp:%d+%%r%i ", orc->offset, orc->reg0);
		else
			printf("sp:%%r%i ", orc->reg0);
		printf("ra:%%r%i", orc->reg1);
		break;
	case ORC_TYPE_RESTORE:
		mask = orc->mask;
		for (first = 6; first < 16; first++)
			if (mask & (0x8000U >> first))
				break;
		if (mask & (0x8000U >> 15))
			printf("sp:%d(%%r%i) ",
			       orc->offset + (15 - first)*8, orc->reg0);
		else
			printf("sp:%%r%i ", orc->reg0);
		if (mask & (0x8000U >> 14))
			printf("ra:%d(%%r%i) ",
			       orc->offset + (14 - first)*8, orc->reg0);
		else
			printf("ra:%%r14 ");
		printf("%d(%%r%i):", orc->offset, orc->reg0);
		for (i = first; i < 16; i++) {
			if (!(mask & (0x8000U >> i)))
				continue;
			mask &= ~(0x8000U >> i);
			for (j = i; j < 15; j++) {
				if (mask & (0x4000U >> j))
					mask &= ~(0x4000U >> j);
				else
					break;
			}
			if (i == j)
				printf("%%r%i", i);
			else
				printf("%%r%i-%%r%i", i, j);
			if (mask)
				printf(",");
			i = j;
		}
		break;
	case ORC_TYPE_PTREGS:
		if (orc->offset)
			printf("ptregs:%d+%%r%i", orc->offset, orc->reg0);
		else
			printf("ptregs:%%r%i", orc->reg0);
		break;
	case ORC_TYPE_EXPOLINE:
		printf("expoline branch register %%r%i", orc->reg0);
		break;
	}
}

static void orc_dump_entries(struct elf *elf, struct section *sec_orc,
			     struct section *sec_ip, struct section *sec_rela,
			     const char *name)
{
	Elf64_Addr orc_ip_addr, addr;
	struct orc_entry *orc;
	unsigned int symndx;
	struct symbol *sym;
	int i, nr_entries;
	GElf_Rela rela;
	int *orc_ip;

	if (sec_orc->len != sec_ip->len ||
	    (sec_orc->len % sizeof(struct orc_entry)) != 0) {
		WARN("bad .orc_unwind section size");
		return;
	}

	orc = sec_orc->data->d_buf;
	orc_ip = sec_ip->data->d_buf;
	orc_ip_addr = sec_ip->sh.sh_addr;
	nr_entries = sec_orc->len / sizeof(*orc);

	if (sec_rela && name)
		printf("%s:\n", name);

	for (i = 0; i < nr_entries; i++) {
		if (sec_rela) {
			if (!gelf_getrela(sec_rela->data, i, &rela)) {
				WARN_ELF("gelf_getrela");
				return;
			}
			addr = rela.r_addend;
		} else {
			addr = (orc_ip_addr + i*sizeof(int)) + orc_ip[i];
		}

		if (sec_rela && !name) {
			symndx = GELF_R_SYM(rela.r_info);
			sym = find_symbol_by_index(elf, symndx);
			printf("%s+0x%lx:", sym->name, addr);
		} else {
			printf("0x%08lx:", addr);
		}
		orc_dump_one_entry(orc + i);
		printf("\n");
	}
	printf("\n");
}

static struct section *orc_dump_find_section(struct elf *elf,
					     const char *prefix,
					     const char *name)
{
	struct section *sec;
	size_t len1, len2;
	char *str;

	if (name) {
		len1 = strlen(prefix);
		len2 = strlen(name);
		str = malloc(len1 + len2 + 1);
		if (!str) {
			WARN("malloc failed");
			return NULL;
		}
		memcpy(str, prefix, len1);
		memcpy(str + len1, name, len2);
		str[len1 + len2] = 0;
	} else {
		str = strdup(prefix);
	}
	sec = find_section_by_name(elf, str);
	free(str);
	return sec;
}

static void orc_dump_by_name(struct elf *elf, const char *name)
{
	struct section *sec_orc, *sec_ip, *sec_rela;

	sec_orc = orc_dump_find_section(elf, ".orc_unwind", name);
	if (!sec_orc)
		return;
	sec_ip = orc_dump_find_section(elf, ".orc_unwind_ip", name);
	if (!sec_ip)
		return;

	sec_rela = orc_dump_find_section(elf, ".rela.orc_unwind_ip", name);

	orc_dump_entries(elf, sec_orc, sec_ip, sec_rela, name);

}

int orc_dump(const char *_objname)
{
	struct section *sec;
	struct elf *elf;

	elf = elf_open(_objname, O_RDONLY);
	if (!elf)
		return -1;

	list_for_each_entry(sec, &elf->sections, list) {
		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;
		orc_dump_by_name(elf, sec->name);
	}
	orc_dump_by_name(elf, NULL);

	elf_close(elf);

	return 0;
}
