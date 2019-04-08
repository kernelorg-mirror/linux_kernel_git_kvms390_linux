// SPDX-License-Identifier: GPL-2.0
/*
 * s390 code for kexec_file_load system call
 *
 * Copyright IBM Corp. 2018
 *
 * Author(s): Philipp Rudo <prudo@linux.vnet.ibm.com>
 */

#include <linux/elf.h>
#include <linux/kexec.h>
#include <asm/setup.h>

const struct kexec_file_ops * const kexec_file_loaders[] = {
	&s390_kexec_elf_ops,
	&s390_kexec_image_ops,
	NULL,
};

int *kexec_file_update_kernel(struct kimage *image,
			      struct s390_load_data *data)
{
	unsigned long *loc;

	if (image->cmdline_buf_len >= ARCH_COMMAND_LINE_SIZE)
		return ERR_PTR(-EINVAL);

	if (image->cmdline_buf_len)
		memcpy(data->kernel_buf + COMMAND_LINE_OFFSET,
		       image->cmdline_buf, image->cmdline_buf_len);

	if (image->type == KEXEC_TYPE_CRASH) {
		loc = (unsigned long *)(data->kernel_buf + OLDMEM_BASE_OFFSET);
		*loc = crashk_res.start;

		loc = (unsigned long *)(data->kernel_buf + OLDMEM_SIZE_OFFSET);
		*loc = crashk_res.end - crashk_res.start + 1;
	}

	if (image->initrd_buf) {
		loc = (unsigned long *)(data->kernel_buf + INITRD_START_OFFSET);
		*loc = data->initrd_load_addr;

		loc = (unsigned long *)(data->kernel_buf + INITRD_SIZE_OFFSET);
		*loc = image->initrd_buf_len;
	}

	return NULL;
}

static int kexec_file_update_purgatory(struct kimage *image)
{
	u64 entry, type;
	int ret;

	if (image->type == KEXEC_TYPE_CRASH) {
		entry = STARTUP_KDUMP_OFFSET;
		type = KEXEC_TYPE_CRASH;
	} else {
		entry = STARTUP_NORMAL_OFFSET;
		type = KEXEC_TYPE_DEFAULT;
	}

	ret = kexec_purgatory_get_set_symbol(image, "kernel_entry", &entry,
					     sizeof(entry), false);
	if (ret)
		return ret;

	ret = kexec_purgatory_get_set_symbol(image, "kernel_type", &type,
					     sizeof(type), false);
	if (ret)
		return ret;

	if (image->type == KEXEC_TYPE_CRASH) {
		u64 crash_size;

		ret = kexec_purgatory_get_set_symbol(image, "crash_start",
						     &crashk_res.start,
						     sizeof(crashk_res.start),
						     false);
		if (ret)
			return ret;

		crash_size = crashk_res.end - crashk_res.start + 1;
		ret = kexec_purgatory_get_set_symbol(image, "crash_size",
						     &crash_size,
						     sizeof(crash_size),
						     false);
	}
	return ret;
}

int kexec_file_add_purgatory(struct kimage *image, struct s390_load_data *data)
{
	struct kexec_buf buf;
	int ret;

	buf.image = image;

	data->memsz = ALIGN(data->memsz, PAGE_SIZE);
	buf.mem = data->memsz;
	if (image->type == KEXEC_TYPE_CRASH)
		buf.mem += crashk_res.start;

	ret = kexec_load_purgatory(image, &buf);
	if (ret)
		return ret;

	ret = kexec_file_update_purgatory(image);
	return ret;
}

int kexec_file_add_initrd(struct kimage *image, struct s390_load_data *data,
			  char *initrd, unsigned long initrd_len)
{
	struct kexec_buf buf;
	int ret;

	buf.image = image;

	buf.buffer = initrd;
	buf.bufsz = initrd_len;

	data->memsz = ALIGN(data->memsz, PAGE_SIZE);
	buf.mem = data->memsz;
	if (image->type == KEXEC_TYPE_CRASH)
		buf.mem += crashk_res.start;
	buf.memsz = buf.bufsz;

	data->initrd_load_addr = buf.mem;
	data->memsz += buf.memsz;

	ret = kexec_add_buffer(&buf);
	return ret;
}

int arch_kexec_apply_relocations_add(struct purgatory_info *pi,
				     Elf_Shdr *section,
				     const Elf_Shdr *relsec,
				     const Elf_Shdr *symtab)
{
	Elf_Rela *relas;
	int i, r_type;

	relas = (void *)pi->ehdr + relsec->sh_offset;

	for (i = 0; i < relsec->sh_size / sizeof(*relas); i++) {
		const Elf_Sym *sym;	/* symbol to relocate */
		unsigned long addr;	/* final location after relocation */
		unsigned long val;	/* relocated symbol value */
		void *loc;		/* tmp location to modify */

		sym = (void *)pi->ehdr + symtab->sh_offset;
		sym += ELF64_R_SYM(relas[i].r_info);

		if (sym->st_shndx == SHN_UNDEF)
			return -ENOEXEC;

		if (sym->st_shndx == SHN_COMMON)
			return -ENOEXEC;

		if (sym->st_shndx >= pi->ehdr->e_shnum &&
		    sym->st_shndx != SHN_ABS)
			return -ENOEXEC;

		loc = pi->purgatory_buf;
		loc += section->sh_offset;
		loc += relas[i].r_offset;

		val = sym->st_value;
		if (sym->st_shndx != SHN_ABS)
			val += pi->sechdrs[sym->st_shndx].sh_addr;
		val += relas[i].r_addend;

		addr = section->sh_addr + relas[i].r_offset;

		r_type = ELF64_R_TYPE(relas[i].r_info);
		arch_kexec_do_relocs(r_type, loc, val, addr);
	}
	return 0;
}

int arch_kexec_kernel_image_probe(struct kimage *image, void *buf,
				  unsigned long buf_len)
{
	/* A kernel must be at least large enough to contain head.S. During
	 * load memory in head.S will be accessed, e.g. to register the next
	 * command line. If the next kernel were smaller the current kernel
	 * will panic at load.
	 */
	if (buf_len < HEAD_END)
		return -ENOEXEC;

	return kexec_image_probe_default(image, buf, buf_len);
}
