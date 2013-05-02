/*
 * IOCTL interface for hypfs
 *
 * Copyright IBM Corp. 2013
 *
 * Author: Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#ifndef _ASM_HYPFS_CTL_H
#define _ASM_HYPFS_CTL_H

#include <linux/types.h>

struct hypfs_diag304 {
	__u8	reserved[3];
	__u8	cpu_type;
	__u32	sub_code;
	__u64	lpib_ptr;
	__u64	return_code;
} __attribute__((packed));

#define HYPFS_IOCTL_MAGIC 0x10

#define HYPFS_DIAG304 \
	_IOWR(HYPFS_IOCTL_MAGIC, 0x20, struct hypfs_diag304)

#endif
