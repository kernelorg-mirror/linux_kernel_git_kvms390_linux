/*
 * early_printk.c - code for early console output with virtio_console
 * split off from kvm_virtio.c
 *
 * Copyright IBM Corp. 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (version 2 only)
 * as published by the Free Software Foundation.
 *
 *    Author(s): Christian Borntraeger <borntraeger@de.ibm.com>
 */

#include <linux/kernel_stat.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/virtio_console.h>
#include <asm/kvm_para.h>
#include <asm/kvm_virtio.h>
#include <asm/setup.h>
#include <asm/sclp.h>

static __init int early_put_chars(u32 vtermno, const char *buf, int count)
{
	char scratch[17];
	unsigned int len = count;

	if (len > sizeof(scratch) - 1)
		len = sizeof(scratch) - 1;
	scratch[len] = '\0';
	memcpy(scratch, buf, len);
	kvm_hypercall1(KVM_S390_VIRTIO_NOTIFY, __pa(scratch));
	return len;
}

static int __init s390_virtio_console_init(void)
{
	if (sclp_has_vt220() || sclp_has_linemode())
		return -ENODEV;
	return virtio_cons_early_init(early_put_chars);
}
console_initcall(s390_virtio_console_init);
