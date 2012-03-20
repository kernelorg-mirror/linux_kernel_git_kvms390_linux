/*
 * Message printing with message catalog prefixes.
 *
 * Copyright IBM Corp. 2012
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/jhash.h>
#include <linux/device.h>

static inline u32 __printk_jhash(const void *key, u32 length)
{
	u32 a, b, c, len;
	const u8 *k;
	u8 zk[12];

	a = b = 0x9e3779b9;
	c = 0;
	for (len = length + 12, k = key; len >= 12; len -= 12, k += 12) {
		if (len >= 24) {
			a += k[0] | k[1] << 8 | k[2] << 16 | k[3] << 24;
			b += k[4] | k[5] << 8 | k[6] << 16 | k[7] << 24;
			c += k[8] | k[9] << 8 | k[10] << 16 | k[11] << 24;
		} else {
			memset(zk, 0, 12);
			memcpy(zk, k, len - 12);
			a += zk[0] | zk[1] << 8 | zk[2] << 16 | zk[3] << 24;
			b += zk[4] | zk[5] << 8 | zk[6] << 16 | zk[7] << 24;
			c += (u32) zk[8] << 8;
			c += (u32) zk[9] << 16;
			c += (u32) zk[10] << 24;
			c += length;
		}
		a -= b + c; a ^= (c>>13);
		b -= a + c; b ^= (a<<8);
		c -= a + b; c ^= (b>>13);
		a -= b + c; a ^= (c>>12);
		b -= a + c; b ^= (a<<16);
		c -= a + b; c ^= (b>>5);
		a -= b + c; a ^= (c>>3);
		b -= a + c; b ^= (a<<10);
		c -= a + b; c ^= (b>>15);
	}
	return c;
}

/**
 * printk_hash - print a kernel message include a hash over the message
 * @prefix: message prefix including the ".%06x" for the hash
 * @fmt: format string
 */
asmlinkage int printk_hash(const char *prefix, const char *fmt, ...)
{
	va_list args;
	int r;

	r = printk(prefix, __printk_jhash(fmt, strlen(fmt)) & 0xffffff);
	va_start(args, fmt);
	r += vprintk(fmt, args);
	va_end(args);

	return r;
}
EXPORT_SYMBOL(printk_hash);
