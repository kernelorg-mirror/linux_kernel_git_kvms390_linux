/*
 * Cryptographic API.
 *
 * s390 implementation of the GHASH algorithm for GCM (Galois/Counter Mode).
 *
 * Copyright IBM Corp. 2011
 * Author(s): Gerald Schaefer <gerald.schaefer@de.ibm.com>
 */

#include <crypto/internal/hash.h>
#include <linux/module.h>
#include <linux/cpufeature.h>
#include <asm/fpu/api.h>
#include <asm/cpacf.h>

void ghash_vx_init(unsigned char *key, unsigned char *key8);
void ghash_vx(const u8 *src, unsigned int len, const u8 *key, u8 *hash);

#define GHASH_BLOCK_SIZE	16
#define GHASH_DIGEST_SIZE	16

static int ghash_use_vx;

struct ghash_ctx {
	u8 key[GHASH_BLOCK_SIZE];
};

struct ghash_desc_ctx {
	u8 icv[GHASH_BLOCK_SIZE];
	u8 key[GHASH_BLOCK_SIZE];
	u8 buffer[GHASH_BLOCK_SIZE];
	u8 key8[GHASH_BLOCK_SIZE*8];
	u32 bytes;
};

static int ghash_init(struct shash_desc *desc)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	struct ghash_ctx *ctx = crypto_shash_ctx(desc->tfm);
	struct kernel_fpu vxstate;

	memset(dctx, 0, sizeof(*dctx));
	memcpy(dctx->key, ctx->key, GHASH_BLOCK_SIZE);
	if (ghash_use_vx) {
		kernel_fpu_begin(&vxstate, KERNEL_VXR);
		ghash_vx_init(dctx->key, dctx->key8);
		kernel_fpu_end(&vxstate, KERNEL_VXR);
	}

	return 0;
}

static int ghash_setkey(struct crypto_shash *tfm,
			const u8 *key, unsigned int keylen)
{
	struct ghash_ctx *ctx = crypto_shash_ctx(tfm);

	if (keylen != GHASH_BLOCK_SIZE) {
		crypto_shash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(ctx->key, key, GHASH_BLOCK_SIZE);

	return 0;
}

static int ghash_update(struct shash_desc *desc,
			 const u8 *src, unsigned int srclen)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	u8 *buf = dctx->buffer;
	struct kernel_fpu vxstate;
	unsigned int n;

	if (dctx->bytes) {
		u8 *pos = buf + (GHASH_BLOCK_SIZE - dctx->bytes);

		n = min(srclen, dctx->bytes);
		dctx->bytes -= n;
		srclen -= n;

		memcpy(pos, src, n);
		src += n;

		if (!dctx->bytes) {
			if (ghash_use_vx) {
				kernel_fpu_begin(&vxstate, KERNEL_VXR);
				ghash_vx(buf, GHASH_BLOCK_SIZE,
					 dctx->key8, dctx->icv);
				kernel_fpu_end(&vxstate, KERNEL_VXR);
			} else {
				cpacf_kimd(CPACF_KIMD_GHASH, dctx,
					   buf, GHASH_BLOCK_SIZE);
			}
		}
	}

	n = srclen & ~(GHASH_BLOCK_SIZE - 1);
	if (n) {
		if (ghash_use_vx) {
			kernel_fpu_begin(&vxstate, KERNEL_VXR);
			ghash_vx(src, n, dctx->key8, dctx->icv);
			kernel_fpu_end(&vxstate, KERNEL_VXR);
		} else {
			cpacf_kimd(CPACF_KIMD_GHASH, dctx, src, n);
		}
		src += n;
		srclen -= n;
	}

	if (srclen) {
		dctx->bytes = GHASH_BLOCK_SIZE - srclen;
		memcpy(buf, src, srclen);
	}

	return 0;
}

static int ghash_flush(struct ghash_desc_ctx *dctx)
{
	struct kernel_fpu vxstate;
	u8 *pos, *buf;

	if (!dctx->bytes)
		return 0;

	buf = dctx->buffer;
	if (ghash_use_vx) {
		kernel_fpu_begin(&vxstate, KERNEL_VXR);
		ghash_vx(buf, GHASH_BLOCK_SIZE - dctx->bytes,
			 dctx->key8, dctx->icv);
		kernel_fpu_end(&vxstate, KERNEL_VXR);
	} else {
		pos = buf + (GHASH_BLOCK_SIZE - dctx->bytes);
		memset(pos, 0, dctx->bytes);

		cpacf_kimd(CPACF_KIMD_GHASH, dctx,
			   buf, GHASH_BLOCK_SIZE);
	}
	dctx->bytes = 0;
	return 0;
}

static int ghash_final(struct shash_desc *desc, u8 *dst)
{
	struct ghash_desc_ctx *dctx = shash_desc_ctx(desc);
	int ret;

	ret = ghash_flush(dctx);
	if (!ret)
		memcpy(dst, dctx->icv, GHASH_BLOCK_SIZE);
	return ret;
}

static struct shash_alg ghash_alg = {
	.digestsize	= GHASH_DIGEST_SIZE,
	.init		= ghash_init,
	.update		= ghash_update,
	.final		= ghash_final,
	.setkey		= ghash_setkey,
	.descsize	= sizeof(struct ghash_desc_ctx),
	.base		= {
		.cra_name		= "ghash",
		.cra_driver_name	= "ghash-s390",
		.cra_priority		= 300,
		.cra_flags		= CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize		= GHASH_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct ghash_ctx),
		.cra_module		= THIS_MODULE,
	},
};

static int __init ghash_mod_init(void)
{
	struct cpuid cpu_id;

	get_cpu_id(&cpu_id);
	if (MACHINE_HAS_VX && (cpu_id.machine == 0x2964 ||
			       cpu_id.machine == 0x2965))
		ghash_use_vx = 1;
	else if (!cpacf_query(CPACF_KIMD, CPACF_KIMD_GHASH))
		return -ENODEV;

	return crypto_register_shash(&ghash_alg);
}

static void __exit ghash_mod_exit(void)
{
	crypto_unregister_shash(&ghash_alg);
}

static const struct cpu_feature ghash_cpu_features[] = {
	{ .feature = cpu_feature(MSA) },
	{ .feature = cpu_feature(VXRS) },
	{ },
};
MODULE_DEVICE_TABLE(cpu, ghash_cpu_features);

module_init(ghash_mod_init);
module_exit(ghash_mod_exit);

MODULE_ALIAS_CRYPTO("ghash");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GHASH Message Digest Algorithm, s390 implementation");
