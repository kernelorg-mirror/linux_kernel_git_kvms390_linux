// SPDX-License-Identifier: GPL-2.0

#include <linux/export.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>

#include <asm/aef.h>
#include <asm/sae.h>
#include <asm/sclp.h>

static struct qaaf_qmc_block qmc = {};
static struct kvm_sae_save_area save_area = {};

const struct kvm_sae_save_area *aef_gisrsa(void)
{
	return &save_area;
}
EXPORT_SYMBOL_GPL(aef_gisrsa);

const struct qaaf_qmc_block *aef_qmc(void)
{
	return &qmc;
}
EXPORT_SYMBOL_GPL(aef_qmc);

/* set once the QMC block and GISRSA save area were fetched successfully */
static bool aef_valid;

/**
 * aef_usable() - Report whether the QAAF query data is available
 *
 * false if sclp.has_aef is not set or the QAAF instruction failed.
 */
bool aef_usable(void)
{
	return aef_valid;
}
EXPORT_SYMBOL_GPL(aef_usable);

static int __init aef_init_save_area(void)
{
	int ret;

	union qaaf_gr0_gisrsa gr0 = {
		.fc = QAAF_FC_GISRSA,
		.saf = SAE_SAVE_AREA_FORMAT_0,
	};

	if (!sclp.has_aef)
		return 0;

	ret = qaaf(gr0.val, (union qaaf_block *)&save_area);
	if (ret)
		return -EIO;

	return 0;
}

static int __init aef_query_info(void)
{
	int ret;

	if (!sclp.has_aef)
		return 0;

	ret = qaaf(QAAF_FC_QMC, (union qaaf_block *)&qmc);
	if (ret)
		return -EIO;

	return 0;
}

static int __init aef_sysfs_init(void)
{
	int rc;

	if (!sclp.has_aef)
		return 0;

	rc = aef_query_info();
	if (rc)
		return rc;

	rc = aef_init_save_area();
	if (rc)
		return rc;

	aef_valid = true;

	return 0;
}

arch_initcall(aef_sysfs_init);
