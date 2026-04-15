// SPDX-License-Identifier: GPL-2.0

#include "linux/export.h"
#include <linux/kconfig.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>

#include <asm/aef.h>
#include <asm/boot_data.h>
#include <asm/sae.h>
#include <asm/sclp.h>
#include <asm/sections.h>

static struct qaaf_qmc_block qmc = {};
static struct kvm_sae_save_area save_area = {};
static struct aef_info info = {};

/**
 * kvm_init_save_area() - Initialize Guest Save Area
 * @save_area: Pointer to kvm_sae_save_area structure to initialize
 *
 * Context: Must be called before using the save area with lasrm/stiasrm instructions.
 */
void kvm_vcpu_init_save_area(struct kvm_sae_save_area *sa)
{
	memcpy(sa, &save_area, sizeof(save_area));
}
EXPORT_SYMBOL(kvm_vcpu_init_save_area);

struct qaaf_qmc_block *aef_qmc(void)
{
	return &qmc;
}
EXPORT_SYMBOL(aef_qmc);

const struct aef_info *aef_info(void)
{
	return &info;
}
EXPORT_SYMBOL(aef_info);

static int __init aef_init_save_area(void)
{
	int ret;

	union qaaf_gr0_gisrsa gr0 = {
		.fc = QAAF_FC_GISRSA,
		.saf = SAE_SAVE_AREA_FORMAT_0,
	};

	ret = qaaf(gr0.val, (union qaaf_block *)&save_area);
	if (ret)
		return ret;

	return 0;
}

static int  __init aef_query_info(void)
{
	int ret;

	if (IS_ENABLED(CONFIG_KVM_S390_ARM64)) {
		info.sae_avail = sclp.has_aef;
		info.ptff_avail = ptff_query(PTFF_QAGTO) &&
				  ptff_query(PTFF_QAGPT);
		info.arm_guest_supp = info.sae_avail && info.ptff_avail;
	}
	if (!info.sae_avail)
		return 0;

	ret = qaaf(QAAF_FC_QMC, (union qaaf_block *)&qmc);
	if (ret)
		return ret;

	info.supp_state_desc_formats = qmc.ssdf;
	info.supp_save_area_formats = qmc.ssaf;
	info.max_num_vcpu = qmc.maxncpu;

	return 0;
}

static int __init aef_sysfs_init(void)
{
	int rc = -ENOMEM;

	if (!IS_ENABLED(CONFIG_KVM_S390_ARM64))
		return 0;

	rc = aef_query_info();
	if (rc)
		return rc;

	rc = aef_init_save_area();
	if (rc)
		return rc;

	return 0;
}

arch_initcall(aef_sysfs_init);
