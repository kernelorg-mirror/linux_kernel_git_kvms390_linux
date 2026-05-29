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

static struct kset *aef_query_kset;
static struct kobject *aef_kobj;

#define aef_sysfs_qval_def(_name)					\
	static ssize_t _name##_show(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    char *buf)				\
	{								\
		return sysfs_emit(buf, "%lx\n", info._name);		\
	}								\
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define aef_sysfs_qval_attr(_name) &_name##_attr.attr

aef_sysfs_qval_def(arm_guest_supp);
aef_sysfs_qval_def(sae_avail);
aef_sysfs_qval_def(ptff_avail);
aef_sysfs_qval_def(supp_state_desc_formats);
aef_sysfs_qval_def(supp_save_area_formats);
aef_sysfs_qval_def(max_num_vcpu);

static ssize_t qmc_read(struct file *filp, struct kobject *kobj,
			const struct bin_attribute *attr, char *buf, loff_t off,
			size_t count)
{
	return memory_read_from_buffer(buf, count, &off, &qmc, sizeof(qmc));
}

BIN_ATTR_RO(qmc, sizeof(qmc));

static ssize_t save_area_read(struct file *filp, struct kobject *kobj,
			      const struct bin_attribute *attr, char *buf,
			      loff_t off, size_t count)
{
	return memory_read_from_buffer(buf, count, &off, &save_area,
				       sizeof(save_area));
}

BIN_ATTR_RO(save_area, sizeof(save_area));

static struct attribute *aef_query_attrs[] = {
	aef_sysfs_qval_attr(sae_avail),
	aef_sysfs_qval_attr(ptff_avail),
	aef_sysfs_qval_attr(supp_state_desc_formats),
	aef_sysfs_qval_attr(supp_save_area_formats),
	aef_sysfs_qval_attr(max_num_vcpu),
	NULL,
};

static const struct bin_attribute *aef_query_bin_attrs[] = {
	&bin_attr_qmc,
	&bin_attr_save_area,
	NULL,
};

static struct attribute_group aef_query_attr_group = {
	.attrs = aef_query_attrs,
	.bin_attrs = aef_query_bin_attrs,
};

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

	aef_kobj = kobject_create_and_add("aef", firmware_kobj);
	if (!aef_kobj)
		return -ENOMEM;

	rc = sysfs_create_file(aef_kobj, aef_sysfs_qval_attr(arm_guest_supp));
	if (rc)
		goto out_kobj;

	aef_query_kset = kset_create_and_add("query", NULL, aef_kobj);
	if (!aef_query_kset)
		goto out_arm_guest_supp;

	rc = sysfs_create_group(&aef_query_kset->kobj, &aef_query_attr_group);
	if (rc)
		goto out_kset;

	return 0;

out_kset:
	kset_unregister(aef_query_kset);
out_arm_guest_supp:
	sysfs_remove_file(aef_kobj, &arm_guest_supp_attr.attr);
out_kobj:
	kobject_del(aef_kobj);
	kobject_put(aef_kobj);

	return rc;
}

arch_initcall(aef_sysfs_init);
