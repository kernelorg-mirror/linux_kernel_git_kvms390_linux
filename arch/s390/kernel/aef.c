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
static struct aef_info {
	unsigned long arm_guest_supp;
	unsigned long sae_avail;
	unsigned long ptff_avail;
	unsigned long edat2_avail;
	unsigned long supp_state_desc_formats;
	unsigned long supp_save_area_formats;
	unsigned long max_num_vcpu;
} info = {};

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

static struct kset *aef_query_kset;
static struct kobject *aef_kobj;

#define aef_sysfs_qval_def(_name, _fmt)				\
	static ssize_t _name##_show(struct kobject *kobj,		\
				    struct kobj_attribute *attr,	\
				    char *buf)				\
	{								\
		return sysfs_emit(buf, _fmt "\n", info._name);		\
	}								\
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define aef_sysfs_qval_attr(_name) &_name##_attr.attr

aef_sysfs_qval_def(arm_guest_supp, "%lu");
aef_sysfs_qval_def(sae_avail, "%lu");
aef_sysfs_qval_def(ptff_avail, "%lu");
aef_sysfs_qval_def(edat2_avail, "%lu");
aef_sysfs_qval_def(supp_state_desc_formats, "0x%lx");
aef_sysfs_qval_def(supp_save_area_formats, "0x%lx");
aef_sysfs_qval_def(max_num_vcpu, "%lu");

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
	aef_sysfs_qval_attr(edat2_avail),
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

static void __init aef_info_init(void)
{
	info.sae_avail = sclp.has_aef;
	info.ptff_avail = ptff_query(PTFF_QAGTO) && ptff_query(PTFF_QAGPT);
	info.edat2_avail = cpu_has_edat2();
	info.arm_guest_supp = info.sae_avail && info.ptff_avail && info.edat2_avail;
	info.supp_state_desc_formats = qmc.ssdf;
	info.supp_save_area_formats = qmc.ssaf;
	info.max_num_vcpu = qmc.maxncpu + 1;
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

	/* sysfs failure below does not invalidate the AEF data */
	aef_valid = true;

	aef_info_init();

	aef_kobj = kobject_create_and_add("aef", firmware_kobj);
	if (!aef_kobj)
		return -ENOMEM;

	rc = sysfs_create_file(aef_kobj, aef_sysfs_qval_attr(arm_guest_supp));
	if (rc)
		goto out_kobj;

	aef_query_kset = kset_create_and_add("query", NULL, aef_kobj);
	if (!aef_query_kset) {
		rc = -ENOMEM;
		goto out_arm_guest_supp;
	}

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
