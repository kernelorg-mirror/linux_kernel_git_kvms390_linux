// SPDX-License-Identifier: GPL-2.0

#include <arm64/spectre.h>
#include <arm64/sysreg.h>

#include "feature.h"

enum mitigation_state arm64_get_spectre_v2_state(void)
{
	u64 pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);
	enum mitigation_state ms = SPECTRE_VULNERABLE;

	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, CSV2, pfr0) >= ID_AA64PFR0_EL1_CSV2_IMP)
		ms = SPECTRE_UNAFFECTED;

	return ms;
}

enum mitigation_state arm64_get_meltdown_state(void)
{
	u64 pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);
	enum mitigation_state ms = SPECTRE_VULNERABLE;

	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, CSV3, pfr0) >= ID_AA64PFR0_EL1_CSV3_IMP)
		ms = SPECTRE_UNAFFECTED;

	return ms;
}

enum mitigation_state arm64_get_spectre_v4_state(void)
{
	u64 pfr1 = read_sanitised_ftr_reg(SYS_ID_AA64PFR1_EL1);
	/* TODO: assuming the core is affected by spectre v4 */
	enum mitigation_state ms = SPECTRE_VULNERABLE;

	if (SYS_FIELD_GET(ID_AA64PFR1_EL1, SSBS, pfr1) >= ID_AA64PFR1_EL1_SSBS_IMP)
		ms = SPECTRE_MITIGATED;

	return ms;
}

enum mitigation_state arm64_get_spectre_bhb_state(void)
{
	u64 pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);
	enum mitigation_state ms = SPECTRE_VULNERABLE;

	if (SYS_FIELD_GET(ID_AA64PFR0_EL1, CSV2, pfr0) >= ID_AA64PFR0_EL1_CSV2_CSV2_3)
		ms = SPECTRE_UNAFFECTED;

	return ms;
}
