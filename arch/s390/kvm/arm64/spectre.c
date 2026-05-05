// SPDX-License-Identifier: GPL-2.0

#include <arm64/spectre.h>

enum mitigation_state arm64_get_spectre_v2_state(void)
{
	return SPECTRE_UNAFFECTED;
}

enum mitigation_state arm64_get_meltdown_state(void)
{
	return SPECTRE_UNAFFECTED;
}

