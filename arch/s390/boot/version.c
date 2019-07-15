// SPDX-License-Identifier: GPL-2.0
#include <generated/utsrelease.h>
#include <generated/compile.h>

const char kernel_version[] = UTS_RELEASE
	" (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") " UTS_VERSION;
