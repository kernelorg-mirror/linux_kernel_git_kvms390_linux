// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Generic netlink support functions to interact with SMC module
 *
 *  Copyright IBM Corp. 2020
 *
 *  Author(s):  Guvenc Gulce <guvenc@linux.ibm.com>
 */

#include <linux/module.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/mutex.h>
#include <linux/if.h>
#include <linux/smc.h>

#include "smc_core.h"
#include "smc_netlink.h"

static const struct nla_policy smc_gen_nl_policy[SMC_GEN_MAX + 1] = {
	[SMC_GEN_UNSPEC]	= { .type = NLA_UNSPEC, },
	[SMC_GEN_SYS_INFO]	= { .type = NLA_NESTED, },
	[SMC_GEN_LGR_SMCR]	= { .type = NLA_NESTED, },
	[SMC_GEN_LINK_SMCR]	= { .type = NLA_NESTED, },
};

static int smc_nl_start(struct netlink_callback *cb)
{
	struct smc_nl_dmp_ctx *cb_ctx = smc_nl_dmp_ctx(cb);

	cb_ctx->pos[0] = 0;
	return 0;
}

/* SMC_GENL generic netlink operation definition */
static const struct genl_ops smc_gen_nl_ops[] = {
	{
		.cmd = SMC_NETLINK_GET_SYS_INFO,
		/* can be retrieved by unprivileged users */
		.dumpit = smc_nl_get_sys_info,
		.start = smc_nl_start
	},
	{
		.cmd = SMC_NETLINK_GET_LGR_SMCR,
		/* can be retrieved by unprivileged users */
		.dumpit = smcr_nl_get_lgr,
		.start = smc_nl_start
	},
	{
		.cmd = SMC_NETLINK_GET_LINK_SMCR,
		/* can be retrieved by unprivileged users */
		.dumpit = smcr_nl_get_link,
		.start = smc_nl_start
	},
};

/* SMC_GENL family definition */
struct genl_family smc_gen_nl_family __ro_after_init = {
	.hdrsize = 0,
	.name = SMC_GENL_FAMILY_NAME,
	.version = SMC_GENL_FAMILY_VERSION,
	.maxattr = SMC_GEN_MAX,
	.policy = smc_gen_nl_policy,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = smc_gen_nl_ops,
	.n_ops =  ARRAY_SIZE(smc_gen_nl_ops)
};

int __init smc_nl_init(void)
{
	return genl_register_family(&smc_gen_nl_family);
}

void smc_nl_exit(void)
{
	genl_unregister_family(&smc_gen_nl_family);
}
