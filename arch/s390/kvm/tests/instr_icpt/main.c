
#include <linux/kernel.h>
#include <linux/module.h>
#include "instr_icpt.h"

MODULE_DESCRIPTION("zKVM instruction interception tests");
MODULE_LICENSE("GPL");

static struct {
	const char *name;
	int (*func)(void);
} tests[] = {
	{ "epsw", test_epsw },
	{ "pfmf", test_pfmf },
	{ "sck", test_sck },
	{ "tb", test_tb },
	{ "tprot", test_tprot },
	{ "stsi", test_stsi },
	{ "msch", test_msch },
	{ "ssch", test_ssch },
	{ "stcrw", test_stcrw },
	{ "stsch", test_stsch },
	{ "tsch", test_tsch },
	{ "*qbs", test_qbs },
	{ NULL, NULL }
};

static char last_error[256] = "n/a";

void ztst_set_err_str(const char *str)
{
	strlcpy(last_error, str, sizeof(last_error));
}

static int __init instr_icpt_mod_init(void)
{
	int i, ret;

	pr_info("----- INSTRUCTION INTERCEPTION TEST MODULE STARTED -----\n");

	for (i = 0; tests[i].func != NULL; i++) {
		pr_info("  testing %5s ...  ", tests[i].name);
		ret = tests[i].func();
		if (ret) {
			pr_err("[ FAILED ]\n");
			pr_err("Error (%i): %s\n", ret, last_error);
			return ret;
		}
		pr_info("[ OK ]\n");
	}

	pr_info("All tests done.\n");

	return 0;
}

static void __exit instr_icpt_mod_exit(void)
{
	pr_info("----- INSTRUCTION INTERCEPTION TEST MODULE STOPPED -----\n");
}

module_init(instr_icpt_mod_init);
module_exit(instr_icpt_mod_exit);
