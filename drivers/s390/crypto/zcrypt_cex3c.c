// SPDX-License-Identifier: GPL-2.0+
/*
 *  zcrypt 2.1.0
 *
 *  Copyright IBM Corp. 2001, 2018
 *  Author(s): Robert Burroughs
 *	       Eric Rossman (edrossma@us.ibm.com)
 *
 *  Hotplug & misc device support: Jochen Roehrig (roehrig@de.ibm.com)
 *  Major cleanup & driver split: Martin Schwidefsky <schwidefsky@de.ibm.com>
 *				  Ralph Wuerthner <rwuerthn@de.ibm.com>
 *  MSGTYPE restruct:		  Holger Dengler <hd@linux.vnet.ibm.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/mod_devicetable.h>

#include "ap_bus.h"
#include "zcrypt_api.h"
#include "zcrypt_error.h"
#include "zcrypt_msgtype6.h"
#include "zcrypt_cex3c.h"
#include "zcrypt_cca_key.h"

#define CEX3C_MIN_MOD_SIZE	 16	/*  128 bits	*/
#define CEX3C_MAX_MOD_SIZE	512	/* 4096 bits	*/

#define CEX3C_MAX_XCRB_MESSAGE_SIZE (12*1024)

#define CEX3C_CLEANUP_TIME	(15*HZ)

MODULE_AUTHOR("IBM Corporation");
MODULE_DESCRIPTION("CEX3C Cryptographic Coprocessor device driver, " \
		   "Copyright IBM Corp. 2001, 2018");
MODULE_LICENSE("GPL");

static struct ap_device_id zcrypt_cex3c_card_ids[] = {
	{ .dev_type = AP_DEVICE_TYPE_CEX3C,
	  .match_flags = AP_DEVICE_ID_MATCH_CARD_TYPE },
	{ /* end of list */ },
};

MODULE_DEVICE_TABLE(ap, zcrypt_cex3c_card_ids);

static struct ap_device_id zcrypt_cex3c_queue_ids[] = {
	{ .dev_type = AP_DEVICE_TYPE_CEX3C,
	  .match_flags = AP_DEVICE_ID_MATCH_QUEUE_TYPE },
	{ /* end of list */ },
};

MODULE_DEVICE_TABLE(ap, zcrypt_cex3c_queue_ids);

/**
 * Probe function for CEX3C card devices. It always accepts the
 * AP device since the bus_match already checked the hardware type.
 * @ap_dev: pointer to the AP card device.
 */
static int zcrypt_cex3c_card_probe(struct ap_device *ap_dev)
{
	/*
	 * Normalized speed ratings per crypto adapter
	 * MEX_1k, MEX_2k, MEX_4k, CRT_1k, CRT_2k, CRT_4k, RNG, SECKEY
	 */
	static const int CEX3C_SPEED_IDX[] = {
		500,  700, 1400,  550,	800, 1500,  80, 10};

	struct ap_card *ac = to_ap_card(&ap_dev->device);
	struct zcrypt_card *zc;
	int rc = 0;

	zc = zcrypt_card_alloc();
	if (!zc)
		return -ENOMEM;
	zc->card = ac;
	ac->private = zc;

	if (ac->ap_dev.device_type == AP_DEVICE_TYPE_CEX3C) {
		zc->user_space_type = ZCRYPT_CEX3C;
		zc->type_string = "CEX3C";
		memcpy(zc->speed_rating, CEX3C_SPEED_IDX,
		       sizeof(CEX3C_SPEED_IDX));
		zc->min_mod_size = CEX3C_MIN_MOD_SIZE;
		zc->max_mod_size = CEX3C_MAX_MOD_SIZE;
		zc->max_exp_bit_length = CEX3C_MAX_MOD_SIZE;
	} else {
		zcrypt_card_free(zc);
		return -ENODEV;
	}
	zc->online = 1;

	rc = zcrypt_card_register(zc);
	if (rc) {
		ac->private = NULL;
		zcrypt_card_free(zc);
	}

	return rc;
}

/**
 * This is called to remove the CEX3C card driver information
 * if an AP card device is removed.
 */
static void zcrypt_cex3c_card_remove(struct ap_device *ap_dev)
{
	struct zcrypt_card *zc = to_ap_card(&ap_dev->device)->private;

	if (zc)
		zcrypt_card_unregister(zc);
}

static struct ap_driver zcrypt_cex3c_card_driver = {
	.probe = zcrypt_cex3c_card_probe,
	.remove = zcrypt_cex3c_card_remove,
	.ids = zcrypt_cex3c_card_ids,
};

/**
 * Probe function for CEX3C queue devices. It always accepts the
 * AP device since the bus_match already checked the hardware type.
 * @ap_dev: pointer to the AP card device.
 */
static int zcrypt_cex3c_queue_probe(struct ap_device *ap_dev)
{
	struct ap_queue *aq = to_ap_queue(&ap_dev->device);
	struct zcrypt_queue *zq;
	int rc;

	zq = zcrypt_queue_alloc(CEX3C_MAX_XCRB_MESSAGE_SIZE);
	if (!zq)
		return -ENOMEM;
	zq->ops = zcrypt_msgtype(MSGTYPE06_NAME, MSGTYPE06_VARIANT_DEFAULT);
	zq->queue = aq;
	zq->online = 1;
	atomic_set(&zq->load, 0);
	ap_queue_init_reply(aq, &zq->reply);
	aq->request_timeout = CEX3C_CLEANUP_TIME;
	aq->private = zq;
	rc = zcrypt_queue_register(zq);
	if (rc) {
		aq->private = NULL;
		zcrypt_queue_free(zq);
	}

	return rc;
}

/**
 * This is called to remove the CEX3C queue driver information
 * if an AP queue device is removed.
 */
static void zcrypt_cex3c_queue_remove(struct ap_device *ap_dev)
{
	struct ap_queue *aq = to_ap_queue(&ap_dev->device);
	struct zcrypt_queue *zq = aq->private;

	ap_queue_remove(aq);
	if (zq)
		zcrypt_queue_unregister(zq);
}

static struct ap_driver zcrypt_cex3c_queue_driver = {
	.probe = zcrypt_cex3c_queue_probe,
	.remove = zcrypt_cex3c_queue_remove,
	.suspend = ap_queue_suspend,
	.resume = ap_queue_resume,
	.ids = zcrypt_cex3c_queue_ids,
};

int __init zcrypt_cex3c_init(void)
{
	int rc;

	rc = ap_driver_register(&zcrypt_cex3c_card_driver,
				THIS_MODULE, "cex3ccard");
	if (rc)
		return rc;

	rc = ap_driver_register(&zcrypt_cex3c_queue_driver,
				THIS_MODULE, "cex3cqueue");
	if (rc)
		ap_driver_unregister(&zcrypt_cex3c_card_driver);

	return rc;
}

void zcrypt_cex3c_exit(void)
{
	ap_driver_unregister(&zcrypt_cex3c_queue_driver);
	ap_driver_unregister(&zcrypt_cex3c_card_driver);
}

module_init(zcrypt_cex3c_init);
module_exit(zcrypt_cex3c_exit);
