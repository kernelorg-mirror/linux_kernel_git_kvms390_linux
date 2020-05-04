/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Definitions for generic netlink based configuration of an SMC-R PNET table
 *  Definitions for SMC Linkgroup and Devices.
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Thomas Richter <tmricht@linux.vnet.ibm.com>
 */

#ifndef _UAPI_LINUX_SMC_H_
#define _UAPI_LINUX_SMC_H_

/* Netlink SMC_PNETID attributes */
enum {
	SMC_PNETID_UNSPEC,
	SMC_PNETID_NAME,
	SMC_PNETID_ETHNAME,
	SMC_PNETID_IBNAME,
	SMC_PNETID_IBPORT,
	__SMC_PNETID_MAX,
	SMC_PNETID_MAX = __SMC_PNETID_MAX - 1
};

enum {				/* SMC PNET Table commands */
	SMC_PNETID_GET = 1,
	SMC_PNETID_ADD,
	SMC_PNETID_DEL,
	SMC_PNETID_FLUSH
};

#define SMCR_GENL_FAMILY_NAME		"SMC_PNETID"
#define SMCR_GENL_FAMILY_VERSION	1

#define SMC_MAX_PNETID_LEN		16 /* Max. length of PNET id */
#define SMC_LGR_ID_SIZE			4
#define SMC_MAX_HOSTNAME_LEN		32 /* Max length of hostname */
#define SMC_MAX_EID_LEN			32 /* Max length of eid */
#define SMC_MAX_PORTS			2 /* Max # of ports per ib device */
#define SMC_PCI_ID_STR_LEN		16 /* Max length of pci id string */
#endif /* _UAPI_LINUX_SMC_H */
