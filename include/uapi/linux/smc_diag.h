/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_SMC_DIAG_H_
#define _UAPI_SMC_DIAG_H_

#include <linux/types.h>
#include <linux/inet_diag.h>
#include <linux/smc.h>
#include <rdma/ib_user_verbs.h>

#define SMC_DIAG_EXTS_PER_CMD 16
/* Sequence numbers */
enum {
	MAGIC_SEQ = 123456,
	MAGIC_SEQ_V2,
	MAGIC_SEQ_V2_ACK,
};

/* Request structure */
struct smc_diag_req {
	__u8	diag_family;
	__u8	pad[2];
	__u8	diag_ext;		/* Query extended information */
	struct inet_diag_sockid	id;
};

/* Request structure v2 */
struct smc_diag_req_v2 {
	__u8	diag_family;
	__u8	pad[2];
	__u8	diag_ext;		/* Query extended information */
	struct inet_diag_sockid	id;
	__u32	cmd;
	__u32	cmd_ext;
	__u8	cmd_val[8];
};

/* Base info structure. It contains socket identity (addrs/ports/cookie) based
 * on the internal clcsock, and more SMC-related socket data
 */
struct smc_diag_msg {
	__u8		diag_family;
	__u8		diag_state;
	union {
		__u8	diag_mode;
		__u8	diag_fallback; /* the old name of the field */
	};
	__u8		diag_shutdown;
	struct inet_diag_sockid id;

	__u32		diag_uid;
	__aligned_u64	diag_inode;
};

/* Mode of a connection */
enum {
	SMC_DIAG_MODE_SMCR,
	SMC_DIAG_MODE_FALLBACK_TCP,
	SMC_DIAG_MODE_SMCD,
};

/* Extensions */

enum {
	SMC_DIAG_NONE,
	SMC_DIAG_CONNINFO,
	SMC_DIAG_LGRINFO,
	SMC_DIAG_SHUTDOWN,
	SMC_DIAG_DMBINFO,
	SMC_DIAG_FALLBACK,
	__SMC_DIAG_MAX,
};

/* V2 Commands */
enum {
	SMC_DIAG_GET_LGR_INFO = SMC_DIAG_EXTS_PER_CMD,
	SMC_DIAG_GET_DEV_INFO,
	SMC_DIAG_GET_SYS_INFO,
	__SMC_DIAG_EXT_MAX,
};

/* SMC_DIAG_GET_LGR_INFO command extensions */
enum {
	SMC_DIAG_LGR_INFO_SMCR = 1,
	SMC_DIAG_LGR_INFO_SMCR_LINK,
	SMC_DIAG_LGR_INFO_SMCD,
};

/* SMC_DIAG_GET_DEV_INFO command extensions */
enum {
	SMC_DIAG_DEV_INFO_SMCD = 1,
	SMC_DIAG_DEV_INFO_SMCR,
};

/* SMC_DIAG_GET_SYS_INFO command extensions */
enum {
	SMC_DIAG_SYS_INFO = 1,
};

#define SMC_DIAG_MAX (__SMC_DIAG_MAX - 1)
#define SMC_DIAG_EXT_MAX (__SMC_DIAG_EXT_MAX - 1)

/* SMC_DIAG_CONNINFO */

struct smc_diag_cursor {
	__u16	reserved;
	__u16	wrap;
	__u32	count;
};

struct smc_diag_conninfo {
	__u32			token;		/* unique connection id */
	__u32			sndbuf_size;	/* size of send buffer */
	__u32			rmbe_size;	/* size of RMB element */
	__u32			peer_rmbe_size;	/* size of peer RMB element */
	/* local RMB element cursors */
	struct smc_diag_cursor	rx_prod;	/* received producer cursor */
	struct smc_diag_cursor	rx_cons;	/* received consumer cursor */
	/* peer RMB element cursors */
	struct smc_diag_cursor	tx_prod;	/* sent producer cursor */
	struct smc_diag_cursor	tx_cons;	/* sent consumer cursor */
	__u8			rx_prod_flags;	/* received producer flags */
	__u8			rx_conn_state_flags; /* recvd connection flags*/
	__u8			tx_prod_flags;	/* sent producer flags */
	__u8			tx_conn_state_flags; /* sent connection flags*/
	/* send buffer cursors */
	struct smc_diag_cursor	tx_prep;	/* prepared to be sent cursor */
	struct smc_diag_cursor	tx_sent;	/* sent cursor */
	struct smc_diag_cursor	tx_fin;		/* confirmed sent cursor */
};

struct smc_diag_v2_lgr_info {
	__u8		smc_version;		/* SMC Version */
	__u8		peer_smc_release;	/* Peer SMC Version */
	__u8		peer_os;		/* Peer operating system */
	__u8		negotiated_eid[SMC_MAX_EID_LEN]; /* Negotiated EID */
	__u8		peer_hostname[SMC_MAX_HOSTNAME_LEN]; /* Peer host */
};


struct smc_system_info {
	__u8		smc_version;		/* SMC Version */
	__u8		smc_release;		/* SMC Release */
	__u8		ueid_count;		/* Number of UEIDs */
	__u8		smc_ism_is_v2;		/* Is ISM SMC v2 capable */
	__u32		reserved;		/* Reserved for future use */
	__u8		local_hostname[SMC_MAX_HOSTNAME_LEN]; /* Hostnames */
	__u8		seid[SMC_MAX_EID_LEN];	/* System EID */
	__u8		ueid[SMC_MAX_EID][SMC_MAX_EID_LEN]; /* User EIDs */
};

/* SMC_DIAG_LINKINFO */

struct smc_diag_linkinfo {
	__u8 link_id;			/* link identifier */
	__u8 ibname[IB_DEVICE_NAME_MAX]; /* name of the RDMA device */
	__u8 ibport;			/* RDMA device port number */
	__u8 gid[40];			/* local GID */
	__u8 peer_gid[40];		/* peer GID */
	/* Fields above used by legacy v1 code */
	__u32 conn_cnt;
	__u8 netdev[IFNAMSIZ];		/* ethernet device name */
	__u8 link_uid[4];		/* unique link id */
	__u8 peer_link_uid[4];		/* unique peer link id */
	__u32 link_state;		/* link state */
};

struct smc_diag_lgrinfo {
	struct smc_diag_linkinfo	lnk[1];
	__u8				role;
};

struct smc_diag_fallback {
	__u32 reason;
	__u32 peer_diagnosis;
};

struct smcd_diag_dmbinfo {		/* SMC-D Socket internals */
	__u32		linkid;		/* Link identifier */
	__aligned_u64	peer_gid;	/* Peer GID */
	__aligned_u64	my_gid;		/* My GID */
	__aligned_u64	token;		/* Token of DMB */
	__aligned_u64	peer_token;	/* Token of remote DMBE */
	/* Fields above used by legacy v1 code */
	__u8		pnet_id[SMC_MAX_PNETID_LEN]; /* Pnet ID */
	__u32		conns_num;	/* Number of connections */
	__u16		chid;		/* Linkgroup CHID */
	__u8		vlan_id;	/* Linkgroup vlan id */
	struct smc_diag_v2_lgr_info v2_lgr_info; /* SMCv2 info */
};

struct smc_diag_dev_info {
	/* Pnet ID per device port */
	__u8		pnet_id[SMC_MAX_PORTS][SMC_MAX_PNETID_LEN];
	/* whether pnetid is set by user */
	__u8		pnetid_by_user[SMC_MAX_PORTS];
	__u32		use_cnt;		/* Number of linkgroups */
	__u8		is_critical;		/* Is device critical */
	__u32		pci_fid;		/* PCI FID */
	__u16		pci_pchid;		/* PCI CHID */
	__u16		pci_vendor;		/* PCI Vendor */
	__u16		pci_device;		/* PCI Device Vendor ID */
	__u8		pci_id[SMC_PCI_ID_STR_LEN]; /* PCI ID */
	__u8		dev_name[IB_DEVICE_NAME_MAX]; /* IB Device name */
	__u8		netdev[SMC_MAX_PORTS][IFNAMSIZ]; /* Netdev name(s) */
	__u8		port_state[SMC_MAX_PORTS]; /* IB Port State */
	__u8		port_valid[SMC_MAX_PORTS]; /* Is IB Port valid */
	__u32		lnk_cnt_by_port[SMC_MAX_PORTS]; /* # lnks per port */
};

struct smc_diag_lgr {
	__u8		lgr_id[SMC_LGR_ID_SIZE]; /* Linkgroup identifier */
	__u8		lgr_role;		/* Linkgroup role */
	__u8		lgr_type;		/* Linkgroup type */
	__u8		pnet_id[SMC_MAX_PNETID_LEN]; /* Linkgroup pnet id */
	__u8		vlan_id;		/* Linkgroup vland id */
	__u32		conns_num;		/* Number of connections */
	__u8		reserved;		/* Reserved for future use */
	struct smc_diag_v2_lgr_info v2_lgr_info; /* SMCv2 info */
};
#endif /* _UAPI_SMC_DIAG_H_ */
