// SPDX-License-Identifier: GPL-2.0-only
/*
 * Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 * Monitoring SMC transport protocol sockets
 *
 * Copyright IBM Corp. 2016
 *
 * Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/smc_diag.h>
#include <net/netlink.h>
#include <net/smc.h>

#include "smc.h"
#include "smc_ib.h"
#include "smc_core.h"

struct smc_diag_dump_ctx {
	int pos[2];
};

static struct smc_diag_dump_ctx *smc_dump_context(struct netlink_callback *cb)
{
	return (struct smc_diag_dump_ctx *)cb->ctx;
}

static void smc_gid_be16_convert(__u8 *buf, u8 *gid_raw)
{
	sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		be16_to_cpu(((__be16 *)gid_raw)[0]),
		be16_to_cpu(((__be16 *)gid_raw)[1]),
		be16_to_cpu(((__be16 *)gid_raw)[2]),
		be16_to_cpu(((__be16 *)gid_raw)[3]),
		be16_to_cpu(((__be16 *)gid_raw)[4]),
		be16_to_cpu(((__be16 *)gid_raw)[5]),
		be16_to_cpu(((__be16 *)gid_raw)[6]),
		be16_to_cpu(((__be16 *)gid_raw)[7]));
}

static void smc_diag_msg_common_fill(struct smc_diag_msg *r, struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);

	memset(r, 0, sizeof(*r));
	r->diag_family = sk->sk_family;
	sock_diag_save_cookie(sk, r->id.idiag_cookie);
	if (!smc->clcsock)
		return;
	r->id.idiag_sport = htons(smc->clcsock->sk->sk_num);
	r->id.idiag_dport = smc->clcsock->sk->sk_dport;
	r->id.idiag_if = smc->clcsock->sk->sk_bound_dev_if;
	if (sk->sk_protocol == SMCPROTO_SMC) {
		r->id.idiag_src[0] = smc->clcsock->sk->sk_rcv_saddr;
		r->id.idiag_dst[0] = smc->clcsock->sk->sk_daddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (sk->sk_protocol == SMCPROTO_SMC6) {
		memcpy(&r->id.idiag_src, &smc->clcsock->sk->sk_v6_rcv_saddr,
		       sizeof(smc->clcsock->sk->sk_v6_rcv_saddr));
		memcpy(&r->id.idiag_dst, &smc->clcsock->sk->sk_v6_daddr,
		       sizeof(smc->clcsock->sk->sk_v6_daddr));
#endif
	}
}

static bool smc_diag_msg_attrs_fill(struct sock *sk, struct sk_buff *skb,
				    struct smc_diag_msg *r,
				    struct user_namespace *user_ns)
{
	if (nla_put_u8(skb, SMC_DIAG_SHUTDOWN, sk->sk_shutdown) < 0)
		return false;

	r->diag_uid = from_kuid_munged(user_ns, sock_i_uid(sk));
	r->diag_inode = sock_i_ino(sk);
	return true;
}

static bool smc_diag_fill_base_struct(struct sock *sk, struct sk_buff *skb,
				      struct netlink_callback *cb,
				      struct smc_diag_msg *r)
{
	struct smc_sock *smc = smc_sk(sk);
	struct user_namespace *user_ns;

	smc_diag_msg_common_fill(r, sk);
	r->diag_state = sk->sk_state;
	if (smc->use_fallback)
		r->diag_mode = SMC_DIAG_MODE_FALLBACK_TCP;
	else if (smc->conn.lgr && smc->conn.lgr->is_smcd)
		r->diag_mode = SMC_DIAG_MODE_SMCD;
	else
		r->diag_mode = SMC_DIAG_MODE_SMCR;
	user_ns = sk_user_ns(NETLINK_CB(cb->skb).sk);
	if (!smc_diag_msg_attrs_fill(sk, skb, r, user_ns))
		return false;

	return true;
}

static bool smc_diag_fill_fallback(struct sock *sk, struct sk_buff *skb)
{
	struct smc_diag_fallback fallback;
	struct smc_sock *smc = smc_sk(sk);

	memset(&fallback, 0, sizeof(fallback));
	fallback.reason = smc->fallback_rsn;
	fallback.peer_diagnosis = smc->peer_diagnosis;
	if (nla_put(skb, SMC_DIAG_FALLBACK, sizeof(fallback), &fallback) < 0)
		return false;

	return true;
}

static bool smc_diag_fill_conninfo(struct sock *sk, struct sk_buff *skb)
{
	struct smc_host_cdc_msg *local_tx, *local_rx;
	struct smc_diag_conninfo cinfo;
	struct smc_connection *conn;
	struct smc_sock *smc;

	smc = smc_sk(sk);
	conn = &smc->conn;
	local_tx = &conn->local_tx_ctrl;
	local_rx = &conn->local_rx_ctrl;
	memset(&cinfo, 0, sizeof(cinfo));
	cinfo.token = conn->alert_token_local;
	cinfo.sndbuf_size = conn->sndbuf_desc ? conn->sndbuf_desc->len : 0;
	cinfo.rmbe_size = conn->rmb_desc ? conn->rmb_desc->len : 0;
	cinfo.peer_rmbe_size = conn->peer_rmbe_size;

	cinfo.rx_prod.wrap = local_rx->prod.wrap;
	cinfo.rx_prod.count = local_rx->prod.count;
	cinfo.rx_cons.wrap = local_rx->cons.wrap;
	cinfo.rx_cons.count = local_rx->cons.count;

	cinfo.tx_prod.wrap = local_tx->prod.wrap;
	cinfo.tx_prod.count = local_tx->prod.count;
	cinfo.tx_cons.wrap = local_tx->cons.wrap;
	cinfo.tx_cons.count = local_tx->cons.count;

	cinfo.tx_prod_flags = *(u8 *)&local_tx->prod_flags;
	cinfo.tx_conn_state_flags = *(u8 *)&local_tx->conn_state_flags;
	cinfo.rx_prod_flags = *(u8 *)&local_rx->prod_flags;
	cinfo.rx_conn_state_flags = *(u8 *)&local_rx->conn_state_flags;

	cinfo.tx_prep.wrap = conn->tx_curs_prep.wrap;
	cinfo.tx_prep.count = conn->tx_curs_prep.count;
	cinfo.tx_sent.wrap = conn->tx_curs_sent.wrap;
	cinfo.tx_sent.count = conn->tx_curs_sent.count;
	cinfo.tx_fin.wrap = conn->tx_curs_fin.wrap;
	cinfo.tx_fin.count = conn->tx_curs_fin.count;

	if (nla_put(skb, SMC_DIAG_CONNINFO, sizeof(cinfo), &cinfo) < 0)
		return false;

	return true;
}

static bool smc_diag_fill_lgrinfo(struct sock *sk, struct sk_buff *skb)
{
	struct smc_sock *smc = smc_sk(sk);
	struct smc_diag_lgrinfo linfo;

	memset(&linfo, 0, sizeof(linfo));
	linfo.role = smc->conn.lgr->role;
	linfo.lnk[0].ibport = smc->conn.lnk->ibport;
	linfo.lnk[0].link_id = smc->conn.lnk->link_id;
	memcpy(linfo.lnk[0].ibname, smc->conn.lnk->ibname,
	       sizeof(linfo.lnk[0].ibname));
	smc_gid_be16_convert(linfo.lnk[0].gid,
			     smc->conn.lnk->gid);
	smc_gid_be16_convert(linfo.lnk[0].peer_gid,
			     smc->conn.lnk->peer_gid);

	if (nla_put(skb, SMC_DIAG_LGRINFO, sizeof(linfo), &linfo) < 0)
		return false;

	return true;
}

static bool smc_diag_fill_dmbinfo(struct sock *sk, struct sk_buff *skb)
{
	struct smc_sock *smc = smc_sk(sk);
	struct smcd_diag_dmbinfo dinfo;
	struct smc_connection *conn;

	memset(&dinfo, 0, sizeof(dinfo));
	conn = &smc->conn;
	dinfo.linkid = *((u32 *)conn->lgr->id);
	dinfo.peer_gid = conn->lgr->peer_gid;
	dinfo.my_gid = conn->lgr->smcd->local_gid;
	dinfo.token = conn->rmb_desc->token;
	dinfo.peer_token = conn->peer_token;

	if (nla_put(skb, SMC_DIAG_DMBINFO, sizeof(dinfo), &dinfo) < 0)
		return false;
	return true;
}

static int smc_diag_fill_lgr_link(struct smc_link_group *lgr,
				  struct smc_link *link,
				  struct sk_buff *skb,
				  struct netlink_callback *cb,
				  struct smc_diag_req_v2 *req)
{
	struct smc_diag_linkinfo link_info;
	int dummy = 0, rc = 0;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, MAGIC_SEQ_V2_ACK,
			cb->nlh->nlmsg_type, 0, NLM_F_MULTI);

	memset(&link_info, 0, sizeof(link_info));
	link_info.link_state = link->state;
	link_info.link_id = link->link_id;
	link_info.conn_cnt = atomic_read(&link->conn_cnt);
	link_info.ibport = link->ibport;

	memcpy(link_info.link_uid, link->link_uid,
	       sizeof(link_info.link_uid));
	snprintf(link_info.ibname, sizeof(link_info.ibname), "%s",
		 link->ibname);
	snprintf(link_info.netdev, sizeof(link_info.netdev), "%s",
		 link->ndevname);
	memcpy(link_info.peer_link_uid, link->peer_link_uid,
	       sizeof(link_info.peer_link_uid));

	smc_gid_be16_convert(link_info.gid,
			     link->gid);
	smc_gid_be16_convert(link_info.peer_gid,
			     link->peer_gid);

	/* Just a command place holder to signal back the command reply type */
	if (nla_put(skb, SMC_DIAG_GET_LGR_INFO, sizeof(dummy), &dummy) < 0)
		goto errout;
	if (nla_put(skb, SMC_DIAG_LGR_INFO_SMCR_LINK,
		    sizeof(link_info), &link_info) < 0)
		goto errout;

	nlmsg_end(skb, nlh);
	return rc;

errout:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int smc_diag_fill_lgr(struct smc_link_group *lgr,
			     struct sk_buff *skb,
			     struct netlink_callback *cb,
			     struct smc_diag_req_v2 *req)
{
	struct smc_diag_lgr lgr_link;
	int dummy = 0;
	int rc = 0;

	memset(&lgr_link, 0, sizeof(lgr_link));
	memcpy(&lgr_link.lgr_id, lgr->id, sizeof(lgr->id));
	lgr_link.lgr_role = lgr->role;
	lgr_link.lgr_type = lgr->type;
	lgr_link.conns_num = lgr->conns_num;
	lgr_link.vlan_id = lgr->vlan_id;
	memcpy(lgr_link.pnet_id, lgr->pnet_id, sizeof(lgr_link.pnet_id));

	/* Just a command place holder to signal back the command reply type */
	if (nla_put(skb, SMC_DIAG_GET_LGR_INFO, sizeof(dummy), &dummy) < 0)
		goto errout;
	if (nla_put(skb, SMC_DIAG_LGR_INFO_SMCR,
		    sizeof(lgr_link), &lgr_link) < 0)
		goto errout;

	return rc;
errout:
	return -EMSGSIZE;
}

static int smc_diag_handle_lgr(struct smc_link_group *lgr,
			       struct sk_buff *skb,
			       struct netlink_callback *cb,
			       struct smc_diag_req_v2 *req)
{
	struct nlmsghdr *nlh;
	int i, rc = 0;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, MAGIC_SEQ_V2_ACK,
			cb->nlh->nlmsg_type, 0, NLM_F_MULTI);
	if (!nlh)
		return -EMSGSIZE;

	rc = smc_diag_fill_lgr(lgr, skb, cb, req);
	if (rc < 0)
		goto errout;

	nlmsg_end(skb, nlh);

	if ((req->cmd_ext & (1 << (SMC_DIAG_LGR_INFO_SMCR_LINK - 1)))) {
		for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++) {
			if (!smc_link_usable(&lgr->lnk[i]))
				continue;
			rc = smc_diag_fill_lgr_link(lgr, &lgr->lnk[i], skb,
						    cb, req);
			if (rc < 0)
				goto errout;
		}
	}
	return rc;

errout:
	nlmsg_cancel(skb, nlh);
	return rc;
}

static int smc_diag_fill_lgr_list(struct smc_lgr_list *smc_lgr,
				  struct sk_buff *skb,
				  struct netlink_callback *cb,
				  struct smc_diag_req_v2 *req)
{
	struct smc_diag_dump_ctx *cb_ctx = smc_dump_context(cb);
	struct smc_link_group *lgr;
	int snum = cb_ctx->pos[0];
	int rc = 0, num = 0;

	spin_lock_bh(&smc_lgr->lock);
	list_for_each_entry(lgr, &smc_lgr->list, list) {
		if (num < snum)
			goto next;
		rc = smc_diag_handle_lgr(lgr, skb, cb, req);
		if (rc < 0)
			goto errout;
next:
		num++;
	}
errout:
	spin_unlock_bh(&smc_lgr->lock);
	cb_ctx->pos[0] = num;
	return rc;
}

static int __smc_diag_dump(struct sock *sk, struct sk_buff *skb,
			   struct netlink_callback *cb,
			   const struct smc_diag_req *req)
{
	struct smc_sock *smc = smc_sk(sk);
	struct smc_diag_msg *r;
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			cb->nlh->nlmsg_type, sizeof(*r), NLM_F_MULTI);
	if (!nlh)
		return -EMSGSIZE;

	r = nlmsg_data(nlh);
	if (!smc_diag_fill_base_struct(sk, skb, cb, r))
		goto errout;

	if (!smc_diag_fill_fallback(sk, skb))
		goto errout;

	if ((req->diag_ext & (1 << (SMC_DIAG_CONNINFO - 1))) &&
	    smc->conn.alert_token_local) {
		if (!smc_diag_fill_conninfo(sk, skb))
			goto errout;
	}

	if (smc->conn.lgr && !smc->conn.lgr->is_smcd &&
	    (req->diag_ext & (1 << (SMC_DIAG_LGRINFO - 1))) &&
	    !list_empty(&smc->conn.lgr->list)) {
		if (!smc_diag_fill_lgrinfo(sk, skb))
			goto errout;
	}
	if (smc->conn.lgr && smc->conn.lgr->is_smcd &&
	    (req->diag_ext & (1 << (SMC_DIAG_DMBINFO - 1))) &&
	    !list_empty(&smc->conn.lgr->list)) {
		if (!smc_diag_fill_dmbinfo(sk, skb))
			goto errout;
	}

	nlmsg_end(skb, nlh);
	return 0;

errout:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int smc_diag_dump_proto(struct proto *prot, struct sk_buff *skb,
			       struct netlink_callback *cb, int p_type)
{
	struct smc_diag_dump_ctx *cb_ctx = smc_dump_context(cb);
	struct net *net = sock_net(skb->sk);
	int snum = cb_ctx->pos[p_type];
	struct hlist_head *head;
	int rc = 0, num = 0;
	struct sock *sk;

	read_lock(&prot->h.smc_hash->lock);
	head = &prot->h.smc_hash->ht;
	if (hlist_empty(head))
		goto out;

	sk_for_each(sk, head) {
		if (!net_eq(sock_net(sk), net))
			continue;
		if (num < snum)
			goto next;
		rc = __smc_diag_dump(sk, skb, cb, nlmsg_data(cb->nlh));
		if (rc < 0)
			goto out;
next:
		num++;
	}

out:
	read_unlock(&prot->h.smc_hash->lock);
	cb_ctx->pos[p_type] = num;
	return rc;
}

static int smc_diag_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	int rc = 0;

	rc = smc_diag_dump_proto(&smc_proto, skb, cb, SMCPROTO_SMC);
	if (!rc)
		smc_diag_dump_proto(&smc_proto6, skb, cb, SMCPROTO_SMC6);
	return skb->len;
}

static int smc_diag_dump_ext(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct smc_diag_req_v2 *req = nlmsg_data(cb->nlh);

	if (req->cmd == SMC_DIAG_GET_LGR_INFO) {
		if ((req->cmd_ext & (1 << (SMC_DIAG_LGR_INFO_SMCR - 1))))
			smc_diag_fill_lgr_list(&smc_lgr_list, skb, cb,
					       req);
	}

	return skb->len;
}

static int smc_diag_handler_dump(struct sk_buff *skb, struct nlmsghdr *h)
{
	struct net *net = sock_net(skb->sk);
	struct netlink_dump_control c = {
		.min_dump_alloc = SKB_WITH_OVERHEAD(32768),
	};
	if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
	    h->nlmsg_flags & NLM_F_DUMP) {
		if (h->nlmsg_seq >= MAGIC_SEQ_V2)
			c.dump = smc_diag_dump_ext;
		else
			c.dump = smc_diag_dump;
		return netlink_dump_start(net->diag_nlsk, skb, h, &c);
	}
	return 0;
}

static const struct sock_diag_handler smc_diag_handler = {
	.family = AF_SMC,
	.dump = smc_diag_handler_dump,
};

static int __init smc_diag_init(void)
{
	return sock_diag_register(&smc_diag_handler);
}

static void __exit smc_diag_exit(void)
{
	sock_diag_unregister(&smc_diag_handler);
}

module_init(smc_diag_init);
module_exit(smc_diag_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 43 /* AF_SMC */);
