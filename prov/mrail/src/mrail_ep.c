/*
 * Copyright (c) 2018 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <ofi_iov.h>

#include "mrail.h"

#define MRAIL_HDR_INITIALIZER(op_type, tag_val)		\
{							\
	.version 	= MRAIL_HDR_VERSION,		\
	.op		= op_type,			\
	.tag		= tag_val,			\
}

#define MRAIL_HDR_INITIALIZER_MSG MRAIL_HDR_INITIALIZER(ofi_op_msg, 0)

#define MRAIL_HDR_INITIALIZER_TAGGED(tag) \
	MRAIL_HDR_INITIALIZER(ofi_op_tagged, tag)

#define mrail_util_ep(ep_fid) \
	container_of(ep_fid, struct util_ep, ep_fid.fid)

#define mrail_comp_flag(ep_fid) \
	(mrail_util_ep(ep_fid)->tx_op_flags & FI_COMPLETION)

#define mrail_inject_flags(ep_fid) \
	((mrail_util_ep(ep_fid)->tx_op_flags & ~FI_COMPLETION) | FI_INJECT)

static int mrail_match_recv_any(struct dlist_entry *item, const void *arg)
{
	OFI_UNUSED(item);
	OFI_UNUSED(arg);
	return 1;
}

static int mrail_match_recv_addr(struct dlist_entry *item, const void *arg)
{
	struct mrail_match_attr *match_attr = (struct mrail_match_attr *)arg;
	struct mrail_recv *recv =
		container_of(item, struct mrail_recv, entry);

	return ofi_match_addr(recv->addr, match_attr->addr);
}

static int mrail_match_recv_tag(struct dlist_entry *item, const void *arg)
{
	struct mrail_match_attr *match_attr = (struct mrail_match_attr *)arg;
	struct mrail_recv *recv =
		container_of(item, struct mrail_recv, entry);

	return ofi_match_tag(recv->tag, recv->ignore, match_attr->tag);
}

static int mrail_match_recv_addr_tag(struct dlist_entry *item, const void *arg)
{
	struct mrail_match_attr *match_attr = (struct mrail_match_attr *)arg;
	struct mrail_recv *recv =
		container_of(item, struct mrail_recv, entry);

	return ofi_match_addr(recv->addr, match_attr->addr) &&
		ofi_match_tag(recv->tag, recv->ignore, match_attr->tag);
}

static int mrail_match_unexp_any(struct dlist_entry *item, const void *arg)
{
	OFI_UNUSED(item);
	OFI_UNUSED(arg);
	return 1;
}

static int mrail_match_unexp_addr(struct dlist_entry *item, const void *arg)
{
	struct mrail_recv *recv = (struct mrail_recv *)arg;
	struct mrail_unexp_msg_entry *unexp_msg_entry =
		container_of(item, struct mrail_unexp_msg_entry, entry);

	return ofi_match_addr(unexp_msg_entry->addr, recv->addr);
}

static int mrail_match_unexp_tag(struct dlist_entry *item, const void *arg)
{
	struct mrail_recv *recv = (struct mrail_recv *)arg;
	struct mrail_unexp_msg_entry *unexp_msg_entry =
		container_of(item, struct mrail_unexp_msg_entry, entry);

	return ofi_match_tag(recv->tag, recv->ignore, unexp_msg_entry->tag);
}

static int mrail_match_unexp_addr_tag(struct dlist_entry *item, const void *arg)
{
	struct mrail_recv *recv = (struct mrail_recv *)arg;
	struct mrail_unexp_msg_entry *unexp_msg_entry =
		container_of(item, struct mrail_unexp_msg_entry, entry);

	return ofi_match_addr(recv->addr, unexp_msg_entry->addr) &&
		ofi_match_tag(recv->tag, recv->ignore, unexp_msg_entry->tag);
}

int mrail_reprocess_directed_recvs(struct mrail_recv_queue *recv_queue)
{
	// TODO
	return -FI_ENOSYS;
}

struct mrail_recv *
mrail_match_recv_handle_unexp(struct mrail_recv_queue *recv_queue, uint64_t tag,
			      uint64_t addr, char *data, size_t len, void *context)
{
	struct dlist_entry *entry;
	struct mrail_unexp_msg_entry *unexp_msg_entry;
	struct mrail_match_attr match_attr = {
		.tag	= tag,
		.addr	= addr,
	};

	entry = dlist_remove_first_match(&recv_queue->recv_list,
					 recv_queue->match_recv, &match_attr);
	if (OFI_UNLIKELY(!entry)) {
		unexp_msg_entry = recv_queue->get_unexp_msg_entry(recv_queue,
								  context);
		if (!unexp_msg_entry) {
			FI_WARN(recv_queue->prov, FI_LOG_CQ,
				"Unable to get unexp_msg_entry!");
			assert(0);
			return NULL;
		}

		unexp_msg_entry->addr		= addr;
		unexp_msg_entry->tag		= tag;
		unexp_msg_entry->context	= context;
		memcpy(unexp_msg_entry->data, data, len);

		FI_DBG(recv_queue->prov, FI_LOG_CQ, "No matching recv found for"
		       " incoming msg with addr: 0x%" PRIx64 " tag: 0x%" PRIx64
		       "\n", unexp_msg_entry->addr, unexp_msg_entry->tag);

		FI_DBG(recv_queue->prov, FI_LOG_CQ, "Enqueueing unexp_msg_entry to "
		       "unexpected msg list\n");

		dlist_insert_tail(&unexp_msg_entry->entry,
				  &recv_queue->unexp_msg_list);
		return NULL;
	}
	return container_of(entry, struct mrail_recv, entry);
}

static void mrail_init_recv(struct mrail_recv *recv, void *arg)
{
	recv->ep		= arg;
	recv->iov[0].iov_base 	= &recv->hdr;
	recv->iov[0].iov_len 	= sizeof(recv->hdr);
	recv->comp_flags	= FI_RECV;
}

#define mrail_recv_assert(recv)						\
({									\
	assert(recv->ep == mrail_ep);					\
	assert(recv->iov[0].iov_base == &recv->hdr);			\
	assert(recv->iov[0].iov_len == sizeof(recv->hdr));		\
	assert(recv->comp_flags & FI_RECV);				\
	assert(recv->count <= mrail_ep->info->rx_attr->iov_limit + 1);	\
})

static void mrail_recv_queue_init(struct fi_provider *prov,
				  struct mrail_recv_queue *recv_queue,
				  dlist_func_t match_recv,
				  dlist_func_t match_unexp,
				  mrail_get_unexp_msg_entry_func get_unexp_msg_entry)
{
	recv_queue->prov = prov;
	dlist_init(&recv_queue->recv_list);
	dlist_init(&recv_queue->unexp_msg_list);
	recv_queue->match_recv = match_recv;
	recv_queue->match_unexp = match_unexp;
	recv_queue->get_unexp_msg_entry = get_unexp_msg_entry;
}

// TODO go for separate recv functions (recvmsg, recvv, etc) to be optimal
static ssize_t
mrail_recv_common(struct mrail_ep *mrail_ep, struct mrail_recv_queue *recv_queue,
		  struct iovec *iov, size_t count, void *context,
		  fi_addr_t src_addr, uint64_t tag, uint64_t ignore,
		  uint64_t flags, uint64_t comp_flags)
{
	struct mrail_recv *recv;
	struct mrail_unexp_msg_entry *unexp_msg_entry;

	recv = mrail_pop_recv(mrail_ep);
	if (!recv)
		return -FI_EAGAIN;

	recv->count 		= count + 1;
	recv->context 		= context;
	recv->flags 		= flags;
	recv->comp_flags 	|= comp_flags;
	recv->addr	 	= src_addr;
	recv->tag 		= tag;
	recv->ignore 		= ignore;

	memcpy(&recv->iov[1], iov, sizeof(*iov) * count);

	FI_DBG(&mrail_prov, FI_LOG_EP_DATA, "Posting recv of length: %zu "
	       "src_addr: 0x%" PRIx64 " tag: 0x%" PRIx64 " ignore: 0x%" PRIx64
	       "\n", ofi_total_iov_len(iov, count), recv->addr,
	       recv->tag, recv->ignore);

	fastlock_acquire(&mrail_ep->util_ep.lock);
	unexp_msg_entry = container_of(dlist_remove_first_match(
						&recv_queue->unexp_msg_list,
						recv_queue->match_unexp,
						recv),
				       struct mrail_unexp_msg_entry,
				       entry);
	if (!unexp_msg_entry) {
		dlist_insert_tail(&recv->entry, &recv_queue->recv_list);
		fastlock_release(&mrail_ep->util_ep.lock);
		return 0;
	}
	fastlock_release(&mrail_ep->util_ep.lock);

	FI_DBG(recv_queue->prov, FI_LOG_EP_DATA, "Match for posted recv"
	       " with addr: 0x%" PRIx64 ", tag: 0x%" PRIx64 " ignore: "
	       "0x%" PRIx64 " found in unexpected msg queue\n",
	       recv->addr, recv->tag, recv->ignore);

	return mrail_cq_process_buf_recv((mrail_cq_entry_t *)unexp_msg_entry->data,
					 recv);
}

static ssize_t mrail_recv(struct fid_ep *ep_fid, void *buf, size_t len,
			  void *desc, fi_addr_t src_addr, void *context)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
					     util_ep.ep_fid.fid);
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= len,
	};
	return mrail_recv_common(mrail_ep, &mrail_ep->recv_queue, &iov,
				 1, context, src_addr, 0, 0,
				 mrail_ep->util_ep.rx_op_flags, FI_MSG);
}

static ssize_t mrail_recvmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
		uint64_t flags)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
					     util_ep.ep_fid.fid);

	return mrail_recv_common(mrail_ep, &mrail_ep->recv_queue,
				 (struct iovec *)msg->msg_iov, msg->iov_count,
				 msg->context, msg->addr, 0, 0, flags, FI_MSG);
}

static ssize_t mrail_trecv(struct fid_ep *ep_fid, void *buf, size_t len,
			    void *desc, fi_addr_t src_addr, uint64_t tag,
			    uint64_t ignore, void *context)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
					     util_ep.ep_fid.fid);
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= len,
	};
	return mrail_recv_common(mrail_ep, &mrail_ep->trecv_queue, &iov,
				 1, context, src_addr, tag, ignore,
				 mrail_ep->util_ep.rx_op_flags, FI_TAGGED);
}

static void mrail_copy_iov_hdr(struct mrail_hdr *hdr, struct iovec *iov_dest,
			       const struct iovec *iov_src, size_t count)
{
	iov_dest[0].iov_base = hdr;
	iov_dest[0].iov_len = sizeof(*hdr);
	memcpy(&iov_dest[1], iov_src, sizeof(*iov_src) * count);
}

static ssize_t
mrail_send_common(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		  size_t count, size_t len, fi_addr_t dest_addr, uint64_t data,
		  void *context, uint64_t flags)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
						 util_ep.ep_fid.fid);
	struct mrail_peer_addr *peer_addr;
	struct iovec *iov_dest = alloca(sizeof(*iov_dest) * (count + 1));
	struct mrail_hdr hdr = MRAIL_HDR_INITIALIZER_MSG;
	uint32_t i = mrail_get_tx_rail(mrail_ep);
	struct fi_msg msg;
	ssize_t ret;

	peer_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int) dest_addr);

	mrail_ep->lock_acquire(&mrail_ep->util_ep.lock);

	hdr.seq = peer_addr->seq_no++;
	FI_DBG(&mrail_prov, FI_LOG_EP_DATA, "sending seq=%d\n", hdr.seq);
	hdr.seq = htonl(hdr.seq);
	mrail_copy_iov_hdr(&hdr, iov_dest, iov, count);

	msg.msg_iov 	= iov_dest;
	msg.desc    	= desc;
	msg.iov_count	= count + 1;
	msg.addr	= peer_addr->addr[i];
	msg.context	= context;
	msg.data	= data;

	if (len < mrail_ep->rails[i].info->tx_attr->inject_size)
		flags |= FI_INJECT;

	FI_DBG(&mrail_prov, FI_LOG_EP_DATA, "Posting send of length: %" PRIu64
	       " dest_addr: 0x%" PRIx64 " on rail: %d\n", len, dest_addr, i);
	ret = fi_sendmsg(mrail_ep->rails[i].ep, &msg, flags);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to fi_sendmsg on rail: %" PRIu32 "\n", i);
		peer_addr->seq_no--;
	}

	mrail_ep->lock_release(&mrail_ep->util_ep.lock);
	return ret;
}

static ssize_t
mrail_tsend_common(struct fid_ep *ep_fid, const struct iovec *iov, void **desc,
		   size_t count, size_t len, fi_addr_t dest_addr, uint64_t tag,
		   uint64_t data, void *context, uint64_t flags)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
						 util_ep.ep_fid.fid);
	struct mrail_peer_addr *peer_addr;
	struct iovec *iov_dest = alloca(sizeof(*iov_dest) * (count + 1));
	struct mrail_hdr hdr = MRAIL_HDR_INITIALIZER_TAGGED(tag);
	uint32_t i = mrail_get_tx_rail(mrail_ep);
	struct fi_msg msg;
	ssize_t ret;

	peer_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int) dest_addr);

	mrail_ep->lock_acquire(&mrail_ep->util_ep.lock);

	hdr.seq = peer_addr->seq_no++;
	FI_DBG(&mrail_prov, FI_LOG_EP_DATA, "sending seq=%d\n", hdr.seq);
	hdr.seq = htonl(hdr.seq);
	mrail_copy_iov_hdr(&hdr, iov_dest, iov, count);

	msg.msg_iov 	= iov_dest;
	msg.desc    	= desc;
	msg.iov_count	= count + 1;
	msg.addr	= peer_addr->addr[i];
	msg.context	= context;
	msg.data	= data;

	if (len < mrail_ep->rails[i].info->tx_attr->inject_size)
		flags |= FI_INJECT;

	FI_DBG(&mrail_prov, FI_LOG_EP_DATA, "Posting tsend of length: %" PRIu64
	       " dest_addr: 0x%" PRIx64 " tag: 0x%" PRIx64 " on rail: %d\n",
	       len, dest_addr, tag, i);
	ret = fi_sendmsg(mrail_ep->rails[i].ep, &msg, flags);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to fi_sendmsg on rail: %" PRIu32 "\n", i);
		peer_addr->seq_no--;
	}

	mrail_ep->lock_release(&mrail_ep->util_ep.lock);
	return ret;
}

static ssize_t mrail_sendmsg(struct fid_ep *ep_fid, const struct fi_msg *msg,
			     uint64_t flags)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
						 util_ep.ep_fid.fid);
	if (!(mrail_ep->util_ep.tx_op_flags & FI_SELECTIVE_COMPLETION))
		flags |= FI_COMPLETION;
	return mrail_send_common(ep_fid, msg->msg_iov, msg->desc, msg->iov_count,
				 ofi_total_iov_len(msg->msg_iov, msg->iov_count),
				 msg->addr, msg->data, msg->context, flags);
}

static ssize_t mrail_send(struct fid_ep *ep_fid, const void *buf, size_t len,
			  void *desc, fi_addr_t dest_addr, void *context)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_send_common(ep_fid, &iov, &desc, 1, len, dest_addr, 0,
				 context, mrail_comp_flag(ep_fid));
}

static ssize_t mrail_inject(struct fid_ep *ep_fid, const void *buf, size_t len,
			    fi_addr_t dest_addr)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_send_common(ep_fid, &iov, NULL, 1, len, dest_addr, 0,
				 NULL, mrail_inject_flags(ep_fid));
}

static ssize_t mrail_injectdata(struct fid_ep *ep_fid, const void *buf,
				size_t len, uint64_t data, fi_addr_t dest_addr)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_send_common(ep_fid, &iov, NULL, 1, len, dest_addr, data,
				 NULL, (mrail_inject_flags(ep_fid) |
					FI_REMOTE_CQ_DATA));
}

static ssize_t
mrail_tsendmsg(struct fid_ep *ep_fid, const struct fi_msg_tagged *msg,
	       uint64_t flags)
{
	struct mrail_ep *mrail_ep = container_of(ep_fid, struct mrail_ep,
						 util_ep.ep_fid.fid);
	if (!(mrail_ep->util_ep.tx_op_flags & FI_SELECTIVE_COMPLETION))
		flags |= FI_COMPLETION;
	return mrail_tsend_common(ep_fid, msg->msg_iov, msg->desc, msg->iov_count,
				  ofi_total_iov_len(msg->msg_iov, msg->iov_count),
				  msg->addr, msg->tag, msg->data, msg->context,
				  flags);
}

static ssize_t mrail_tsend(struct fid_ep *ep_fid, const void *buf, size_t len,
			   void *desc, fi_addr_t dest_addr, uint64_t tag,
			   void *context)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_tsend_common(ep_fid, &iov, &desc, 1, len, dest_addr, tag,
				  0, context, mrail_comp_flag(ep_fid));
}

static ssize_t mrail_tsenddata(struct fid_ep *ep_fid, const void *buf, size_t len,
			       void *desc, uint64_t data, fi_addr_t dest_addr,
			       uint64_t tag, void *context)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_tsend_common(ep_fid, &iov, &desc, 1, len, dest_addr, tag,
				  data, context, (mrail_comp_flag(ep_fid) |
						  FI_REMOTE_CQ_DATA));
}

static ssize_t mrail_tinject(struct fid_ep *ep_fid, const void *buf, size_t len,
			     fi_addr_t dest_addr, uint64_t tag)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_tsend_common(ep_fid, &iov, NULL, 1, len, dest_addr, tag,
				  0, NULL, mrail_inject_flags(ep_fid));
}

static ssize_t mrail_tinjectdata(struct fid_ep *ep_fid, const void *buf,
				 size_t len, uint64_t data, fi_addr_t dest_addr,
				 uint64_t tag)
{
	struct iovec iov = {
		.iov_base 	= (void *)buf,
		.iov_len 	= len,
	};
	return mrail_tsend_common(ep_fid, &iov, NULL, 1, len, dest_addr, tag,
				  data, NULL, (mrail_inject_flags(ep_fid) |
					       FI_REMOTE_CQ_DATA));
}

static struct mrail_unexp_msg_entry *
mrail_get_unexp_msg_entry(struct mrail_recv_queue *recv_queue, void *context)
{
	// TODO use buf pool
	// context would be mrail_ep from which u can get the buf pool
	struct mrail_unexp_msg_entry *unexp_msg_entry =
		malloc(sizeof(*unexp_msg_entry) + sizeof(mrail_cq_entry_t));
	return unexp_msg_entry;
}

static int mrail_getname(fid_t fid, void *addr, size_t *addrlen)
{
	struct mrail_ep *mrail_ep =
		container_of(fid, struct mrail_ep, util_ep.ep_fid.fid);
	struct mrail_domain *mrail_domain =
		container_of(mrail_ep->util_ep.domain, struct mrail_domain,
			     util_domain);
	size_t i, offset = 0, rail_addrlen;
	int ret;

	if (*addrlen < mrail_domain->addrlen)
		return -FI_ETOOSMALL;

	for (i = 0; i < mrail_ep->num_eps; i++) {
		rail_addrlen = *addrlen - offset;
		ret = fi_getname(&mrail_ep->rails[i].ep->fid,
				 (char *)addr + offset, &rail_addrlen);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_EP_CTRL,
				"Unable to get name for rail: %zd\n", i);
			return ret;
		}
		offset += rail_addrlen;
	}
	return 0;
}

static int mrail_ep_close(fid_t fid)
{
	struct mrail_ep *mrail_ep =
		container_of(fid, struct mrail_ep, util_ep.ep_fid.fid);
	int ret, retv = 0;
	size_t i;

	util_buf_pool_destroy(mrail_ep->req_pool);
	mrail_recv_fs_free(mrail_ep->recv_fs);

	for (i = 0; i < mrail_ep->num_eps; i++) {
		ret = fi_close(&mrail_ep->rails[i].ep->fid);
		if (ret)
			retv = ret;
	}
	free(mrail_ep->rails);

	ret = ofi_endpoint_close(&mrail_ep->util_ep);
	if (ret)
		retv = ret;
	free(mrail_ep);
	return retv;
}

static int mrail_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct mrail_ep *mrail_ep =
		container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	struct mrail_cq *mrail_cq;
	struct mrail_av *mrail_av;
	struct util_cntr *cntr;
	int ret = 0;
	size_t i;

	switch (bfid->fclass) {
	case FI_CLASS_AV:
		mrail_av = container_of(bfid, struct mrail_av,
					util_av.av_fid.fid);
		ret = ofi_ep_bind_av(&mrail_ep->util_ep, &mrail_av->util_av);
		if (ret)
			return ret;
		for (i = 0; i < mrail_ep->num_eps; i++) {
			ret = fi_ep_bind(mrail_ep->rails[i].ep,
					 &mrail_av->avs[i]->fid, flags);
			if (ret)
				return ret;
		}
		break;
	case FI_CLASS_CQ:
		mrail_cq = container_of(bfid, struct mrail_cq,
					util_cq.cq_fid.fid);

		ret = ofi_ep_bind_cq(&mrail_ep->util_ep, &mrail_cq->util_cq,
				     flags);
		if (ret)
			return ret;
		for (i = 0; i < mrail_ep->num_eps; i++) {
			if (flags & FI_TRANSMIT)
				flags |= FI_SELECTIVE_COMPLETION;

			ret = fi_ep_bind(mrail_ep->rails[i].ep,
					 &mrail_cq->cqs[i]->fid, flags);
			if (ret)
				return ret;
		}
		break;
	case FI_CLASS_CNTR:
		cntr = container_of(bfid, struct util_cntr, cntr_fid.fid);

		ret = ofi_ep_bind_cntr(&mrail_ep->util_ep, cntr, flags);
		if (ret)
			return ret;
		break;
	case FI_CLASS_EQ:
		ret = -FI_ENOSYS;
		break;
	default:
		FI_WARN(&mrail_prov, FI_LOG_EP_CTRL, "invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int mrail_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct mrail_ep *mrail_ep;
	size_t i;
	int ret;

	mrail_ep = container_of(fid, struct mrail_ep, util_ep.ep_fid.fid);

	switch (command) {
	case FI_ENABLE:
		if (!mrail_ep->util_ep.rx_cq || !mrail_ep->util_ep.tx_cq)
			return -FI_ENOCQ;
		if (!mrail_ep->util_ep.av)
			return -FI_ENOAV;
		for (i = 0; i < mrail_ep->num_eps; i++) {
			ret = fi_enable(mrail_ep->rails[i].ep);
			if (ret)
				return ret;
		}
		break;
	default:
		return -FI_ENOSYS;
	}
	return 0;
}

static struct fi_ops mrail_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = mrail_ep_close,
	.bind = mrail_ep_bind,
	.control = mrail_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static int mrail_ep_setopt(fid_t fid, int level, int optname,
		const void *optval, size_t optlen)
{
	struct mrail_ep *mrail_ep;
	size_t i;
	int ret = 0;

	mrail_ep = container_of(fid, struct mrail_ep, util_ep.ep_fid.fid);

	for (i = 0; i < mrail_ep->num_eps; i++) {
		ret = fi_setopt(&mrail_ep->rails[i].ep->fid, level, optname,
				optval, optlen);
		if (ret)
			return ret;
	}

	return ret;
}

static struct fi_ops_ep mrail_ops_ep = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_no_getopt,
	.setopt = mrail_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static struct fi_ops_cm mrail_ops_cm = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = mrail_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

static struct fi_ops_msg mrail_ops_msg = {
	.size = sizeof(struct fi_ops_msg),
	.recv = mrail_recv,
	.recvv = fi_no_msg_recvv,
	.recvmsg = mrail_recvmsg,
	.send = mrail_send,
	.sendv = fi_no_msg_sendv,
	.sendmsg = mrail_sendmsg,
	.inject = mrail_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = mrail_injectdata,
};

struct fi_ops_tagged mrail_ops_tagged = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = mrail_trecv,
	.recvv = fi_no_tagged_recvv,
	.recvmsg = fi_no_tagged_recvmsg,
	.send = mrail_tsend,
	.sendv = fi_no_tagged_sendv,
	.sendmsg = mrail_tsendmsg,
	.inject = mrail_tinject,
	.senddata = mrail_tsenddata,
	.injectdata = mrail_tinjectdata,
};

void mrail_ep_progress(struct util_ep *ep)
{
	struct mrail_ep *mrail_ep;
	mrail_ep = container_of(ep, struct mrail_ep, util_ep);
	mrail_progress_deferred_reqs(mrail_ep);
}

int mrail_ep_open(struct fid_domain *domain_fid, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct mrail_domain *mrail_domain =
		container_of(domain_fid, struct mrail_domain,
			     util_domain.domain_fid);
	struct mrail_ep *mrail_ep;
	struct fi_info *fi;
	size_t i, rxq_total_size;
	size_t buf_size;
	int ret;

	if (strcmp(mrail_domain->info->domain_attr->name,
		    info->domain_attr->name)) {
		FI_WARN(&mrail_prov, FI_LOG_EP_CTRL, "info domain name: %s "
			"doesn't match fid_domain name: %s!\n",
			info->domain_attr->name,
			mrail_domain->info->domain_attr->name);
		return -FI_EINVAL;
	}

	mrail_ep = calloc(1, sizeof(*mrail_ep));
	if (!mrail_ep)
		return -FI_ENOMEM;

	// TODO detect changes b/w mrail_domain->info and info arg
	// this may be difficult and we may not support such changes
	mrail_ep->info = mrail_domain->info;
	mrail_ep->num_eps = mrail_domain->num_domains;

	ret = ofi_endpoint_init(domain_fid, &mrail_util_prov, info, &mrail_ep->util_ep,
				context, &mrail_ep_progress);
	if (ret) {
		goto free_ep;
	}

	mrail_ep->rails = calloc(mrail_ep->num_eps, sizeof(*mrail_ep->rails));
	if (!mrail_ep->rails) {
		ret = -FI_ENOMEM;
		goto err;
	}

	for (i = 0, fi = mrail_ep->info->next, rxq_total_size = 0; fi;
	     fi = fi->next, i++) {
		fi->tx_attr->op_flags &= ~FI_COMPLETION;
		ret = fi_endpoint(mrail_domain->domains[i], fi,
				  &mrail_ep->rails[i].ep, mrail_ep);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_EP_CTRL,
				"Unable to open EP\n");
			goto err;
		}
		mrail_ep->rails[i].info = fi;
		rxq_total_size += fi->rx_attr->size;
	}

	mrail_ep->recv_fs = mrail_recv_fs_create(rxq_total_size, mrail_init_recv,
						 mrail_ep);
	if (!mrail_ep->recv_fs) {
		ret = -FI_ENOMEM;
		goto err;
	}

	buf_size = sizeof(struct mrail_req) +
		(mrail_ep->num_eps * sizeof(struct mrail_subreq));

	ret = util_buf_pool_create(&mrail_ep->req_pool, buf_size,
			sizeof(void *), 0, 64);
	if (ret) {
		ret = -FI_ENOMEM;
		goto err;
	}

	slist_init(&mrail_ep->deferred_reqs);

	if (mrail_ep->info->caps & FI_DIRECTED_RECV) {
		mrail_recv_queue_init(&mrail_prov, &mrail_ep->recv_queue,
				      mrail_match_recv_addr,
				      mrail_match_unexp_addr,
				      mrail_get_unexp_msg_entry);
		mrail_recv_queue_init(&mrail_prov, &mrail_ep->trecv_queue,
				      mrail_match_recv_addr_tag,
				      mrail_match_unexp_addr_tag,
				      mrail_get_unexp_msg_entry);
	} else {
		mrail_recv_queue_init(&mrail_prov, &mrail_ep->recv_queue,
				      mrail_match_recv_any,
				      mrail_match_unexp_any,
				      mrail_get_unexp_msg_entry);
		mrail_recv_queue_init(&mrail_prov, &mrail_ep->trecv_queue,
				      mrail_match_recv_tag,
				      mrail_match_unexp_tag,
				      mrail_get_unexp_msg_entry);
	}

	ofi_atomic_initialize32(&mrail_ep->tx_rail, 0);
	ofi_atomic_initialize32(&mrail_ep->rx_rail, 0);

	if (mrail_domain->util_domain.threading != FI_THREAD_SAFE) {
		mrail_ep->lock_acquire = ofi_fastlock_acquire_noop;
		mrail_ep->lock_release = ofi_fastlock_release_noop;
	} else {
		mrail_ep->lock_acquire = ofi_fastlock_acquire;
		mrail_ep->lock_release = ofi_fastlock_release;
	}

	*ep_fid = &mrail_ep->util_ep.ep_fid;
	(*ep_fid)->fid.ops = &mrail_ep_fi_ops;
	(*ep_fid)->ops = &mrail_ops_ep;
	(*ep_fid)->cm = &mrail_ops_cm;
	(*ep_fid)->msg = &mrail_ops_msg;
	(*ep_fid)->tagged = &mrail_ops_tagged;
	(*ep_fid)->rma = &mrail_ops_rma;

	return 0;
err:
	mrail_ep_close(&mrail_ep->util_ep.ep_fid.fid);
free_ep:
	free(mrail_ep);
	return ret;
}
