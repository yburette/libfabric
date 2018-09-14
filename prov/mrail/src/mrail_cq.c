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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

int mrail_cq_write_recv_comp(struct mrail_ep *mrail_ep, struct mrail_hdr *hdr,
			     struct fi_cq_tagged_entry *comp,
			     struct mrail_recv *recv)
{
	FI_DBG(&mrail_prov, FI_LOG_CQ, "writing recv completion: length: %zu "
	       "tag: 0x%" PRIx64 "\n", comp->len - sizeof(struct mrail_pkt),
	       hdr->tag);
	return ofi_cq_write(mrail_ep->util_ep.rx_cq, recv->context,
			   recv->comp_flags |
			   (comp->flags & FI_REMOTE_CQ_DATA),
			   comp->len - sizeof(struct mrail_pkt),
			   NULL, comp->data, hdr->tag);
}

int mrail_cq_process_buf_recv(struct fi_cq_tagged_entry *comp,
			      struct mrail_recv *recv)
{
	struct fi_recv_context *recv_ctx = comp->op_context;
	struct fi_msg msg = {
		.context = recv_ctx,
	};
	struct mrail_ep *mrail_ep;
	struct mrail_pkt *mrail_pkt;
	size_t size, len;
	int ret, retv = 0;

	if (comp->flags & FI_MORE) {
		msg.msg_iov	= recv->iov;
		msg.iov_count	= recv->count;
		msg.addr	= recv->addr;

		recv_ctx->context = recv;

		ret = fi_recvmsg(recv_ctx->ep, &msg, FI_CLAIM);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Unable to claim buffered recv\n");
			assert(0);
			// TODO write cq error entry
		}
		return ret;
	}

	mrail_ep = recv_ctx->ep->fid.context;
	mrail_pkt = (struct mrail_pkt *)comp->buf;

	len = comp->len - sizeof(*mrail_pkt);

	size = ofi_copy_to_iov(&recv->iov[1], recv->count - 1, 0,
			       mrail_pkt->data, len);

	if (size < len) {
		FI_WARN(&mrail_prov, FI_LOG_CQ, "Message truncated recv buf "
			"size: %zu message length: %zu\n", size, len);
		ret = ofi_cq_write_error_trunc(
			mrail_ep->util_ep.rx_cq, recv->context,
			recv->comp_flags | (comp->flags & FI_REMOTE_CQ_DATA),
			0, NULL, comp->data, mrail_pkt->hdr.tag, comp->len - size);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Unable to write truncation error to util cq\n");
			retv = ret;
		}
		goto out;
	}
	ret = mrail_cq_write_recv_comp(mrail_ep, &mrail_pkt->hdr, comp, recv);
	if (ret)
		retv = ret;
out:
	ret = fi_recvmsg(recv_ctx->ep, &msg, FI_DISCARD);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_CQ,
			"Unable to discard buffered recv\n");
		retv = ret;
	}
	mrail_push_recv(recv);
	return retv;
}

static int mrail_cq_process_comp_buf_recv(struct mrail_ep *mrail_ep,
					  struct fi_cq_tagged_entry *comp)
{
	struct mrail_hdr *hdr = comp->buf;
	struct mrail_recv *recv;

	mrail_ep->lock_acquire(&mrail_ep->util_ep.lock);
	if (hdr->op == ofi_op_msg) {
		FI_DBG(&mrail_prov, FI_LOG_CQ, "Got MSG op\n");
		// TODO pass the right address
		recv = mrail_match_recv_handle_unexp(&mrail_ep->recv_queue, 0,
						     FI_ADDR_UNSPEC,
						     (char *)comp, sizeof(*comp),
						     NULL);
	} else {
		assert(hdr->op == ofi_op_tagged);
		FI_DBG(&mrail_prov, FI_LOG_CQ, "Got TAGGED op\n");
		recv = mrail_match_recv_handle_unexp(&mrail_ep->trecv_queue,
						     hdr->tag, FI_ADDR_UNSPEC,
						     (char *)comp, sizeof(*comp),
						     NULL);
	}
	mrail_ep->lock_release(&mrail_ep->util_ep.lock);
	if (OFI_UNLIKELY(!recv))
		return 0;

	return mrail_cq_process_buf_recv(comp, recv);
}

static
struct mrail_early_comp *mrail_peer_get_next(struct mrail_peer_info *peer_info)
{
	struct slist *queue = &peer_info->early_recv_comps;
	struct mrail_early_comp *early_comp;

	if (!slist_empty(queue)) {
		early_comp = container_of(queue->head, struct
				mrail_early_comp, entry);
		if (early_comp->seq_no == peer_info->expected_seq_no) {
			slist_remove_head(queue);
			peer_info->expected_seq_no++;
			return early_comp;
		}
	}
	return NULL;
}

static int mrail_process_early_comps(struct mrail_ep *mrail_ep,
				     struct mrail_peer_info *peer_info)
{
	struct mrail_early_comp *early_comp;
	int ret;

	while ((early_comp = mrail_peer_get_next(peer_info))) {
		FI_DBG(&mrail_prov, FI_LOG_CQ, "found early_comp seq=%d\n",
				early_comp->seq_no);
		ret = mrail_cq_process_comp_buf_recv(mrail_ep,
				&early_comp->comp);
		if (ret)
			return ret;
		mrail_free_early_comp(mrail_ep, early_comp);
	}

	return 0;
}

static int mrail_early_comp_before(struct slist_entry *item, const void *arg)
{
	struct mrail_early_comp *early_comp;
	struct mrail_early_comp *new_comp;

	/* Check whether the given item's follower has a higher seq_no. */

	if (!item->next) {
		/* item is the last element in the list */
		return 0;
	}

	early_comp = container_of(item->next, struct mrail_early_comp, entry);
	new_comp = container_of((struct slist_entry *)arg,
			struct mrail_early_comp, entry);

	return (new_comp->seq_no < early_comp->seq_no);
}

static void mrail_save_early_comp(struct mrail_ep *mrail_ep,
				  struct mrail_peer_info *peer_info,
				  uint32_t seq_no,
				  struct fi_cq_tagged_entry *comp)
{
	struct slist *queue = &peer_info->early_recv_comps;
	struct mrail_early_comp *early_comp;

	early_comp = mrail_alloc_early_comp(mrail_ep);
	if (!early_comp) {
		FI_WARN(&mrail_prov, FI_LOG_CQ, "Cannot allocate early_comp\n");
		assert(0);
	}
	early_comp->seq_no = seq_no;
	memcpy(&early_comp->comp, comp, sizeof(*comp));

	slist_insert_order(queue, mrail_early_comp_before, &early_comp->entry);

	FI_DBG(&mrail_prov, FI_LOG_CQ, "saved early_comp seq=%d\n", seq_no);
}

static int mrail_handle_recv_completion(struct fi_cq_tagged_entry *comp,
					fi_addr_t src_addr)
{
	struct fi_recv_context *recv_ctx;
	struct mrail_peer_info *peer_info;
	struct mrail_ep *mrail_ep;
	struct mrail_recv *recv;
	struct mrail_hdr *hdr;
	uint32_t seq_no;
	int ret;

	if (comp->flags & FI_CLAIM) {
		/* This message has already been processed and claimed.
		 * See mrail_cq_process_buf_recv().
		 */
		recv = comp->op_context;
		assert(recv->hdr.version == MRAIL_HDR_VERSION);
		ret =  mrail_cq_write_recv_comp(recv->ep, &recv->hdr, comp,
						recv->context);
		mrail_push_recv(recv);
		goto exit;
	}

	recv_ctx = comp->op_context;
	mrail_ep = recv_ctx->ep->fid.context;
	hdr = comp->buf;

	// TODO make rxm send buffered recv amount of data for large message
	assert(hdr->version == MRAIL_HDR_VERSION);

	seq_no = ntohl(hdr->seq);
	peer_info = ofi_av_get_addr(mrail_ep->util_ep.av, (int) src_addr);
	FI_DBG(&mrail_prov, FI_LOG_CQ,
			"ep=%p peer=%d received seq=%d, expected=%d\n",
			mrail_ep, (int)peer_info->addr, seq_no,
			peer_info->expected_seq_no);
	// TODO: make this thread-safe
	if (seq_no == peer_info->expected_seq_no) {
		/* This message was received in order */
		ret = mrail_cq_process_comp_buf_recv(mrail_ep, comp);
		if (ret)
			goto exit;
		peer_info->expected_seq_no++;

		/* Process any next-in-order message that had already arrived */
		ret = mrail_process_early_comps(mrail_ep, peer_info);
	} else {
		/* This message was received early.
		 * Save it into the early recv comps queue.
		 */
		mrail_save_early_comp(mrail_ep, peer_info, seq_no, comp);
	}
	ret = 0;
exit:
	return ret;
}

static int mrail_cq_close(fid_t fid)
{
	struct mrail_cq *mrail_cq = container_of(fid, struct mrail_cq, util_cq.cq_fid.fid);
	int ret, retv = 0;

	ret = mrail_close_fids((struct fid **)mrail_cq->cqs,
			       mrail_cq->num_cqs);
	if (ret)
		retv = ret;
	free(mrail_cq->cqs);

	ret = ofi_cq_cleanup(&mrail_cq->util_cq);
	if (ret)
		retv = ret;

	free(mrail_cq);
	return retv;
}

static struct fi_ops mrail_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = mrail_cq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_cq mrail_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = ofi_cq_read,
	.readfrom = ofi_cq_readfrom,
	.readerr = ofi_cq_readerr,
	.sread = ofi_cq_sread,
	.sreadfrom = ofi_cq_sreadfrom,
	.signal = ofi_cq_signal,
	// TODO define cq strerror, may need to pass rail index
	// in err_data
	.strerror = fi_no_cq_strerror,
};

static void mrail_handle_rma_completion(struct util_cq *cq,
		struct fi_cq_tagged_entry *comp)
{
	int ret;
	struct mrail_req *req;
	struct mrail_subreq *subreq;

	subreq = comp->op_context;
	req = subreq->parent;

	if (ofi_atomic_dec32(&req->expected_subcomps) == 0) {
		ret = ofi_cq_write(cq, req->comp.op_context, req->comp.flags,
				req->comp.len, req->comp.buf, req->comp.data,
				req->comp.tag);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Cannot write to util cq\n");
			/* This should not happen unless totally out of memory,
			 * in which case there is nothing we can do.  */
			assert(0);
		}

		mrail_free_req(req->mrail_ep, req);
	}
}

void mrail_poll_cq(struct util_cq *cq)
{
	struct mrail_cq *mrail_cq;
	struct fi_cq_tagged_entry comp;
	fi_addr_t src_addr;
	size_t i;
	int ret;

	mrail_cq = container_of(cq, struct mrail_cq, util_cq);

	for (i = 0; i < mrail_cq->num_cqs; i++) {
		ret = fi_cq_readfrom(mrail_cq->cqs[i], &comp, 1, &src_addr);
		if (ret == -FI_EAGAIN || !ret)
			continue;
		if (ret < 0) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Unable to read rail completion: %s\n",
				fi_strerror(-ret));
			goto err;
		}
		// TODO handle variable length message
		if (comp.flags & FI_RECV) {
			ret = mrail_cq->process_comp(&comp, src_addr);
			if (ret)
				goto err;
		} else if (comp.flags & (FI_READ | FI_WRITE)) {
			mrail_handle_rma_completion(cq, &comp);
		} else {
			assert(comp.flags & (FI_SEND | FI_REMOTE_WRITE));
			ret = ofi_cq_write(cq, comp.op_context, comp.flags,
					   0, NULL, 0, 0);
			if (ret) {
				FI_WARN(&mrail_prov, FI_LOG_CQ,
					"Unable to write to util cq\n");
				goto err;
			}
		}
	}

	return;

err:
	// TODO write error to cq
	assert(0);
}

static void mrail_cq_progress(struct util_cq *cq)
{
	mrail_poll_cq(cq);

	/* Progress the bound EPs */
	ofi_cq_progress(cq);
}

int mrail_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		   struct fid_cq **cq_fid, void *context)
{
	struct mrail_domain *mrail_domain;
	struct mrail_cq *mrail_cq;
	struct fi_cq_attr rail_cq_attr = {
		.wait_obj = FI_WAIT_NONE,
		.format = MRAIL_RAIL_CQ_FORMAT,
		.size = attr->size,
	};
	size_t i;
	int ret;

	mrail_cq = calloc(1, sizeof(*mrail_cq));
	if (!mrail_cq)
		return -FI_ENOMEM;

	ret = ofi_cq_init(&mrail_prov, domain, attr, &mrail_cq->util_cq,
			  &mrail_cq_progress, context);
	if (ret) {
		free(mrail_cq);
		return ret;
	}

	mrail_domain = container_of(domain, struct mrail_domain,
				    util_domain.domain_fid);

	mrail_cq->cqs = calloc(mrail_domain->num_domains,
			       sizeof(*mrail_cq->cqs));
	if (!mrail_cq->cqs)
		goto err;

	mrail_cq->num_cqs = mrail_domain->num_domains;

	for (i = 0; i < mrail_cq->num_cqs; i++) {
		ret = fi_cq_open(mrail_domain->domains[i], &rail_cq_attr,
				 &mrail_cq->cqs[i], NULL);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_EP_CTRL,
				"Unable to open rail CQ\n");
			goto err;
		}
	}

	// TODO add regular process comp when FI_BUFFERED_RECV not set
	mrail_cq->process_comp = mrail_handle_recv_completion;

	*cq_fid = &mrail_cq->util_cq.cq_fid;
	(*cq_fid)->fid.ops = &mrail_cq_fi_ops;
	(*cq_fid)->ops = &mrail_cq_ops;

	return 0;
err:
	mrail_cq_close(&mrail_cq->util_cq.cq_fid.fid);
	return ret;
}
