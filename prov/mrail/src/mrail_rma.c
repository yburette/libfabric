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

#include "mrail.h"

static inline void mrail_iov_to_rail(const struct iovec *iov, const void *desc,
		const uint32_t rail, struct iovec *out_iov, void **out_desc)
{
	const struct mrail_mr *mrail_mr = desc;

	//TODO: add base address from mrail_mr
	out_iov->iov_base 	= (void*)((uintptr_t)iov->iov_base);
	out_iov->iov_len	= iov->iov_len;

	*out_desc = (mrail_mr ? fi_mr_desc(mrail_mr->rails[rail].mr) : NULL);
}

static inline void mrail_rma_iov_to_rail(const struct fi_rma_iov *rma_iov,
		const uint32_t rail, struct fi_rma_iov *out_rma_iov)
{
	struct mrail_addr_key *mr_map = (struct mrail_addr_key *)rma_iov->key;

	//TODO: add base address from mrail_addr_key
	out_rma_iov->addr 	= rma_iov->addr;
	out_rma_iov->len	= rma_iov->len;
	out_rma_iov->key	= mr_map[rail].key;
}

static void mrail_subreq_to_rail(struct mrail_subreq *subreq, uint32_t rail,
		struct iovec *out_iovs, void **out_descs,
		struct fi_rma_iov *out_rma_iovs)
{
	size_t i;

	for (i = 0; i < subreq->iov_count; ++i) {
		mrail_iov_to_rail(&subreq->iov[i], subreq->descs[i], rail,
				&out_iovs[i], &out_descs[i]);
	}

	for (i = 0; i < subreq->rma_iov_count; ++i) {
		mrail_rma_iov_to_rail(subreq->rma_iov, rail, &out_rma_iovs[i]);
	}
}

static ssize_t mrail_try_posting_subreq(uint32_t rail,
		struct mrail_subreq *subreq)
{
	ssize_t ret;
	struct iovec rail_iov[MRAIL_IOV_LIMIT];
	void *rail_descs[MRAIL_IOV_LIMIT];
	struct fi_rma_iov rail_rma_iov[MRAIL_IOV_LIMIT];
	struct fi_msg_rma msg;

	struct mrail_req *req = subreq->parent;
	struct mrail_ep *mrail_ep = req->mrail_ep;

	mrail_subreq_to_rail(subreq, rail, rail_iov, rail_descs, rail_rma_iov);

	msg.msg_iov		= rail_iov;
	msg.desc		= rail_descs;
	msg.iov_count		= subreq->iov_count;
	msg.addr		= req->remote_addrs[rail];
	msg.rma_iov		= rail_rma_iov;
	msg.rma_iov_count	= subreq->rma_iov_count;
	msg.context		= &subreq->context;
	//TODO: we may not want to send immediate data with all subreqs
	msg.data		= req->data;

	switch (req->op_type) {
	case FI_READ:
		ret = fi_readmsg(mrail_ep->rails[rail].ep, &msg, req->flags);
		break;
	case FI_WRITE:
		ret = fi_writemsg(mrail_ep->rails[rail].ep, &msg, req->flags);
		break;
	default:
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unsupported operation: %d\n",
			req->op_type);
		ret = -FI_EINVAL;
	};

	return ret;
}

static ssize_t mrail_try_posting_req(struct mrail_req *req)
{
	size_t i;
	uint32_t rail;
	ssize_t ret = 0;

	while (req->pending_subreq >= 0) {
		/* Try all rails before giving up */
		for (i = 0; i < req->mrail_ep->num_eps; ++i) {
			rail = mrail_get_tx_rail(req->mrail_ep);

			ret = mrail_try_posting_subreq(rail,
					&req->subreqs[req->pending_subreq]);
			if (ret != -FI_EAGAIN) {
				break;
			} else {
				/* One of the rails is busy. Try progressing. */
				mrail_poll_cq(req->mrail_ep->util_ep.tx_cq);
			}
		}

		if (ret != 0) {
			if (ret == -FI_EAGAIN) {
				break;
			}
			/* TODO: Handle errors besides FI_EAGAIN */
			assert(0);
		}
		req->pending_subreq--;
	}

	return ret;
}

static struct mrail_req *mrail_dequeue_deferred_req(struct mrail_ep *mrail_ep)
{
	struct slist_entry *e;

	e = slist_remove_head(&mrail_ep->deferred_reqs);
	if (!e) {
		return NULL;
	}
	return container_of(e, struct mrail_req, entry);
}

static inline void mrail_push_deferred_req(struct mrail_ep *mrail_ep,
		struct mrail_req *req)
{
	slist_insert_head(&req->entry, &mrail_ep->deferred_reqs);
}

static inline void mrail_enqueue_deferred_req(struct mrail_ep *mrail_ep,
		struct mrail_req *req)
{
	slist_insert_tail(&req->entry, &mrail_ep->deferred_reqs);
}

void mrail_progress_deferred_reqs(struct mrail_ep *mrail_ep)
{
	struct mrail_req *req;
	ssize_t ret;

	req = mrail_dequeue_deferred_req(mrail_ep);
	while (req) {
		ret = mrail_try_posting_req(req);
		if (ret) {
			mrail_push_deferred_req(mrail_ep, req);
			break;
		}
		req = mrail_dequeue_deferred_req(mrail_ep);
	}
}

static size_t mrail_prepare_rma_subreqs(struct mrail_ep *mrail_ep,
		const struct fi_msg_rma *msg, struct mrail_req *req)
{
	ssize_t ret;
	struct mrail_subreq *subreq;
	size_t subreq_count;
	size_t total_len;
	size_t chunk_len;
	size_t subreq_len;
	size_t iov_index;
	size_t iov_offset;
	size_t rma_iov_index;
	size_t rma_iov_offset;
	int i;

	/* For now, stripe across all rails.
	 * This could be determined by a dynamic scheduler instead.
	 */
	subreq_count = mrail_ep->num_eps;

	total_len = ofi_total_iov_len(msg->msg_iov, msg->iov_count); 
	chunk_len = total_len / subreq_count;

	/* The first chunk is the longest */
	subreq_len =  chunk_len + (total_len % subreq_count);
	iov_index = 0;
	iov_offset = 0;
	rma_iov_index = 0;
	rma_iov_offset = 0;

	/* The array is filled in reverse order -- i.e. first subreq at
	 * last position in the array. Filling the array in this order saves
	 * us from having to use two variables, to track the total number of
	 * subreqs, and to know which one to try posting next.
	 * Instead, a single variable (req->pending_subreq) is used to keep
	 * track of which subreq to post next, starting at the end of the
	 * array.
	 */
	for (i = (subreq_count - 1); i >= 0; --i) {
		subreq = &req->subreqs[i];

		subreq->parent = req;

		ret = ofi_copy_iov_desc(subreq->iov, subreq->descs,
				&subreq->iov_count,
				(struct iovec *)msg->msg_iov, msg->desc,
				msg->iov_count, &iov_index, &iov_offset,
				subreq_len);
		if (ret) {
			return 0;
		}

		ret = ofi_copy_rma_iov(subreq->rma_iov, &subreq->rma_iov_count,
				(struct fi_rma_iov *)msg->rma_iov,
				msg->rma_iov_count, &rma_iov_index,
				&rma_iov_offset, subreq_len);
		if (ret) {
			return 0;
		}

		/* All the other chunks have the same length */
		subreq_len = chunk_len;
	}

	return subreq_count;
}

static ssize_t mrail_init_rma_req(struct mrail_ep *mrail_ep,
		struct mrail_req *req, const struct fi_msg_rma *msg,
		uint64_t flags, int op_type)
{
	size_t subreq_count;

	subreq_count = mrail_prepare_rma_subreqs(mrail_ep, msg, req);
	if (subreq_count <= 0) {
		return -FI_EINVAL;
	}

	req->op_type		= op_type;
	req->flags		= flags;
	req->data		= msg->data;
	req->mrail_ep		= mrail_ep;
	req->remote_addrs	= ofi_av_get_addr(mrail_ep->util_ep.av,
						(int)msg->addr);
	req->comp.op_context	= msg->context;
	req->comp.flags		= flags;
	ofi_atomic_initialize32(&req->expected_subcomps, subreq_count);

	/* pending_subreq is the index of the next subreq to post.
	 * The array was filled in reverse order in mrail_prepare_rma_subreqs()
	 */
	req->pending_subreq	= subreq_count - 1;

	return 0;
}

static ssize_t mrail_ep_post_rma(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags, int op_type)
{
	ssize_t ret;
	struct mrail_ep *mrail_ep;
	struct mrail_req *req;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);

	/* TODO: reserve a CQ entry for the req's completion */
	req = mrail_alloc_req(mrail_ep);
	if (!req) {
		return -FI_ENOMEM;
	}

	ret = mrail_init_rma_req(mrail_ep, req, msg, flags, op_type);
	if (ret) {
		mrail_free_req(mrail_ep, req);
		return ret;
	}

	mrail_enqueue_deferred_req(mrail_ep, req);

	/* Initiate progress here. See mrail_ep_progress() for any remaining
	 * reqs. */
	mrail_progress_deferred_reqs(mrail_ep);

	return 0;
}

static ssize_t mrail_ep_readmsg(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags)
{
	return mrail_ep_post_rma(ep_fid, msg, flags, FI_READ);
}

/* TODO: separate the different operations to optimize performance */
static ssize_t mrail_ep_read(struct fid_ep *ep_fid, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct mrail_ep *mrail_ep;
	struct iovec iovec = {
		.iov_base = (void*)buf,
		.iov_len = len
	};
	struct fi_rma_iov rma_iov= {
		.addr = addr,
		.len = len,
		.key = key
	};
	struct fi_msg_rma msg = {
		.msg_iov = &iovec,
		.desc = &desc,
		.iov_count = 1,
		.addr = src_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0
	};

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);

	return mrail_ep_readmsg(ep_fid, &msg, mrail_ep->util_ep.tx_op_flags);
}

static ssize_t mrail_ep_writemsg(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags)
{
	return mrail_ep_post_rma(ep_fid, msg, flags, FI_WRITE);
}

static ssize_t mrail_ep_write(struct fid_ep *ep_fid, const void *buf,
		size_t len, void *desc, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct mrail_ep *mrail_ep;
	struct iovec iovec = {
		.iov_base = (void*)buf,
		.iov_len = len
	};
	struct fi_rma_iov rma_iov= {
		.addr = addr,
		.len = len,
		.key = key
	};
	struct fi_msg_rma msg = {
		.msg_iov = &iovec,
		.desc = &desc,
		.iov_count = 1,
		.addr = dest_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = context,
		.data = 0
	};

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);

	return mrail_ep_writemsg(ep_fid, &msg, mrail_ep->util_ep.tx_op_flags);
}

static ssize_t mrail_ep_inject_write(struct fid_ep *ep_fid, const void *buf,
		size_t len, fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct mrail_ep *mrail_ep;
	struct mrail_addr_key *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_addr_key*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);

	rail = mrail_get_tx_rail(mrail_ep);

	assert(rail_fi_addr);

	ret = fi_inject_write(mrail_ep->rails[rail].ep, buf, len,
			rail_fi_addr[rail], addr,
			mr_map[rail].key);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post inject write on rail: %" PRIu32 "\n",
			rail);
		return ret;
	}

	return 0;
}

struct fi_ops_rma mrail_ops_rma = {
	.size = sizeof (struct fi_ops_rma),
	.read = mrail_ep_read,
	.readv = fi_no_rma_readv,
	.readmsg = mrail_ep_readmsg,
	.write = mrail_ep_write,
	.writev = fi_no_rma_writev,
	.writemsg = mrail_ep_writemsg,
	.inject = mrail_ep_inject_write,
	.writedata = fi_no_rma_writedata,
	.injectdata = fi_no_rma_injectdata,
};
