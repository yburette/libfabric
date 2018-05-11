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

typedef ssize_t mrail_rma_msg_fn(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags);

static ssize_t mrail_ep_post_rma(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags,
		mrail_rma_msg_fn *rma_fn)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	ssize_t ret;

	size_t num_rails;
	size_t remaining_len;
	size_t chunk_len;
	size_t offset;
	size_t sublen;
	size_t i;

	struct mrail_req *req;
	struct mrail_subreq *subreq;
	void *rail_desc;

	if (msg->iov_count > 1) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
				"Cannot handle iov_count > 1");
		return -FI_ENOSYS;
	}

	if (msg->rma_iov_count > 1) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
				"Cannot handle rma_iov_count > 1");
		return -FI_ENOSYS;
	}

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)msg->addr);
	mr_map = (struct mrail_mr_map_raw*)msg->rma_iov->key;

	num_rails = mrail_ep->num_eps;
	remaining_len = msg->msg_iov->iov_len;
	chunk_len = remaining_len / num_rails;

	req = calloc(1, sizeof *req);
	if (!req) {
		return -FI_ENOMEM;
	}

	req->remaining_comps	= num_rails;
	req->op_context		= msg->context;
	req->flags		= flags;

	offset = 0;
	for (i=0; i<num_rails; ++i) {
		struct iovec rail_iovec;
		struct fi_msg_rma rail_msg;
		struct fi_rma_iov rail_rma_iov;

		sublen = remaining_len;
		if ((remaining_len > chunk_len) && (i < (num_rails-1))) {
			sublen = chunk_len;
		}

		subreq = calloc(1, sizeof *subreq);
		if (!subreq) {
			ret = -FI_ENOMEM;
			goto error1;
		}
		subreq->parent = req;

		rail = mrail_get_rma_rail(mrail_ep);

		rail_iovec.iov_base	= msg->msg_iov->iov_base + offset;
		rail_iovec.iov_len	= sublen;

		rail_rma_iov.addr	= msg->rma_iov->addr + offset;
		rail_rma_iov.len	= sublen;
		rail_rma_iov.key	= mr_map->rkeys[rail];

		rail_msg.msg_iov	= &rail_iovec;
		rail_msg.desc		= NULL;
		if (msg->desc && msg->desc[0]) {
			struct mrail_mr *mrail_mr = msg->desc[0];
			rail_desc = fi_mr_desc(mrail_mr->mrs[rail]);
			rail_msg.desc = &rail_desc;
		}
		rail_msg.iov_count 	= msg->iov_count;
		rail_msg.addr 		= rail_fi_addr[rail];
		rail_msg.rma_iov 	= &rail_rma_iov;
		rail_msg.rma_iov_count 	= msg->rma_iov_count;
		rail_msg.context 	= &subreq->context;
		rail_msg.data 		= msg->data;

		ret = rma_fn(mrail_ep->eps[rail], &rail_msg, flags);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
				"Unable to post RMA on rail: %" PRIu32
				" ret=%ld\n",
				rail, ret);
			goto error2;
		}

		remaining_len	-= sublen;
		offset 		+= sublen;
	}

	assert(remaining_len == 0);

	return 0;

error2:
	free(subreq);
error1:
	free(req);
	return ret;
}

static ssize_t mrail_ep_readmsg(struct fid_ep *ep_fid,
		const struct fi_msg_rma *msg, uint64_t flags)
{
	return mrail_ep_post_rma(ep_fid, msg, flags, fi_readmsg);
}

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
	return mrail_ep_post_rma(ep_fid, msg, flags, fi_writemsg);
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
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);
	rail = mrail_get_rma_rail(mrail_ep);

	assert(rail_fi_addr);

	ret = fi_inject_write(mrail_ep->eps[rail], buf, len, rail_fi_addr[rail],
			addr, mr_map->rkeys[rail]);
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

