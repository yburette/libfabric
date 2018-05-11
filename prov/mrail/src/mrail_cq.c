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
	.strerror = fi_no_cq_strerror,
};

static int handle_write_completion(struct mrail_cq *mrail_cq,
		struct util_ep *ep, struct fi_cq_tagged_entry *comp)
{
	int ret;
	struct mrail_req *req;
	struct mrail_subreq *subreq;

	subreq = comp->op_context;
	req = subreq->parent;

	req->remaining_comps--;

	if (req->remaining_comps == 0) {
		ret = ofi_cq_write(&mrail_cq->util_cq, req->op_context,
				req->flags, req->len, req->buf, req->data,
				req->tag);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Cannot write to util cq\n");
			goto error;
		}

		mrail_cntr_inc(ep->wr_cntr);

		free(req);
	}

	free(subreq);

	return FI_SUCCESS;
error:
	return ret;
}

static int handle_read_completion(struct mrail_cq *mrail_cq,
		struct util_ep *ep, struct fi_cq_tagged_entry *comp)
{
	int ret;
	struct mrail_req *req;
	struct mrail_subreq *subreq;

	subreq = comp->op_context;
	req = subreq->parent;

	req->remaining_comps--;

	if (req->remaining_comps == 0) {
		ret = ofi_cq_write(&mrail_cq->util_cq, req->op_context,
				req->flags, req->len, req->buf, req->data,
				req->tag);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Cannot write to util cq\n");
			goto error;
		}

		mrail_cntr_inc(ep->rd_cntr);

		free(req);
	}

	free(subreq);

	return FI_SUCCESS;
error:
	return ret;
}

static int handle_completion(struct mrail_cq *mrail_cq, struct util_ep *ep,
		struct fi_cq_tagged_entry *comp)
{
	int ret;

	if (comp->flags & FI_WRITE) {
		return handle_write_completion(mrail_cq, ep, comp);
	}
	if (comp->flags & FI_READ) {
		return handle_read_completion(mrail_cq, ep, comp);
	}

	ret = ofi_cq_write(&mrail_cq->util_cq, comp->op_context, comp->flags,
			comp->len, comp->buf, comp->data, comp->tag);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_CQ,
			"Cannot write to util cq\n");
		goto error;
	}

	if (comp->flags & FI_TRANSMIT) {
		mrail_cntr_inc(ep->tx_cntr);
	}
	if (comp->flags & FI_RECV) {
		mrail_cntr_inc(ep->rx_cntr);
	}
	return FI_SUCCESS;
error:
	return ret;
}

void mrail_cq_progress(struct util_cq *cq, struct util_ep *ep)
{
	struct mrail_cq *mrail_cq;
	struct fi_cq_tagged_entry comp;
	size_t i;
	int ret;

	mrail_cq = container_of(cq, struct mrail_cq, util_cq);

	for (i = 0; i < mrail_cq->num_cqs; i++) {
		ret = fi_cq_read(mrail_cq->cqs[i], &comp, 1);
		if (ret == -FI_EAGAIN || !ret)
			continue;
		if (ret < 0) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Unable to read rail completion\n");
			goto err;
		}
		ret = handle_completion(mrail_cq, ep, &comp);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_CQ,
				"Cannot handle completion: %d\n", ret);
			goto err;
		}
	}
	return;
err:
	// TODO write error to cq
	assert(0);
}

int mrail_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		   struct fid_cq **cq_fid, void *context)
{
	struct mrail_domain *mrail_domain;
	struct mrail_cq *mrail_cq;
	struct fi_cq_attr rail_attr;
	size_t i;
	int ret;

	mrail_cq = calloc(1, sizeof(*mrail_cq));
	if (!mrail_cq)
		return -FI_ENOMEM;

	ret = ofi_cq_init(&mrail_prov, domain, attr, &mrail_cq->util_cq,
			&ofi_cq_progress, context);
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

	/* Force cq format so that we can properly handle the completions */
	/* TODO: see if there is a better way of doing this */
	rail_attr = *attr;
	rail_attr.format = FI_CQ_FORMAT_TAGGED;

	for (i = 0; i < mrail_cq->num_cqs; i++) {
		ret = fi_cq_open(mrail_domain->domains[i], &rail_attr,
				&mrail_cq->cqs[i], NULL);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_EP_CTRL,
				"Unable to open rail CQ\n");
			goto err;
		}

	}

	*cq_fid = &mrail_cq->util_cq.cq_fid;
	(*cq_fid)->fid.ops = &mrail_cq_fi_ops;
	(*cq_fid)->ops = &mrail_cq_ops;

	return 0;
err:
	mrail_cq_close(&mrail_cq->util_cq.cq_fid.fid);
	return ret;
}
