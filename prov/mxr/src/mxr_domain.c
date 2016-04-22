/*
 * Copyright (c) 2016 Intel Corporation, Inc.  All rights reserved.
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

#include <rdma/fi_log.h>

#include "mxr.h"

int	mxr_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
        struct fid_cq **cq, void *context)
{
    struct mxr_fid_domain *mxr_domain = (struct mxr_fid_domain*)domain;
    return fi_cq_open(mxr_domain->rd_domain, attr, cq, context);
}

static struct fi_ops_domain mxr_domain_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = fi_no_av_open,
	.cq_open = mxr_cq_open,
	.endpoint = mxr_ep_open,
	.scalable_ep = fi_no_scalable_ep,
	.cntr_open = fi_no_cntr_open,
	.poll_open = fi_poll_create,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
};

static int mxr_domain_close(fid_t fid)
{
	int ret;
	struct util_domain *domain;
	domain = container_of(fid, struct util_domain, domain_fid.fid);
	ret = ofi_domain_close(domain);
	if (ret)
		return ret;
	free(domain);
	return 0;
}

static struct fi_ops mxr_domain_fi_ops = {
    .size = sizeof(struct fi_ops),
    .close = mxr_domain_close,
    .bind = fi_no_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open,
};

int mxr_domain_open(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_domain **domain, void *context)
{
	int ret;
	struct mxr_fid_domain *mxr_domain;
    struct mxr_fid_fabric *mxr_fabric = (struct mxr_fid_fabric*)fabric;

	mxr_domain = calloc(1, sizeof(*mxr_domain));
	if (!mxr_domain) {
		return -FI_ENOMEM;
    }

	ret = ofi_domain_init(fabric, info, &mxr_domain->util_domain, context);
	if (ret) {
        goto freedomain;
    }

    ret = fi_domain(mxr_fabric->rd_fabric, mxr_fabric->rd_info,
                    &mxr_domain->rd_domain, context);
	if (ret) {
        goto closedomain;
    }

	*domain = &mxr_domain->util_domain.domain_fid;
	(*domain)->fid.ops = &mxr_domain_fi_ops;
	(*domain)->ops = &mxr_domain_ops;
	return 0;
closedomain:
    fi_close((fid_t)&mxr_domain->util_domain);
freedomain:
    free(mxr_domain);
    return ret;
}
