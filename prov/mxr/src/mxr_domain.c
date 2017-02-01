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

#include "mxr.h"

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
    struct mxr_conn_buf *cm_buf;
    struct mxr_fid_domain *mxr_domain = container_of(fid,
                                                     struct mxr_fid_domain,
                                                     util_domain.domain_fid);

    mxr_domain->refcnt--;

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "Closing mxr_domain %p rd_domain %p rd_av %p refcnt %d\n",
            mxr_domain, mxr_domain->rd_domain, mxr_domain->rd_av,
            mxr_domain->refcnt);

    if (mxr_domain->refcnt > 0) {
        return 0;
    }

    while (!dlist_empty(&mxr_domain->cm_rx_queue)) {
        cm_buf = container_of(mxr_domain->cm_rx_queue.next, struct mxr_conn_buf,
                              list_entry);
        ret = fi_cancel((fid_t)mxr_domain->cm_rd_ep, &cm_buf->ctx);
        if (ret) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "Couldn't cancel RX CM buffer\n", ret);
            return ret;
        }
        dlist_remove(&cm_buf->list_entry);
        free(cm_buf);
    }

    while (!dlist_empty(&mxr_domain->cm_tx_queue)) {
        cm_buf = container_of(&mxr_domain->cm_tx_queue.next, struct mxr_conn_buf,
                              list_entry);
        dlist_remove(&cm_buf->list_entry);
        free(cm_buf);
    }

    ret = fi_close((fid_t)mxr_domain->cm_rd_ep);
    if (ret)
        return ret;

    ret = fi_close((fid_t)mxr_domain->cm_rd_cq);
    if (ret)
        return ret;

    ret = fi_close((fid_t)mxr_domain->rd_av);
    if (ret)
        return ret;

    ret = fi_close((fid_t)mxr_domain->rd_domain);
    if (ret)
        return ret;

	ret = ofi_domain_close(&mxr_domain->util_domain);
	if (ret)
        return ret;

    /* Reset mxr_fabric */
    mxr_domain->mxr_fabric->domain = NULL;

    free(mxr_domain);
    return 0;
}

static struct fi_ops mxr_domain_fi_ops = {
    .size = sizeof(struct fi_ops),
    .close = mxr_domain_close,
    .bind = fi_no_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open,
};


static int mxr_mr_reg(struct fid *fid, const void *buf, size_t len,
        uint64_t access, uint64_t offset, uint64_t requested_key,
        uint64_t flags, struct fid_mr **mr, void *context)
{
    struct mxr_fid_domain *mxr_domain = container_of(fid,
                                                     struct mxr_fid_domain,
                                                     util_domain.domain_fid);
    return fi_mr_reg(mxr_domain->rd_domain, buf, len, access, offset,
                     requested_key, flags, mr, context);
}

static struct fi_ops_mr mxr_domain_ops_mr = {
    .size = sizeof(struct fi_ops_mr),
    .reg = mxr_mr_reg,
    .regv = fi_no_mr_regv,
    .regattr = fi_no_mr_regattr,
};

int post_rx_cm_buffers(struct mxr_fid_domain *mxr_domain)
{
    int ret;
    struct mxr_conn_buf *cm_buf;

    cm_buf = calloc(1, sizeof(struct mxr_conn_buf));
    if (!cm_buf) {
        return -FI_ENOMEM;
    }

    dlist_insert_head(&cm_buf->list_entry, &mxr_domain->cm_rx_queue);

    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Posting CM buffers\n");

    ret = fi_recv(mxr_domain->cm_rd_ep,
                  &cm_buf->data,
                  sizeof(struct mxr_conn_pkt),
                  NULL,
                  FI_ADDR_UNSPEC,
                  (void *) &cm_buf->ctx);
    if (ret) {
        /* TODO: What will happen once this is a list? */
        goto freebuf;
    }

    return 0;
freebuf:
    free(cm_buf);
    return ret;
}

int mxr_domain_open(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_domain **domain, void *context)
{
	int ret;
	struct mxr_fid_domain *mxr_domain;
    struct mxr_fid_fabric *mxr_fabric;
    struct fi_av_attr av_attr = {0};
    struct fi_cq_attr cq_attr = {0};

    mxr_fabric = container_of(fabric, struct mxr_fid_fabric,
                              util_fabric.fabric_fid);

    if (mxr_fabric->domain) {
        /* domain was already initialized by passive_ep or fi_domain */
        *domain = &mxr_fabric->domain->util_domain.domain_fid;
        mxr_fabric->domain->refcnt++;
        return 0;
    }

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

    av_attr.type = FI_AV_TABLE;
    ret = fi_av_open(mxr_domain->rd_domain, &av_attr,
                     &mxr_domain->rd_av, context); 
    if (ret) {
        goto closerddomain;
    }

    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    ret = fi_cq_open(mxr_domain->rd_domain, &cq_attr,
                     &mxr_domain->cm_rd_cq, context);
    if (ret) {
        goto closerdav;
    }

    /* TODO: info or mxr_fabric->rd_info? */
    ret = fi_endpoint(mxr_domain->rd_domain, info,
                      &mxr_domain->cm_rd_ep, context);
    if (ret) {
        goto closerdcq;
    }

    ret = fi_ep_bind(mxr_domain->cm_rd_ep, (fid_t)mxr_domain->rd_av, 0);
    if (ret) {
        goto closerdep;
    }

    ret = fi_ep_bind(mxr_domain->cm_rd_ep, (fid_t)mxr_domain->cm_rd_cq,
                     FI_SEND | FI_RECV);
    if (ret) {
        goto closerdep;
    }

    ret = fi_enable(mxr_domain->cm_rd_ep);
    if (ret) {
        goto closerdep;
    }

#if 0
    ret = mxr_cm_map_remote_ports(mxr_domain);
    if (ret) {
        goto closerdep;
    }
#endif

    dlist_init(&mxr_domain->cm_tx_queue);
    dlist_init(&mxr_domain->cm_rx_queue);

    ret = post_rx_cm_buffers(mxr_domain);
    if (ret) {
        goto closerdep;
    }

    mxr_domain->util_domain.domain_fid.fid.ops = &mxr_domain_fi_ops;
    mxr_domain->util_domain.domain_fid.ops = &mxr_domain_ops;
    mxr_domain->util_domain.domain_fid.mr = &mxr_domain_ops_mr;
    mxr_domain->mxr_fabric = mxr_fabric;
    mxr_domain->refcnt = 1;

    mxr_fabric->domain = mxr_domain;

	*domain = &mxr_domain->util_domain.domain_fid;

	return 0;

closerdep:
    fi_close((fid_t)mxr_domain->cm_rd_ep);
closerdcq:
    fi_close((fid_t)mxr_domain->cm_rd_cq);
closerdav:
    fi_close((fid_t)mxr_domain->rd_av);
closerddomain:
    fi_close((fid_t)mxr_domain->rd_domain);
closedomain:
    ofi_domain_close(&mxr_domain->util_domain);
freedomain:
    free(mxr_domain);
    return ret;
}
