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

extern struct fi_ops_cm mxr_ops_cm;
extern struct fi_ops_msg mxr_ops_msg;

static int mxr_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
    int ret;
    struct mxr_fid_pep* mxr_pep;
    struct mxr_fid_eq* mxr_eq;
    struct fi_cq_attr cq_attr;

    mxr_pep = container_of(fid, struct mxr_fid_pep, pep.fid);
    mxr_eq = container_of(bfid, struct mxr_fid_eq, eq.fid);

    mxr_pep->eq = mxr_eq;
    mxr_eq->pep = mxr_pep;
    
    /* TODO: What if bfid is not EQ? */
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    ret = fi_cq_open(mxr_pep->rd_domain, &cq_attr, &mxr_eq->rd_cq, NULL);
    if (ret) {
        goto errout;
    }

    ret = fi_ep_bind(mxr_pep->rd_ep, (fid_t)mxr_eq->rd_cq, FI_RECV);
    if (ret) {
        goto closecq;
    }

    return 0;
closecq:
    fi_close((fid_t)mxr_eq->rd_cq);
errout:
    return ret;
}

static int mxr_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
    int ret;
    struct mxr_fid_ep* mxr_ep;
    struct mxr_fid_eq* mxr_eq;
    struct fi_cq_attr cq_attr;

    mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid);
    mxr_eq = container_of(bfid, struct mxr_fid_eq, eq.fid);

    mxr_ep->eq = mxr_eq;
    mxr_eq->ep = mxr_ep;
    mxr_eq->rd_domain = mxr_ep->domain->rd_domain;

    /* TODO: What if bfid is not EQ? */
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
    ret = fi_cq_open(mxr_ep->domain->rd_domain, &cq_attr, &mxr_eq->rd_cq, NULL);
    if (ret) {
        goto errout;
    }

    ret = fi_ep_bind(mxr_ep->rd_ep, (fid_t)mxr_eq->rd_cq, FI_RECV);
    if (ret) {
        goto closecq;
    }

    return 0;
closecq:
    fi_close((fid_t)mxr_eq->rd_cq);
errout:
    return ret;
}

static int mxr_ep_control(struct fid *fid, int command, void *arg)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;
    ssize_t count;

    if (!fid) {
        return -FI_EINVAL;
    }

    switch (fid->fclass) {
    case FI_CLASS_EP:
        mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid); 
        ret = mxr_ep->rd_ep->fid.ops->control(&mxr_ep->rd_ep->fid,
                                              command, arg);

        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Unsupported FI_CLASS: %d\n", fid->fclass);
        return -FI_EINVAL;
    }

    return ret;
}

static ssize_t	mxr_ep_cancel(fid_t fid, void *context)
{
    struct mxr_fid_ep *ep = container_of(fid, struct mxr_fid_ep, ep.fid);
	return fi_cancel((fid_t)ep->rd_ep, context);
}

static int mxr_ep_getopt(fid_t fid, int level, int optname,
        void *optval, size_t *optlen)
{
	return -FI_ENOSYS;
}

static int mxr_ep_setopt(fid_t fid, int level, int optname,
        const void *optval, size_t optlen)
{
	return -FI_ENOSYS;
}

static int mxr_ep_close(fid_t fid)
{
    return -FI_ENOSYS;
}

struct fi_ops_ep mxr_ops_ep = {
    .size = sizeof(struct fi_ops_ep),
    .cancel = mxr_ep_cancel,
    .getopt = mxr_ep_getopt,
    .setopt = mxr_ep_setopt,
    .tx_ctx = fi_no_tx_ctx,
    .rx_ctx = fi_no_rx_ctx,
    .rx_size_left = fi_no_rx_size_left,
    .tx_size_left = fi_no_tx_size_left
};

struct fi_ops mxr_fi_ops_ep = {
    .size = sizeof(struct fi_ops),
    .close = mxr_ep_close,
    .bind = mxr_ep_bind,
    .control = mxr_ep_control,
    .ops_open = fi_no_ops_open
};

struct fi_ops mxr_fi_ops_pep = {
    .size = sizeof(struct fi_ops),
    .close = mxr_ep_close,
    .bind = mxr_pep_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open
};

int mxr_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_pep **pep, void *context)
{
    int ret;
    int err;
    struct mxr_fid_pep *mxr_pep;
    struct mxr_fid_fabric *mxr_fabric = (struct mxr_fid_fabric*)fabric;
    struct fi_av_attr av_attr = {0};

    mxr_pep = (struct mxr_fid_pep*) calloc(1, sizeof(struct mxr_fid_pep));
    if (!mxr_pep) {
        err = -FI_ENOMEM;
        goto errout;
    }

    ret = fi_domain(mxr_fabric->rd_fabric, mxr_fabric->rd_info,
                    &mxr_pep->rd_domain, context);
    if (ret) {
        err = ret;
        goto freepep;
    }

    ret = fi_endpoint(mxr_pep->rd_domain, info, &mxr_pep->rd_ep, context);
    if (ret) {
        err = ret;
        goto closedomain;
    }

    av_attr.type = FI_AV_TABLE;
    ret = fi_av_open(mxr_pep->rd_domain, &av_attr, &mxr_pep->rd_av, context); 
    if (ret) {
        goto closeep;
    }

    ret = fi_ep_bind(mxr_pep->rd_ep, (fid_t)mxr_pep->rd_av, 0);
    if (ret) {
        goto closeav;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "new RD endpoint created: %p (mxr_pep %p)\n",
            mxr_pep->rd_ep, mxr_pep);

    mxr_pep->info = info;

    mxr_pep->pep.fid.fclass = FI_CLASS_PEP;
    mxr_pep->pep.fid.context = context;
    mxr_pep->pep.fid.ops = &mxr_fi_ops_pep;
    mxr_pep->pep.ops = &mxr_ops_ep;
    mxr_pep->pep.cm = &mxr_ops_cm;
    mxr_pep->mxr_fabric = mxr_fabric;

    *pep = &mxr_pep->pep;

    return 0;
closeav:
    fi_close((fid_t)mxr_pep->rd_av);
closeep:
    fi_close((fid_t)mxr_pep->rd_ep);
closedomain:
    fi_close((fid_t)mxr_pep->rd_domain);
freepep:
    free(mxr_pep);
errout:
    return err;
}

int mxr_ep_open(struct fid_domain *domain, struct fi_info *info,
        struct fid_ep **ep, void *context)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_fid_domain *mxr_domain = (struct mxr_fid_domain*)domain;
    struct fi_av_attr av_attr = {0};

    mxr_ep = (struct mxr_fid_ep*) calloc(1, sizeof(*mxr_ep));
    if (!mxr_ep) {
        ret = -FI_ENOMEM;
        goto errout;
    }
    mxr_ep->domain = mxr_domain;
    mxr_ep->pep = (struct mxr_fid_pep*)info->handle;

    /* Save dest_addr if provided. */
    if (info->dest_addr && info->dest_addrlen > 0) {
        mxr_ep->peername = calloc(info->dest_addrlen, sizeof(char));
        if (!mxr_ep->peername) {
            goto freeep;
        }
        memcpy(mxr_ep->peername, info->dest_addr, info->dest_addrlen);
    }

    if (mxr_ep->pep) {
        mxr_ep->rd_ep = mxr_ep->pep->rd_ep;
        mxr_ep->rd_av = mxr_ep->pep->rd_av;
    } else {

        /* TODO: Shouldn't we pass the base info here instead? */
        ret = fi_endpoint(mxr_domain->rd_domain, info, &mxr_ep->rd_ep, context);
        if (ret) {
            goto freepeername;
        }
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "new RD endpoint created: %p (mxr_ep %p, mxr_pep %p)\n",
                mxr_ep->rd_ep, mxr_ep, mxr_ep->pep);

        av_attr.type = FI_AV_TABLE;
        ret = fi_av_open(mxr_domain->rd_domain, &av_attr, &mxr_ep->rd_av, context); 
        if (ret) {
            goto closeep;
        }

        ret = fi_ep_bind(mxr_ep->rd_ep, (fid_t)mxr_ep->rd_av, 0);
        if (ret) {
            goto closeav;
        }
    }

    mxr_ep->ep.fid.fclass = FI_CLASS_EP;
    mxr_ep->ep.fid.context = context;
    mxr_ep->ep.fid.ops = &mxr_fi_ops_ep;
    mxr_ep->ep.ops = &mxr_ops_ep;
    mxr_ep->ep.cm = &mxr_ops_cm;
    mxr_ep->ep.msg = &mxr_ops_msg;
    mxr_ep->ep.rma = NULL;
    mxr_ep->ep.tagged = NULL;
    mxr_ep->ep.atomic = NULL;

    *ep = &mxr_ep->ep;

    return 0;
closeav:
    fi_close((fid_t)&mxr_ep->rd_av);
closeep:
    fi_close((fid_t)&mxr_ep->rd_ep);
freepeername:
    if (mxr_ep->peername)
        free(mxr_ep->peername);
freeep:
    free(mxr_ep);
errout:
    return ret;
}
