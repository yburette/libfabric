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

extern struct fi_ops_cm mxr_ops_cm;
extern struct fi_ops_msg mxr_ops_msg;
extern struct fi_ops_rma mxr_ops_rma;

static int mxr_pep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
    struct mxr_fid_pep* pep;
    struct mxr_fid_eq* eq;

    FI_INFO(&mxr_prov, FI_LOG_FABRIC,
            "binding PEP to a class %d\n", bfid->fclass);

    if (bfid->fclass != FI_CLASS_EQ) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "class %d cannot be bound to PEP\n", bfid->fclass);
        return -FI_EINVAL;
    }

    pep = container_of(fid, struct mxr_fid_pep, pep_fid.fid);
    eq = container_of(bfid, struct mxr_fid_eq, eq_fid.fid);

    pep->eq = eq;
    eq->pep = pep;

    if (eq->domain && (eq->domain != pep->mxr_domain)) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "EQ was already bound to a different domain\n");
        return -FI_EINVAL;
    }
    eq->domain = pep->mxr_domain;

    return 0;
}

static int mxr_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
    int ret;
    struct mxr_fid_eq* eq;
    struct mxr_fid_cq* cq;
    struct mxr_fid_ep* ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid);

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "binding EP to a class %d\n", bfid->fclass);

    switch (bfid->fclass) {
    case FI_CLASS_EQ:
        eq = container_of(bfid, struct mxr_fid_eq, eq_fid.fid);
        ep->eq = eq;
        eq->ep = ep;
        if (eq->domain && (eq->domain != ep->mxr_domain)) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "EQ was already bound to a different domain\n");
            return -FI_EINVAL;
        }
        eq->domain = ep->mxr_domain;
        ret = 0;
        break;
    case FI_CLASS_CQ:
        cq = container_of(bfid, struct mxr_fid_cq, cq.fid);
        ret = fi_ep_bind(ep->rd_ep, &cq->rd_cq->fid, flags);
        break;
    default:
        ret = -FI_EINVAL;
    }

    return ret;
}

static int mxr_ep_control(struct fid *fid, int command, void *arg)
{
    int ret;
    struct mxr_fid_ep *ep;

    if (!fid) {
        return -FI_EINVAL;
    }

    switch (fid->fclass) {
    case FI_CLASS_EP:
        ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid); 
        ret = ep->rd_ep->fid.ops->control(&ep->rd_ep->fid, command, arg);
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Unsupported FI_CLASS: %d\n", fid->fclass);
        return -FI_EINVAL;
    }

    return ret;
}

static ssize_t mxr_ep_cancel(fid_t fid, void *context)
{
    ssize_t ret;
    struct mxr_request *req;
    struct dlist_entry *entry;
    struct mxr_fid_ep *ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid);

    dlist_foreach(&ep->reqs, entry) {
        req = container_of(entry, struct mxr_request, list_entry);
        if (req->user_ptr == context) {
            break;
        }
    }

    if (!req) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Unknown context: %p\n", context);
        return -FI_EINVAL;
    }

	ret = fi_cancel((fid_t)ep->rd_ep, &req->ctx);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Cannot cancel: %p (fi_context %p)\n", context, &req->ctx);
        return ret;
    }

    dlist_remove(entry);
    free(req);

    return ret;
}

static int mxr_ep_getopt(fid_t fid, int level, int optname,
        void *optval, size_t *optlen)
{
    if (level != FI_OPT_ENDPOINT) {
        return -FI_ENOPROTOOPT;
    }

    switch (optname) {
    case FI_OPT_CM_DATA_SIZE:
        *(size_t *)optval = MXR_MAX_CM_DATA_SIZE;
        *optlen = sizeof(size_t);
        break;
    default:
        return -FI_ENOPROTOOPT;
    }

	return 0;
}

static int mxr_ep_setopt(fid_t fid, int level, int optname,
        const void *optval, size_t optlen)
{
	return -FI_ENOSYS;
}

static int mxr_ep_close(fid_t fid)
{
    int ret;
    struct mxr_fid_ep *ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid);
    struct dlist_entry *entry;
    struct mxr_request *req;

    FI_WARN(&mxr_prov, FI_LOG_FABRIC, "closing EP %p\n", ep);

    while(!dlist_empty(&ep->reqs)) {
        entry = ep->reqs.next;
        req = container_of(entry, struct mxr_request, list_entry);
        ret = fi_cancel((fid_t)ep->rd_ep, &req->ctx);
        if (ret) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "Couldn't cancel request: %d\n", ret);
            return ret;
        }
        dlist_remove(entry);
        free(req);
    }

    ret = fi_close((fid_t)ep->rd_ep);
    if (ret) {
        goto errout;
    }

    free(ep);
errout:
    return ret; 
}

static int mxr_pep_close(fid_t fid)
{
    struct mxr_fid_pep *pep;
    pep = container_of(fid, struct mxr_fid_pep, pep_fid.fid);

    FI_WARN(&mxr_prov, FI_LOG_FABRIC, "closing PEP: %p\n", pep);
    free(pep);
    return 0; 
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
    .close = mxr_pep_close,
    .bind = mxr_pep_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open
};

int mxr_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_pep **pep, void *context)
{
    int ret;
    struct mxr_fid_pep *mxr_pep;
    struct fid_domain *domain;
    struct mxr_fid_fabric *mxr_fabric = (struct mxr_fid_fabric*)fabric;

    mxr_fabric = container_of(fabric, struct mxr_fid_fabric,
                              util_fabric.fabric_fid);

    if (!mxr_fabric->domain) {
        /* This initializes mxr_fabric->domain. See mxr_domain.c */
        ret = fi_domain(fabric, info, &domain, context);
        if (ret) {
            return ret;
        }
    }

    mxr_pep = (struct mxr_fid_pep*) calloc(1, sizeof(struct mxr_fid_pep));
    if (!mxr_pep) {
        return -FI_ENOMEM;
    }
    mxr_pep->mxr_domain = mxr_fabric->domain;

    if (info->src_addr && (info->src_addrlen == sizeof(struct sockaddr))) {
        memcpy(&mxr_pep->bound_addr, info->src_addr, sizeof(struct sockaddr));
    }

    mxr_pep->info = info;

    mxr_pep->pep_fid.fid.fclass = FI_CLASS_PEP;
    mxr_pep->pep_fid.fid.context = context;
    mxr_pep->pep_fid.fid.ops = &mxr_fi_ops_pep;
    mxr_pep->pep_fid.ops = &mxr_ops_ep;
    mxr_pep->pep_fid.cm = &mxr_ops_cm;
    mxr_pep->mxr_fabric = mxr_fabric;

    *pep = &mxr_pep->pep_fid;

    return 0;
}

int mxr_ep_open(struct fid_domain *domain, struct fi_info *info,
        struct fid_ep **ep, void *context)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_fid_pep *mxr_pep;
    struct mxr_fid_domain *mxr_domain = (struct mxr_fid_domain*)domain;

    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Creating new EP\n");

    mxr_ep = (struct mxr_fid_ep*) calloc(1, sizeof(*mxr_ep));
    if (!mxr_ep) {
        return -FI_ENOMEM;
    }
    memset(mxr_ep, 0, sizeof *mxr_ep);
    mxr_ep->mxr_domain = mxr_domain;
    mxr_ep->peer_fi_addr = FI_ADDR_UNSPEC;

    if (info->handle) {
        /* PEP's fid; copy bound_addr */
        mxr_pep = container_of(info->handle, struct mxr_fid_pep, pep_fid.fid);
        memcpy(&mxr_ep->bound_addr, &mxr_pep->bound_addr,
               sizeof mxr_ep->bound_addr);
    } else if (info->src_addr &&
               (info->src_addrlen == sizeof mxr_ep->bound_addr)) {
        memcpy(&mxr_ep->bound_addr, info->src_addr, info->src_addrlen);
    } else {
        /* Initialize bound_addr to 0.0.0.0:0 */
        mxr_ep->bound_addr.sin_family = AF_INET;
    }
    if (info->dest_addr && (info->dest_addrlen == sizeof(struct sockaddr))) {
        memcpy(&mxr_ep->peer_addr, info->dest_addr, info->dest_addrlen);
    }

    /* TODO: Shouldn't we pass the base info here instead? */
    ret = fi_endpoint(mxr_domain->rd_domain, info, &mxr_ep->rd_ep, context);
    if (ret) {
        goto freeep;
    }

    ret = fi_ep_bind(mxr_ep->rd_ep, (fid_t)mxr_domain->rd_av, 0);
    if (ret) {
        goto closerdep;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC, "new EP %p\n", mxr_ep);

    mxr_ep->ep_fid.fid.fclass = FI_CLASS_EP;
    mxr_ep->ep_fid.fid.context = context;
    mxr_ep->ep_fid.fid.ops = &mxr_fi_ops_ep;
    mxr_ep->ep_fid.ops = &mxr_ops_ep;
    mxr_ep->ep_fid.cm = &mxr_ops_cm;
    mxr_ep->ep_fid.msg = &mxr_ops_msg;
    mxr_ep->ep_fid.rma = &mxr_ops_rma;
    mxr_ep->ep_fid.tagged = NULL;
    mxr_ep->ep_fid.atomic = NULL;

    mxr_ep->connected = 0;

    dlist_init(&mxr_ep->reqs);

    *ep = &mxr_ep->ep_fid;

    return 0;

closerdep:
    fi_close((fid_t)&mxr_ep->rd_ep);
freeep:
    free(mxr_ep);
    return ret;
}
