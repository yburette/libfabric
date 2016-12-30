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
    int ret;
    struct mxr_fid_pep* mxr_pep;
    struct mxr_fid_eq* mxr_eq;
    struct fi_cq_attr cq_attr;

    FI_INFO(&mxr_prov, FI_LOG_FABRIC,
            "binding PEP to a class %d\n", bfid->fclass);

    if (bfid->fclass != FI_CLASS_EQ) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "class %d cannot be bound to PEP\n", bfid->fclass);
        return -FI_EINVAL;
    }

    mxr_pep = container_of(fid, struct mxr_fid_pep, pep.fid);
    mxr_eq = container_of(bfid, struct mxr_fid_eq, eq.fid);

    mxr_pep->mxr_eq = mxr_eq;
    mxr_eq->mxr_pep = mxr_pep;
    
#if 0
    cq_attr.format = FI_CQ_FORMAT_TAGGED;
#endif
    ret = fi_cq_open(mxr_pep->mxr_domain->rd_domain, &mxr_eq->cq_attr,
                     &mxr_eq->rd_cq, NULL);
    if (ret) {
        goto errout;
    }

    ret = fi_ep_bind(mxr_pep->ctrl_ep, (fid_t)mxr_eq->rd_cq,
                     FI_RECV | FI_SEND);
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

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "binding EP to a class %d\n", bfid->fclass);

    mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid);

    switch (bfid->fclass) {
    case FI_CLASS_EQ:
        mxr_eq = container_of(bfid, struct mxr_fid_eq, eq.fid);

        mxr_ep->mxr_eq = mxr_eq;
        mxr_eq->mxr_ep = mxr_ep;
        mxr_eq->rd_domain = mxr_ep->mxr_domain->rd_domain;

        /* 
         * Client's EQ needs an underlying CQ;
         * Server's EQ already set up in mxr_pep_bind.
         */
        if (!mxr_eq->rd_cq) {
#if 0
            cq_attr.format = FI_CQ_FORMAT_TAGGED;
#endif
            ret = fi_cq_open(mxr_ep->mxr_domain->rd_domain, &mxr_eq->cq_attr,
                             &mxr_eq->rd_cq, NULL);
            if (ret) {
                goto errout;
            }
        }

        ret = fi_ep_bind(mxr_ep->ctrl_ep, (fid_t)mxr_eq->rd_cq,
                         FI_RECV | FI_SEND);
        if (ret) {
            fi_close((fid_t)mxr_eq->rd_cq);
            goto errout;
        }
        ret = 0;
        break;
    case FI_CLASS_CQ:
        ret = fi_ep_bind(mxr_ep->data_ep, bfid, flags);
        break;
    default:
        ret = -FI_EINVAL;
    }

errout:
    return ret;
}

static int mxr_ep_control(struct fid *fid, int command, void *arg)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;

    if (!fid) {
        return -FI_EINVAL;
    }

    switch (fid->fclass) {
    case FI_CLASS_EP:
        mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid); 
        ret = mxr_ep->ctrl_ep->fid.ops->control(&mxr_ep->ctrl_ep->fid,
                                                command, arg);
        if (ret) {
            break;
        }
        ret = mxr_ep->data_ep->fid.ops->control(&mxr_ep->data_ep->fid,
                                                command, arg);
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
    struct mxr_fid_ep *mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid);
	return fi_cancel((fid_t)mxr_ep->data_ep, context);
}

static int mxr_ep_getopt(fid_t fid, int level, int optname,
        void *optval, size_t *optlen)
{
    if (level != FI_OPT_ENDPOINT) {
        return -FI_ENOPROTOOPT;
    }

    switch (optname) {
    case FI_OPT_CM_DATA_SIZE:
        *(size_t *)optval = MXR_MAX_CM_SIZE;
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
    struct mxr_fid_ep *mxr_ep = container_of(fid, struct mxr_fid_ep, ep.fid);

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "closing EP %p ctrl_ep %p data_ep %p mxr_domain %p rd_domain %p\n",
            mxr_ep, mxr_ep->ctrl_ep, mxr_ep->data_ep,
            mxr_ep->mxr_domain, mxr_ep->mxr_domain->rd_domain);

    ret = fi_close((fid_t)mxr_ep->ctrl_ep);
    if (ret) {
        goto errout;
    }

    ret = fi_close((fid_t)mxr_ep->data_ep);
    if (ret) {
        goto errout;
    }

    free(mxr_ep);
errout:
    return ret; 
}

static int mxr_pep_close(fid_t fid)
{
    int ret;
    struct mxr_fid_pep *mxr_pep = container_of(fid, struct mxr_fid_pep, pep.fid);
    struct mxr_fid_eq *mxr_eq = mxr_pep->mxr_eq;
	struct slist_entry *entry;
	struct mxr_conn_buf *req;

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "closing PEP: %p ctrl_ep %p rd_domain %p\n",
            mxr_pep, mxr_pep->ctrl_ep, mxr_pep->mxr_domain->rd_domain);

    if (mxr_eq) {
        while (!slist_empty(&mxr_eq->connreqs)) {
            entry = slist_remove_head(&mxr_eq->connreqs);
            req = container_of(entry, struct mxr_conn_buf, list_entry);
            ret = fi_cancel((fid_t)mxr_pep->ctrl_ep, &req->ctx);
            if (ret) {
                FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                        "Couldn't cancel request\n", ret);
                return ret;
            }
            free(req);
        }

        mxr_eq->mxr_pep = NULL;
    }

    ret = fi_close((fid_t)mxr_pep->ctrl_ep);
    if (ret) {
        goto errout;
    }
#if 0

    ret = mxr_stop_nameserver(mxr_pep);
    if (ret) {
        goto errout;
    }
#endif

    free(mxr_pep);
errout:
    return ret; 
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
    int err;
    struct mxr_fid_pep *mxr_pep;
    struct mxr_fid_domain *mxr_domain;
    struct fid_domain *domain;
    struct mxr_fid_fabric *mxr_fabric = (struct mxr_fid_fabric*)fabric;

    mxr_fabric = container_of(fabric, struct mxr_fid_fabric,
                              util_fabric.fabric_fid);

    if (!mxr_fabric->mxr_domain) {
        /* This initializes mxr_fabric->mxr_domain. See mxr_domain.c */
        ret = fi_domain(fabric, info, &domain, context);
        if (ret) {
            goto errout;
        }
    }
    mxr_domain = mxr_fabric->mxr_domain;

    mxr_pep = (struct mxr_fid_pep*) calloc(1, sizeof(struct mxr_fid_pep));
    if (!mxr_pep) {
        err = -FI_ENOMEM;
        goto errout;
    }

    mxr_pep->mxr_domain = mxr_domain;

    ret = fi_endpoint(mxr_domain->rd_domain, info, &mxr_pep->ctrl_ep, context);
    if (ret) {
        err = ret;
        goto freepep;
    }

    ret = fi_ep_bind(mxr_pep->ctrl_ep, (fid_t)mxr_domain->rd_av, 0);
    if (ret) {
        err = ret;
        goto closerdep;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "new PEP: %p ctrl_ep %p rd_domain %p\n",
            mxr_pep, mxr_pep->ctrl_ep, mxr_domain->rd_domain);

    mxr_pep->info = info;

    mxr_pep->pep.fid.fclass = FI_CLASS_PEP;
    mxr_pep->pep.fid.context = context;
    mxr_pep->pep.fid.ops = &mxr_fi_ops_pep;
    mxr_pep->pep.ops = &mxr_ops_ep;
    mxr_pep->pep.cm = &mxr_ops_cm;
    mxr_pep->mxr_fabric = mxr_fabric;

    *pep = &mxr_pep->pep;

    return 0;

closerdep:
    fi_close((fid_t)mxr_pep->ctrl_ep);
freepep:
    free(mxr_pep);
errout:
    return err;
}

static int parse_epnames(void *buf, size_t len, void **ctrl, void **data)
{
    int ret;
    size_t namelen;
    char *ctrl_name;
    char *data_name;

    if((len % 2) != 0) {
        return -FI_EINVAL;
    }

    namelen = len / 2;

    ctrl_name = calloc(namelen, sizeof(char));
    if (!ctrl_name) {
        return -FI_ENOMEM;
    }

    data_name = calloc(namelen, sizeof(char));
    if (!data_name) {
        ret = -FI_ENOMEM;
        goto freectrlname;
    }

    memcpy(ctrl_name, buf, namelen);
    memcpy(data_name, buf+namelen, namelen);

    *ctrl = ctrl_name;
    *data = data_name;

    return 0;
freectrlname:
    free(ctrl_name);
    return ret;
}

int mxr_ep_open(struct fid_domain *domain, struct fi_info *info,
        struct fid_ep **ep, void *context)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_fid_domain *mxr_domain = (struct mxr_fid_domain*)domain;

    mxr_ep = (struct mxr_fid_ep*) calloc(1, sizeof(*mxr_ep));
    if (!mxr_ep) {
        ret = -FI_ENOMEM;
        goto errout;
    }
    mxr_ep->mxr_domain = mxr_domain;

    /* Save dest_addr if provided. */
    if (info->dest_addr && info->dest_addrlen > 0) {

        ret = parse_epnames(info->dest_addr,
                            info->dest_addrlen,
                            &mxr_ep->peer_ctrl_epname,
                            &mxr_ep->peer_data_epname);
        if (ret) {
            goto freeep;
        }
    }

    if (info->src_addr && info->src_addrlen > 0) {
#if 0
        switch (info->addr_format) {
        case FI_SOCKADDR:
        case FI_SOCKADDR_IN:
        case FI_SOCKADDR_IN6:
#endif
            memcpy(&mxr_ep->bound_addr, info->src_addr, info->src_addrlen);
            mxr_ep->bound_addrlen = info->src_addrlen;
#if 0
            break;
        default:
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "cannot handle addr_format: %d\n", info->addr_format);
        };
#endif
    }

    /* TODO: Shouldn't we pass the base info here instead? */
    ret = fi_endpoint(mxr_domain->rd_domain, info, &mxr_ep->ctrl_ep, context);
    if (ret) {
        goto freepeernames;
    }

    ret = fi_endpoint(mxr_domain->rd_domain, info, &mxr_ep->data_ep, context);
    if (ret) {
        goto closectrlep;
    }

    ret = fi_ep_bind(mxr_ep->ctrl_ep, (fid_t)mxr_domain->rd_av, 0);
    if (ret) {
        goto closedataep;
    }

    ret = fi_ep_bind(mxr_ep->data_ep, (fid_t)mxr_domain->rd_av, 0);
    if (ret) {
        goto closedataep;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "new EP %p ctrl_ep %p data_ep %p mxr_domain %p rd_domain %p\n",
            mxr_ep, mxr_ep->ctrl_ep, mxr_ep->data_ep,
            mxr_domain, mxr_domain->rd_domain);

    mxr_ep->ep.fid.fclass = FI_CLASS_EP;
    mxr_ep->ep.fid.context = context;
    mxr_ep->ep.fid.ops = &mxr_fi_ops_ep;
    mxr_ep->ep.ops = &mxr_ops_ep;
    mxr_ep->ep.cm = &mxr_ops_cm;
    mxr_ep->ep.msg = &mxr_ops_msg;
    mxr_ep->ep.rma = &mxr_ops_rma;
    mxr_ep->ep.tagged = NULL;
    mxr_ep->ep.atomic = NULL;

    mxr_ep->connected = 0;

    *ep = &mxr_ep->ep;

    return 0;

closedataep:
    fi_close((fid_t)&mxr_ep->data_ep);
closectrlep:
    fi_close((fid_t)&mxr_ep->ctrl_ep);
freepeernames:
    if (mxr_ep->peer_ctrl_epname)
        free(mxr_ep->peer_ctrl_epname);
    if (mxr_ep->peer_data_epname)
        free(mxr_ep->peer_data_epname);
freeep:
    free(mxr_ep);
errout:
    return ret;
}
