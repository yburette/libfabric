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

static ssize_t mxr_read(struct fid_ep *ep, void *buf, size_t len, void *desc,
        fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = context;

    return fi_read(mxr_ep->rd_ep, buf, len, desc,
                   mxr_ep->peer_fi_addr, addr, key, &mxr_req->ctx);
}

static ssize_t mxr_readv(struct fid_ep *ep, const struct iovec *iov, void **desc,
        size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key,
        void *context)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = context;

    return fi_readv(mxr_ep->rd_ep, iov, desc, count,
                    mxr_ep->peer_fi_addr, addr, key, &mxr_req->ctx);
}

static ssize_t mxr_readmsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
        uint64_t flags)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;
    struct fi_msg_rma rd_msg;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);
    if (!msg) {
        return -FI_EINVAL;
    }

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = msg->context;


    /* msg is const. Use proxy fi_msg to set remote addr */ 
    memset(&rd_msg, 0, sizeof rd_msg);
    rd_msg.msg_iov       = msg->msg_iov;
    rd_msg.desc          = msg->desc;
    rd_msg.iov_count     = msg->iov_count;
    rd_msg.addr          = mxr_ep->peer_fi_addr;
    rd_msg.rma_iov       = msg->rma_iov;
    rd_msg.rma_iov_count = msg->rma_iov_count;
    rd_msg.context       = &mxr_req->ctx;
    rd_msg.data          = msg->data;

    return fi_readmsg(mxr_ep->rd_ep, msg, flags);
}

static ssize_t mxr_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
        fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = context;

    return fi_write(mxr_ep->rd_ep, buf, len, desc,
                    mxr_ep->peer_fi_addr, addr, key, &mxr_req->ctx);
}

static ssize_t mxr_writev(struct fid_ep *ep, const struct iovec *iov, void **desc,
        size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
        void *context)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = context;

    return fi_writev(mxr_ep->rd_ep, iov, desc, count,
                     mxr_ep->peer_fi_addr, addr, key, &mxr_req->ctx);
}

static ssize_t mxr_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
        uint64_t flags)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;
    struct fi_msg_rma rd_msg;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);
    if (!msg) {
        return -FI_EINVAL;
    }

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = msg->context;

    /* msg is const. Use proxy fi_msg to set remote addr */ 
    memset(&rd_msg, 0, sizeof rd_msg);
    rd_msg.msg_iov       = msg->msg_iov;
    rd_msg.desc          = msg->desc;
    rd_msg.iov_count     = msg->iov_count;
    rd_msg.addr          = mxr_ep->peer_fi_addr;
    rd_msg.rma_iov       = msg->rma_iov;
    rd_msg.rma_iov_count = msg->rma_iov_count;
    rd_msg.context       = &mxr_req->ctx;
    rd_msg.data          = msg->data;

    return fi_writemsg(mxr_ep->rd_ep, msg, flags);
}

static ssize_t mxr_inject(struct fid_ep *ep, const void *buf, size_t len,
        fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);
    return fi_inject_write(mxr_ep->rd_ep, buf, len,
                           mxr_ep->peer_fi_addr, addr, key);
}

static ssize_t mxr_writedata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
        uint64_t data, fi_addr_t dest_addr, uint64_t addr, uint64_t key,
        void *context)
{
    struct mxr_fid_ep *mxr_ep;
    struct mxr_request *mxr_req;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);

    NEW_MXR_REQ(mxr_ep, mxr_req);
    mxr_req->user_ptr = context;

    return fi_writedata(mxr_ep->rd_ep, buf, len, desc, data,
                        mxr_ep->peer_fi_addr, addr, key, &mxr_req->ctx);
}

static ssize_t mxr_injectdata(struct fid_ep *ep, const void *buf, size_t len,
        uint64_t data, fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep_fid.fid);
    return fi_inject_writedata(mxr_ep->rd_ep, buf, len, data,
                               mxr_ep->peer_fi_addr, addr, key);
}

struct fi_ops_rma mxr_ops_rma = {
	.size = sizeof(struct fi_ops_rma),
	.read = mxr_read,
	.readv = mxr_readv,
	.readmsg = mxr_readmsg,
	.write = mxr_write,
	.writev = mxr_writev,
	.writemsg = mxr_writemsg,
	.inject = mxr_inject,
	.writedata = mxr_writedata,
	.injectdata = mxr_injectdata
};
