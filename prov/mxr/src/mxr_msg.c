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

static ssize_t mxr_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
        fi_addr_t src_addr, void *context)
{
    struct mxr_fid_ep *mxr_ep;
    fi_addr_t addr = FI_ADDR_UNSPEC;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (mxr_ep->connected) {
        addr = mxr_ep->peer_data_addr;
    }
    return fi_recv(mxr_ep->data_ep, buf, len, desc, addr, context);
}

static ssize_t mxr_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
                              uint64_t flags)
{
    struct mxr_fid_ep *mxr_ep;
    struct fi_msg rd_msg;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (!msg) {
        return -FI_EINVAL;
    }

    /* msg is const. Use proxy fi_msg to set remote addr */ 
    memset(&rd_msg, 0, sizeof rd_msg);
    rd_msg.msg_iov   = msg->msg_iov;
    rd_msg.desc      = msg->desc;
    rd_msg.iov_count = msg->iov_count;
    rd_msg.addr      = mxr_ep->peer_data_addr;
    rd_msg.context   = msg->context;

    return fi_recvmsg(mxr_ep->data_ep, msg, flags);
}

static ssize_t mxr_recvv(struct fid_ep *ep, const struct iovec *iov,
		       void **desc, size_t count, fi_addr_t src_addr,
		       void *context)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (!mxr_ep->connected) {
        return -FI_EINVAL;
    }
    return fi_recvv(mxr_ep->data_ep, iov, desc, count,
                    mxr_ep->peer_data_addr, context);
}

static ssize_t mxr_send(struct fid_ep *ep, const void *buf, size_t len,
		      void *desc, fi_addr_t dest_addr, void *context)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if ((dest_addr != FI_ADDR_UNSPEC) && (dest_addr != mxr_ep->peer_data_addr)) {
        return -FI_EINVAL;
    }
    return fi_send(mxr_ep->data_ep, buf, len, desc, mxr_ep->peer_data_addr, context);
}

static ssize_t mxr_sendv(struct fid_ep *ep, const struct iovec *iov,
		       void **desc, size_t count, fi_addr_t dest_addr,
		       void *context)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (!mxr_ep->connected) {
        return -FI_EINVAL;
    }
    return fi_sendv(mxr_ep->data_ep, iov, desc, count,
                    mxr_ep->peer_data_addr, context);
}

ssize_t mxr_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
			uint64_t flags)
{
    struct mxr_fid_ep *mxr_ep;
    struct fi_msg rd_msg;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (!msg) {
        return -FI_EINVAL;
    }

    /* msg is const. Use proxy fi_msg to set remote addr */ 
    memset(&rd_msg, 0, sizeof rd_msg);
    rd_msg.msg_iov   = msg->msg_iov;
    rd_msg.desc      = msg->desc;
    rd_msg.iov_count = msg->iov_count;
    rd_msg.addr      = mxr_ep->peer_data_addr;
    rd_msg.context   = msg->context;
    
    return fi_sendmsg(mxr_ep->data_ep, &rd_msg, flags);
}

static ssize_t mxr_senddata(struct fid_ep *ep, const void *buf, size_t len,
			  void *desc, uint64_t data, fi_addr_t dest_addr,
			  void *context)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (dest_addr && (dest_addr != mxr_ep->peer_data_addr)) {
        return -FI_EINVAL;
    }
    return fi_senddata(mxr_ep->data_ep, buf, len, desc, data,
                       mxr_ep->peer_data_addr, context);
}

static ssize_t mxr_inject(struct fid_ep *ep, const void *buf, size_t len,
			fi_addr_t dest_addr)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (dest_addr && (dest_addr != mxr_ep->peer_data_addr)) {
        return -FI_EINVAL;
    }
    return fi_inject(mxr_ep->data_ep, buf, len, mxr_ep->peer_data_addr);
}

static ssize_t	mxr_injectdata(struct fid_ep *ep, const void *buf,
				size_t len, uint64_t data, fi_addr_t dest_addr)
{
    struct mxr_fid_ep *mxr_ep;

    mxr_ep = container_of(ep, struct mxr_fid_ep, ep.fid);
    if (dest_addr && (dest_addr != mxr_ep->peer_data_addr)) {
        return -FI_EINVAL;
    }
    return fi_injectdata(mxr_ep->data_ep, buf, len, data,
                         mxr_ep->peer_data_addr);
}

struct fi_ops_msg mxr_ops_msg = {
	.size = sizeof(struct fi_ops_msg),
	.recv = mxr_recv,
	.recvv = mxr_recvv,
	.recvmsg = mxr_recvmsg,
	.send = mxr_send,
	.sendv = mxr_sendv,
	.sendmsg = mxr_sendmsg,
	.inject = mxr_inject,
	.senddata = mxr_senddata,
	.injectdata = mxr_injectdata
};
