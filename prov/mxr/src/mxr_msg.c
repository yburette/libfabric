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

static ssize_t mxr_ep_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
        fi_addr_t src_addr, void *context)
{
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;
    if (src_addr && (src_addr != mxr_ep->peeraddr)) {
        return -FI_EINVAL;
    }
    return fi_recv(mxr_ep->rd_ep, buf, len, desc, mxr_ep->peeraddr, context);
}

static ssize_t mxr_ep_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
                              uint64_t flags)
{
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;
    if (!msg || (msg->addr && (msg->addr != mxr_ep->peeraddr))) {
        return -FI_EINVAL;
    }
    /* FIXME: msg is const. Copy the entire struct? */
    //msg->addr = mxr_ep->peer;
    return fi_recvmsg(mxr_ep->rd_ep, msg, flags);
}

static ssize_t mxr_ep_recvv(struct fid_ep *ep, const struct iovec *iov,
		       void **desc, size_t count, fi_addr_t src_addr,
		       void *context)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_ep_send(struct fid_ep *ep, const void *buf, size_t len,
		      void *desc, fi_addr_t dest_addr, void *context)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_ep_sendv(struct fid_ep *ep, const struct iovec *iov,
		       void **desc, size_t count, fi_addr_t dest_addr,
		       void *context)
{
    return -FI_ENOSYS;
}

ssize_t mxr_ep_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
			uint64_t flags)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_ep_senddata(struct fid_ep *ep, const void *buf, size_t len,
			  void *desc, uint64_t data, fi_addr_t dest_addr,
			  void *context)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_ep_inject(struct fid_ep *ep, const void *buf, size_t len,
			fi_addr_t dest_addr)
{
    return -FI_ENOSYS;
}

static ssize_t	mxr_ep_injectdata(struct fid_ep *ep, const void *buf,
				size_t len, uint64_t data, fi_addr_t dest_addr)
{
    return -FI_ENOSYS;
}

struct fi_ops_msg mxr_ops_msg = {
	.size = sizeof(struct fi_ops_msg),
	.recv = mxr_ep_recv,
	.recvv = mxr_ep_recvv,
	.recvmsg = mxr_ep_recvmsg,
	.send = mxr_ep_send,
	.sendv = mxr_ep_sendv,
	.sendmsg = mxr_ep_sendmsg,
	.inject = mxr_ep_inject,
	.senddata = mxr_ep_senddata,
	.injectdata = mxr_ep_injectdata
};
