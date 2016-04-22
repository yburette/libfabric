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

int mxr_getname(fid_t fid, void *addr, size_t *addrlen)
{
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)fid;
    return fi_getname((fid_t)mxr_ep->rd_ep, addr, addrlen);
}

int mxr_connect(struct fid_ep *ep, const void *addr, const void *param,
       size_t paramlen)
{
    int ret;
    size_t len;
    size_t count;
    struct mxr_conn_buf *connreq_buf;
    struct mxr_conn_buf *connresp_buf;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;
    size_t namelen = FI_NAME_MAX;
    fi_addr_t remote;

    if (!addr) {
        return -FI_EINVAL;
    }

    count = fi_av_insert(mxr_ep->rd_av, addr, 1, &remote, 0, NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    mxr_ep->peeraddr = remote;

    connreq_buf = calloc(1, sizeof(struct mxr_conn_buf));
    if (!connreq_buf) {
        return -FI_ENOMEM;
    }

    connreq_buf->data.hdr.type = ofi_ctrl_connreq;
    
    ret = fi_getname((fid_t)mxr_ep->rd_ep, &connreq_buf->data.addr, &namelen);
    if (ret) {
        free(connreq_buf);
        return ret;
    }

    len = sizeof(struct ofi_ctrl_hdr) + namelen;

    connresp_buf = calloc(1, sizeof(struct mxr_conn_buf));
    if (!connresp_buf) {
        free(connreq_buf);
        return -FI_ENOMEM;
    }

    ret = fi_recv(mxr_ep->rd_ep, &connresp_buf->data, len, NULL, remote,
                  (void *) &connresp_buf->ctx);
    if (ret) {
        free(connreq_buf);
        free(connresp_buf);
        return ret;
    }

    ret = fi_send(mxr_ep->rd_ep, &connreq_buf->data, len, NULL, remote,
                  (void *) &connreq_buf->ctx); 
    if (ret) {
        free(connreq_buf);
        return ret;
    }

    return 0;
} 

int mxr_listen(struct fid_pep *pep)
{
    int ret;
    struct mxr_conn_buf *connreq_buf;
    struct mxr_fid_pep *mxr_pep = (struct mxr_fid_pep*)pep;

    /* TODO: This should actually be a list of buffers as deep as the EQ? */
    connreq_buf = calloc(1, sizeof(struct mxr_conn_buf));
    if (!connreq_buf) {
        return -FI_ENOMEM;
    }

    ret = fi_enable(mxr_pep->rd_ep);
    if (ret) {
        goto freebuf;
    }

    ret = fi_recv(mxr_pep->rd_ep,
                  &connreq_buf->data,
                  sizeof(struct mxr_conn_pkt),
                  NULL,
                  FI_ADDR_UNSPEC,
                  (void *) &connreq_buf->ctx);
    if (ret) {
        /* TODO: What will happen once this is a list? */
        goto freebuf;
    }

    return 0;
freebuf:
    free(connreq_buf);
    return ret;
}

int mxr_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
    int ret;
    size_t namelen;
    size_t len;
    ssize_t count;
    fi_addr_t remote;
    struct mxr_conn_buf *connresp_buf;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;

    if (!mxr_ep->peername) {
        return -FI_EINVAL;
    }

    if (!mxr_ep->pep) {
        return -FI_EINVAL;
    }

    count = fi_av_insert(mxr_ep->pep->rd_av,
                         mxr_ep->peername,
                         1,
                         &remote,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    count = fi_av_insert(mxr_ep->rd_av,
                         mxr_ep->peername,
                         1,
                         &mxr_ep->peeraddr,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    connresp_buf = calloc(1, sizeof(struct mxr_conn_buf));
    if (!connresp_buf) {
        return -FI_ENOMEM;
    }

    connresp_buf->data.hdr.type = ofi_ctrl_connresp;
    
    ret = fi_getname((fid_t)mxr_ep->rd_ep, &connresp_buf->data.addr, &namelen);
    if (ret) {
        free(connresp_buf);
        return ret;
    }

    len = sizeof(struct ofi_ctrl_hdr) + namelen;

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "Sending a ofi_ctrl_connresp (mxr_ep %p pep %p)\n",
            mxr_ep, mxr_ep->pep);
    ret = fi_send(mxr_ep->pep->rd_ep, &connresp_buf->data, len, NULL,
                  remote, (void *) &connresp_buf->ctx);
    if(ret) {
        free(connresp_buf);
        return ret;
    }

    return 0;
}

int mxr_reject(struct fid_pep *pep, fid_t handle, const void *param,
        size_t paramlen)
{
    /* TODO: Send CONNREJ. */
    return -FI_ENOSYS;
}

struct fi_ops_cm mxr_ops_cm = {
    .size = sizeof(struct fi_ops_cm),
    .setname = fi_no_setname,
    .getname = mxr_getname,
    .getpeer = fi_no_getpeer,
    .connect = mxr_connect,
    .listen = mxr_listen,
    .accept = mxr_accept,
    .reject = mxr_reject,
    .shutdown = fi_no_shutdown
};

