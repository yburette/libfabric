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

inline
size_t extract_cm_data(struct fi_eq_cm_entry *entry, struct mxr_conn_buf *buf)
{
    size_t datalen = buf->data.hdr.cm_datalen;
    if (datalen) {
        memcpy(&entry->data, buf->data.hdr.cm_data, datalen);
    }
    return datalen;
}

int prepare_cm_req(struct mxr_conn_buf *req, int type,
        struct mxr_fid_ep *mxr_ep, const void *param, size_t paramlen,
        size_t *len)
{
    int ret;
    char *name;
    size_t len1 = FI_NAME_MAX;
    size_t len2 = FI_NAME_MAX;

    req->mxr_ep = mxr_ep;
    req->data.hdr.type = type;
    *len = sizeof(struct mxr_conn_hdr);

    switch(type) {
    case MXR_CONN_REQ:
    case MXR_CONN_RESP:
        name = req->data.epnames;
        ret = fi_getname((fid_t)mxr_ep->ctrl_ep, name, &len1);
        if (ret) {
            return ret;
        }

        name += len1;
        ret = fi_getname((fid_t)mxr_ep->data_ep, name, &len2);
        if (ret) {
            return ret;
        }

        assert(len1 == len2);

        *len += len1 + len2;
        /* Fall through */
    case MXR_CONN_ACK:
    case MXR_CONN_REJ:
        if (paramlen > 0) {
            if (paramlen > sizeof(req->data.hdr.cm_data)) {
                return -FI_EINVAL;
            }
            memcpy((void*)&req->data.hdr.cm_data, param, paramlen);
        }
        req->data.hdr.cm_datalen = paramlen;
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown cm req type\n");
        return -FI_EINVAL;
    }

    return 0;
}

int mxr_getname(fid_t fid, void *addr, size_t *addrlen)
{
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)fid;
    return fi_getname((fid_t)mxr_ep->data_ep, addr, addrlen);
}

int mxr_connect(struct fid_ep *ep, const void *addr, const void *param,
       size_t paramlen)
{
    /* Send to the passive side:
     *  - our control EP name
     *  - our data EP name
     * Receive ACK:
     *  - other side's control EP name
     *  - other side's data EP name
     */
    int ret;
    size_t len;
    size_t count;
    struct mxr_conn_buf *req;
    struct mxr_conn_buf *resp;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;

    if (!addr) {
        return -FI_EINVAL;
    }

    count = fi_av_insert(mxr_ep->mxr_domain->rd_av, addr, 1,
                         &mxr_ep->peer_ctrl_addr, 0, NULL);
    if (1 != count) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "fi_av_insert failed: %ld\n", count);
        return -FI_EOTHER;
    }

    req = calloc(1, sizeof(struct mxr_conn_buf));
    if (!req) {
        return -FI_ENOMEM;
    }

    ret = prepare_cm_req(req, MXR_CONN_REQ, mxr_ep, param, paramlen, &len);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "prepare_cm_req failed\n");
        goto freereq;
    }

    resp = calloc(1, sizeof(struct mxr_conn_buf));
    if (!resp) {
        ret = -FI_ENOMEM;
        goto freereq;
    }
    resp->mxr_ep = mxr_ep;

    ret = fi_recv(mxr_ep->ctrl_ep, &resp->data, len, NULL,
                  FI_ADDR_UNSPEC, (void *) &resp->ctx);
    if (ret) {
        goto freeresp;
    }

    ret = fi_send(mxr_ep->ctrl_ep, &req->data, len, NULL,
                  mxr_ep->peer_ctrl_addr, (void *) &req->ctx); 
    if (ret) {
        /* TODO: cancel resp */
        goto freereq;
    }

    return 0;
freeresp:
    free(resp);
freereq:
    free(req);
    return ret;
} 

int mxr_listen(struct fid_pep *pep)
{
    int ret;
    struct mxr_conn_buf *req;
    struct mxr_fid_pep *mxr_pep = (struct mxr_fid_pep*)pep;

    /* TODO: This should actually be a list of buffers as deep as the EQ? */
    req = calloc(1, sizeof(struct mxr_conn_buf));
    if (!req) {
        return -FI_ENOMEM;
    }

    slist_insert_tail(&req->list_entry, &mxr_pep->mxr_eq->connreqs);

    ret = fi_enable(mxr_pep->ctrl_ep);
    if (ret) {
        goto freebuf;
    }

    ret = fi_recv(mxr_pep->ctrl_ep,
                  &req->data,
                  sizeof(struct mxr_conn_pkt),
                  NULL,
                  FI_ADDR_UNSPEC,
                  (void *) &req->ctx);
    if (ret) {
        /* TODO: What will happen once this is a list? */
        goto freebuf;
    }

    return 0;
freebuf:
    free(req);
    return ret;
}

int mxr_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
    int ret;
    size_t len;
    ssize_t count;
    struct mxr_conn_buf *resp;
    struct mxr_conn_buf *ack;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;

    if (!mxr_ep->peer_ctrl_epname || !mxr_ep->peer_data_epname) {
        return -FI_EINVAL;
    }

    count = fi_av_insert(mxr_ep->mxr_domain->rd_av,
                         mxr_ep->peer_ctrl_epname,
                         1,
                         &mxr_ep->peer_ctrl_addr,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    count = fi_av_insert(mxr_ep->mxr_domain->rd_av,
                         mxr_ep->peer_data_epname,
                         1,
                         &mxr_ep->peer_data_addr,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    ack = calloc(1, sizeof(struct mxr_conn_buf));
    if (!ack) {
        return -FI_ENOMEM;
    }
    ack->mxr_ep = mxr_ep;

    resp = calloc(1, sizeof(struct mxr_conn_buf));
    if (!resp) {
        ret = -FI_ENOMEM;
        goto freeack;
    }

    ret = prepare_cm_req(resp, MXR_CONN_RESP, mxr_ep, param, paramlen, &len);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "prepare_cm_req failed\n");
        goto freeresp;
    }

    ret = fi_recv(mxr_ep->ctrl_ep, &ack->data, sizeof(struct mxr_conn_hdr),
                  NULL, mxr_ep->peer_ctrl_addr, (void *) &ack->ctx);
    if (ret) {
        goto freeresp;
    }

    FI_INFO(&mxr_prov, FI_LOG_FABRIC,
            "Sending a MXR_CONN_RESP (mxr_ep %p pep %p)\n",
            mxr_ep, mxr_ep->pep);

    ret = fi_send(mxr_ep->ctrl_ep, &resp->data, len, NULL,
                  mxr_ep->peer_ctrl_addr, (void *) &resp->ctx);
    if(ret) {
        /* TODO: cancel ack? */
        goto freeresp;
    }

    return 0;
freeresp:
    free(resp);
freeack:
    free(ack);
    return ret;
}

int mxr_reject(struct fid_pep *pep, fid_t handle, const void *param,
        size_t paramlen)
{
    int ret;
    size_t count;
    size_t len;
    struct mxr_conn_buf *rej;
    fi_addr_t remote_fi_addr;
    struct fi_info *info;
    struct mxr_fid_pep *mxr_pep = (struct mxr_fid_pep*)pep;

    info = (struct fi_info *)handle;

    count = fi_av_insert(mxr_pep->mxr_domain->rd_av,
                         info->dest_addr,
                         1,
                         &remote_fi_addr,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    rej = calloc(1, sizeof(struct mxr_conn_buf));
    if (!rej) {
        return -FI_ENOMEM;
    }

    ret = prepare_cm_req(rej, MXR_CONN_REJ, NULL, param, paramlen, &len);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "prepare_cm_req failed\n");
        goto freerej;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "Sending a MXR_CONN_REJ (mxr_pep %p)\n", mxr_pep);

    ret = fi_send(mxr_pep->ctrl_ep, &rej->data, len, NULL,
                  remote_fi_addr, (void *) &rej->ctx);
    if(ret) {
        goto freerej;
    }

    return 0;
freerej:
    free(rej);
    return ret;
}

static int mxr_shutdown(struct fid_ep *ep, uint64_t flags)
{
    int ret;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;
    struct fi_eq_cm_entry *entry;

    if (!mxr_ep->mxr_eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Error: EP %p isn't bound to any EQ\n", mxr_ep);
        return -FI_EINVAL;
    }

    if (mxr_ep->mxr_eq->shutdown_entry) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Error: shutdown_entry already initialized\n");
        return -FI_EOTHER;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return -FI_ENOMEM;
    }
    entry->fid = &ep->fid;
    mxr_ep->mxr_eq->shutdown_entry = entry;

    /* TODO: Notify other side using ctrl EP */
    /* TODO: Shutdown both EPs if necessary... */

    ret = fi_shutdown(mxr_ep->ctrl_ep, flags);
    if (ret) {
        goto errout;
    }

    ret = fi_shutdown(mxr_ep->data_ep, flags);
   
errout:
    return ret;
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
    .shutdown = mxr_shutdown
};

